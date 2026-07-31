//! What a user may change about their own account, from their own client.
//!
//! Outer type 1003, `UserdataEnvelope`. Until this existed the envelope was
//! decoded by nothing at all: a client could send every message in it and the
//! server would drop each one without a line in any log — a whole surface that
//! silently did nothing.
//!
//! # The account is never on the wire
//!
//! Every action here applies to the account behind the session the frame
//! arrived on, resolved through `session-view`. There is no account id in
//! `AccountAction` to get wrong, to forget to check, or to change in a debugger.
//! This is the same rule `permissions::CheckSession` exists to enforce, for the
//! same reason.
//!
//! # Why the password is asked for again
//!
//! A session is a connection someone has already authenticated, and that is
//! exactly what a hijacked session also is. Requiring the current password for
//! anything sensitive means the worst an attacker on a live session can do is
//! read; they cannot take the account. It is checked **once**, here, before
//! anything dispatches, rather than inside each verb where one of them would
//! eventually forget.
//!
//! # Enrolling a second factor takes two messages
//!
//! `ENABLE_TOTP` with no code returns a fresh secret and stores it **in
//! memory**; `ENABLE_TOTP` carrying a code confirms it and only then does it
//! reach the database. The one-shot alternative — generate, store, enable —
//! locks out any user whose authenticator never got the secret, and they cannot
//! fix it themselves, because logging in is what now needs the code. Held in
//! memory because an enrolment nobody finished should evaporate: a restart
//! costs a re-scan, and that is the cheap direction to be wrong in.

use std::collections::HashMap;

use prost::Message as _;
use starling_proto_fancy::fancy::domain::{
    AccountAck, AccountAction, Settings, SettingsUpdate, UserdataEnvelope, account_action,
    userdata_envelope,
};
use starling_proto_fancy::userdata::{Account, UpdateRequest};
use starling_runtime::ids::now_ms;
use starling_runtime::plane::{Actions, Inbound, to_conn};

use crate::{UserdataService, actor_of, outer_type};

/// How long an unconfirmed enrolment stays valid.
///
/// Long enough to open an authenticator app and type a code, short enough that
/// a secret handed out and abandoned is not sitting in memory at closing time.
const ENROLMENT_MS: u64 = 10 * 60 * 1000;

/// A TOTP secret that has been handed out and not yet confirmed.
#[derive(Debug, Clone)]
pub struct Enrolment {
    secret: Vec<u8>,
    expires_at_ms: u64,
}

/// Unconfirmed enrolments, keyed by account.
pub type Enrolments = HashMap<(u32, u64), Enrolment>;

/// Which verbs may not be attempted on a session alone.
///
/// `UNSPECIFIED` is not in the list and never can be: it is refused before the
/// question of proof arises.
const fn needs_password(kind: account_action::Kind) -> bool {
    !matches!(kind, account_action::Kind::Unspecified)
}

impl UserdataService {
    /// A frame on the userdata envelope.
    pub(crate) async fn on_self_service(&self, inbound: &Inbound) -> Actions {
        let Ok(envelope) = UserdataEnvelope::decode(inbound.payload.as_slice()) else {
            tracing::debug!(
                session = inbound.session,
                len = inbound.payload.len(),
                "undecodable UserdataEnvelope"
            );
            return Actions::new();
        };
        let Some(account) = self.account_of(inbound.scope, inbound.session).await else {
            // A guest. Not an error and not silence either: every one of these
            // actions needs an account to act on, and a client that shows the
            // dialog to an unregistered user should hear why.
            return match envelope.body {
                Some(userdata_envelope::Body::Action(action)) => {
                    vec![self.reply(
                        inbound,
                        refuse(
                            action.kind,
                            "this connection is not signed in to an account",
                        ),
                    )]
                }
                _ => Actions::new(),
            };
        };

        match envelope.body {
            Some(userdata_envelope::Body::Action(action)) => {
                let ack = self.act(inbound, account, action).await;
                vec![self.reply(inbound, ack)]
            }
            Some(userdata_envelope::Body::SettingsQuery(_)) => {
                vec![self.settings_reply(inbound, account)]
            }
            Some(userdata_envelope::Body::SettingsUpdate(update)) => {
                self.write_settings(inbound.scope, account, update).await;
                // The whole set back, not an acknowledgement: the client's copy
                // should be what the server holds, and a client that merges its
                // own optimistic guess is one whose settings differ from the
                // ones being applied.
                vec![self.settings_reply(inbound, account)]
            }
            // Server to client, or an empty envelope.
            Some(userdata_envelope::Body::Ack(_) | userdata_envelope::Body::Settings(_)) | None => {
                Actions::new()
            }
        }
    }

    /// Carry out one action, having established whose account it is.
    async fn act(&self, inbound: &Inbound, account: u64, action: AccountAction) -> AccountAck {
        let kind = account_action::Kind::try_from(action.kind)
            .unwrap_or(account_action::Kind::Unspecified);
        if matches!(kind, account_action::Kind::Unspecified) {
            // The zero value, which is what a client that forgot the field
            // sends. It used to be SET_PASSWORD.
            return refuse(action.kind, "no action was named");
        }

        if needs_password(kind) && !self.proves_password(inbound.scope, account, &action).await {
            self.logger.log(
                starling_runtime::log::LogEvent::notice(
                    starling_runtime::log::Category::Security,
                    "a self-service action was refused: wrong password",
                )
                .with("account", account)
                .with("action", format!("{kind:?}")),
            );
            return refuse(action.kind, "the current password is wrong");
        }

        match kind {
            account_action::Kind::Unspecified => refuse(action.kind, "no action was named"),
            account_action::Kind::SetPassword => self.set_password(inbound, account, &action).await,
            account_action::Kind::SetEmail => self.set_email(inbound, account, &action).await,
            account_action::Kind::Rename => self.rename_self(inbound, account, &action).await,
            account_action::Kind::EnableTotp => self.enable_totp(inbound, account, &action).await,
            account_action::Kind::DisableTotp => self.disable_totp(inbound, account, &action).await,
            account_action::Kind::Unregister => self.unregister_self(inbound, account).await,
        }
    }

    /// Whether the action carries this account's current password.
    ///
    /// On the blocking pool, never inline: it is 210 000 PBKDF2 rounds, and a
    /// runtime worker spending 30 ms on one client's typo is 30 ms of everybody
    /// else's audio and text queued behind it. It is also free to trigger, so
    /// inline it would be a lever an unauthenticated peer can pull.
    async fn proves_password(&self, scope: u32, account: u64, action: &AccountAction) -> bool {
        let accounts = self.accounts.clone();
        let given = action.current_password.clone();
        tokio::task::spawn_blocking(move || accounts.password_matches(scope, account, &given))
            .await
            .unwrap_or_else(|error| {
                // The pool panicked or is shutting down. Refusing is the only
                // safe answer: an unprovable claim is not a proved one.
                tracing::error!(%error, "the password check could not be run");
                false
            })
    }

    async fn set_password(
        &self,
        inbound: &Inbound,
        account: u64,
        action: &AccountAction,
    ) -> AccountAck {
        if action.value.is_empty() {
            // An empty stored password is not "no password set", it is a
            // password every guess matches.
            return refuse(action.kind, "a password cannot be empty");
        }
        let request = UpdateRequest {
            scope: Some(in_scope(inbound.scope)),
            actor: Some(actor_of(inbound.session)),
            id: account,
            fields: vec!["password".to_owned()],
            values: None,
            password: action.value.clone(),
            current_password: action.current_password.clone(),
        };
        self.applied(inbound, account, action.kind, "password", request)
            .await
    }

    async fn set_email(
        &self,
        inbound: &Inbound,
        account: u64,
        action: &AccountAction,
    ) -> AccountAck {
        let request = UpdateRequest {
            scope: Some(in_scope(inbound.scope)),
            actor: Some(actor_of(inbound.session)),
            id: account,
            fields: vec!["email".to_owned()],
            values: Some(Account {
                email: action.value.clone(),
                ..Account::default()
            }),
            password: String::new(),
            current_password: action.current_password.clone(),
        };
        self.applied(inbound, account, action.kind, "email", request)
            .await
    }

    /// Shared tail of the two verbs that are an `update`: apply, trail, answer.
    async fn applied(
        &self,
        inbound: &Inbound,
        account: u64,
        kind: i32,
        field: &str,
        request: UpdateRequest,
    ) -> AccountAck {
        match self.accounts.update(inbound.scope, request).await {
            Ok(_) => {
                self.record_change(inbound, account, field);
                ok(kind)
            }
            Err(why) => refuse(kind, &why),
        }
    }

    async fn rename_self(
        &self,
        inbound: &Inbound,
        account: u64,
        action: &AccountAction,
    ) -> AccountAck {
        // Through `rename` rather than `update(fields: ["name"])`, because only
        // one of the two checks that the name is free. Two accounts with one
        // name is not a cosmetic problem: a name is what a login resolves, so
        // the second one shadows the first.
        match self
            .accounts
            .rename(inbound.scope, account, &action.value)
            .await
        {
            Ok(_) => {
                self.record_change(inbound, account, "name");
                ok(action.kind)
            }
            Err(why) => refuse(action.kind, &why),
        }
    }

    async fn enable_totp(
        &self,
        inbound: &Inbound,
        account: u64,
        action: &AccountAction,
    ) -> AccountAck {
        if self.accounts.totp_enabled(inbound.scope, account) {
            return refuse(action.kind, "this account already has a second factor");
        }

        if action.totp.is_empty() {
            // First half: hand out a secret and remember it, unconfirmed.
            let secret = crate::secret::new_totp_secret();
            if secret.is_empty() {
                return refuse(action.kind, "the server could not generate a secret");
            }
            let shown = crate::secret::base32(&secret);
            if let Ok(mut enrolling) = self.enrolling.lock() {
                let _ = enrolling.insert(
                    (inbound.scope, account),
                    Enrolment {
                        secret,
                        expires_at_ms: now_ms() + ENROLMENT_MS,
                    },
                );
            }
            return AccountAck {
                kind: action.kind,
                ok: true,
                detail: "scan this, then send the code it shows".to_owned(),
                totp_secret: shown,
            };
        }

        // Second half: the code proves the secret arrived.
        let pending = self
            .enrolling
            .lock()
            .ok()
            .and_then(|enrolling| enrolling.get(&(inbound.scope, account)).cloned());
        let Some(pending) = pending.filter(|held| held.expires_at_ms > now_ms()) else {
            return refuse(action.kind, "start again: that enrolment has expired");
        };
        if !crate::secret::verify_totp(&pending.secret, &action.totp, now_ms() / 1000) {
            return refuse(action.kind, "that code does not match");
        }
        match self
            .accounts
            .set_totp(inbound.scope, account, Some(pending.secret))
            .await
        {
            Ok(()) => {
                if let Ok(mut enrolling) = self.enrolling.lock() {
                    let _ = enrolling.remove(&(inbound.scope, account));
                }
                self.record_change(inbound, account, "totp");
                ok(action.kind)
            }
            Err(why) => refuse(action.kind, &why),
        }
    }

    async fn disable_totp(
        &self,
        inbound: &Inbound,
        account: u64,
        action: &AccountAction,
    ) -> AccountAck {
        if !self.accounts.totp_enabled(inbound.scope, account) {
            return refuse(action.kind, "this account has no second factor");
        }
        // The password was already proved above; a current code is asked for as
        // well, because the two together are what "the owner, holding their
        // device" means. Somebody who has lost the device asks an operator,
        // which is a slower path on purpose.
        if !self
            .accounts
            .totp_matches(inbound.scope, account, &action.totp)
        {
            return refuse(action.kind, "that code does not match");
        }
        match self.accounts.set_totp(inbound.scope, account, None).await {
            Ok(()) => {
                self.record_change(inbound, account, "totp");
                ok(action.kind)
            }
            Err(why) => refuse(action.kind, &why),
        }
    }

    async fn unregister_self(&self, inbound: &Inbound, account: u64) -> AccountAck {
        let kind = account_action::Kind::Unregister as i32;
        if account == starling_proto_fancy::identity::SUPERUSER {
            // A server whose administrator account is gone cannot be
            // administered, and nothing else can put it back.
            return refuse(kind, "the SuperUser account cannot be unregistered");
        }
        self.accounts.delete(inbound.scope, account).await;
        self.record_change(inbound, account, "unregistered");
        ok(kind)
    }

    /// The account behind a session, or `None` for a guest.
    async fn account_of(&self, scope: u32, session: u32) -> Option<u64> {
        self.sessions(scope)
            .await
            .iter()
            .find(|other| other.session == session)
            .and_then(|other| {
                starling_proto_fancy::identity::account(other.registered, other.account)
            })
    }

    /// This account's stored settings, as a delivery.
    fn settings_reply(
        &self,
        inbound: &Inbound,
        account: u64,
    ) -> starling_proto_fancy::control::ServerAction {
        let values = self
            .accounts
            .by_id(inbound.scope, account)
            .map(|stored| stored.settings)
            .unwrap_or_default();
        to_conn(
            inbound.conn,
            outer_type(),
            UserdataEnvelope {
                body: Some(userdata_envelope::Body::Settings(Settings { values })),
            }
            .encode_to_vec(),
        )
    }

    /// Apply a settings change: `set` wins over `unset` for a key in both.
    async fn write_settings(&self, scope: u32, account: u64, update: SettingsUpdate) {
        let Some(mut stored) = self.accounts.by_id(scope, account) else {
            return;
        };
        for key in &update.unset {
            let _ = stored.settings.remove(key);
        }
        stored.settings.extend(update.set);

        let request = UpdateRequest {
            scope: Some(in_scope(scope)),
            actor: None,
            id: account,
            fields: vec!["settings".to_owned()],
            values: Some(stored),
            password: String::new(),
            current_password: String::new(),
        };
        if let Err(why) = self.accounts.update(scope, request).await {
            tracing::warn!(account, why, "could not store the settings");
        }
    }

    /// Wrap an acknowledgement for the connection it answers.
    fn reply(
        &self,
        inbound: &Inbound,
        ack: AccountAck,
    ) -> starling_proto_fancy::control::ServerAction {
        to_conn(
            inbound.conn,
            outer_type(),
            UserdataEnvelope {
                body: Some(userdata_envelope::Body::Ack(ack)),
            }
            .encode_to_vec(),
        )
    }

    /// Put the change in the operator's record.
    ///
    /// Every one of these is somebody's account changing, which is precisely
    /// what an operator investigating a compromise needs to be able to see.
    fn record_change(&self, inbound: &Inbound, account: u64, field: &str) {
        self.trail.record(
            inbound.scope,
            starling_runtime::trail::Record::new(
                starling_runtime::trail::category::REGISTER,
                "changed their own account",
            )
            .actor(actor_of(inbound.session), String::new())
            .target_account(account)
            .detail(field.to_owned()),
        );
    }
}

/// A refusal that says why.
///
/// Always sent, never dropped: an action that silently does nothing is
/// indistinguishable from one still in flight, and the client's only remaining
/// move is to try again.
fn refuse(kind: i32, detail: &str) -> AccountAck {
    AccountAck {
        kind,
        ok: false,
        detail: detail.to_owned(),
        totp_secret: String::new(),
    }
}

const fn ok(kind: i32) -> AccountAck {
    AccountAck {
        kind,
        ok: true,
        detail: String::new(),
        totp_secret: String::new(),
    }
}

/// The virtual server, in the shape every request carries it.
const fn in_scope(virtual_server: u32) -> starling_proto_fancy::common::Scope {
    starling_proto_fancy::common::Scope { virtual_server }
}

#[cfg(test)]
mod tests {
    use super::*;
    use starling_proto_fancy::userdata::Account as StoredAccount;
    use starling_runtime::log::Logger;
    use starling_runtime::storage::Store;
    use std::collections::HashMap;

    /// A service with no session-view and no permissions behind it.
    ///
    /// Every test here is about what happens *before* either is consulted: the
    /// proof, the verb, and what ends up stored. The only thing an unreachable
    /// session-view changes is that `account_of` finds nobody, so these call the
    /// verbs with the account already resolved — which is exactly the split the
    /// module is written around.
    async fn service() -> (UserdataService, u64) {
        use std::sync::atomic::{AtomicU64, Ordering};
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let id = NEXT.fetch_add(1, Ordering::Relaxed);
        let store = Store::open(
            &format!("sqlite:file:selfservice-test-{id}?mode=memory&cache=shared"),
            1,
        )
        .await
        .expect("in-memory database");
        let accounts = crate::Accounts::open(store).await.expect("accounts");
        let account = accounts
            .register(
                1,
                StoredAccount {
                    name: "ada".to_owned(),
                    ..StoredAccount::default()
                },
                "correct horse",
            )
            .await
            .expect("registered");

        let nowhere = starling_runtime::channel::Resolver::new(
            std::sync::Arc::new(starling_runtime::config::Config::default()),
            starling_runtime::inproc::Broker::default(),
        );
        (
            UserdataService {
                accounts,
                fanout: starling_runtime::plane::Fanout::default(),
                logger: Logger::null(),
                permit: starling_runtime::permit::Permit::new(nowhere.clone()),
                resolver: nowhere.clone(),
                trail: starling_runtime::trail::Trail::new(nowhere),
                enrolling: std::sync::Mutex::default(),
            },
            account.id,
        )
    }

    fn inbound() -> Inbound {
        Inbound {
            scope: 1,
            conn: 1,
            session: 7,
            type_id: outer_type(),
            payload: Vec::new(),
            gateway: String::new(),
        }
    }

    fn action(kind: account_action::Kind, password: &str) -> AccountAction {
        AccountAction {
            kind: kind as i32,
            current_password: password.to_owned(),
            value: String::new(),
            totp: String::new(),
        }
    }

    /// The code an authenticator would be showing right now for `secret`.
    fn code_for(secret: &[u8]) -> String {
        format!("{:06}", crate::secret::totp(secret, now_ms() / 1000 / 30))
    }

    #[tokio::test]
    async fn the_zero_value_is_not_an_action() {
        // It used to be SET_PASSWORD, so a client that left the field unset —
        // or a decode of the wrong bytes — asked to set the password to the
        // empty string, and would have got it.
        let (service, account) = service().await;
        let ack = service
            .act(
                &inbound(),
                account,
                action(account_action::Kind::Unspecified, "correct horse"),
            )
            .await;
        assert!(!ack.ok);
        assert!(
            service
                .accounts
                .password_matches(1, account, "correct horse"),
            "the password must be untouched"
        );
    }

    #[tokio::test]
    async fn a_wrong_password_changes_nothing() {
        let (service, account) = service().await;
        let mut request = action(account_action::Kind::SetPassword, "not it");
        request.value = "hunter2".to_owned();

        let ack = service.act(&inbound(), account, request).await;
        assert!(!ack.ok);
        assert_eq!(ack.detail, "the current password is wrong");
        assert!(
            service
                .accounts
                .password_matches(1, account, "correct horse")
        );
    }

    #[tokio::test]
    async fn the_right_password_changes_it() {
        let (service, account) = service().await;
        let mut request = action(account_action::Kind::SetPassword, "correct horse");
        request.value = "hunter2".to_owned();

        assert!(service.act(&inbound(), account, request).await.ok);
        assert!(service.accounts.password_matches(1, account, "hunter2"));
    }

    #[tokio::test]
    async fn an_empty_new_password_is_refused() {
        // Not "no password set" — a password every guess matches.
        let (service, account) = service().await;
        let ack = service
            .act(
                &inbound(),
                account,
                action(account_action::Kind::SetPassword, "correct horse"),
            )
            .await;
        assert!(!ack.ok);
        assert!(
            service
                .accounts
                .password_matches(1, account, "correct horse")
        );
    }

    #[tokio::test]
    async fn enrolling_a_second_factor_takes_a_code_as_well_as_a_secret() {
        // The half that matters: the first message must not enable anything.
        // If it did, a user whose authenticator never received the secret is
        // locked out of their own account and cannot undo it, because logging
        // in is what now needs the code.
        let (service, account) = service().await;
        let handed = service
            .act(
                &inbound(),
                account,
                action(account_action::Kind::EnableTotp, "correct horse"),
            )
            .await;
        assert!(handed.ok);
        assert!(!handed.totp_secret.is_empty(), "the secret is shown once");
        assert!(
            !service.accounts.totp_enabled(1, account),
            "an unconfirmed enrolment must not be enabled"
        );

        let secret = service
            .enrolling
            .lock()
            .expect("not poisoned")
            .get(&(1, account))
            .expect("the enrolment is held")
            .secret
            .clone();
        let mut confirm = action(account_action::Kind::EnableTotp, "correct horse");
        confirm.totp = code_for(&secret);

        assert!(service.act(&inbound(), account, confirm).await.ok);
        assert!(service.accounts.totp_enabled(1, account));
    }

    #[tokio::test]
    async fn a_wrong_confirmation_code_does_not_enable_it() {
        let (service, account) = service().await;
        let _ = service
            .act(
                &inbound(),
                account,
                action(account_action::Kind::EnableTotp, "correct horse"),
            )
            .await;
        let secret = service
            .enrolling
            .lock()
            .expect("not poisoned")
            .get(&(1, account))
            .expect("the enrolment is held")
            .secret
            .clone();

        // A code that is definitely not the current one, taken from the far
        // side of the drift window rather than picked and hoped for.
        let mut confirm = action(account_action::Kind::EnableTotp, "correct horse");
        confirm.totp = format!(
            "{:06}",
            crate::secret::totp(&secret, now_ms() / 1000 / 30 + 50)
        );

        let ack = service.act(&inbound(), account, confirm).await;
        assert!(!ack.ok);
        assert!(!service.accounts.totp_enabled(1, account));
    }

    #[tokio::test]
    async fn a_second_factor_cannot_be_removed_without_the_device() {
        // The password alone is not enough, or a stolen password undoes the
        // whole point of having a second factor.
        let (service, account) = service().await;
        let secret = crate::secret::new_totp_secret();
        service
            .accounts
            .set_totp(1, account, Some(secret.clone()))
            .await
            .expect("enabled");

        let ack = service
            .act(
                &inbound(),
                account,
                action(account_action::Kind::DisableTotp, "correct horse"),
            )
            .await;
        assert!(!ack.ok);
        assert!(service.accounts.totp_enabled(1, account));

        let mut with_code = action(account_action::Kind::DisableTotp, "correct horse");
        with_code.totp = code_for(&secret);
        assert!(service.act(&inbound(), account, with_code).await.ok);
        assert!(!service.accounts.totp_enabled(1, account));
    }

    #[tokio::test]
    async fn settings_round_trip_and_unset_removes_only_what_it_names() {
        let (service, account) = service().await;
        let mut set = HashMap::new();
        let _ = set.insert("theme".to_owned(), "dark".to_owned());
        let _ = set.insert("push".to_owned(), "on".to_owned());
        service
            .write_settings(
                1,
                account,
                SettingsUpdate {
                    set,
                    unset: Vec::new(),
                },
            )
            .await;
        let stored = service.accounts.by_id(1, account).expect("account");
        assert_eq!(
            stored.settings.get("theme").map(String::as_str),
            Some("dark")
        );

        service
            .write_settings(
                1,
                account,
                SettingsUpdate {
                    set: HashMap::new(),
                    unset: vec!["theme".to_owned()],
                },
            )
            .await;
        let stored = service.accounts.by_id(1, account).expect("account");
        assert!(!stored.settings.contains_key("theme"));
        assert_eq!(
            stored.settings.get("push").map(String::as_str),
            Some("on"),
            "unsetting one key must not clear the rest"
        );
    }

    #[tokio::test]
    async fn the_superuser_cannot_unregister_itself() {
        // The account that administers the server, removed by one message from
        // a client, with nothing able to put it back.
        let (service, _) = service().await;
        let ack = service
            .unregister_self(&inbound(), starling_proto_fancy::identity::SUPERUSER)
            .await;
        assert!(!ack.ok);
    }
}
