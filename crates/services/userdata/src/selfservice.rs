//! What a user may change about their own account, from their own client.
//!
//! Outer type 1003, `UserdataEnvelope`. Until this existed the envelope was
//! decoded by nothing at all: a client could send every message in it and the
//! server would drop each one without a line in any log, a whole surface that
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
//! reach the database. The one-shot alternative, generate, store, enable,
//! locks out any user whose authenticator never got the secret, and they cannot
//! fix it themselves, because logging in is what now needs the code. Held in
//! memory because an enrolment nobody finished should evaporate: a restart
//! costs a re-scan, and that is the cheap direction to be wrong in.

use std::collections::HashMap;

use prost::Message as _;
use starling_proto_fancy::fancy::domain::{
    AccountAck, AccountAction, AccountState, Record, RecordGet, RecordKeys, RecordList, RecordPut,
    Settings, SettingsUpdate, UserdataEnvelope, account_action, userdata_envelope,
};
use starling_proto_fancy::fancy::wire::{Refusal, refusal};
use starling_proto_fancy::userdata::{Account, UpdateRequest};
use starling_runtime::ids::now_ms;
use starling_runtime::plane::{Actions, Inbound, to_conn};

use crate::records::{Denied, MAX_RECORD_BYTES};
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

/// The prefix in an account's settings map that belongs to the server.
///
/// Everything under it is what the server keeps *about* this account rather
/// than what the account keeps for itself: which greeting they have been
/// shown, and whatever else comes to be recorded there. A client may write
/// any other key it likes.
pub const RESERVED_PREFIX: &str = "srv.";

/// Whether `key` belongs to the server rather than to the account.
#[must_use]
pub fn is_reserved(key: &str) -> bool {
    key.starts_with(RESERVED_PREFIX)
}

/// What a guest is told when it asks for records.
fn guest_refusal() -> Refusal {
    Refusal {
        kind: refusal::Kind::Permission as i32,
        detail: "records are kept per account, and this connection is a guest".to_owned(),
        retry_after_ms: 0,
    }
}

/// What the store refused, as the client is told it.
///
/// The ceiling is named in the message, the way `files` names its upload
/// limit: a client that has just been told "too large" and not how large is a
/// client whose next attempt is another guess.
fn denial(denied: Denied, size: usize) -> Refusal {
    let (kind, detail) = match denied {
        Denied::TooLarge => (
            refusal::Kind::Limit,
            format!("a record may be at most {MAX_RECORD_BYTES} bytes, and this one is {size}"),
        ),
        Denied::BadKey => (
            refusal::Kind::Invalid,
            "a record key must be between 1 and 190 characters".to_owned(),
        ),
        Denied::Storage => (
            refusal::Kind::Other,
            "the record could not be stored".to_owned(),
        ),
    };
    Refusal {
        kind: kind as i32,
        detail,
        retry_after_ms: 0,
    }
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
                // A guest asking about their account gets the answer, which is
                // that there is not one. Silence here is what left the client's
                // own account page loading for ever.
                Some(userdata_envelope::Body::AccountQuery(_)) => {
                    vec![self.state_reply(inbound, AccountState::default())]
                }
                // The records are the account's, and a guest has no account to
                // keep them under. Refused rather than answered empty: a
                // client told "no such record" would go on to write one and
                // lose it, and one told nothing at all waits for ever - which
                // is the bug that sent a registered user a "you aren't
                // registered" warning on a server that simply had no store.
                Some(userdata_envelope::Body::RecordGet(get)) => {
                    vec![self.record_refused(inbound, &get.request_id, &get.key, guest_refusal())]
                }
                Some(userdata_envelope::Body::RecordPut(put)) => {
                    vec![self.record_refused(inbound, &put.request_id, &put.key, guest_refusal())]
                }
                Some(userdata_envelope::Body::RecordList(list)) => {
                    vec![self.keys_refused(inbound, &list.request_id, guest_refusal())]
                }
                _ => Actions::new(),
            };
        };

        match envelope.body {
            Some(userdata_envelope::Body::Action(action)) => {
                let ack = self.act(inbound, account, action).await;
                // The ack says whether it worked; the state says what it left
                // behind. Both, because a client that derives the new state
                // from a successful ack is a client that guesses, and after an
                // UNREGISTER it would guess wrong about the only field that
                // decides whether the page is offered at all.
                let changed = ack.ok;
                let mut actions = vec![self.reply(inbound, ack)];
                if changed {
                    let state = self.account_state(inbound, account).await;
                    actions.push(self.state_reply(inbound, state));
                }
                actions
            }
            Some(userdata_envelope::Body::AccountQuery(_)) => {
                let state = self.account_state(inbound, account).await;
                vec![self.state_reply(inbound, state)]
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
            Some(userdata_envelope::Body::RecordGet(get)) => {
                vec![self.read_record(inbound, account, get).await]
            }
            Some(userdata_envelope::Body::RecordPut(put)) => {
                vec![self.write_record(inbound, account, put).await]
            }
            Some(userdata_envelope::Body::RecordList(list)) => {
                vec![self.list_records(inbound, account, list).await]
            }
            // Server to client, or an empty envelope.
            Some(
                userdata_envelope::Body::Ack(_)
                | userdata_envelope::Body::Settings(_)
                | userdata_envelope::Body::Account(_)
                | userdata_envelope::Body::Record(_)
                | userdata_envelope::Body::RecordKeys(_),
            )
            | None => Actions::new(),
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
            account_action::Kind::ClearPassword => {
                self.clear_password(inbound, account, &action).await
            }
            account_action::Kind::SetEmail => self.set_email(inbound, account, &action).await,
            account_action::Kind::Rename => self.rename_self(inbound, account, &action).await,
            account_action::Kind::EnableTotp => self.enable_totp(inbound, account, &action).await,
            account_action::Kind::DisableTotp => self.disable_totp(inbound, account, &action).await,
            account_action::Kind::Unregister => self.unregister_self(inbound, account).await,
        }
    }

    /// Whether the action carries this account's current password.
    ///
    /// An account with **no** stored password is proved by its certificate,
    /// which is the only way to reach it and is therefore what the session
    /// already presented. Demanding a password there refused every action such
    /// an account can take, starting with the one that gives it a password, and
    /// `Accounts::update` carries this same carve-out one layer down - so the
    /// two disagreed and this one, being first, always won.
    ///
    /// On the blocking pool, never inline: it is 210 000 PBKDF2 rounds, and a
    /// runtime worker spending 30 ms on one client's typo is 30 ms of everybody
    /// else's audio and text queued behind it. It is also free to trigger, so
    /// inline it would be a lever an unauthenticated peer can pull.
    async fn proves_password(&self, scope: u32, account: u64, action: &AccountAction) -> bool {
        if !self.accounts.has_password(scope, account) {
            return true;
        }
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

    /// Back to certificate-only login.
    ///
    /// Gated on the connection's certificate being the account's, and that gate
    /// is the whole point: an account with neither a password nor a matching
    /// certificate cannot be logged into by anyone, its owner included, and no
    /// self-service path can put it back.
    async fn clear_password(
        &self,
        inbound: &Inbound,
        account: u64,
        action: &AccountAction,
    ) -> AccountAck {
        if !self.cert_matches(inbound, account).await {
            return refuse(
                action.kind,
                "connect with the certificate this account is bound to first",
            );
        }
        match self.accounts.clear_password(inbound.scope, account).await {
            Ok(()) => {
                self.record_change(inbound, account, "password");
                ok(action.kind)
            }
            Err(why) => refuse(action.kind, &why),
        }
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
            let name = self
                .accounts
                .by_id(inbound.scope, account)
                .map(|stored| stored.name)
                .unwrap_or_default();
            return AccountAck {
                kind: action.kind,
                ok: true,
                detail: "scan this, then send the code it shows".to_owned(),
                totp_uri: otpauth_uri(&self.issuer(inbound.scope), &name, &shown),
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
        // The records go with the account. Ids are handed out again, and a
        // library left behind would open as the next holder's own.
        self.records.forget_account(inbound.scope, account).await;
        self.record_change(inbound, account, "unregistered");
        ok(kind)
    }

    /// The account behind a session, or `None` for a guest.
    async fn account_of(&self, scope: u32, session: u32) -> Option<u64> {
        self.view_of(scope, session).await.and_then(|other| {
            starling_proto_fancy::identity::account(other.registered, other.account)
        })
    }

    /// The session-view's record of one session.
    ///
    /// Named for the view rather than the session because `directory` next door
    /// already owns `session_of`, which asks the mirror image: given an account,
    /// which session is it on.
    async fn view_of(
        &self,
        scope: u32,
        session: u32,
    ) -> Option<starling_proto_fancy::sessionview::Session> {
        self.sessions(scope)
            .await
            .into_iter()
            .find(|other| other.session == session)
    }

    /// Whether this connection holds the certificate the account is bound to.
    ///
    /// An account with no certificate on file answers `false`: there is nothing
    /// for the connection to match, and treating "neither has one" as a match
    /// is how the password comes off an account that then admits nobody.
    async fn cert_matches(&self, inbound: &Inbound, account: u64) -> bool {
        let Some(stored) = self.accounts.by_id(inbound.scope, account) else {
            return false;
        };
        if stored.cert_hash.is_empty() {
            return false;
        }
        self.view_of(inbound.scope, inbound.session)
            .await
            .is_some_and(|other| other.cert_hash == stored.cert_hash)
    }

    /// Everything the owner's own client shows about their account.
    ///
    /// Nothing secret is on it, by construction: the password is a hash this
    /// never reads, and the TOTP secret is sent once, in the ack that hands it
    /// out. What is here is what a client needs to decide which controls to
    /// offer - clearing the password needs `cert_matches_session`, and enabling
    /// a second factor needs to know there is not one already.
    async fn account_state(&self, inbound: &Inbound, account: u64) -> AccountState {
        let Some(stored) = self.accounts.by_id(inbound.scope, account) else {
            // Registered a moment ago and gone now: an UNREGISTER that worked.
            return AccountState::default();
        };
        AccountState {
            registered: true,
            id: stored.id,
            name: stored.name,
            email: stored.email,
            has_password: self.accounts.has_password(inbound.scope, account),
            totp_enabled: self.accounts.totp_enabled(inbound.scope, account),
            cert_matches_session: self.cert_matches(inbound, account).await,
            cert_hash: stored.cert_hash,
        }
    }

    /// What an authenticator app should call this server.
    ///
    /// The directory name where the operator set one - it is the only name this
    /// server has for itself - and the protocol's own name where they did not,
    /// because a blank issuer makes every server one entry in the app's list.
    fn issuer(&self, scope: u32) -> String {
        let listed = self.settings.get(scope).registry_name;
        if listed.is_empty() {
            "Mumble".to_owned()
        } else {
            listed
        }
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

    /// Answer one record.
    async fn read_record(
        &self,
        inbound: &Inbound,
        account: u64,
        get: RecordGet,
    ) -> starling_proto_fancy::control::ServerAction {
        let stored = self.records.get(inbound.scope, account, &get.key).await;
        self.record_reply(
            inbound,
            Record {
                request_id: get.request_id,
                key: get.key,
                value: stored.as_ref().map(|s| s.value.clone()).unwrap_or_default(),
                found: stored.is_some(),
                updated_at_ms: stored.map(|s| s.updated_at_ms).unwrap_or_default(),
                refused: None,
            },
        )
    }

    /// Store or remove one record, and answer with what now stands.
    ///
    /// The value is read back from the store rather than echoed from the
    /// request: a client's copy should be what the server holds, which is the
    /// same rule `SettingsUpdate` follows.
    async fn write_record(
        &self,
        inbound: &Inbound,
        account: u64,
        put: RecordPut,
    ) -> starling_proto_fancy::control::ServerAction {
        if put.remove {
            self.records.remove(inbound.scope, account, &put.key).await;
            return self.record_reply(
                inbound,
                Record {
                    request_id: put.request_id,
                    key: put.key,
                    ..Record::default()
                },
            );
        }

        let size = put.value.len();
        match self
            .records
            .put(inbound.scope, account, &put.key, &put.value)
            .await
        {
            Ok(updated_at_ms) => self.record_reply(
                inbound,
                Record {
                    request_id: put.request_id,
                    key: put.key,
                    value: put.value,
                    found: true,
                    updated_at_ms,
                    refused: None,
                },
            ),
            Err(denied) => {
                self.record_refused(inbound, &put.request_id, &put.key, denial(denied, size))
            }
        }
    }

    /// Answer which records exist under a prefix.
    async fn list_records(
        &self,
        inbound: &Inbound,
        account: u64,
        list: RecordList,
    ) -> starling_proto_fancy::control::ServerAction {
        let keys = self
            .records
            .list(inbound.scope, account, &list.prefix)
            .await;
        to_conn(
            inbound.conn,
            outer_type(),
            UserdataEnvelope {
                body: Some(userdata_envelope::Body::RecordKeys(RecordKeys {
                    request_id: list.request_id,
                    keys,
                    refused: None,
                })),
            }
            .encode_to_vec(),
        )
    }

    /// Wrap one record for the connection that asked.
    fn record_reply(
        &self,
        inbound: &Inbound,
        record: Record,
    ) -> starling_proto_fancy::control::ServerAction {
        to_conn(
            inbound.conn,
            outer_type(),
            UserdataEnvelope {
                body: Some(userdata_envelope::Body::Record(record)),
            }
            .encode_to_vec(),
        )
    }

    /// Say why a record operation did not happen, on the record body so the
    /// client can match it to the request it made.
    fn record_refused(
        &self,
        inbound: &Inbound,
        request_id: &str,
        key: &str,
        refusal: Refusal,
    ) -> starling_proto_fancy::control::ServerAction {
        self.record_reply(
            inbound,
            Record {
                request_id: request_id.to_owned(),
                key: key.to_owned(),
                refused: Some(refusal),
                ..Record::default()
            },
        )
    }

    /// The same, for a listing.
    fn keys_refused(
        &self,
        inbound: &Inbound,
        request_id: &str,
        refusal: Refusal,
    ) -> starling_proto_fancy::control::ServerAction {
        to_conn(
            inbound.conn,
            outer_type(),
            UserdataEnvelope {
                body: Some(userdata_envelope::Body::RecordKeys(RecordKeys {
                    request_id: request_id.to_owned(),
                    keys: Vec::new(),
                    refused: Some(refusal),
                })),
            }
            .encode_to_vec(),
        )
    }

    /// Apply a settings change: `set` wins over `unset` for a key in both.
    ///
    /// Keys under [`RESERVED_PREFIX`] are dropped rather than written. This
    /// map is the account's own settings and a client may write what it
    /// likes into it - which is right for a client's own preferences and
    /// wrong for anything the *server* keeps about them. Without this a user
    /// could write their own `srv.greet.…` entry and mark a greeting
    /// dismissed that they were never shown, which is the whole of what the
    /// ledger is for.
    ///
    /// Dropped silently to the client, and logged here: a refusal would have
    /// to be a new ack arm, and there is no legitimate client that sends
    /// one - anything doing so is either probing or broken, and both are
    /// things to read about in a log rather than to answer politely.
    async fn write_settings(&self, scope: u32, account: u64, update: SettingsUpdate) {
        let Some(mut stored) = self.accounts.by_id(scope, account) else {
            return;
        };

        let refused = update
            .unset
            .iter()
            .filter(|key| is_reserved(key))
            .chain(update.set.keys().filter(|key| is_reserved(key)))
            .count();
        if refused > 0 {
            tracing::info!(
                account,
                refused,
                "refused a settings write under the reserved prefix"
            );
        }

        for key in update.unset.iter().filter(|key| !is_reserved(key)) {
            let _ = stored.settings.remove(key);
        }
        stored
            .settings
            .extend(update.set.into_iter().filter(|(key, _)| !is_reserved(key)));

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

    /// Wrap an account snapshot for the connection that asked.
    fn state_reply(
        &self,
        inbound: &Inbound,
        state: AccountState,
    ) -> starling_proto_fancy::control::ServerAction {
        to_conn(
            inbound.conn,
            outer_type(),
            UserdataEnvelope {
                body: Some(userdata_envelope::Body::Account(state)),
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
        totp_uri: String::new(),
    }
}

const fn ok(kind: i32) -> AccountAck {
    AccountAck {
        kind,
        ok: true,
        detail: String::new(),
        totp_secret: String::new(),
        totp_uri: String::new(),
    }
}

/// The enrolment as an `otpauth://` URI, which is what a QR code encodes.
///
/// Built here rather than left to the client because the issuer is the server's
/// name for itself, and a client that invents one puts a different label in
/// every user's authenticator for the same server.
fn otpauth_uri(issuer: &str, account: &str, secret: &str) -> String {
    format!(
        "otpauth://totp/{}:{}?secret={secret}&issuer={}",
        percent_encode(issuer),
        percent_encode(account),
        percent_encode(issuer),
    )
}

/// Percent-encode everything an `otpauth` label or issuer may not carry raw.
///
/// A server name is operator-set free text, so it arrives with spaces, colons
/// and `&` in it; each of those ends a field early and silently enrols the user
/// against a truncated label.
fn percent_encode(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for byte in text.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(byte));
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

/// The server instance, in the shape every request carries it.
const fn in_scope(instance: u32) -> starling_proto_fancy::common::Scope {
    starling_proto_fancy::common::Scope { instance }
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
    /// verbs with the account already resolved, which is exactly the split the
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
        let records = crate::Records::open(store.clone()).await.expect("records");
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
                trail: starling_runtime::trail::Trail::new(nowhere.clone()),
                enrolling: std::sync::Mutex::default(),
                settings: starling_runtime::settings::Settings::new(nowhere),
                records,
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
        // It used to be SET_PASSWORD, so a client that left the field unset,
        // or a decode of the wrong bytes, asked to set the password to the
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
    async fn the_account_answers_for_itself() {
        // The question the client's account page asks on open. Until this
        // existed the page had no way to be told anything and sat loading.
        let (service, account) = service().await;
        let state = service.account_state(&inbound(), account).await;
        assert!(state.registered);
        assert_eq!(state.name, "ada");
        assert!(state.has_password);
        assert!(!state.totp_enabled);
        // No session-view behind this service, so no certificate can match; the
        // page reads that as "clearing the password is not offered".
        assert!(!state.cert_matches_session);
    }

    #[tokio::test]
    async fn an_unregistered_account_says_it_is_gone() {
        // The one state a client cannot derive from a successful ack: after an
        // UNREGISTER there is nothing left to describe, and a page that assumed
        // otherwise would go on offering to rename it.
        let (service, account) = service().await;
        assert!(
            service
                .act(
                    &inbound(),
                    account,
                    action(account_action::Kind::Unregister, "correct horse"),
                )
                .await
                .ok
        );
        assert!(!service.account_state(&inbound(), account).await.registered);
    }

    #[tokio::test]
    async fn a_certificate_only_account_can_give_itself_a_password() {
        // It has no password to prove, so demanding one refused the only route
        // it has to acquiring one - the account could never be secured at all.
        let (service, account) = service().await;
        service
            .accounts
            .clear_password(1, account)
            .await
            .expect("cleared");

        let mut request = action(account_action::Kind::SetPassword, "");
        request.value = "hunter2".to_owned();
        assert!(service.act(&inbound(), account, request).await.ok);
        assert!(service.accounts.password_matches(1, account, "hunter2"));
    }

    #[tokio::test]
    async fn the_password_does_not_come_off_without_the_certificate() {
        // Otherwise the account has neither, and nobody - the owner included -
        // can log into it again.
        let (service, account) = service().await;
        let ack = service
            .act(
                &inbound(),
                account,
                action(account_action::Kind::ClearPassword, "correct horse"),
            )
            .await;
        assert!(!ack.ok);
        assert!(
            service
                .accounts
                .password_matches(1, account, "correct horse")
        );
    }

    #[test]
    fn an_enrolment_uri_survives_a_server_name_with_punctuation_in_it() {
        // Operator-set free text: a raw space or `&` ends the field early and
        // enrols the user against a truncated label.
        let uri = otpauth_uri("Ada & Co", "ada", "JBSWY3DP");
        assert_eq!(
            uri,
            "otpauth://totp/Ada%20%26%20Co:ada?secret=JBSWY3DP&issuer=Ada%20%26%20Co"
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
        // Not "no password set", a password every guess matches.
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
    async fn a_client_cannot_write_the_servers_own_keys() {
        // The ledger of which greeting somebody has been shown lives under
        // this prefix. A user who could write it themselves could dismiss a
        // greeting they were never shown, which is the one thing the record
        // exists to know.
        let (service, account) = service().await;
        let mut set = HashMap::new();
        let _ = set.insert("srv.greet.rules".to_owned(), "9".to_owned());
        let _ = set.insert("theme".to_owned(), "dark".to_owned());
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
        assert!(
            !stored.settings.contains_key("srv.greet.rules"),
            "a reserved key must not be written by a client"
        );
        // The rest of the same message still lands: one refused key is not
        // grounds for discarding a legitimate preference beside it.
        assert_eq!(
            stored.settings.get("theme").map(String::as_str),
            Some("dark")
        );
    }

    #[tokio::test]
    async fn a_client_cannot_clear_the_servers_own_keys_either() {
        // The other half, and the one that is easy to miss: refusing writes
        // while allowing unsets would let a user delete their own record and
        // be shown the greeting again, which is the same forgery backwards.
        let (service, account) = service().await;
        let mut stored = service.accounts.by_id(1, account).expect("account");
        let _ = stored
            .settings
            .insert("srv.greet.rules".to_owned(), "9".to_owned());
        let request = UpdateRequest {
            scope: Some(in_scope(1)),
            actor: None,
            id: account,
            fields: vec!["settings".to_owned()],
            values: Some(stored),
            password: String::new(),
            current_password: String::new(),
        };
        let _ = service.accounts.update(1, request).await.expect("stored");

        service
            .write_settings(
                1,
                account,
                SettingsUpdate {
                    set: HashMap::new(),
                    unset: vec!["srv.greet.rules".to_owned()],
                },
            )
            .await;

        let after = service.accounts.by_id(1, account).expect("account");
        assert_eq!(
            after.settings.get("srv.greet.rules").map(String::as_str),
            Some("9"),
            "a client must not be able to clear the server's own record"
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

    /// One frame in, one frame out, decoded.
    ///
    /// Goes through `on_self_service` rather than the handlers, because the
    /// guest path is the thing under test in half of these and it is decided
    /// there: with no session-view to ask, `account_of` finds nobody, which is
    /// exactly what a guest looks like.
    async fn as_guest(
        service: &UserdataService,
        body: userdata_envelope::Body,
    ) -> UserdataEnvelope {
        let mut inbound = inbound();
        inbound.payload = UserdataEnvelope { body: Some(body) }.encode_to_vec();
        let actions = service.on_self_service(&inbound).await;
        let action = actions.into_iter().next().expect("a reply, not silence");
        let Some(starling_proto_fancy::control::server_action::Action::Send(sent)) = action.action
        else {
            panic!("a reply is a send");
        };
        UserdataEnvelope::decode(sent.payload.as_slice()).expect("a userdata envelope")
    }

    /// The record inside a reply.
    fn as_record(envelope: UserdataEnvelope) -> Record {
        match envelope.body {
            Some(userdata_envelope::Body::Record(record)) => record,
            other => panic!("expected a record, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn a_record_written_reads_back_on_the_next_connection() {
        let (service, account) = service().await;

        let stored = service
            .write_record(
                &inbound(),
                account,
                RecordPut {
                    request_id: "1".to_owned(),
                    key: "livedoc/sidebar".to_owned(),
                    value: b"{\"sections\":[]}".to_vec(),
                    remove: false,
                },
            )
            .await;
        assert!(sent_record(stored).found);

        let read = service
            .read_record(
                &inbound(),
                account,
                RecordGet {
                    request_id: "2".to_owned(),
                    key: "livedoc/sidebar".to_owned(),
                },
            )
            .await;
        let record = sent_record(read);
        assert!(record.found);
        assert_eq!(record.value, b"{\"sections\":[]}");
        assert_eq!(record.request_id, "2", "the answer names the question");
    }

    #[tokio::test]
    async fn a_record_that_is_not_there_is_absent_and_not_refused() {
        let (service, account) = service().await;

        let record = sent_record(
            service
                .read_record(
                    &inbound(),
                    account,
                    RecordGet {
                        request_id: "1".to_owned(),
                        key: "nothing".to_owned(),
                    },
                )
                .await,
        );

        assert!(!record.found);
        assert!(
            record.refused.is_none(),
            "an empty library is a normal first run, not an error"
        );
    }

    #[tokio::test]
    async fn a_record_past_the_ceiling_is_refused_with_the_limit_in_the_message() {
        let (service, account) = service().await;

        let record = sent_record(
            service
                .write_record(
                    &inbound(),
                    account,
                    RecordPut {
                        request_id: "1".to_owned(),
                        key: "big".to_owned(),
                        value: vec![b'x'; MAX_RECORD_BYTES + 1],
                        remove: false,
                    },
                )
                .await,
        );

        let refusal = record.refused.expect("a refusal");
        assert_eq!(refusal.kind, refusal::Kind::Limit as i32);
        assert!(
            refusal.detail.contains(&MAX_RECORD_BYTES.to_string()),
            "a client told only \"too large\" can do nothing but guess again: {}",
            refusal.detail
        );
    }

    #[tokio::test]
    async fn removing_a_record_leaves_it_absent() {
        let (service, account) = service().await;
        let put = |value: &'static [u8], remove| RecordPut {
            request_id: "1".to_owned(),
            key: "k".to_owned(),
            value: value.to_vec(),
            remove,
        };

        let _ = service
            .write_record(&inbound(), account, put(b"x", false))
            .await;
        let removed = sent_record(
            service
                .write_record(&inbound(), account, put(b"", true))
                .await,
        );
        assert!(!removed.found);

        let read = sent_record(
            service
                .read_record(
                    &inbound(),
                    account,
                    RecordGet {
                        request_id: "2".to_owned(),
                        key: "k".to_owned(),
                    },
                )
                .await,
        );
        assert!(!read.found);
    }

    #[tokio::test]
    async fn a_guest_is_refused_rather_than_left_waiting() {
        // The bug this whole store exists to end: a client with nowhere to
        // store its library was told nothing at all, so its sidebar sat
        // loading, and the client filled the silence by guessing that the user
        // was not registered.
        let (service, _) = service().await;

        let record = as_record(
            as_guest(
                &service,
                userdata_envelope::Body::RecordGet(RecordGet {
                    request_id: "1".to_owned(),
                    key: "livedoc/sidebar".to_owned(),
                }),
            )
            .await,
        );

        let refusal = record.refused.expect("a guest hears why");
        assert_eq!(refusal.kind, refusal::Kind::Permission as i32);
        assert_eq!(record.request_id, "1");
    }

    #[tokio::test]
    async fn a_guest_listing_is_refused_rather_than_answered_empty() {
        let (service, _) = service().await;

        let envelope = as_guest(
            &service,
            userdata_envelope::Body::RecordList(RecordList {
                request_id: "7".to_owned(),
                prefix: String::new(),
            }),
        )
        .await;

        match envelope.body {
            Some(userdata_envelope::Body::RecordKeys(keys)) => {
                assert_eq!(keys.request_id, "7");
                assert_eq!(
                    keys.refused.expect("a refusal").kind,
                    refusal::Kind::Permission as i32,
                    "answering an empty list would have the client store into a void"
                );
            }
            other => panic!("expected keys, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn a_guest_put_is_refused_rather_than_silently_dropped() {
        let (service, _) = service().await;

        let record = as_record(
            as_guest(
                &service,
                userdata_envelope::Body::RecordPut(RecordPut {
                    request_id: "1".to_owned(),
                    key: "k".to_owned(),
                    value: b"x".to_vec(),
                    remove: false,
                }),
            )
            .await,
        );

        assert_eq!(
            record.refused.expect("a refusal").kind,
            refusal::Kind::Permission as i32
        );
    }

    #[tokio::test]
    async fn listing_names_the_keys_and_not_their_contents() {
        let (service, account) = service().await;
        for key in ["livedoc/sidebar", "livedoc/sources", "calendar"] {
            let _ = service
                .write_record(
                    &inbound(),
                    account,
                    RecordPut {
                        request_id: "1".to_owned(),
                        key: key.to_owned(),
                        value: vec![b'x'; 1024],
                        remove: false,
                    },
                )
                .await;
        }

        let envelope = sent(
            service
                .list_records(
                    &inbound(),
                    account,
                    RecordList {
                        request_id: "9".to_owned(),
                        prefix: "livedoc/".to_owned(),
                    },
                )
                .await,
        );

        match envelope.body {
            Some(userdata_envelope::Body::RecordKeys(keys)) => {
                assert_eq!(
                    keys.keys,
                    vec!["livedoc/sidebar".to_owned(), "livedoc/sources".to_owned()]
                );
                assert!(keys.refused.is_none());
            }
            other => panic!("expected keys, got {other:?}"),
        }
    }

    /// Decode a reply built by one of the record handlers.
    fn sent(action: starling_proto_fancy::control::ServerAction) -> UserdataEnvelope {
        let Some(starling_proto_fancy::control::server_action::Action::Send(sent)) = action.action
        else {
            panic!("a reply is a send");
        };
        UserdataEnvelope::decode(sent.payload.as_slice()).expect("a userdata envelope")
    }

    /// The record inside a handler's reply.
    fn sent_record(action: starling_proto_fancy::control::ServerAction) -> Record {
        as_record(sent(action))
    }
}
