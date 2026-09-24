//! `invites`: one-click links into the server.
//!
//! # What an invite is for
//!
//! Getting somebody onto a private Mumble server has always meant sending them
//! three things - an address, a port and a password - and the third one can
//! never be taken back from one person without changing it for everyone. An
//! invite is a code that stands in for all three: it expires, it counts, it is
//! revocable on its own, and the client turns it into a link that is the whole
//! join flow.
//!
//! # What this service owns, and what it does not
//!
//! It owns the codes: minting them for a client that may, listing and revoking
//! them, and answering the handshake's one question, [`rpc`]'s `Redeem`. It
//! does **not** decide who gets in: the handshake does, because the server
//! password is checked there, and an answer of "admitted" is only what lets it
//! skip that check when the operator allowed it (`invite_skips_password`).
//!
//! # Who may mint one
//!
//! The operator's call, through `invites` in the settings form: nobody, the
//! people who may edit those settings (Write on the root, the same authority
//! every server-wide act here takes), anybody with an account, or everybody.
//! A channel invite additionally needs the creator to be allowed into that
//! channel, so an invite can never be a way past a room's own ACL: the invitee
//! still lands only where the ACL lets them.
//!
//! # Uses are people, not logins
//!
//! An invite that admits "five people" and is spent by one person reconnecting
//! five times is a bug nobody would forgive, so a use is keyed on who presented
//! it - their certificate, or their name when they have none - and the same
//! person coming back costs nothing. See the `store` module.

pub mod rpc;
mod store;

use std::sync::Arc;
use std::time::Duration;

use prost::Message as _;
use starling_proto_fancy::common::{Actor, actor};
use starling_proto_fancy::fancy::invites::{
    Invite, InviteCreate, InviteCreated, InviteList, InviteListQuery, InviteRefused, InviteRevoke,
    InviteRevoked, InviteSupport, InvitesEnvelope, invite_refused, invites_envelope,
};
use starling_proto_fancy::perm::Perm;
use starling_proto_fancy::serverconfig::Snapshot;
use starling_proto_fancy::types::ServiceKind;
use starling_runtime::Settings;
use starling_runtime::ids::now_ms;
use starling_runtime::permit::Permit;
use starling_runtime::plane::{Actions, ClientService, Fanout, Inbound, Plane, to_conn};
use starling_runtime::roster::Roster;
use starling_runtime::serve::{Serve, ServiceContext, ServiceError};
use starling_runtime::settings::{
    INVITES_ADMINS, INVITES_EVERYONE, INVITES_OFF, INVITES_REGISTERED,
};
use starling_runtime::storage::Store;
use starling_runtime::trail::{self, Record, Trail};

use store::Row;

/// Where server-wide authority is checked, as everywhere else.
const ROOT_CHANNEL: u32 = 0;

/// The readiness gate that stays closed until the roster has a snapshot.
///
/// A cold roster cannot say who a session is, so every creator would look like
/// a guest and "registered" would refuse everybody.
const VIEW_GATE: &str = "invites_roster_warm";

/// How often lapsed invites are deleted.
const SWEEP: Duration = Duration::from_secs(3600);

/// The letters a code is written in: no `0`/`O`, no `1`/`l`/`I`, because a code
/// is sometimes read aloud or copied off a screen by hand.
const ALPHABET: &[u8] = b"23456789abcdefghijkmnpqrstuvwxyz";

/// How long a code is. Thirty-two letters, twelve times: sixty bits, which no
/// login rate limit lets anybody walk.
const CODE_LEN: usize = 12;

/// The service.
#[derive(Debug)]
pub struct InvitesService {
    store: Store,
    roster: Arc<Roster>,
    permit: Permit,
    settings: Settings,
    trail: Trail,
    fanout: Fanout,
    /// How many live invites one creator may hold, administrators aside.
    ///
    /// Not a setting in the form: it is a guard against a script minting codes
    /// in a loop, not a policy an operator has an opinion about.
    per_creator: u32,
}

/// Why a request was refused, before it is framed.
struct Refusal(invite_refused::Reason, &'static str);

/// Who a session is, as far as invites care.
struct Caller {
    /// The durable key "mine" is decided on. See [`identity_key`].
    key: String,
    name: String,
    account: Option<u64>,
    /// Whether they hold Write on the root: may mint regardless of `invites`
    /// (unless it is off), and may list and revoke everybody's.
    manages: bool,
}

/// What `invites` currently lets which sessions do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Policy {
    Off,
    Admins,
    Registered,
    Everyone,
}

impl Policy {
    /// Read the setting. Anything this build does not know is `Off`: a typo
    /// must close the door, not open it.
    fn of(config: &Snapshot) -> Self {
        match config.invites.as_str() {
            INVITES_ADMINS => Self::Admins,
            INVITES_REGISTERED => Self::Registered,
            INVITES_EVERYONE => Self::Everyone,
            INVITES_OFF => Self::Off,
            other => {
                tracing::warn!(
                    value = other,
                    "unknown `invites` setting; treating it as off"
                );
                Self::Off
            }
        }
    }

    /// Whether somebody with `account` who does or does not `manage` may mint.
    const fn may_create(self, account: Option<u64>, manages: bool) -> bool {
        match self {
            Self::Off => false,
            Self::Admins => manages,
            Self::Registered => manages || account.is_some(),
            Self::Everyone => true,
        }
    }
}

/// The durable key for "who is this", strongest identity first.
///
/// An account is the person; a certificate is the keypair a guest keeps across
/// reconnects; a name is all that is left for somebody with neither, and is a
/// weak key on purpose - two certificate-less guests calling themselves the
/// same thing are, to this service, the same guest.
fn identity_key(account: Option<u64>, cert_hash: &[u8], name: &str) -> String {
    if let Some(account) = account {
        return format!("account:{account}");
    }
    if !cert_hash.is_empty() {
        return format!("cert:{}", hex(cert_hash));
    }
    format!("name:{}", name.to_lowercase())
}

/// The key a *redemption* is counted on. No account here: the handshake asks
/// before it knows one, and an account is always behind a certificate or a
/// name anyway.
pub(crate) fn redeemer_key(cert_hash: &[u8], name: &str) -> String {
    identity_key(None, cert_hash, name)
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut out, byte| {
            let _ = write!(out, "{byte:02x}");
            out
        })
}

/// A fresh code.
fn mint_code() -> String {
    use rand::RngExt as _;
    let mut rng = rand::rng();
    (0..CODE_LEN)
        .filter_map(|_| ALPHABET.get(rng.random_range(0..ALPHABET.len())))
        .map(|&letter| char::from(letter))
        .collect()
}

/// Whether `code` could be one this service minted. Checked before any
/// database is asked, so a login carrying rubbish costs nothing.
pub(crate) fn plausible(code: &str) -> bool {
    code.len() == CODE_LEN && code.bytes().all(|byte| ALPHABET.contains(&byte))
}

/// The lifetime an invite gets, in milliseconds from creation, zero for never.
///
/// Zero asks for the longest allowed; more than the ceiling is clamped to it
/// rather than refused, because a client offering "a month" on a server that
/// allows a week should get a week, not an error to retry.
pub(crate) fn lifetime_ms(asked_s: u64, max_hours: u32) -> u64 {
    let ceiling_s = u64::from(max_hours) * 3600;
    let seconds = match (asked_s, ceiling_s) {
        (asked, 0) => asked,
        (0, ceiling) => ceiling,
        (asked, ceiling) => asked.min(ceiling),
    };
    seconds.saturating_mul(1000)
}

/// How many people an invite may admit, zero for unlimited, clamped the same
/// way as [`lifetime_ms`].
pub(crate) const fn use_limit(asked: u32, ceiling: u32) -> u32 {
    match (asked, ceiling) {
        (asked, 0) => asked,
        (0, ceiling) => ceiling,
        (asked, ceiling) => {
            if asked < ceiling {
                asked
            } else {
                ceiling
            }
        }
    }
}

impl Row {
    /// The wire shape, as `asker` sees it.
    fn to_wire(&self, asker: &str) -> Invite {
        Invite {
            code: self.code.clone(),
            channel_id: self.channel,
            created_ms: self.created_ms,
            expires_ms: self.expires_ms,
            max_uses: self.max_uses,
            uses: self.uses,
            creator: self.creator.clone(),
            mine: self.creator_key == asker,
        }
    }
}

impl ClientService for InvitesService {
    async fn frame(&self, inbound: Inbound) -> Actions {
        if inbound.type_id != ServiceKind::Invites.outer_type() {
            return Actions::new();
        }
        let Ok(envelope) = InvitesEnvelope::decode(inbound.payload.as_slice()) else {
            tracing::debug!(
                conn = inbound.conn,
                session = inbound.session,
                len = inbound.payload.len(),
                "undecodable InvitesEnvelope"
            );
            return Actions::new();
        };
        let answer = match envelope.body {
            Some(invites_envelope::Body::SupportQuery(asked)) => {
                invites_envelope::Body::Support(self.support(&inbound, asked.request_id).await)
            }
            Some(invites_envelope::Body::Create(create)) => {
                let request_id = create.request_id.clone();
                match self.create(&inbound, create).await {
                    Ok(invite) => invites_envelope::Body::Created(InviteCreated {
                        request_id,
                        invite: Some(invite),
                    }),
                    Err(refusal) => refused(request_id, refusal),
                }
            }
            Some(invites_envelope::Body::ListQuery(query)) => {
                let request_id = query.request_id.clone();
                match self.list(&inbound, &query).await {
                    Ok(invites) => invites_envelope::Body::List(InviteList {
                        request_id,
                        invites,
                    }),
                    Err(refusal) => refused(request_id, refusal),
                }
            }
            Some(invites_envelope::Body::Revoke(revoke)) => {
                let request_id = revoke.request_id.clone();
                match self.revoke(&inbound, &revoke).await {
                    Ok(()) => invites_envelope::Body::Revoked(InviteRevoked {
                        request_id,
                        code: revoke.code,
                    }),
                    Err(refusal) => refused(request_id, refusal),
                }
            }
            // Server -> client bodies from a client: confused, or newer than
            // this server. Nothing here answers one.
            _ => return Actions::new(),
        };
        vec![framed(inbound.conn, answer)]
    }
}

impl InvitesService {
    /// Who `inbound`'s session is.
    async fn caller(&self, inbound: &Inbound) -> Caller {
        let account = self.roster.account_of(inbound.session);
        let cert = self.roster.cert_of(inbound.session).unwrap_or_default();
        let name = self.roster.name_of(inbound.session).unwrap_or_default();
        let manages = self
            .permit
            .allows(inbound, ROOT_CHANNEL, Perm::WRITE.bits())
            .await;
        Caller {
            key: identity_key(account, &cert, &name),
            name,
            account,
            manages,
        }
    }

    /// What this session may do, said up front.
    async fn support(&self, inbound: &Inbound, request_id: String) -> InviteSupport {
        let config = self.settings.get(inbound.scope);
        let policy = Policy::of(&config);
        if policy == Policy::Off {
            return InviteSupport {
                request_id,
                ..InviteSupport::default()
            };
        }
        let caller = self.caller(inbound).await;
        InviteSupport {
            request_id,
            available: true,
            may_create: policy.may_create(caller.account, caller.manages),
            may_manage: caller.manages,
            max_age_s: u64::from(config.invite_max_hours) * 3600,
            max_uses: config.invite_max_uses,
            address: config.invite_address,
            skips_password: config.invite_skips_password,
        }
    }

    /// Mint one for a client.
    async fn create(&self, inbound: &Inbound, create: InviteCreate) -> Result<Invite, Refusal> {
        let config = self.settings.get(inbound.scope);
        let policy = Policy::of(&config);
        if policy == Policy::Off {
            return Err(Refusal(
                invite_refused::Reason::Unavailable,
                "invites are switched off on this server",
            ));
        }
        let caller = self.caller(inbound).await;
        if !policy.may_create(caller.account, caller.manages) {
            return Err(Refusal(
                invite_refused::Reason::Permission,
                "you may not create invites on this server",
            ));
        }
        if create.channel_id != ROOT_CHANNEL
            && !self
                .permit
                .allows(inbound, create.channel_id, Perm::ENTER.bits())
                .await
        {
            // The ACL is the ceiling on where an invite may point: somebody who
            // cannot go somewhere cannot send anybody else there either.
            return Err(Refusal(
                invite_refused::Reason::Permission,
                "you may not invite people into a channel you cannot enter",
            ));
        }
        let now = now_ms();
        if !caller.manages {
            let held = store::live_count(&self.store, inbound.scope, &caller.key, now)
                .await
                .map_err(|error| self.failed("count", &error))?;
            if held >= self.per_creator {
                return Err(Refusal(
                    invite_refused::Reason::Limit,
                    "you already have as many open invites as you may; revoke one first",
                ));
            }
        }

        let lifetime = lifetime_ms(create.max_age_s, config.invite_max_hours);
        let row = Row {
            code: mint_code(),
            channel: create.channel_id,
            created_ms: now,
            expires_ms: if lifetime == 0 { 0 } else { now + lifetime },
            max_uses: use_limit(create.max_uses, config.invite_max_uses),
            uses: 0,
            creator: caller.name.clone(),
            creator_key: caller.key.clone(),
            creator_account: caller.account,
        };
        store::insert(&self.store, inbound.scope, &row)
            .await
            .map_err(|error| self.failed("insert", &error))?;
        tracing::info!(
            session = inbound.session,
            channel = row.channel,
            expires_ms = row.expires_ms,
            max_uses = row.max_uses,
            "invite created"
        );
        self.trail.record(
            inbound.scope,
            Record::new(trail::category::INVITE, "invite created")
                .actor(session_actor(inbound.session), caller.name.clone())
                .target_channel(row.channel)
                .detail(describe(&row)),
        );
        Ok(row.to_wire(&caller.key))
    }

    /// The caller's own invites, or everybody's for an administrator.
    async fn list(
        &self,
        inbound: &Inbound,
        query: &InviteListQuery,
    ) -> Result<Vec<Invite>, Refusal> {
        if Policy::of(&self.settings.get(inbound.scope)) == Policy::Off {
            // Listed anyway would be harmless, but an admin screen that shows
            // invites on a server where none of them work is a screen that
            // lies; the refusal says why the list is empty.
            return Err(Refusal(
                invite_refused::Reason::Unavailable,
                "invites are switched off on this server",
            ));
        }
        let caller = self.caller(inbound).await;
        if query.everyone && !caller.manages {
            return Err(Refusal(
                invite_refused::Reason::Permission,
                "only an administrator may list everybody's invites",
            ));
        }
        let only = (!query.everyone).then_some(caller.key.as_str());
        let rows = store::live(&self.store, inbound.scope, only, now_ms())
            .await
            .map_err(|error| self.failed("list", &error))?;
        Ok(rows.iter().map(|row| row.to_wire(&caller.key)).collect())
    }

    /// Revoke one: any for an administrator, only their own for anybody else.
    async fn revoke(&self, inbound: &Inbound, revoke: &InviteRevoke) -> Result<(), Refusal> {
        let caller = self.caller(inbound).await;
        let only = (!caller.manages).then_some(caller.key.as_str());
        let found = store::remove(&self.store, inbound.scope, &revoke.code, only)
            .await
            .map_err(|error| self.failed("revoke", &error))?;
        if !found {
            // The same answer for "no such code" and "somebody else's": telling
            // them apart would let anybody test whether a code exists.
            return Err(Refusal(
                invite_refused::Reason::NotFound,
                "no such invite of yours",
            ));
        }
        tracing::info!(session = inbound.session, "invite revoked");
        self.trail.record(
            inbound.scope,
            Record::new(trail::category::INVITE, "invite revoked")
                .actor(session_actor(inbound.session), caller.name)
                .detail(format!("code {}…", code_prefix(&revoke.code))),
        );
        Ok(())
    }

    /// Log a storage failure and turn it into the refusal a client gets.
    fn failed(&self, what: &str, error: &starling_runtime::storage::StoreError) -> Refusal {
        tracing::warn!(what, %error, "invites storage failed");
        Refusal(
            invite_refused::Reason::Other,
            "the server could not do that right now",
        )
    }

    /// Delete everything that has lapsed, for every scope this process serves.
    async fn sweep(&self, scopes: &[u32]) {
        for &scope in scopes {
            match store::sweep(&self.store, scope, now_ms()).await {
                Ok(0) => {}
                Ok(removed) => tracing::debug!(scope, removed, "expired invites swept"),
                Err(error) => tracing::warn!(scope, %error, "sweeping expired invites failed"),
            }
        }
    }
}

/// An `Actor` for a connected session.
fn session_actor(session: u32) -> Actor {
    Actor {
        who: Some(actor::Who::Session(session)),
    }
}

/// The first few letters of a code, for a record that must identify it to an
/// administrator without being a usable copy of it.
fn code_prefix(code: &str) -> &str {
    code.get(..4).unwrap_or(code)
}

/// One line about an invite, for the audit record. Never the whole code: the
/// audit log is read by more people than the invite was meant for.
fn describe(row: &Row) -> String {
    let expires = if row.expires_ms == 0 {
        "never expires".to_owned()
    } else {
        format!(
            "expires in {} h",
            row.expires_ms.saturating_sub(row.created_ms) / 3_600_000
        )
    };
    let uses = if row.max_uses == 0 {
        "unlimited uses".to_owned()
    } else {
        format!("{} uses", row.max_uses)
    };
    format!("code {}…, {expires}, {uses}", code_prefix(&row.code))
}

/// A refusal, as the envelope body a client gets.
fn refused(request_id: String, Refusal(reason, detail): Refusal) -> invites_envelope::Body {
    invites_envelope::Body::Refused(InviteRefused {
        request_id,
        reason: reason as i32,
        detail: detail.to_owned(),
    })
}

/// Any answer, framed and addressed to one connection.
fn framed(conn: u64, body: invites_envelope::Body) -> starling_proto_fancy::control::ServerAction {
    to_conn(
        conn,
        ServiceKind::Invites.outer_type(),
        InvitesEnvelope { body: Some(body) }.encode_to_vec(),
    )
}

impl Serve for InvitesService {
    const NAME: &'static str = "invites";

    async fn build(ctx: ServiceContext) -> Result<Arc<Self>, ServiceError> {
        let store = ctx.storage().await?;
        store.migrate(store::SCHEMA).await?;
        Ok(Arc::new(Self {
            store,
            roster: Arc::new(Roster::new()),
            permit: Permit::new(ctx.resolver.clone()),
            settings: Settings::new(ctx.resolver.clone()),
            trail: Trail::new(ctx.resolver.clone()),
            fanout: Fanout::default(),
            per_creator: ctx
                .service()
                .option::<u32>("invites_per_creator")
                .unwrap_or(25),
        }))
    }

    async fn run(self: Arc<Self>, ctx: ServiceContext) -> Result<(), ServiceError> {
        let scopes = ctx.instances();
        let follower = Arc::clone(&self.roster).follow(ctx.clone(), Self::NAME, VIEW_GATE);
        let watchers = self.settings.watch(&scopes);
        let sweeper = tokio::spawn({
            let service = Arc::clone(&self);
            async move {
                loop {
                    service.sweep(&scopes).await;
                    tokio::time::sleep(SWEEP).await;
                }
            }
        });
        ctx.shutdown.wait().await;
        follower.abort();
        sweeper.abort();
        for watcher in watchers {
            watcher.abort();
        }
        Ok(())
    }

    fn routes(self: Arc<Self>) -> tonic::service::Routes {
        let plane = Plane::new(Arc::clone(&self), self.fanout.clone(), Self::NAME).into_server();
        tonic::service::Routes::default()
            .add_service(rpc::server(Arc::clone(&self)))
            .add_service(plane)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(crate) async fn memory_store() -> Store {
        // A name unique per call: `cache=shared` makes same-named in-memory
        // databases visible to every connection that names them.
        use std::sync::atomic::{AtomicU64, Ordering};
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let id = NEXT.fetch_add(1, Ordering::Relaxed);
        let store = Store::open(
            &format!("sqlite:file:invites-test-{id}?mode=memory&cache=shared"),
            1,
        )
        .await
        .expect("in-memory database");
        store.migrate(store::SCHEMA).await.expect("schema");
        store
    }

    fn row(code: &str, expires_ms: u64, max_uses: u32) -> Row {
        Row {
            code: code.to_owned(),
            channel: 7,
            created_ms: 1,
            expires_ms,
            max_uses,
            uses: 0,
            creator: "alice".to_owned(),
            creator_key: "account:1".to_owned(),
            creator_account: Some(1),
        }
    }

    #[test]
    fn a_code_is_long_unambiguous_and_recognisable() {
        for _ in 0..100 {
            let code = mint_code();
            assert!(plausible(&code), "{code}");
            assert!(!code.contains(['0', 'o', '1', 'l']), "{code}");
        }
        assert!(!plausible("short"));
        assert!(!plausible("ABCDEFGHJKMN"), "upper case is never minted");
        assert!(!plausible("aaaaaaaaaaa0"));
    }

    #[test]
    fn asking_for_more_than_the_server_allows_gets_what_it_allows() {
        // No ceiling: what was asked, and zero is forever.
        assert_eq!(lifetime_ms(0, 0), 0);
        assert_eq!(lifetime_ms(60, 0), 60_000);
        // A week's ceiling: zero and "a year" both mean a week.
        let week = 168 * 3600 * 1000;
        assert_eq!(lifetime_ms(0, 168), week);
        assert_eq!(lifetime_ms(365 * 86_400, 168), week);
        assert_eq!(lifetime_ms(3600, 168), 3_600_000);

        assert_eq!(use_limit(0, 0), 0);
        assert_eq!(use_limit(3, 0), 3);
        assert_eq!(use_limit(0, 10), 10);
        assert_eq!(use_limit(50, 10), 10);
        assert_eq!(use_limit(1, 10), 1);
    }

    #[test]
    fn an_unknown_policy_closes_the_door() {
        let mut config = starling_runtime::settings::defaults(1);
        assert_eq!(Policy::of(&config), Policy::Admins, "the default");
        config.invites = "admin".to_owned();
        assert_eq!(Policy::of(&config), Policy::Off);

        assert!(!Policy::Off.may_create(Some(1), true));
        assert!(!Policy::Admins.may_create(Some(1), false));
        assert!(Policy::Admins.may_create(None, true));
        assert!(!Policy::Registered.may_create(None, false));
        assert!(Policy::Registered.may_create(Some(1), false));
        assert!(Policy::Everyone.may_create(None, false));
    }

    #[test]
    fn identity_prefers_the_account_then_the_certificate_then_the_name() {
        assert_eq!(identity_key(Some(4), &[1, 2], "Bob"), "account:4");
        assert_eq!(identity_key(None, &[0xab, 0x01], "Bob"), "cert:ab01");
        assert_eq!(identity_key(None, &[], "Bob"), "name:bob");
    }

    #[tokio::test]
    async fn a_use_is_a_person_and_a_returning_person_is_not_a_second_use() {
        let store = memory_store().await;
        store::insert(&store, 1, &row("aaaaaaaaaaaa", 0, 2))
            .await
            .expect("insert");

        let admitted = store::Redeemed::Admitted { channel: 7 };
        assert_eq!(
            store::redeem(&store, 1, "aaaaaaaaaaaa", "cert:01", 10)
                .await
                .expect("redeem"),
            admitted
        );
        // The same person, reconnecting: free.
        assert_eq!(
            store::redeem(&store, 1, "aaaaaaaaaaaa", "cert:01", 11)
                .await
                .expect("redeem"),
            admitted
        );
        assert_eq!(
            store::redeem(&store, 1, "aaaaaaaaaaaa", "cert:02", 12)
                .await
                .expect("redeem"),
            admitted
        );
        // A third stranger finds it used up...
        assert!(matches!(
            store::redeem(&store, 1, "aaaaaaaaaaaa", "cert:03", 13)
                .await
                .expect("redeem"),
            store::Redeemed::Refused(_)
        ));
        // ...while the two it admitted still get back in.
        assert_eq!(
            store::redeem(&store, 1, "aaaaaaaaaaaa", "cert:02", 14)
                .await
                .expect("redeem"),
            admitted
        );
        let stored = store::find(&store, 1, "aaaaaaaaaaaa")
            .await
            .expect("find")
            .expect("a row");
        assert_eq!(stored.uses, 2);
    }

    #[tokio::test]
    async fn an_expired_or_revoked_invite_admits_nobody() {
        let store = memory_store().await;
        store::insert(&store, 1, &row("bbbbbbbbbbbb", 100, 0))
            .await
            .expect("insert");
        store::insert(&store, 1, &row("cccccccccccc", 0, 0))
            .await
            .expect("insert");

        assert!(matches!(
            store::redeem(&store, 1, "bbbbbbbbbbbb", "cert:01", 100)
                .await
                .expect("redeem"),
            store::Redeemed::Refused(_)
        ));
        // Another scope's code is no code at all here.
        assert!(matches!(
            store::redeem(&store, 2, "cccccccccccc", "cert:01", 1)
                .await
                .expect("redeem"),
            store::Redeemed::Refused(_)
        ));

        // Somebody else's revoke does not touch it; the creator's does.
        assert!(
            !store::remove(&store, 1, "cccccccccccc", Some("account:2"))
                .await
                .expect("remove")
        );
        assert!(
            store::remove(&store, 1, "cccccccccccc", Some("account:1"))
                .await
                .expect("remove")
        );
        assert!(matches!(
            store::redeem(&store, 1, "cccccccccccc", "cert:01", 1)
                .await
                .expect("redeem"),
            store::Redeemed::Refused(_)
        ));
    }

    #[tokio::test]
    async fn the_sweep_takes_only_what_has_lapsed() {
        let store = memory_store().await;
        store::insert(&store, 1, &row("dddddddddddd", 100, 0))
            .await
            .expect("insert");
        store::insert(&store, 1, &row("eeeeeeeeeeee", 0, 0))
            .await
            .expect("insert");
        store::insert(&store, 1, &row("ffffffffffff", 1_000, 0))
            .await
            .expect("insert");

        assert_eq!(store::sweep(&store, 1, 500).await.expect("sweep"), 1);
        let live = store::live(&store, 1, None, 500).await.expect("live");
        let codes: Vec<&str> = live.iter().map(|row| row.code.as_str()).collect();
        assert_eq!(codes.len(), 2);
        assert!(codes.contains(&"eeeeeeeeeeee") && codes.contains(&"ffffffffffff"));
        assert_eq!(
            store::live_count(&store, 1, "account:1", 500)
                .await
                .expect("count"),
            2
        );
        assert_eq!(
            store::live_count(&store, 1, "account:1", 2_000)
                .await
                .expect("count"),
            1
        );
    }
}
