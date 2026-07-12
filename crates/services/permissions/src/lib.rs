//! `permissions` — ACL evaluation.
//!
//! Stateless, and scaled out by **coalescing** identical in-flight queries
//! rather than by caching. That is Discord's data-services trick, and the
//! reason it is the right one here: ACL evaluation walks the channel tree, a
//! busy channel produces many identical concurrent queries, and a cache needs
//! invalidation while coalescing does not
//! (`docs/ARCHITECTURE.md` §6, `docs/diagrams/scaling.puml`).
//!
//! **A stale deny is safe; a stale grant is a security bug** — so a revocation
//! is published to subscribers before it is acknowledged, and a grant may
//! arrive lazily.

pub mod perm;

pub mod coalesce;
pub mod evaluate;
pub mod group;

pub use coalesce::Coalescer;
pub use evaluate::{Acls, evaluate};
pub use perm::{AllowAll, Perm, Permissions};

use std::sync::Arc;

use prost::Message as _;
use starling_proto_fancy::common::{Decision, Scope};
use starling_proto_fancy::permissions::permissions_server::{
    Permissions as PermissionsRpc, PermissionsServer,
};
use starling_proto_fancy::permissions::{
    AclRequest, AclResult, AclSet, CheckRequest, EffectiveRequest, EffectiveResponse, Invalidation,
    SessionCheckRequest, SetAclRequest, Subject, TemporaryGroupRequest, temporary_group_request,
};
use starling_proto_fancy::sessionview::GetRequest as SessionGetRequest;
use starling_proto_fancy::sessionview::session_view_client::SessionViewClient;
use starling_proto_fancy::types::ServiceKind;
use starling_runtime::channel::Resolver;
use starling_runtime::log::{Category, LogEvent, Logger};
use starling_runtime::permit::permission_denied;
use starling_runtime::plane::{Actions, ClientService, Fanout, Inbound, Plane, to_conn};
use starling_runtime::serve::{Serve, ServiceContext, ServiceError};
use starling_runtime::storage::{Migration, Store};
use tokio::sync::broadcast;
use tonic::{Request, Response, Status};

/// Upstream `PermissionQuery`.
const PERMISSION_QUERY: u16 = 20;
/// Upstream `ACL`.
const ACL: u16 = 13;

/// How many invalidations a subscriber may fall behind before it must assume
/// everything is stale. Falling behind on a *revocation* is the dangerous
/// direction, so the shed policy is "assume the worst", not "carry on".
const EVENT_BUFFER: usize = 256;

/// The schema: one row per channel, holding that channel's whole ACL set.
///
/// Stored as the encoded `AclSet` rather than a row per entry, the same shape
/// `server-config` uses for its snapshot. An ACL set is replaced wholesale by
/// `SetAcl` and is never queried by parts — the evaluator reads the whole set
/// for a channel — so a row per entry would buy a join and cost the ordering
/// within a set, which is load-bearing: deny beats allow *at the same level*.
const SCHEMA: &[Migration<'static>] = &[Migration::new(
    "0001_channel_acl",
    &["CREATE TABLE IF NOT EXISTS channel_acl (\
           server_id BIGINT NOT NULL, channel_id BIGINT NOT NULL, \
           acls BLOB NOT NULL, \
           PRIMARY KEY (server_id, channel_id))"],
)];

/// The service.
#[derive(Debug)]
pub struct PermissionsService {
    acls: Acls,
    coalescer: Coalescer,
    invalidations: broadcast::Sender<Invalidation>,
    fanout: Fanout,
    logger: Logger,
    /// How to reach `session-view`, to find out who is asking.
    ///
    /// `None` in tests, which construct the service directly and evaluate
    /// against a `Subject` they built themselves.
    resolver: Option<Resolver>,
    /// Where the ACL tables live between restarts.
    ///
    /// `None` in tests. In a deployment an absent store would mean every grant
    /// an operator makes is lost on the next restart — and since an ACL entry is
    /// the only way to hand out anything beyond the default set, that is the
    /// whole of a server's configured authority disappearing silently.
    store: Option<Store>,
}

impl PermissionsService {
    /// The ACL tables, for the operator surface and tests.
    #[must_use]
    pub fn acls(&self) -> &Acls {
        &self.acls
    }

    /// Whether `granted` satisfies `wanted`.
    ///
    /// **Every** requested bit must be held, and an empty request is refused.
    /// murmur asks with one bit at a time and tests `granted & perm != 0`, which
    /// for a multi-bit question answers "any of them" — an authorisation check
    /// that says yes when half the requirement is met. Asking for nothing is
    /// refused because there is no action to authorise, so a caller that
    /// computed a permission mask and got zero is told no rather than yes.
    #[must_use]
    pub const fn permits(granted: u32, wanted: u32) -> bool {
        wanted != 0 && granted & wanted == wanted
    }

    /// Evaluate and record, returning what the caller should be told.
    ///
    /// One path, so the answer and the record cannot disagree about what was
    /// decided — and so a new caller cannot get the decision without the log.
    fn decide(&self, scope: u32, subject: &Subject, channel: u32, permission: u32) -> Decision {
        let granted = evaluate(&self.acls, scope, subject, channel);
        let allowed = Self::permits(granted, permission);
        let reason = if allowed {
            String::new()
        } else {
            Perm::from_bits_truncate(permission & !granted).describe()
        };

        // A grant is per-frame and would drown the log; a refusal is what the
        // user reports as "it doesn't work" and the operator has no other way
        // to see. Naming the missing bit is the difference between this record
        // and a support ticket.
        if allowed {
            tracing::trace!(channel, permission, "allowed");
        } else {
            self.logger.log(
                LogEvent::info(Category::Permission, "permission denied")
                    .with("session", subject.session)
                    .with("name", subject.name.clone())
                    .with("account", subject.account)
                    .with("registered", subject.registered)
                    .with("channel", channel)
                    .with("permission", permission)
                    .with("missing", reason.clone())
                    .with("scope", scope),
            );
        }

        Decision {
            allowed,
            missing: if allowed { 0 } else { permission & !granted },
            reason,
        }
    }

    /// Write one channel's ACL set through to the database.
    ///
    /// Write-*through*, not write-behind. Everywhere else in the control plane
    /// the durable record may lag the memory it was derived from, because losing
    /// the tail costs a little state. Here the tail is an operator's grant or,
    /// worse, their revocation — and a revocation that was acknowledged and then
    /// lost in a restart is a permission somebody keeps holding after being told
    /// they had lost it.
    async fn persist(&self, scope: u32, acls: &AclSet) {
        let Some(store) = &self.store else {
            return;
        };
        let result = sqlx::query(
            "INSERT INTO channel_acl (server_id, channel_id, acls) VALUES (?, ?, ?) \
             ON CONFLICT (server_id, channel_id) DO UPDATE SET acls = excluded.acls",
        )
        .bind(i64::from(scope))
        .bind(i64::from(acls.channel))
        .bind(acls.encode_to_vec())
        .execute(store.pool())
        .await;

        if let Err(error) = result {
            // Loud, and on the operator's own record. The change *has* taken
            // effect in memory, so the server is now running a policy that will
            // silently revert the next time it starts.
            tracing::error!(%error, channel = acls.channel, "could not persist an ACL change");
            self.logger.log(
                LogEvent::error(Category::Permission, "acl change was not persisted")
                    .with("channel", acls.channel)
                    .with("scope", scope)
                    .with("error", error.to_string())
                    .with("effective_now", true)
                    .with("survives_restart", false),
            );
        }
    }

    /// Follow the channel tree, so the ancestor walk has a tree to walk.
    ///
    /// Evaluation inherits from a channel's parents, and until this existed the
    /// parent table was only ever written by tests — so in a running server
    /// every channel evaluated as though it were the root, and an ACL set on a
    /// parent reached none of its children. That is silent: the entry is there,
    /// it is simply never consulted.
    ///
    /// A subscription rather than a lookup per evaluation, because `ancestry` is
    /// on the hot path of every permission check and **nothing on that path may
    /// make a request** (`docs/ARCHITECTURE.md` §4). `metadata` sends a snapshot
    /// first and deltas after, so the table is complete from the first message.
    ///
    /// Re-subscribes on failure. A metadata restart is a rolling deploy, not an
    /// incident — but note what a stale tree means here: a channel whose parent
    /// changed keeps inheriting from the old one until the stream reconnects.
    /// That is why the retry is short.
    async fn follow_tree(&self, scope: u32) {
        use starling_proto_fancy::metadata::TreeRequest;
        use starling_proto_fancy::metadata::metadata_client::MetadataClient;

        /// How long to wait before re-subscribing.
        const RETRY: std::time::Duration = std::time::Duration::from_secs(1);

        let Some(resolver) = &self.resolver else {
            return;
        };
        loop {
            let stream = match resolver.channel("metadata") {
                Ok(transport) => {
                    MetadataClient::new(transport)
                        .watch(TreeRequest {
                            scope: Some(Scope {
                                virtual_server: scope,
                            }),
                        })
                        .await
                }
                Err(error) => {
                    tracing::warn!(%error, "cannot reach metadata; retrying");
                    tokio::time::sleep(RETRY).await;
                    continue;
                }
            };
            let Ok(stream) = stream else {
                tokio::time::sleep(RETRY).await;
                continue;
            };

            let mut events = stream.into_inner();
            while let Ok(Some(event)) = events.message().await {
                self.apply_tree_event(scope, event);
            }
            tokio::time::sleep(RETRY).await;
        }
    }

    /// Fold one tree event into the parent map the evaluator walks.
    ///
    /// Split from the subscribe loop above rather than written inline: a
    /// `match` with a loop in one arm, inside a `while`, inside a reconnect
    /// `loop`, is four levels of nesting to read past before reaching what the
    /// event actually does.
    fn apply_tree_event(&self, scope: u32, event: starling_proto_fancy::metadata::TreeEvent) {
        use starling_proto_fancy::metadata::tree_event;

        match event.event {
            Some(tree_event::Event::Snapshot(tree)) => {
                for channel in tree.channels {
                    self.record_parent(scope, channel.id, channel.parent);
                }
            }
            Some(tree_event::Event::Upsert(channel)) => {
                self.record_parent(scope, channel.id, channel.parent);
            }
            Some(tree_event::Event::Removed(channel)) => {
                self.acls.forget(scope, channel);
            }
            _ => {}
        }
    }

    /// Record where one channel sits, and whether it inherits at all.
    fn record_parent(&self, scope: u32, channel: u32, parent: Option<u32>) {
        // The root has no parent, and saying it is its own would make `ancestry`
        // walk in a circle until its bound stopped it.
        if let Some(parent) = parent
            && parent != channel
        {
            self.acls.set_parent(scope, channel, parent);
        }
    }

    /// Load every stored ACL set into memory.
    ///
    /// Read once at boot. The database is the durable record, never a read path
    /// for evaluation (`docs/STORAGE.md` L7): a permission check that touched
    /// the disk would put I/O inside the hot path of every frame.
    async fn warm(&self) {
        use sqlx::Row as _;
        let Some(store) = &self.store else {
            return;
        };
        let rows = sqlx::query("SELECT server_id, acls FROM channel_acl")
            .fetch_all(store.pool())
            .await
            .unwrap_or_default();

        let mut loaded = 0_usize;
        for row in rows {
            let scope = row.try_get::<i64, _>("server_id").unwrap_or(1) as u32;
            let Ok(bytes) = row.try_get::<Vec<u8>, _>("acls") else {
                continue;
            };
            // A row that will not decode is skipped rather than fatal, and said
            // out loud: refusing to start would take the whole server down over
            // one channel's table, and starting silently would apply an ACL set
            // nobody can see.
            match AclSet::decode(bytes.as_slice()) {
                Ok(set) => {
                    self.acls.set(scope, set);
                    loaded += 1;
                }
                Err(error) => {
                    tracing::error!(%error, scope, "skipping an unreadable ACL row");
                }
            }
        }
        tracing::info!(loaded, "acl tables loaded");
    }

    /// Add or remove one temporary group membership.
    ///
    /// One function for both directions because everything except the final
    /// call is shared, and the two drifting apart is how a grant ends up
    /// validated differently from the revocation that undoes it.
    ///
    /// Not persisted, and the invalidation is published before the caller is
    /// acknowledged — the same order every other write here uses, for the same
    /// reason: a revocation that races an acknowledgement is a stale grant.
    async fn temporary(
        &self,
        req: &TemporaryGroupRequest,
        add: bool,
    ) -> Result<Response<AclResult>, Status> {
        let scope = scope_of(req.scope);
        let refuse = |why: &str| {
            Ok(Response::new(AclResult {
                applied: false,
                refused: why.to_owned(),
            }))
        };

        // A group *name*, not a specification. Accepting `#token` or `!admin`
        // here would store a membership of something the evaluator parses as a
        // predicate, which no walk would ever consult.
        if req.group.is_empty() {
            return refuse("no group was named");
        }
        if req.group.starts_with(['!', '~', '#', '$']) {
            return refuse("a temporary membership names a group, not a specification");
        }
        let Some(member) = req.member else {
            return refuse("no member was named");
        };
        let member = match member {
            temporary_group_request::Member::Account(account) => evaluate::Member::Account(account),
            // Zero is "no session"; a grant naming it could never be matched,
            // because no allocator issues it.
            temporary_group_request::Member::Session(0) => {
                return refuse("session 0 is not a session");
            }
            temporary_group_request::Member::Session(session) => evaluate::Member::Session(session),
        };

        if add {
            // **A grant may only name a session that is currently connected**,
            // which is murmur's rule (`NEED_PLAYER` ahead of
            // `MumbleServerIce.cpp:2307`, raising `InvalidSessionException`) and
            // is load-bearing rather than input validation. Departures are what
            // clear these grants; a grant made for an id that has *already* gone
            // has therefore missed its only cleanup, and would sit in the table
            // until the pool reissues that id to somebody else.
            //
            // Only on the way in. Refusing a *revocation* because the holder has
            // already left would be refusing a no-op, and of the two directions
            // it is the one that must never be blocked.
            if let evaluate::Member::Session(session) = member
                && self.resolve(scope, session).await.is_none()
            {
                return refuse("that session is not connected");
            }
            self.acls
                .add_temporary(scope, req.channel, &req.group, member);
        } else {
            self.acls
                .remove_temporary(scope, req.channel, &req.group, member);
        }

        self.logger.log(
            LogEvent::notice(Category::Permission, "temporary group membership changed")
                .with("channel", req.channel)
                .with("group", req.group.clone())
                .with("added", add)
                .with("member", format!("{member:?}"))
                .with("scope", scope),
        );

        let _ = self.invalidations.send(Invalidation {
            channels: vec![req.channel],
            accounts: Vec::new(),
            everything: true,
        });
        self.coalescer.clear();

        Ok(Response::new(AclResult {
            applied: true,
            refused: String::new(),
        }))
    }

    /// Drop a departed session's temporary memberships.
    ///
    /// A subscription rather than a call from `session-lifecycle`, because this
    /// service already learns who a session is through `session-view` and that
    /// is the edge `docs/ARCHITECTURE.md` §4 draws — a disconnect hook pointing
    /// the other way would be a second one.
    ///
    /// **Fail-safe is not "carry on" here.** A lost `Gone` leaves a grant
    /// attached to a session id that gets reissued, so a dropped stream clears
    /// every session-scoped grant rather than trusting its own copy: the cost is
    /// an external authority having to re-grant, and the alternative is somebody
    /// silently inheriting a stranger's group.
    async fn follow_sessions(&self, scope: u32) {
        use starling_proto_fancy::sessionview::{SubscribeRequest, view_event};

        /// How long to wait before re-subscribing.
        const RETRY: std::time::Duration = std::time::Duration::from_secs(1);

        let Some(resolver) = &self.resolver else {
            return;
        };
        loop {
            let stream = match resolver.channel("session-view") {
                Ok(transport) => {
                    SessionViewClient::new(transport)
                        .subscribe(SubscribeRequest {
                            scope: Some(Scope {
                                virtual_server: scope,
                            }),
                            subscriber: Self::NAME.to_owned(),
                        })
                        .await
                }
                Err(error) => {
                    tracing::warn!(%error, "cannot reach session-view; retrying");
                    tokio::time::sleep(RETRY).await;
                    continue;
                }
            };
            let Ok(stream) = stream else {
                tokio::time::sleep(RETRY).await;
                continue;
            };

            let mut events = stream.into_inner();
            while let Ok(Some(event)) = events.message().await {
                if let Some(view_event::Event::Gone(gone)) = event.event {
                    self.acls.forget_session(gone.session);
                    self.coalescer.clear();
                }
            }

            // The stream ended, so a `Gone` may have been missed. Anything
            // session-scoped is now suspect.
            tracing::warn!("the session stream ended; clearing session-scoped group grants");
            self.acls.forget_every_session();
            self.coalescer.clear();
            tokio::time::sleep(RETRY).await;
        }
    }

    /// Evaluate, coalescing identical concurrent questions into one walk.
    pub async fn effective(&self, scope: u32, subject: &Subject, channel: u32) -> u32 {
        let acls = self.acls.clone();
        let subject = subject.clone();
        self.coalescer
            .run(
                (scope, subject.session, subject.account, channel),
                move || evaluate(&acls, scope, &subject, channel),
            )
            .await
    }
}

/// The gRPC surface, as a type this crate owns.
#[derive(Debug, Clone)]
pub struct PermissionsGrpc(Arc<PermissionsService>);

#[tonic::async_trait]
impl PermissionsRpc for PermissionsGrpc {
    async fn effective(
        &self,
        request: Request<EffectiveRequest>,
    ) -> Result<Response<EffectiveResponse>, Status> {
        let req = request.into_inner();
        let scope = scope_of(req.scope);
        let subject = req.subject.unwrap_or_default();
        let granted = self.0.effective(scope, &subject, req.channel).await;
        Ok(Response::new(EffectiveResponse {
            granted,
            groups: self.0.acls.groups_of(scope, &subject, req.channel),
        }))
    }

    async fn check(&self, request: Request<CheckRequest>) -> Result<Response<Decision>, Status> {
        let req = request.into_inner();
        let scope = scope_of(req.scope);
        // The caller states the identity. Only two callers legitimately can —
        // `session-view`, which *is* the authority on who a session is, and
        // `operator-api`, which carries an operator rather than a session. A
        // service enforcing a client's action must use `CheckSession` instead,
        // where the identity is resolved here and cannot be asserted.
        let subject = req.subject.unwrap_or_default();
        let decision = self.0.decide(scope, &subject, req.channel, req.permission);
        Ok(Response::new(decision))
    }

    async fn check_session(
        &self,
        request: Request<SessionCheckRequest>,
    ) -> Result<Response<Decision>, Status> {
        let req = request.into_inner();
        let scope = scope_of(req.scope);
        // No identity, no authorisation. This is an *enforcement* answer, so an
        // unresolvable session is refused outright rather than answered as a
        // guest — otherwise `session-view` being down would quietly grant every
        // caller the default set.
        let Some(mut subject) = self.0.resolve(scope, req.session).await else {
            return Ok(Response::new(Decision {
                allowed: false,
                missing: req.permission,
                reason: "the session could not be identified".to_owned(),
            }));
        };
        // Tokens the caller sent with *this* request — a channel password typed
        // into the join dialog. Added to the session's own for the length of
        // this call and no longer, which is upstream's scope for them
        // (`Messages.cpp:110`, where a destructor takes them away again).
        subject.tokens.extend(req.temporary_tokens);
        let decision = self.0.decide(scope, &subject, req.channel, req.permission);
        Ok(Response::new(decision))
    }

    async fn get_acl(&self, request: Request<AclRequest>) -> Result<Response<AclSet>, Status> {
        let req = request.into_inner();
        Ok(Response::new(
            self.0.acls.get(scope_of(req.scope), req.channel),
        ))
    }

    async fn set_acl(
        &self,
        request: Request<SetAclRequest>,
    ) -> Result<Response<AclResult>, Status> {
        let req = request.into_inner();
        let scope = scope_of(req.scope);
        let Some(acls) = req.acls else {
            return Ok(Response::new(AclResult {
                applied: false,
                refused: "no ACL set was given".to_owned(),
            }));
        };
        let channel = acls.channel;
        let (groups, entries) = (acls.groups.len(), acls.acls.len());
        self.0.acls.set(scope, acls.clone());
        self.0.persist(scope, &acls).await;

        // Who may do what, changed. This is the record that explains why a
        // permission that worked yesterday does not today.
        tracing::info!(channel, groups, entries, "acl set");
        self.0.logger.log(
            LogEvent::notice(Category::Permission, "acl changed")
                .with("channel", channel)
                .with("groups", groups)
                .with("entries", entries)
                .with("scope", scope),
        );

        // Published *before* the caller is acknowledged: a revocation that
        // races an acknowledgement is a stale grant, and a stale grant is a
        // security bug. The channel list is empty on purpose — an ACL change on
        // an inheriting parent can alter any descendant, and computing the
        // exact set here would duplicate the evaluator in every subscriber.
        let _ = self.0.invalidations.send(Invalidation {
            channels: vec![channel],
            accounts: Vec::new(),
            everything: true,
        });
        self.0.coalescer.clear();

        Ok(Response::new(AclResult {
            applied: true,
            refused: String::new(),
        }))
    }

    async fn add_temporary_group(
        &self,
        request: Request<TemporaryGroupRequest>,
    ) -> Result<Response<AclResult>, Status> {
        self.0.temporary(&request.into_inner(), true).await
    }

    async fn remove_temporary_group(
        &self,
        request: Request<TemporaryGroupRequest>,
    ) -> Result<Response<AclResult>, Status> {
        self.0.temporary(&request.into_inner(), false).await
    }

    type WatchInvalidationsStream =
        tokio_stream::wrappers::ReceiverStream<Result<Invalidation, Status>>;

    async fn watch_invalidations(
        &self,
        _request: Request<Scope>,
    ) -> Result<Response<Self::WatchInvalidationsStream>, Status> {
        let (tx, rx) = tokio::sync::mpsc::channel(EVENT_BUFFER);
        let mut invalidations = self.0.invalidations.subscribe();
        drop(tokio::spawn(async move {
            loop {
                match invalidations.recv().await {
                    Ok(invalidation) => {
                        if tx.send(Ok(invalidation)).await.is_err() {
                            return;
                        }
                    }
                    // Missed a revocation: tell the subscriber everything is
                    // stale rather than letting it keep a grant that may have
                    // been taken away.
                    Err(broadcast::error::RecvError::Lagged(_)) => {
                        let _ = tx
                            .send(Ok(Invalidation {
                                channels: Vec::new(),
                                accounts: Vec::new(),
                                everything: true,
                            }))
                            .await;
                    }
                    Err(broadcast::error::RecvError::Closed) => return,
                }
            }
        }));
        Ok(Response::new(tokio_stream::wrappers::ReceiverStream::new(
            rx,
        )))
    }
}

impl ClientService for PermissionsService {
    async fn frame(&self, inbound: Inbound) -> Actions {
        match inbound.type_id {
            PERMISSION_QUERY => self.on_permission_query(&inbound).await,
            ACL => self.on_acl_query(&inbound).await,
            _ => Actions::new(),
        }
    }
}

impl PermissionsService {
    /// Who is asking, resolved through `session-view`.
    ///
    /// An `Inbound` carries a session id and no identity, and the whole answer
    /// turns on identity: the SuperUser bypasses evaluation, a registered user
    /// is in `@auth`, a guest is in neither. Answering from the frame alone
    /// reports every client — including the administrator — as an anonymous
    /// guest, which is what left every action greyed out in the client with no
    /// ACL entry anywhere to explain it.
    ///
    /// **A lookup per query, not a cached snapshot.** `docs/ARCHITECTURE.md` §4
    /// prefers a subscription, and the reason it gives is that *nothing on the
    /// audio path may make a request* — this is not the audio path. A
    /// `PermissionQuery` is a control message on murmur's 1/s bucket, and
    /// murmur evaluates it synchronously too. A snapshot subscription is the
    /// upgrade when this becomes hot; it is a cache with an invalidation
    /// problem, and it is not worth one to save a call nobody is making often.
    ///
    /// Who is asking, for a reply that only *describes* permissions.
    ///
    /// Falls back to a stranger, which under-reports rather than over-reports:
    /// the client is shown fewer permissions than it holds, and the actions it
    /// then attempts are authorised again on their own path.
    async fn asker(&self, inbound: &Inbound) -> Subject {
        self.resolve(inbound.scope, inbound.session)
            .await
            .unwrap_or_else(|| Self::stranger(inbound.session))
    }

    /// A subject that holds nothing, for a session that could not be resolved.
    fn stranger(session: u32) -> Subject {
        Subject {
            session,
            registered: false,
            ..Subject::default()
        }
    }

    /// The subject holding `session`, or `None` when that cannot be established.
    ///
    /// The distinction matters and used to be lost. Resolving to "an anonymous
    /// guest" is a real answer — a guest holds the default permissions and may
    /// speak and type. *Failing* to resolve is not that answer: it happens when
    /// `session-view` is unreachable or the session has gone, and treating it as
    /// "guest" would mean that taking `session-view` down promotes every caller
    /// to one, with the default set that comes with it.
    async fn resolve(&self, scope: u32, session: u32) -> Option<Subject> {
        let resolver = self.resolver.as_ref()?;
        let transport = resolver.channel("session-view").ok()?;
        let resolved = SessionViewClient::new(transport)
            .get(SessionGetRequest {
                scope: Some(Scope {
                    virtual_server: scope,
                }),
                session,
            })
            .await
            .ok()?
            .into_inner();
        Some(Subject {
            session: resolved.session,
            // The pair, never re-derived: `account` alone cannot tell the
            // administrator from a guest, because both are zero.
            account: resolved.account,
            registered: resolved.registered,
            name: resolved.name,
            cert_hash: resolved.cert_hash,
            // The channel the session is *standing in*, which is not the
            // channel being evaluated: `in`, `out` and `sub` compare the two,
            // and without this every one of them reads the user as being at the
            // root (`crate::group`).
            channel: resolved.channel,
            // Access tokens, so `#password` groups can match at all. Written as
            // `Vec::new()` at every call site until now, which is why channel
            // passwords opened nothing (`docs/GAP-ANALYSIS.md` G2).
            tokens: resolved.tokens,
            strong_cert: resolved.strong_cert,
        })
    }

    async fn on_permission_query(&self, inbound: &Inbound) -> Actions {
        let Ok(query) =
            starling_proto::proto::tcp::PermissionQuery::decode(inbound.payload.as_slice())
        else {
            return Actions::new();
        };
        let channel = query.channel_id.unwrap_or_default();
        let subject = self.asker(inbound).await;
        let granted = self.effective(inbound.scope, &subject, channel).await;
        // What the client's menus are gated on. A wrong mask here is invisible
        // in the UI — the action is simply absent — so the answer is worth
        // being able to read back.
        tracing::debug!(
            session = inbound.session,
            channel,
            granted = format!("{granted:#x}"),
            registered = subject.registered,
            account = subject.account,
            "permission query answered"
        );
        let reply = starling_proto::proto::tcp::PermissionQuery {
            channel_id: Some(channel),
            permissions: Some(granted),
            flush: Some(false),
        };
        vec![to_conn(
            inbound.conn,
            PERMISSION_QUERY,
            reply.encode_to_vec(),
        )]
    }

    /// A client rewriting a channel's ACL table — the editor's Save.
    ///
    /// This used to be refused outright on the grounds that rewriting ACLs is
    /// an operator action. That was wrong twice over: murmur has always allowed
    /// it (`Messages.cpp:2599`), and the client's ACL and role editors are
    /// built on it — they read correctly and then saved nothing, silently, so a
    /// role appeared to be created and was gone on the next read
    /// (`docs/GAP-ANALYSIS.md` G1).
    ///
    /// **`Write` on the channel *or* on the root**, which is murmur's rule and
    /// not a convenience: without the root clause, a user who may create a
    /// channel can deny `Write` to everyone inside it and make it ungovernable
    /// — an admin could no longer edit the very ACL that locked them out.
    ///
    /// The table is replaced wholesale. The editor sends what it is showing,
    /// so merging would restore whatever the operator had just deleted.
    async fn on_acl_write(
        &self,
        inbound: &Inbound,
        acl: &starling_proto::proto::tcp::Acl,
    ) -> Actions {
        let subject = self.asker(inbound).await;
        let channel = acl.channel_id;

        let here = self.effective(inbound.scope, &subject, channel).await;
        let root = self.effective(inbound.scope, &subject, 0).await;
        if !Self::permits(here, Perm::WRITE.bits()) && !Self::permits(root, Perm::WRITE.bits()) {
            tracing::info!(
                session = inbound.session,
                channel,
                "acl write refused: no Write here or at the root"
            );
            return vec![permission_denied(inbound, Perm::WRITE, channel)];
        }

        let set = evaluate::from_wire(acl);
        let (groups, entries) = (set.groups.len(), set.acls.len());
        self.acls.set(inbound.scope, set.clone());
        self.persist(inbound.scope, &set).await;

        self.logger.log(
            LogEvent::notice(Category::Permission, "acl changed")
                .with("channel", channel)
                .with("groups", groups)
                .with("entries", entries)
                .with("session", inbound.session)
                .with("scope", inbound.scope),
        );

        // Published before anything else observes the change, for the reason
        // this service exists: a stale deny is safe, a stale grant is not.
        let _ = self.invalidations.send(Invalidation {
            channels: vec![channel],
            accounts: Vec::new(),
            everything: true,
        });
        self.coalescer.clear();

        // The editor re-reads after saving, and murmur answers that read from
        // the stored table. Sending the stored set straight back saves the
        // round trip and, more usefully, shows the client what was actually
        // kept — inherited rows dropped, defaults filled in.
        let stored = self.acls.get(inbound.scope, channel);
        vec![to_conn(
            inbound.conn,
            ACL,
            evaluate::to_wire(&stored).encode_to_vec(),
        )]
    }

    async fn on_acl_query(&self, inbound: &Inbound) -> Actions {
        let Ok(query) = starling_proto::proto::tcp::Acl::decode(inbound.payload.as_slice()) else {
            return Actions::new();
        };
        if !query.query.unwrap_or(false) {
            return self.on_acl_write(inbound, &query).await;
        }

        // Reading a channel's ACL table takes `Write` on it, as murmur asks.
        // The table names accounts and groups, and says which of them can do
        // what — handing that to anyone who asks is a map of the server's
        // administrators and of every private channel's membership.
        //
        // Resolved here rather than through `Permit`: this *is* the permission
        // service, so asking itself over gRPC would be a round trip to reach a
        // function two lines away.
        let subject = self.asker(inbound).await;
        let granted = self
            .effective(inbound.scope, &subject, query.channel_id)
            .await;
        // `here` *or* the root, exactly as `on_acl_write` next door decides it.
        // Write at the root administers the whole tree in murmur, so an operator
        // who can save a table must be able to read it back — and checking only
        // `here` made saving self-locking: the editor wrote a set it was then
        // refused sight of. It also papers over a real race while it lasts —
        // `follow_tree` learns a new channel's parent asynchronously, and until
        // that arrives the ancestor walk finds nothing and returns the seed set,
        // which is why the refusal was intermittent rather than constant.
        let at_root = self.effective(inbound.scope, &subject, 0).await;
        if !Self::permits(granted, Perm::WRITE.bits())
            && !Self::permits(at_root, Perm::WRITE.bits())
        {
            // Said out loud, as the write path next door already does. A client
            // reading an ACL waits for an `ACL` and skips anything else, so a
            // silent refusal here is indistinguishable from the server never
            // answering — the editor simply hangs, and nothing anywhere names
            // the permission that was missing.
            tracing::info!(
                session = inbound.session,
                channel = query.channel_id,
                granted,
                "acl read refused: no Write on the channel"
            );
            return vec![permission_denied(inbound, Perm::WRITE, query.channel_id)];
        }

        let set = self.acls.get(inbound.scope, query.channel_id);
        vec![to_conn(
            inbound.conn,
            ACL,
            evaluate::to_wire(&set).encode_to_vec(),
        )]
    }
}

impl Serve for PermissionsService {
    const NAME: &'static str = "permissions";

    async fn build(ctx: ServiceContext) -> Result<Arc<Self>, ServiceError> {
        ctx.health.gate("acls loaded");
        let (invalidations, _) = broadcast::channel(EVENT_BUFFER);

        let store = match ctx.storage().await {
            Ok(store) => {
                store.migrate(SCHEMA).await?;
                Some(store)
            }
            Err(error) => {
                // Said loudly rather than shrugged off. Running without a store
                // works — evaluation is entirely in memory — but every ACL an
                // operator sets is then lost on the next restart, and the only
                // symptom is permissions quietly reverting.
                tracing::error!(%error, "no ACL storage; grants will not survive a restart");
                None
            }
        };

        let service = Self {
            acls: Acls::new(),
            coalescer: Coalescer::new(),
            invalidations,
            fanout: Fanout::default(),
            logger: ctx.logger.clone(),
            resolver: Some(ctx.resolver.clone()),
            store,
        };
        service.warm().await;
        ctx.health.ready("acls loaded");
        Ok(Arc::new(service))
    }

    /// Follow the channel tree for every virtual server, until shutdown.
    ///
    /// One subscription per virtual server: `metadata` shards by it, and a tree
    /// is only meaningful within one.
    async fn run(self: Arc<Self>, ctx: ServiceContext) -> Result<(), ServiceError> {
        let mut followers = Vec::new();
        for scope in ctx.virtual_servers() {
            let service = Arc::clone(&self);
            followers.push(tokio::spawn(
                async move { service.follow_tree(scope).await },
            ));
            // The other subscription: who has *gone*, so a session-scoped group
            // grant cannot outlive the session it names.
            let service = Arc::clone(&self);
            followers.push(tokio::spawn(async move {
                service.follow_sessions(scope).await;
            }));
        }
        ctx.shutdown.wait().await;
        for follower in followers {
            follower.abort();
        }
        Ok(())
    }

    fn routes(self: Arc<Self>) -> tonic::service::Routes {
        let plane = Plane::new(Arc::clone(&self), self.fanout.clone(), Self::NAME).into_server();
        tonic::service::Routes::default()
            .add_service(PermissionsServer::new(PermissionsGrpc(Arc::clone(&self))))
            .add_service(plane)
    }
}

/// The scope a request names, defaulting to the first virtual server.
#[must_use]
pub fn scope_of(scope: Option<Scope>) -> u32 {
    scope.map_or(1, |scope| scope.virtual_server)
}

/// The outer type this service owns.
#[must_use]
pub const fn outer_type() -> u16 {
    ServiceKind::Permissions.outer_type()
}

#[cfg(test)]
mod tests {
    use super::*;
    use starling_proto_fancy::permissions::{AclEntry, Group};

    fn service() -> Arc<PermissionsService> {
        let (invalidations, _) = broadcast::channel(8);
        Arc::new(PermissionsService {
            acls: Acls::new(),
            coalescer: Coalescer::new(),
            invalidations,
            fanout: Fanout::default(),
            logger: Logger::null(),
            // No session-view to ask, so nothing resolves. These tests build the
            // subject they want directly.
            resolver: None,
            store: None,
        })
    }

    #[tokio::test]
    async fn an_acl_set_survives_a_restart() {
        // The whole point of storing them. An operator's grant that vanishes on
        // the next restart is worse than one that was never accepted: it works
        // when they test it and is gone by the time anyone relies on it.
        let store = Store::open("sqlite:file:acl-restart-test?mode=memory&cache=shared", 1)
            .await
            .expect("in-memory database");
        store.migrate(SCHEMA).await.expect("schema");

        let set = AclSet {
            channel: 7,
            inherit: false,
            acls: vec![AclEntry {
                apply_here: true,
                apply_subs: true,
                group: Some("auth".to_owned()),
                grant: Perm::MAKE_CHANNEL.bits(),
                ..AclEntry::default()
            }],
            groups: Vec::new(),
        };

        {
            let (invalidations, _) = broadcast::channel(8);
            let before = PermissionsService {
                acls: Acls::new(),
                coalescer: Coalescer::new(),
                invalidations,
                fanout: Fanout::default(),
                logger: Logger::null(),
                resolver: None,
                store: Some(store.clone()),
            };
            before.acls.set(1, set.clone());
            before.persist(1, &set).await;
        }

        // A second service over the same database is a restart.
        let (invalidations, _) = broadcast::channel(8);
        let after = PermissionsService {
            acls: Acls::new(),
            coalescer: Coalescer::new(),
            invalidations,
            fanout: Fanout::default(),
            logger: Logger::null(),
            resolver: None,
            store: Some(store),
        };
        assert!(
            after.acls.get(1, 7).acls.is_empty(),
            "nothing is in memory before warming"
        );

        after.warm().await;

        let loaded = after.acls.get(1, 7);
        assert_eq!(loaded.acls.len(), 1, "the entry must come back");
        assert!(!loaded.inherit, "and so must the inherit flag");
        assert_eq!(loaded.acls[0].grant, Perm::MAKE_CHANNEL.bits());
    }

    #[test]
    fn a_check_needs_every_bit_it_asked_for() {
        // murmur asks one bit at a time and tests `granted & perm != 0`, which
        // for a two-bit question answers yes when one is held. An authorisation
        // check that passes on half the requirement is the bug this prevents.
        let both = Perm::MAKE_CHANNEL.union(Perm::WRITE).bits();
        assert!(!PermissionsService::permits(Perm::WRITE.bits(), both));
        assert!(!PermissionsService::permits(
            Perm::MAKE_CHANNEL.bits(),
            both
        ));
        assert!(PermissionsService::permits(both, both));
    }

    #[test]
    fn asking_to_authorise_nothing_is_refused() {
        // A caller that computed a mask and got zero has asked for permission to
        // do nothing. Answering yes would let an empty mask stand in for a grant.
        assert!(!PermissionsService::permits(Perm::ALL.bits(), 0));
    }

    #[tokio::test]
    async fn an_unidentifiable_session_is_refused_rather_than_treated_as_a_guest() {
        // The fail-closed property. A guest is a real identity that holds the
        // default set — it may speak and type. A session that cannot be resolved
        // is *not* a guest: it means session-view is unreachable or the session
        // has gone, and answering "guest" there would make taking session-view
        // down a way to hand everyone the default permissions.
        let service = service();
        assert!(service.resolve(1, 7).await.is_none());

        let grpc = PermissionsGrpc(Arc::clone(&service));
        let decision = grpc
            .check_session(Request::new(SessionCheckRequest {
                scope: None,
                session: 7,
                channel: 0,
                // A permission every guest would otherwise hold by default.
                permission: Perm::TEXT_MESSAGE.bits(),
                temporary_tokens: Vec::new(),
            }))
            .await
            .expect("the call itself succeeds")
            .into_inner();

        assert!(
            !decision.allowed,
            "an unidentifiable session must not inherit a guest's permissions"
        );
        assert_eq!(decision.missing, Perm::TEXT_MESSAGE.bits());
    }

    #[tokio::test]
    async fn a_stranger_holds_nothing_administrative() {
        // What the *display* path falls back to. It under-reports rather than
        // over-reports: the client is shown less than it holds, and every action
        // it then tries is authorised again on its own path.
        let stranger = PermissionsService::stranger(7);
        assert!(!stranger.registered);
        let granted = evaluate(&Acls::new(), 1, &stranger, 0);
        assert!(!Perm::from_bits_truncate(granted).contains(Perm::WRITE));
        assert!(!Perm::from_bits_truncate(granted).contains(Perm::MAKE_CHANNEL));
    }

    #[tokio::test]
    async fn a_denied_permission_is_reported_with_the_bit_that_was_missing() {
        // "Permission denied" without saying which is a support ticket.
        let service = service();
        service.acls.set(
            1,
            AclSet {
                channel: 0,
                inherit: true,
                acls: vec![AclEntry {
                    apply_here: true,
                    apply_subs: true,
                    group: Some("all".to_owned()),
                    grant: Perm::TRAVERSE.bits(),
                    deny: Perm::SPEAK.bits(),
                    ..AclEntry::default()
                }],
                groups: Vec::new(),
            },
        );

        let decision = PermissionsGrpc(Arc::clone(&service))
            .check(Request::new(CheckRequest {
                scope: None,
                subject: Some(Subject::default()),
                channel: 0,
                permission: Perm::SPEAK.bits(),
            }))
            .await
            .expect("check")
            .into_inner();

        assert!(!decision.allowed);
        assert_eq!(decision.missing, Perm::SPEAK.bits());
        assert!(!decision.reason.is_empty());
    }

    /// An `ACL`(13) frame carrying `acl`, as a client's editor sends it.
    fn acl_frame(acl: &starling_proto::proto::tcp::Acl) -> Inbound {
        Inbound {
            conn: 4,
            session: 7,
            type_id: ACL,
            payload: acl.encode_to_vec(),
            gateway: "test".to_owned(),
            scope: 1,
        }
    }

    /// What a `Send` action carries, for asserting on a reply.
    fn sent(action: &starling_proto_fancy::control::ServerAction) -> (u16, Vec<u8>) {
        let Some(starling_proto_fancy::control::server_action::Action::Send(send)) = &action.action
        else {
            panic!("the reply must be a Send");
        };
        (send.r#type as u16, send.payload.clone())
    }

    /// A `Write` grant to everybody at `channel`, so a test with no
    /// `session-view` — where every asker resolves to a stranger — can still
    /// reach the authorised path.
    fn write_granted_at(channel: u32) -> AclSet {
        AclSet {
            channel,
            inherit: true,
            acls: vec![AclEntry {
                apply_here: true,
                apply_subs: true,
                group: Some("all".to_owned()),
                grant: Perm::WRITE.bits(),
                ..AclEntry::default()
            }],
            groups: Vec::new(),
        }
    }

    #[tokio::test]
    async fn a_client_without_write_changes_nothing_and_is_told_so() {
        // The refusal half of G1. It must *answer* — silence is what made the
        // ACL editor look like it had saved.
        let service = service();
        let submitted = starling_proto::proto::tcp::Acl {
            channel_id: 3,
            inherit_acls: Some(true),
            query: Some(false),
            groups: vec![starling_proto::proto::tcp::acl::ChanGroup {
                name: "admin".to_owned(),
                ..starling_proto::proto::tcp::acl::ChanGroup::default()
            }],
            acls: Vec::new(),
        };

        let actions = service.on_acl_query(&acl_frame(&submitted)).await;

        assert_eq!(actions.len(), 1, "a refusal is still an answer");
        assert_eq!(sent(&actions[0]).0, 12, "PermissionDenied");
        assert!(
            service.acls.get(1, 3).groups.is_empty(),
            "a refused write must not have been applied"
        );
    }

    #[tokio::test]
    async fn a_client_holding_write_can_rewrite_a_channels_acl_table() {
        // G1 itself: `on_acl_query` used to refuse every `ACL`(13) whose `query`
        // flag was false, so the client's editor submitted and silently changed
        // nothing — a role appeared to be created and was gone on the next read.
        let service = service();
        service.acls.set(1, write_granted_at(3));
        let mut invalidations = service.invalidations.subscribe();

        let submitted = starling_proto::proto::tcp::Acl {
            channel_id: 3,
            inherit_acls: Some(false),
            query: Some(false),
            groups: vec![starling_proto::proto::tcp::acl::ChanGroup {
                name: "moderators".to_owned(),
                add: vec![11],
                ..starling_proto::proto::tcp::acl::ChanGroup::default()
            }],
            acls: vec![starling_proto::proto::tcp::acl::ChanAcl {
                apply_here: Some(true),
                apply_subs: Some(true),
                group: Some("moderators".to_owned()),
                grant: Some(Perm::MUTE_DEAFEN.bits()),
                ..starling_proto::proto::tcp::acl::ChanAcl::default()
            }],
        };

        let actions = service.on_acl_query(&acl_frame(&submitted)).await;

        let stored = service.acls.get(1, 3);
        assert!(!stored.inherit, "the inherit flag is part of the table");
        assert_eq!(stored.groups.len(), 1);
        assert_eq!(stored.groups[0].name, "moderators");
        assert_eq!(stored.groups[0].add, vec![11]);
        assert_eq!(stored.acls.len(), 1);
        assert_eq!(stored.acls[0].grant, Perm::MUTE_DEAFEN.bits());

        // Everything watching is told before the client is, for the reason this
        // service exists: a stale grant is a security bug.
        assert!(
            invalidations
                .try_recv()
                .expect("an invalidation")
                .everything,
            "a rewrite invalidates"
        );

        // And the editor is answered with what was actually kept, so it renders
        // the stored table rather than the one it hoped for.
        let (type_id, payload) = sent(&actions[0]);
        assert_eq!(type_id, ACL);
        let echoed =
            starling_proto::proto::tcp::Acl::decode(payload.as_slice()).expect("an ACL reply");
        assert_eq!(echoed.channel_id, 3);
        assert_eq!(echoed.acls.len(), 1);
        assert_eq!(echoed.query, Some(false));
    }

    #[tokio::test]
    async fn write_at_the_root_is_enough_to_repair_a_channel_that_locked_everyone_out() {
        // murmur's rule, and not a convenience: without it, a user who may
        // create a channel can deny `Write` inside it and make it ungovernable
        // — the admin could no longer edit the ACL that locked them out.
        let service = service();
        service.acls.set(1, write_granted_at(0));
        // The channel itself denies `Write` to everybody.
        service.acls.set(
            1,
            AclSet {
                channel: 5,
                inherit: false,
                acls: vec![AclEntry {
                    apply_here: true,
                    apply_subs: true,
                    group: Some("all".to_owned()),
                    deny: Perm::WRITE.bits(),
                    ..AclEntry::default()
                }],
                groups: Vec::new(),
            },
        );

        let repaired = starling_proto::proto::tcp::Acl {
            channel_id: 5,
            inherit_acls: Some(true),
            query: Some(false),
            groups: Vec::new(),
            acls: Vec::new(),
        };
        let actions = service.on_acl_query(&acl_frame(&repaired)).await;

        assert_eq!(sent(&actions[0]).0, ACL, "the repair is accepted");
        assert!(
            service.acls.get(1, 5).acls.is_empty(),
            "the locking entry is gone"
        );
    }

    #[tokio::test]
    async fn an_access_token_sent_with_one_request_does_not_outlive_it() {
        // The scope that makes a channel password a key to one door. murmur
        // adds a temporary token for the length of one message and takes it
        // away in a destructor (`Messages.cpp:110`); here it lives on the
        // request and is never written to the session at all.
        let service = service();
        service.acls.set(
            1,
            AclSet {
                channel: 0,
                inherit: true,
                acls: vec![AclEntry {
                    apply_here: true,
                    apply_subs: true,
                    group: Some("#hunter2".to_owned()),
                    grant: Perm::MUTE_DEAFEN.bits(),
                    ..AclEntry::default()
                }],
                groups: Vec::new(),
            },
        );

        let holder = Subject {
            session: 7,
            tokens: vec!["hunter2".to_owned()],
            ..Subject::default()
        };
        let granted = service.effective(1, &holder, 0).await;
        assert!(Perm::from_bits_truncate(granted).contains(Perm::MUTE_DEAFEN));

        // The same subject without it holds nothing extra — and the coalescer
        // keys on the session, so this also proves one client's answer is not
        // being served to the next.
        let stranger = Subject {
            session: 7,
            ..Subject::default()
        };
        let granted = service.effective(1, &stranger, 0).await;
        assert!(!Perm::from_bits_truncate(granted).contains(Perm::MUTE_DEAFEN));
    }

    #[tokio::test]
    async fn rewriting_an_acl_invalidates_before_it_acknowledges() {
        // The other order is a window in which a revoked grant is still served.
        let service = service();
        let mut invalidations = service.invalidations.subscribe();

        let _ = PermissionsGrpc(Arc::clone(&service))
            .set_acl(Request::new(SetAclRequest {
                scope: None,
                actor: None,
                acls: Some(AclSet {
                    channel: 3,
                    inherit: true,
                    acls: Vec::new(),
                    groups: vec![Group {
                        name: "admin".to_owned(),
                        ..Group::default()
                    }],
                }),
            }))
            .await
            .expect("set");

        let invalidation = invalidations
            .try_recv()
            .expect("an invalidation was published");
        assert!(invalidation.everything);
    }
}
