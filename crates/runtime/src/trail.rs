//! The operator-facing record of who did what, emitted by the service that did
//! it.
//!
//! # Why this is a type and not a client dialled at each call site
//!
//! The same reason as [`Permit`][crate::permit::Permit]: a record written out
//! by hand at every call site is a record that gets forgotten at one of them,
//! and the one that is forgotten is indistinguishable from the ones that were
//! never meant to be there. So there is one way to emit, it is short enough
//! that writing it out longhand is never tempting, and it cannot fail the
//! action it describes.
//!
//! # Two rules, and they are the opposite of `Permit`'s
//!
//! **An audit failure never fails the action.** `audit` is an *optional* tier
//! service (`docs/ARCHITECTURE.md` §4), and optional means the server keeps
//! working without it. A channel that could not be created because the audit
//! log was unreachable would make an optional dependency essential by the back
//! door. `Permit` fails closed because a missing grant is a denial; this fails
//! open because a missing record is not a refusal.
//!
//! **A failure is still counted and logged.** An audit trail that quietly stops
//! recording looks exactly like a server where nothing happened, and that is
//! the one failure mode an audit trail exists to prevent. Fail open, but never
//! fail silent.
//!
//! # Why it does not block
//!
//! [`Trail::record`] returns immediately and does the call on a spawned task.
//! Awaiting it would put the latency of an optional service in front of every
//! channel edit, mute and registration, the same reasoning that keeps the
//! audio path off request/reply. Ordering between records is not preserved by
//! the spawn, and does not need to be: each entry carries `at_ms`, and the
//! hash chain is assigned by `audit` itself under its own lock, so it links
//! correctly whatever order the calls arrive in.

use starling_proto_fancy::audit::Entry;
use starling_proto_fancy::audit::audit_client::AuditClient;
use starling_proto_fancy::common::{Actor, Scope};

use crate::channel::Resolver;
use crate::ids::now_ms;

/// What kind of thing happened, in the vocabulary the Fancy audit UI filters
/// on.
///
/// These are the fork's own category strings, `AuditLogBridge` and the client's
/// audit tab both key off them, so a new name here is a row the existing UI
/// cannot filter to.
pub mod category {
    /// A channel was created, edited or removed.
    pub const CHANNEL: &str = "audit.channel";
    /// A user was moved between channels.
    pub const MOVE: &str = "audit.move";
    /// Mute, deafen, suppress or priority speaker changed.
    pub const MUTE_DEAFEN_SUPPRESS: &str = "audit.mute_deafen_suppress";
    /// An account was registered.
    pub const REGISTER: &str = "audit.register";
    /// A user was kicked.
    pub const KICK: &str = "audit.kick";
    /// A user was banned.
    pub const BAN: &str = "audit.ban";
    /// An ACL or group was edited.
    pub const ACL: &str = "audit.acl";
    /// A server setting changed.
    pub const CONFIG: &str = "audit.config";
}

/// One thing worth recording, under construction.
///
/// Built rather than passed as eight arguments, because most callers set three
/// of them and an eight-argument call is where the channel id ends up in the
/// account slot.
#[derive(Debug, Clone)]
pub struct Record {
    entry: Entry,
}

impl Record {
    /// A record of `action` within `category`.
    ///
    /// Use a constant from [`category`]; the string is what the client's audit
    /// tab filters on.
    #[must_use]
    pub fn new(category: &str, action: impl Into<String>) -> Self {
        Self {
            entry: Entry {
                at_ms: now_ms(),
                category: category.to_owned(),
                action: action.into(),
                ..Entry::default()
            },
        }
    }

    /// Who did it.
    #[must_use]
    pub fn actor(mut self, actor: Actor, name: impl Into<String>) -> Self {
        self.entry.actor = Some(actor);
        self.entry.actor_name = name.into();
        self
    }

    /// The account this was done to.
    #[must_use]
    pub const fn target_account(mut self, account: u64) -> Self {
        self.entry.target_account = account;
        self
    }

    /// The channel this was done to, or in.
    #[must_use]
    pub const fn target_channel(mut self, channel: u32) -> Self {
        self.entry.target_channel = channel;
        self
    }

    /// Anything else worth keeping, as the operator would read it.
    #[must_use]
    pub fn detail(mut self, detail: impl Into<String>) -> Self {
        self.entry.detail = detail.into();
        self
    }

    /// A producer-assigned offset, so a retry is recorded once.
    ///
    /// `audit` accepts a given offset once per scope and ignores it after, which
    /// is what makes a retry safe for a caller that cannot tell whether its
    /// first attempt landed.
    #[must_use]
    pub const fn once(mut self, offset: u64) -> Self {
        self.entry.event_offset = Some(offset);
        self
    }
}

/// Emits [`Record`]s to the `audit` service, without ever failing its caller.
#[derive(Debug, Clone)]
pub struct Trail {
    resolver: Resolver,
}

impl Trail {
    /// A trail that records through `resolver`.
    #[must_use]
    pub const fn new(resolver: Resolver) -> Self {
        Self { resolver }
    }

    /// Record `what` happened in `scope`.
    ///
    /// Returns immediately. The call happens on a spawned task and its outcome
    /// reaches the caller only as a log line, because there is nothing a caller
    /// could usefully do with the failure, the action it describes has already
    /// happened.
    pub fn record(&self, scope: u32, what: Record) {
        let resolver = self.resolver.clone();
        let mut entry = what.entry;
        entry.scope = Some(Scope {
            virtual_server: scope,
        });

        drop(tokio::spawn(async move {
            let category = entry.category.clone();
            let action = entry.action.clone();

            let Ok(transport) = resolver.channel("audit") else {
                // Not an error: a deployment may legitimately not run `audit`.
                // Said once per record rather than never, because "no rows" and
                // "no audit service" are otherwise the same observation.
                tracing::debug!(scope, %category, %action, "audit is not configured; not recorded");
                return;
            };

            if let Err(status) = AuditClient::new(transport).record(entry).await {
                tracing::warn!(
                    scope,
                    %category,
                    %action,
                    %status,
                    "an auditable action was not recorded"
                );
            }
        }));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::inproc::Broker;
    use std::path::Path;
    use std::sync::Arc;

    fn trail() -> Trail {
        let config = Config::with_defaults(Path::new("/run/starling"));
        Trail::new(Resolver::new(Arc::new(config), Broker::new()))
    }

    #[test]
    fn a_record_carries_the_category_the_client_filters_on() {
        // The client's audit tab filters by these exact strings, so a typo is a
        // row nobody can find rather than a compile error.
        let record = Record::new(category::CHANNEL, "created");
        assert_eq!(record.entry.category, "audit.channel");
        assert_eq!(record.entry.action, "created");
    }

    #[test]
    fn a_record_is_stamped_when_it_is_built_not_when_it_is_sent() {
        // The send is spawned and may be arbitrarily later. `at_ms` has to be
        // the moment of the action or the operator's timeline is the queue's.
        let before = now_ms();
        let record = Record::new(category::MOVE, "moved");
        assert!(record.entry.at_ms >= before);
    }

    #[tokio::test]
    async fn recording_to_an_unreachable_audit_service_does_not_panic() {
        // The property the whole type exists for: taking `audit` down must not
        // take anything else with it. The default config points at a socket
        // nothing is serving.
        trail().record(
            1,
            Record::new(category::CHANNEL, "created")
                .target_channel(7)
                .detail("Lobby"),
        );
        // The spawned task owns the failure; the caller is already past it.
        tokio::task::yield_now().await;
    }

    #[tokio::test]
    async fn a_record_reaches_the_audit_service_with_the_caller_s_scope() {
        // The one test that proves the wire path rather than the builder: an
        // emitter that constructs perfect records and never sends them is
        // exactly the defect this module was written to fix.
        use crate::transport::{InProcess, Transport as _};
        use starling_proto_fancy::audit::audit_server::{Audit, AuditServer};
        use starling_proto_fancy::audit::{
            EntryPage, QueryRequest, RecordResult, VerifyRequest, VerifyResult,
        };
        use tokio::sync::mpsc;
        use tonic::{Request, Response, Status};

        struct Capture(mpsc::UnboundedSender<Entry>);

        #[tonic::async_trait]
        impl Audit for Capture {
            async fn record(
                &self,
                request: Request<Entry>,
            ) -> Result<Response<RecordResult>, Status> {
                let _ = self.0.send(request.into_inner());
                Ok(Response::new(RecordResult::default()))
            }
            async fn query(&self, _: Request<QueryRequest>) -> Result<Response<EntryPage>, Status> {
                Err(Status::unimplemented("the trail only records"))
            }
            async fn verify(
                &self,
                _: Request<VerifyRequest>,
            ) -> Result<Response<VerifyResult>, Status> {
                Err(Status::unimplemented("the trail only records"))
            }
        }

        let broker = Broker::new();
        let incoming = InProcess::new("audit").bind(&broker).await.expect("bind");
        let (tx, mut rx) = mpsc::unbounded_channel();
        drop(tokio::spawn(async move {
            let _ = tonic::transport::Server::builder()
                .add_service(AuditServer::new(Capture(tx)))
                .serve_with_incoming(incoming)
                .await;
        }));

        let mut config = Config::with_defaults(Path::new("/run/starling"));
        config.runtime.all_in_one = true;
        let trail = Trail::new(Resolver::new(Arc::new(config), broker));

        trail.record(
            3,
            Record::new(category::CHANNEL, "created")
                .target_channel(7)
                .detail("Lobby"),
        );

        let entry = tokio::time::timeout(std::time::Duration::from_secs(10), rx.recv())
            .await
            .expect("the record arrives")
            .expect("an entry");
        assert_eq!(entry.scope.map(|s| s.virtual_server), Some(3));
        assert_eq!(entry.category, category::CHANNEL);
        assert_eq!(entry.action, "created");
        assert_eq!(entry.target_channel, 7);
        assert_eq!(entry.detail, "Lobby");
    }

    #[tokio::test]
    async fn the_scope_is_the_caller_s_not_the_record_s() {
        // A Record is built without a scope on purpose: a builder that could
        // carry one would let a service record into a virtual server it is not
        // serving.
        let record = Record::new(category::REGISTER, "registered").target_account(42);
        assert!(record.entry.scope.is_none());
        trail().record(9, record);
        tokio::task::yield_now().await;
    }
}
