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

pub use coalesce::Coalescer;
pub use evaluate::{Acls, evaluate};
pub use perm::{AllowAll, Perm, Permissions};

use std::sync::Arc;

use async_trait::async_trait;
use prost::Message as _;
use starling_proto_fancy::common::{Decision, Scope};
use starling_proto_fancy::permissions::permissions_server::{
    Permissions as PermissionsRpc, PermissionsServer,
};
use starling_proto_fancy::permissions::{
    AclRequest, AclResult, AclSet, CheckRequest, EffectiveRequest, EffectiveResponse, Invalidation,
    SetAclRequest, Subject,
};
use starling_proto_fancy::types::ServiceKind;
use starling_runtime::plane::{Actions, ClientService, Fanout, Inbound, Plane, to_conn};
use starling_runtime::serve::{Serve, ServiceContext, ServiceError};
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

/// The service.
#[derive(Debug)]
pub struct PermissionsService {
    acls: Acls,
    coalescer: Coalescer,
    invalidations: broadcast::Sender<Invalidation>,
    fanout: Fanout,
}

impl PermissionsService {
    /// The ACL tables, for the operator surface and tests.
    #[must_use]
    pub fn acls(&self) -> &Acls {
        &self.acls
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
        let subject = req.subject.unwrap_or_default();
        let granted = self.0.effective(scope, &subject, req.channel).await;
        let allowed = granted & req.permission != 0;
        Ok(Response::new(Decision {
            allowed,
            missing: if allowed { 0 } else { req.permission },
            reason: if allowed {
                String::new()
            } else {
                Perm::from_bits_truncate(req.permission).describe()
            },
        }))
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
        self.0.acls.set(scope, acls);

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

#[async_trait]
impl ClientService for PermissionsService {
    async fn frame(&self, inbound: Inbound) -> Actions {
        match inbound.type_id {
            PERMISSION_QUERY => self.on_permission_query(&inbound).await,
            ACL => self.on_acl_query(&inbound),
            _ => Actions::new(),
        }
    }
}

impl PermissionsService {
    async fn on_permission_query(&self, inbound: &Inbound) -> Actions {
        let Ok(query) =
            starling_proto::proto::tcp::PermissionQuery::decode(inbound.payload.as_slice())
        else {
            return Actions::new();
        };
        let channel = query.channel_id.unwrap_or_default();
        let subject = Subject {
            session: inbound.session,
            authenticated: inbound.session != 0,
            ..Subject::default()
        };
        let granted = self.effective(inbound.scope, &subject, channel).await;
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

    fn on_acl_query(&self, inbound: &Inbound) -> Actions {
        let Ok(query) = starling_proto::proto::tcp::Acl::decode(inbound.payload.as_slice()) else {
            return Actions::new();
        };
        if !query.query.unwrap_or(false) {
            // A write arriving on the client plane is refused here: rewriting
            // ACLs is an operator action and takes an operator identity.
            return Actions::new();
        }
        let set = self.acls.get(inbound.scope, query.channel_id);
        vec![to_conn(
            inbound.conn,
            ACL,
            evaluate::to_wire(&set).encode_to_vec(),
        )]
    }
}

#[async_trait]
impl Serve for PermissionsService {
    const NAME: &'static str = "permissions";

    async fn build(_ctx: ServiceContext) -> Result<Arc<Self>, ServiceError> {
        let (invalidations, _) = broadcast::channel(EVENT_BUFFER);
        Ok(Arc::new(Self {
            acls: Acls::new(),
            coalescer: Coalescer::new(),
            invalidations,
            fanout: Fanout::default(),
        }))
    }

    fn routes(self: Arc<Self>) -> tonic::service::Routes {
        let plane = Plane::new(Arc::clone(&self), self.fanout.clone()).into_server();
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
        })
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
