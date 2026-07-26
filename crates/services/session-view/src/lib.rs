//! `session-view` — the composed live view of every connected session.
//!
//! Every service in the control, core and realtime groups reads here and
//! nowhere else. Without it each would depend on userdata, permissions,
//! metadata and server-config — N×4 edges, and four caches each to keep warm
//! (`docs/ARCHITECTURE.md` §4).
//!
//! Two rules stop it becoming the god service:
//!
//! * **It forwards, but never decides.** Hot facts come from the composed
//!   view; anything else is routed to the owning service untouched. Note the
//!   distinction that makes a strict edge workable: *forwarding* a cold query
//!   is routing, whereas *caching* the `(user, channel)` ACL cross product
//!   would make this a second ACL engine. It does the first and never the
//!   second.
//! * **It is a subscription hub, not a proxy.** Services subscribe to a
//!   snapshot stream and keep their own copy rather than calling per request,
//!   so the rule that nothing on the audio path may make a request still holds.
//!
//! **A stale deny is safe; a stale grant is a security bug** — so a revocation
//! invalidates the composed view before it is acknowledged, while a grant may
//! arrive lazily.
//!
//! It has **no client-facing message type**, which keeps it internal by
//! construction rather than by convention.

pub mod ids;

pub mod cold;
pub mod store;

pub use cold::ColdRouter;
pub use ids::SessionId;
pub use store::Sessions;

use std::sync::Arc;

use async_trait::async_trait;
use starling_proto_fancy::sessionview::session_view_server::{SessionView, SessionViewServer};
use starling_proto_fancy::sessionview::{
    Announcement, ColdAnswer, ColdQuery, GetRequest, Session, Sessions as SessionList,
    SubscribeRequest, ViewEvent, announcement, view_event,
};
use starling_runtime::serve::{Serve, ServiceContext, ServiceError};
use tokio::sync::broadcast;
use tonic::{Request, Response, Status};

/// How many view events a subscriber may fall behind before it is dropped and
/// has to re-subscribe. Bounded, with a shed policy, like every mailbox here.
const EVENT_BUFFER: usize = 256;

/// The service.
#[derive(Debug)]
pub struct SessionViewService {
    sessions: Sessions,
    events: broadcast::Sender<ViewEvent>,
    cold: ColdRouter,
}

impl SessionViewService {
    /// The sessions currently held, for tests and the operator surface.
    #[must_use]
    pub fn sessions(&self) -> &Sessions {
        &self.sessions
    }

    fn publish(&self, event: ViewEvent) {
        let _ = self.events.send(event);
    }
}

/// The gRPC surface, as a type this crate owns.
#[derive(Debug, Clone)]
pub struct ViewRpc(Arc<SessionViewService>);

#[tonic::async_trait]
impl SessionView for ViewRpc {
    type SubscribeStream = tokio_stream::wrappers::ReceiverStream<Result<ViewEvent, Status>>;

    async fn subscribe(
        &self,
        request: Request<SubscribeRequest>,
    ) -> Result<Response<Self::SubscribeStream>, Status> {
        let scope = request.into_inner().scope.map_or(1, |s| s.virtual_server);
        let (tx, rx) = tokio::sync::mpsc::channel(EVENT_BUFFER);

        // Snapshot first, then deltas. A subscriber must never have to ask for
        // what it missed between connecting and its first event.
        let snapshot = self.0.sessions.snapshot(scope);
        let _ = tx
            .send(Ok(ViewEvent {
                event: Some(view_event::Event::Snapshot(snapshot)),
            }))
            .await;

        let mut events = self.0.events.subscribe();
        drop(tokio::spawn(async move {
            loop {
                match events.recv().await {
                    Ok(event) => {
                        if tx.send(Ok(event)).await.is_err() {
                            return;
                        }
                    }
                    // Lagged: this subscriber's copy is now wrong in a way it
                    // cannot repair from a delta, so it is dropped and must
                    // re-subscribe. Silently continuing would leave it serving
                    // a world that no longer exists.
                    Err(broadcast::error::RecvError::Lagged(missed)) => {
                        tracing::warn!(missed, "a view subscriber fell behind and was dropped");
                        return;
                    }
                    Err(broadcast::error::RecvError::Closed) => return,
                }
            }
        }));

        Ok(Response::new(tokio_stream::wrappers::ReceiverStream::new(
            rx,
        )))
    }

    async fn get(&self, request: Request<GetRequest>) -> Result<Response<Session>, Status> {
        let req = request.into_inner();
        let scope = req.scope.map_or(1, |s| s.virtual_server);
        self.0
            .sessions
            .get(scope, req.session)
            .map(Response::new)
            .ok_or_else(|| Status::not_found("no such session"))
    }

    async fn list(
        &self,
        request: Request<SubscribeRequest>,
    ) -> Result<Response<SessionList>, Status> {
        let scope = request.into_inner().scope.map_or(1, |s| s.virtual_server);
        Ok(Response::new(self.0.sessions.snapshot(scope)))
    }

    async fn announce(
        &self,
        request: Request<Announcement>,
    ) -> Result<Response<starling_proto_fancy::common::Ack>, Status> {
        let req = request.into_inner();
        let scope = req.scope.map_or(1, |s| s.virtual_server);
        match req.what {
            Some(announcement::What::Up(session)) => {
                self.0.sessions.upsert(scope, session.clone());
                self.0.publish(ViewEvent {
                    event: Some(view_event::Event::Upsert(session)),
                });
            }
            Some(announcement::What::Changed(session)) => {
                self.0.sessions.upsert(scope, session.clone());
                self.0.publish(ViewEvent {
                    event: Some(view_event::Event::Upsert(session)),
                });
            }
            Some(announcement::What::Down(gone)) => {
                self.0.sessions.remove(scope, gone.session);
                self.0.publish(ViewEvent {
                    event: Some(view_event::Event::Gone(gone)),
                });
            }
            None => {}
        }
        Ok(Response::new(starling_proto_fancy::common::Ack {}))
    }

    async fn cold(&self, request: Request<ColdQuery>) -> Result<Response<ColdAnswer>, Status> {
        // Forwarded untouched to the owning authority. The answer is not cached
        // here: caching a permission decision is what would make this a second
        // ACL engine.
        self.0.cold.forward(request.into_inner()).await.map(Response::new)
    }
}

#[async_trait]
impl Serve for SessionViewService {
    const NAME: &'static str = "session-view";

    async fn build(ctx: ServiceContext) -> Result<Arc<Self>, ServiceError> {
        let (events, _) = broadcast::channel(EVENT_BUFFER);
        Ok(Arc::new(Self {
            sessions: Sessions::new(),
            events,
            cold: ColdRouter::new(ctx.resolver.clone()),
        }))
    }

    fn routes(self: Arc<Self>) -> tonic::service::Routes {
        tonic::service::Routes::default().add_service(SessionViewServer::new(ViewRpc(self)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use starling_proto_fancy::common::Scope;
    use starling_proto_fancy::sessionview::Gone;

    fn service() -> Arc<SessionViewService> {
        let (events, _) = broadcast::channel(EVENT_BUFFER);
        Arc::new(SessionViewService {
            sessions: Sessions::new(),
            events,
            cold: ColdRouter::disconnected(),
        })
    }

    fn session(id: u32) -> Session {
        Session {
            session: id,
            name: format!("user{id}"),
            channel: 0,
            ..Session::default()
        }
    }

    #[tokio::test]
    async fn a_session_announced_up_is_visible_to_a_reader() {
        let rpc = ViewRpc(service());
        let _ = rpc
            .announce(Request::new(Announcement {
                scope: Some(Scope { virtual_server: 1 }),
                what: Some(announcement::What::Up(session(7))),
            }))
            .await
            .expect("announce");

        let got = rpc
            .get(Request::new(GetRequest {
                scope: Some(Scope { virtual_server: 1 }),
                session: 7,
            }))
            .await
            .expect("get")
            .into_inner();
        assert_eq!(got.name, "user7");
    }

    #[tokio::test]
    async fn a_session_that_has_gone_is_not_served_from_a_stale_view() {
        // A stale grant is a security bug; a session that has left must not
        // still be answerable.
        let rpc = ViewRpc(service());
        let scope = Some(Scope { virtual_server: 1 });
        let _ = rpc
            .announce(Request::new(Announcement {
                scope,
                what: Some(announcement::What::Up(session(7))),
            }))
            .await
            .expect("announce up");
        let _ = rpc
            .announce(Request::new(Announcement {
                scope,
                what: Some(announcement::What::Down(Gone {
                    session: 7,
                    reason: "left".to_owned(),
                })),
            }))
            .await
            .expect("announce down");

        assert!(
            rpc.get(Request::new(GetRequest {
                scope: Some(Scope { virtual_server: 1 }),
                session: 7,
            }))
            .await
            .is_err()
        );
    }

    #[tokio::test]
    async fn virtual_servers_do_not_see_each_other_s_sessions() {
        let rpc = ViewRpc(service());
        let _ = rpc
            .announce(Request::new(Announcement {
                scope: Some(Scope { virtual_server: 1 }),
                what: Some(announcement::What::Up(session(7))),
            }))
            .await
            .expect("announce");

        let other = rpc
            .list(Request::new(SubscribeRequest {
                scope: Some(Scope { virtual_server: 2 }),
                subscriber: "test".to_owned(),
            }))
            .await
            .expect("list")
            .into_inner();
        assert!(other.sessions.is_empty());
    }
}
