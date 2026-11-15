//! A `session-view` that knows exactly the sessions a test gives it.
//!
//! For the moment a service's roster has not caught up with the view: the
//! roster is empty, the authority is not, and a decision made from the roster
//! alone is the bug under test.

use std::sync::{Arc, Mutex};

use starling_proto_fancy::common::Ack;
use starling_proto_fancy::sessionview::session_view_server::{SessionView, SessionViewServer};
use starling_proto_fancy::sessionview::{
    Announcement, ColdAnswer, ColdQuery, GetRequest, Session, Sessions, SubscribeRequest, ViewEvent,
};
use tokio_stream::StreamExt as _;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status};

use crate::inproc::{Broker, BrokerError};

/// The sessions this view holds, and how often it was asked for one.
#[derive(Debug, Clone, Default)]
pub struct View {
    sessions: Arc<Mutex<Vec<Session>>>,
    asked: Arc<Mutex<u32>>,
}

impl View {
    /// Serve one holding `sessions` beside whatever else `broker` serves.
    ///
    /// # Errors
    ///
    /// The broker refusing the name, which only a second registration does.
    pub fn serve_on(broker: &Broker, sessions: Vec<Session>) -> Result<Self, BrokerError> {
        let incoming = ReceiverStream::new(broker.register("session-view")?)
            .map(|conn| Ok::<_, std::io::Error>(conn.erase()));
        let view = Self {
            sessions: Arc::new(Mutex::new(sessions)),
            asked: Arc::default(),
        };
        let served = view.clone();
        drop(tokio::spawn(async move {
            let _ended = tonic::transport::Server::builder()
                .add_service(SessionViewServer::new(served))
                .serve_with_incoming(incoming)
                .await;
        }));
        Ok(view)
    }

    /// How many single sessions it has been asked for.
    #[must_use]
    pub fn asked(&self) -> u32 {
        self.asked.lock().map_or(0, |asked| *asked)
    }
}

#[tonic::async_trait]
impl SessionView for View {
    type SubscribeStream = ReceiverStream<Result<ViewEvent, Status>>;

    async fn subscribe(
        &self,
        _: Request<SubscribeRequest>,
    ) -> Result<Response<Self::SubscribeStream>, Status> {
        Err(Status::unimplemented("a test view answers get and list"))
    }

    async fn get(&self, request: Request<GetRequest>) -> Result<Response<Session>, Status> {
        if let Ok(mut asked) = self.asked.lock() {
            *asked += 1;
        }
        let wanted = request.into_inner().session;
        self.sessions
            .lock()
            .ok()
            .and_then(|sessions| sessions.iter().find(|s| s.session == wanted).cloned())
            .map(Response::new)
            .ok_or_else(|| Status::not_found("no such session"))
    }

    async fn list(&self, _: Request<SubscribeRequest>) -> Result<Response<Sessions>, Status> {
        let sessions = self
            .sessions
            .lock()
            .map(|sessions| sessions.clone())
            .unwrap_or_default();
        Ok(Response::new(Sessions {
            sessions,
            ..Sessions::default()
        }))
    }

    async fn announce(&self, _: Request<Announcement>) -> Result<Response<Ack>, Status> {
        Err(Status::unimplemented("a test view answers get and list"))
    }

    async fn cold(&self, _: Request<ColdQuery>) -> Result<Response<ColdAnswer>, Status> {
        Err(Status::unimplemented("a test view answers get and list"))
    }
}
