//! Test doubles a service's own tests share. Built only with `testing`.
//!
//! A service that asks [`Permit`](crate::permit::Permit) cannot be tested on
//! its allowed paths without a `permissions` that says yes, and one that waves
//! everything through cannot test a refusal. This one grants exactly the bits
//! a test gives it, over the same in-process transport `--all-in-one` uses, so
//! the check under test is the real one. `files` and `pchat` each grew a copy
//! of it inside their tests before it lived here.

use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use starling_proto_fancy::common::{Decision, Scope};
use starling_proto_fancy::permissions::permissions_server::{Permissions, PermissionsServer};
use starling_proto_fancy::permissions::{
    AclRequest, AclResult, AclSet, CheckRequest, EffectiveRequest, EffectiveResponse, Invalidation,
    SessionCheckRequest, SetAclRequest, TemporaryGroupRequest,
};
use tokio_stream::StreamExt as _;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status};

use crate::channel::Resolver;
use crate::inproc::{Broker, BrokerError};

pub mod view;

/// A `permissions` that grants exactly what it holds, to every session but 0.
#[derive(Debug, Clone)]
pub struct Granting(Arc<AtomicU32>);

impl Granting {
    /// Serve one holding `held` on the current runtime, and a resolver that
    /// reaches it.
    ///
    /// # Errors
    ///
    /// The broker refusing the name, which only a second registration does.
    pub fn serve(held: u32) -> Result<(Resolver, Self), BrokerError> {
        let broker = Broker::new();
        let granting = Self::serve_on(&broker, held)?;
        Ok((resolver(broker), granting))
    }

    /// Serve one holding `held` beside whatever else `broker` serves.
    ///
    /// # Errors
    ///
    /// The broker refusing the name, which only a second registration does.
    pub fn serve_on(broker: &Broker, held: u32) -> Result<Self, BrokerError> {
        let incoming = ReceiverStream::new(broker.register("permissions")?)
            .map(|conn| Ok::<_, std::io::Error>(conn.erase()));
        let granting = Self(Arc::new(AtomicU32::new(held)));
        let served = granting.clone();
        drop(tokio::spawn(async move {
            let _ended = tonic::transport::Server::builder()
                .add_service(PermissionsServer::new(served))
                .serve_with_incoming(incoming)
                .await;
        }));
        Ok(granting)
    }

    /// Hold `held` from now on.
    pub fn set(&self, held: u32) {
        self.0.store(held, Ordering::Relaxed);
    }
}

/// A resolver reaching whatever `broker` serves, as `--all-in-one` does.
#[must_use]
pub fn resolver(broker: Broker) -> Resolver {
    let mut config = crate::config::Config::with_defaults(std::path::Path::new("/run/starling"));
    config.runtime.all_in_one = true;
    Resolver::new(Arc::new(config), broker)
}

type Invalidations = Pin<Box<dyn tokio_stream::Stream<Item = Result<Invalidation, Status>> + Send>>;

#[tonic::async_trait]
impl Permissions for Granting {
    async fn check_session(
        &self,
        request: Request<SessionCheckRequest>,
    ) -> Result<Response<Decision>, Status> {
        let request = request.into_inner();
        let held = self.0.load(Ordering::Relaxed);
        Ok(Response::new(Decision {
            // Every bit asked for must be held, which is what `Permit`
            // promises its callers; and session 0 is nobody, as in the real one.
            allowed: request.session != 0 && request.permission & held == request.permission,
            ..Decision::default()
        }))
    }

    async fn effective(
        &self,
        _: Request<EffectiveRequest>,
    ) -> Result<Response<EffectiveResponse>, Status> {
        Err(Status::unimplemented(
            "a test double answers check_session only",
        ))
    }

    async fn check(&self, _: Request<CheckRequest>) -> Result<Response<Decision>, Status> {
        Err(Status::unimplemented(
            "a test double answers check_session only",
        ))
    }

    async fn get_acl(&self, _: Request<AclRequest>) -> Result<Response<AclSet>, Status> {
        Err(Status::unimplemented(
            "a test double answers check_session only",
        ))
    }

    async fn set_acl(&self, _: Request<SetAclRequest>) -> Result<Response<AclResult>, Status> {
        Err(Status::unimplemented(
            "a test double answers check_session only",
        ))
    }

    async fn add_temporary_group(
        &self,
        _: Request<TemporaryGroupRequest>,
    ) -> Result<Response<AclResult>, Status> {
        Err(Status::unimplemented(
            "a test double answers check_session only",
        ))
    }

    async fn remove_temporary_group(
        &self,
        _: Request<TemporaryGroupRequest>,
    ) -> Result<Response<AclResult>, Status> {
        Err(Status::unimplemented(
            "a test double answers check_session only",
        ))
    }

    type WatchInvalidationsStream = Invalidations;

    async fn watch_invalidations(
        &self,
        _: Request<Scope>,
    ) -> Result<Response<Self::WatchInvalidationsStream>, Status> {
        Err(Status::unimplemented(
            "a test double answers check_session only",
        ))
    }
}
