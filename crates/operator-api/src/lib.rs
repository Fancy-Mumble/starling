//! `operator-api` — the admin plane, and the replacement for Ice.
//!
//! It can create users, rewrite ACLs, ban and read the database: the
//! highest-privilege surface in the system. Three decisions follow from that,
//! and all three are `docs/ARCHITECTURE.md` §3.
//!
//! **It is plain HTTP with an `OpenAPI` description.** An admin client becomes
//! trivial to write in any language, including a browser panel and `curl`.
//!
//! **Authentication is whatever the operator already runs** — OIDC, a bare JWT,
//! mTLS or a static token — so an existing Keycloak role becomes an
//! authorisation without code. Against Ice, whose `icesecret` *is* the identity,
//! has no scope, and rotates by editing a file and restarting, that is the whole
//! point.
//!
//! **It is not a second policy implementation.** It calls the same gRPC methods
//! the gateway does, carrying an operator identity and its scopes instead of a
//! session. The one thing it does *not* do is read through `session-view`: that
//! view is of *connected* users, while an operator edits registered accounts,
//! offline bans and config.
//!
//! **Audit is fail-closed.** Every operator action is recorded, and a request is
//! refused if it cannot be recorded — written by this process rather than
//! through the `audit` service, because audit is optional and the
//! highest-privilege plane must not depend on a service the operator may not be
//! running.

pub mod audit;
pub mod auth;
pub mod openapi;
pub mod routes;

pub use audit::{AuditLog, AuditRecord};
pub use auth::{Authenticator, Identity, Refusal, authenticator};
pub use openapi::description;
pub use routes::router;

use std::sync::Arc;

use async_trait::async_trait;
use starling_runtime::serve::{Serve, ServiceContext, ServiceError};

/// The service.
#[derive(Debug)]
pub struct OperatorApi {
    auth: Arc<dyn Authenticator>,
    audit: AuditLog,
    listen: String,
    resolver: starling_runtime::channel::Resolver,
}

impl OperatorApi {
    /// Who is asking, from an `Authorization` header.
    ///
    /// # Errors
    ///
    /// [`Refusal`] when the credential is missing, malformed, expired or
    /// carries no scope this deployment maps.
    pub fn identify(&self, header: Option<&str>) -> Result<Identity, Refusal> {
        self.auth.identify(header)
    }

    /// Record an action, refusing if it cannot be recorded.
    ///
    /// # Errors
    ///
    /// The I/O error. Fail-closed is the whole contract: an action that cannot
    /// be recorded does not happen.
    pub fn record(&self, record: &AuditRecord) -> std::io::Result<()> {
        self.audit.record(record)
    }

    /// How to reach the services this API calls.
    #[must_use]
    pub fn resolver(&self) -> &starling_runtime::channel::Resolver {
        &self.resolver
    }
}

#[async_trait]
impl Serve for OperatorApi {
    const NAME: &'static str = "operator-api";

    /// Nothing calls it over gRPC; it is an HTTP listener that calls out.
    const SERVES_GRPC: bool = false;

    async fn build(ctx: ServiceContext) -> Result<Arc<Self>, ServiceError> {
        let service = ctx.service();
        let auth = authenticator(service.auth.clone().unwrap_or_default())
            .map_err(ServiceError::service)?;
        let audit = AuditLog::new(service.audit.clone().unwrap_or_default());
        Ok(Arc::new(Self {
            auth,
            audit,
            // Localhost unless the operator meant otherwise: this surface wants
            // the opposite exposure to the gateway's.
            listen: service
                .listen
                .clone()
                .unwrap_or_else(|| "127.0.0.1:8081".to_owned()),
            resolver: ctx.resolver.clone(),
        }))
    }

    fn routes(self: Arc<Self>) -> tonic::service::Routes {
        tonic::service::Routes::default()
    }

    async fn run(self: Arc<Self>, ctx: ServiceContext) -> Result<(), ServiceError> {
        if !ctx.service().enabled {
            // Off by default, on purpose.
            tracing::info!("the operator API is disabled");
            return Ok(());
        }
        let listener = tokio::net::TcpListener::bind(&self.listen).await?;
        tracing::info!(listen = %self.listen, "operator API listening");

        let shutdown = ctx.shutdown.clone();
        axum::serve(listener, router(Arc::clone(&self)))
            .with_graceful_shutdown(async move { shutdown.wait().await })
            .await?;
        Ok(())
    }
}
