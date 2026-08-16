//! `operator-api`: the admin plane, and the replacement for Ice.
//!
//! It can create users, rewrite ACLs, ban and read the database: the
//! highest-privilege surface in the system. Three decisions follow from that,
//! and all three are `docs/ARCHITECTURE.md` §3.
//!
//! **It is plain HTTP with an `OpenAPI` description.** An admin client becomes
//! trivial to write in any language, including a browser panel and `curl`.
//!
//! **Authentication is whatever the operator already runs**, OIDC, a bare JWT,
//! mTLS or a static token, so an existing Keycloak role becomes an
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
//! refused if it cannot be recorded, written by this process rather than
//! through the `audit` service, because audit is optional and the
//! highest-privilege plane must not depend on a service the operator may not be
//! running. `audit.fail_closed = false` trades that refusal for a logged error
//! and is the operator's decision, not the default.

pub mod audit;
pub mod auth;
pub mod events;
pub mod live;
pub mod openapi;
pub mod routes;
pub mod webtransport;

pub use audit::{AuditLog, AuditRecord};
pub use auth::{Authenticator, Identity, Refusal, authenticator};
pub use events::{Event, EventHub};
pub use openapi::description;
pub use routes::router;

use std::sync::Arc;

use starling_runtime::log::{Category, LogEvent, Logger};
use starling_runtime::serve::{Serve, ServiceContext, ServiceError};

/// The service.
#[derive(Debug)]
pub struct OperatorApi {
    /// How a caller proves who they are, as the operator has it now.
    ///
    /// Live, and the reason is the one credential that most needs rotating: a
    /// static `token` has no expiry and no identity, so the only way to revoke
    /// one is to replace it. Behind an `RwLock` rather than copied per request,
    /// because a leaked admin token must stop working *now*, not at the next
    /// restart of the highest-privilege surface in the system.
    ///
    /// The same applies to the scope maps: an identity-provider role that should no longer
    /// map to `["*"]` is an authorisation withdrawn, and withdrawal that waits
    /// for a restart is not withdrawal.
    auth: std::sync::RwLock<Arc<dyn Authenticator>>,
    audit: AuditLog,
    listen: String,
    resolver: starling_runtime::channel::Resolver,
    events: EventHub,
}

impl OperatorApi {
    /// Who is asking, from an `Authorization` header.
    ///
    /// # Errors
    ///
    /// [`Refusal`] when the credential is missing, malformed, expired or
    /// carries no scope this deployment maps.
    pub fn identify(&self, header: Option<&str>) -> Result<Identity, Refusal> {
        self.authenticator().identify(header)
    }

    /// The authentication strategy in force.
    fn authenticator(&self) -> Arc<dyn Authenticator> {
        match self.auth.read() {
            Ok(held) => Arc::clone(&held),
            // Refusing every request over a poisoned lock would take the admin
            // plane down; the strategy behind it is still the last one set.
            Err(poisoned) => Arc::clone(&poisoned.into_inner()),
        }
    }

    /// Adopt `[services.operator-api.auth]` as the file now states it.
    ///
    /// A configuration the factory refuses -- a mode named without its block --
    /// leaves the previous strategy in force and is reported. The alternative,
    /// falling back to something permissive, would turn a typo into an open
    /// admin plane.
    fn adopt_auth(&self, service: &starling_runtime::config::ServiceConfig, logger: &Logger) {
        match authenticator(service.auth.clone().unwrap_or_default()) {
            Ok(next) => {
                match self.auth.write() {
                    Ok(mut held) => *held = next,
                    Err(poisoned) => *poisoned.into_inner() = next,
                }
                logger.log(LogEvent::notice(
                    Category::Admin,
                    "operator authentication reloaded",
                ));
            }
            Err(error) => logger.log(
                LogEvent::warning(Category::Admin, "operator authentication unchanged")
                    .with("error", error),
            ),
        }
    }

    /// Record an action, refusing it if it cannot be recorded.
    ///
    /// The one place `audit.fail_closed` is read, so every caller can treat an
    /// error as "refuse this request" and none of them has to know the policy.
    ///
    /// # Errors
    ///
    /// The I/O error, when `fail_closed` is set, which is the default and the
    /// whole contract: an action that cannot be recorded does not happen. With
    /// it unset the write still failed and is logged at error, but the request
    /// is allowed to proceed, an operator's decision to take.
    pub fn record(&self, record: &AuditRecord) -> std::io::Result<()> {
        match self.audit.record(record) {
            Ok(()) => Ok(()),
            Err(error) if self.audit.fail_closed() => Err(error),
            Err(error) => {
                tracing::error!(
                    %error,
                    subject = record.subject,
                    action = record.action,
                    "an operator action was not recorded and proceeded anyway (audit.fail_closed = false)"
                );
                Ok(())
            }
        }
    }

    /// Whether a failure to record refuses the request.
    ///
    /// For a caller that needs to describe the policy rather than apply it;
    /// [`Self::record`] applies it.
    #[must_use]
    pub const fn audit_fail_closed(&self) -> bool {
        self.audit.fail_closed()
    }

    /// Keep the authentication strategy following the file.
    ///
    /// Its own task because `run` is blocked in `axum::serve` for the life of
    /// the process.
    fn follow_auth(self: &Arc<Self>, ctx: &ServiceContext) {
        let mut configs = ctx.live.subscribe();
        let api = Arc::clone(self);
        let logger = ctx.logger.clone();
        let name = ctx.name.clone();
        drop(tokio::spawn(async move {
            while configs.changed().await.is_ok() {
                let service = configs.borrow_and_update().services.get(&name).cloned();
                if let Some(service) = service {
                    api.adopt_auth(&service, &logger);
                }
            }
        }));
    }

    /// How to reach the services this API calls.
    #[must_use]
    pub fn resolver(&self) -> &starling_runtime::channel::Resolver {
        &self.resolver
    }

    /// The live event channel: what changed, as it changes.
    #[must_use]
    pub const fn events(&self) -> &EventHub {
        &self.events
    }

    /// Start the WebTransport listener, if this deployment configured one.
    ///
    /// Spawned rather than awaited, and a failure here is logged rather than
    /// returned: a UDP port that will not bind must not take down the HTTP
    /// surface, which serves the same channel over a WebSocket and is what a
    /// proxied deployment uses anyway.
    fn spawn_webtransport(self: &Arc<Self>, ctx: &ServiceContext) {
        let Some(config) = ctx.service().webtransport else {
            return;
        };
        if !config.enabled {
            return;
        }

        let listen = match config.listen.parse() {
            Ok(listen) => listen,
            Err(error) => {
                tracing::error!(
                    listen = config.listen,
                    %error,
                    "the WebTransport listen address is not a socket address"
                );
                return;
            }
        };

        // Alongside the gateway's own pair by default, in the data directory,
        // so a first boot produces something rather than refusing to start.
        let data_dir = ctx.config.runtime.data_dir.clone();
        let cert = config
            .cert
            .unwrap_or_else(|| data_dir.join("webtransport-cert.pem"));
        let key = config
            .key
            .unwrap_or_else(|| data_dir.join("webtransport-key.pem"));

        let api = Arc::clone(self);
        let shutdown = ctx.shutdown.clone();
        drop(tokio::spawn(async move {
            if let Err(error) = webtransport::serve(api, listen, &cert, &key, shutdown).await {
                tracing::error!(%error, "the WebTransport listener stopped");
            }
        }));
    }
}

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
            auth: std::sync::RwLock::new(auth),
            audit,
            // Localhost unless the operator meant otherwise: this surface wants
            // the opposite exposure to the gateway's.
            listen: service
                .listen
                .unwrap_or_else(|| "127.0.0.1:8081".to_owned()),
            resolver: ctx.resolver,
            events: EventHub::new(),
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

        // Started before the listener accepts anything, so the first subscriber
        // to connect is already behind a live bridge rather than behind one
        // that starts when it asks.
        self.events.spawn_bridges(self.resolver.clone());
        self.spawn_webtransport(&ctx);
        self.follow_auth(&ctx);

        let shutdown = ctx.shutdown.clone();
        axum::serve(listener, router(Arc::clone(&self)))
            .with_graceful_shutdown(async move { shutdown.wait().await })
            .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use starling_runtime::config::{Config, OperatorAudit, OperatorAuth, TokenAuth};

    /// An API whose audit log cannot be written: the path is a directory.
    ///
    /// Nothing here touches the network; only [`OperatorApi::record`] is under
    /// test.
    fn api_with_unwritable_audit(fail_closed: bool) -> OperatorApi {
        let auth = authenticator(OperatorAuth {
            token: Some(TokenAuth { tokens: vec![] }),
            ..OperatorAuth::default()
        })
        .expect("an empty token set is a valid authenticator");

        OperatorApi {
            auth: std::sync::RwLock::new(auth),
            audit: AuditLog::new(OperatorAudit {
                path: std::path::PathBuf::from("/"),
                fail_closed,
            }),
            listen: "127.0.0.1:0".to_owned(),
            resolver: starling_runtime::channel::Resolver::new(
                Arc::new(Config::default()),
                starling_runtime::inproc::Broker::new(),
            ),
            events: EventHub::new(),
        }
    }

    fn record() -> AuditRecord {
        AuditRecord {
            subject: "token:ADMIN".to_owned(),
            action: "POST /accounts".to_owned(),
            outcome: "accepted".to_owned(),
        }
    }

    #[test]
    fn fail_closed_refuses_an_action_that_could_not_be_recorded() {
        let api = api_with_unwritable_audit(true);
        assert!(api.audit_fail_closed());
        assert!(
            api.record(&record()).is_err(),
            "the default must refuse: an action that cannot be recorded does not happen"
        );
    }

    #[test]
    fn fail_closed_unset_lets_the_action_proceed() {
        // The bug this prevents: the key was read by nobody, so an operator who
        // turned it off still got a 503 the moment the log filled up.
        let api = api_with_unwritable_audit(false);
        assert!(!api.audit_fail_closed());
        assert!(
            api.record(&record()).is_ok(),
            "with fail_closed unset the write still failed, but the request proceeds"
        );
    }
}
