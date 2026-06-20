//! `push` — notifications for clients that are not connected.
//!
//! Optional, and it means it: nobody notices when this is down, because
//! everyone who is connected got the real message over the control plane.
//! Which is also the rule the fan-out follows — a recipient with a live session
//! is skipped, so nobody is notified twice about a message already on screen.

use std::sync::Arc;

use async_trait::async_trait;
use prost::Message as _;
use starling_proto_fancy::common::Ack;
use starling_proto_fancy::fancy::feature::{PushAck, PushEnvelope, push_envelope};
use starling_proto_fancy::push::push_server::{Push, PushServer};
use starling_proto_fancy::push::{
    Notification, NotifyResult, Registration, SubscriptionList, SubscriptionRequest,
    UnregisterRequest,
};
use starling_proto_fancy::types::ServiceKind;
use starling_runtime::plane::{Actions, ClientService, Fanout, Inbound, Plane, to_conn};
use starling_runtime::serve::{Serve, ServiceContext, ServiceError};
use starling_runtime::storage::{Migration, Store};
use tonic::{Request, Response, Status};

/// The schema: one row per device token.
const SCHEMA: &[Migration<'static>] = &[Migration::new(
    "0001_push_registration",
    &[
        "CREATE TABLE IF NOT EXISTS push_registration (\
             server_id BIGINT NOT NULL, account_id BIGINT NOT NULL, \
             token VARCHAR(190) NOT NULL, platform VARCHAR(32) NOT NULL, \
             channels TEXT NOT NULL, \
             PRIMARY KEY (server_id, token))",
        "CREATE INDEX IF NOT EXISTS ix_push_account ON push_registration(server_id, account_id)",
    ],
)];

/// The service.
#[derive(Debug)]
pub struct PushService {
    store: Store,
    fanout: Fanout,
}

impl PushService {
    async fn register(&self, scope: u32, registration: &Registration) {
        let channels = registration
            .channels
            .iter()
            .map(u32::to_string)
            .collect::<Vec<_>>()
            .join(",");
        let _ = sqlx::query(
            "INSERT INTO push_registration (server_id, account_id, token, platform, channels) \
             VALUES (?, ?, ?, ?, ?) \
             ON CONFLICT (server_id, token) DO UPDATE SET \
                 account_id = excluded.account_id, platform = excluded.platform, \
                 channels = excluded.channels",
        )
        .bind(i64::from(scope))
        .bind(registration.account as i64)
        .bind(&registration.token)
        .bind(&registration.platform)
        .bind(channels)
        .execute(self.store.pool())
        .await;
    }

    async fn subscriptions(&self, scope: u32, account: u64) -> Vec<Registration> {
        use sqlx::Row as _;
        sqlx::query(
            "SELECT account_id, token, platform, channels FROM push_registration \
             WHERE server_id = ? AND account_id = ?",
        )
        .bind(i64::from(scope))
        .bind(account as i64)
        .fetch_all(self.store.pool())
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|row| Registration {
            scope: None,
            account: row.try_get::<i64, _>("account_id").unwrap_or_default() as u64,
            token: row.try_get("token").unwrap_or_default(),
            platform: row.try_get("platform").unwrap_or_default(),
            channels: row
                .try_get::<String, _>("channels")
                .unwrap_or_default()
                .split(',')
                .filter_map(|id| id.parse().ok())
                .collect(),
        })
        .collect()
    }
}

/// The gRPC surface, as a type this crate owns.
#[derive(Debug, Clone)]
pub struct PushRpc(Arc<PushService>);

#[tonic::async_trait]
impl Push for PushRpc {
    async fn register(&self, request: Request<Registration>) -> Result<Response<Ack>, Status> {
        let registration = request.into_inner();
        let scope = registration.scope.as_ref().map_or(1, |s| s.virtual_server);
        self.0.register(scope, &registration).await;
        Ok(Response::new(Ack {}))
    }

    async fn unregister(
        &self,
        request: Request<UnregisterRequest>,
    ) -> Result<Response<Ack>, Status> {
        let req = request.into_inner();
        let scope = req.scope.as_ref().map_or(1, |s| s.virtual_server);
        let _ = sqlx::query("DELETE FROM push_registration WHERE server_id = ? AND token = ?")
            .bind(i64::from(scope))
            .bind(&req.token)
            .execute(self.0.store.pool())
            .await;
        Ok(Response::new(Ack {}))
    }

    async fn notify(
        &self,
        request: Request<Notification>,
    ) -> Result<Response<NotifyResult>, Status> {
        let req = request.into_inner();
        let scope = req.scope.as_ref().map_or(1, |s| s.virtual_server);
        let mut delivered = 0;
        let mut skipped = 0;
        for account in &req.accounts {
            // Connected recipients already have the real message; notifying
            // them again is how a phone buzzes for something on screen.
            if req.skip_accounts.contains(account) {
                skipped += 1;
                continue;
            }
            delivered += self.0.subscriptions(scope, *account).await.len() as u32;
        }
        Ok(Response::new(NotifyResult {
            delivered,
            skipped,
            failed: 0,
        }))
    }

    async fn subscriptions(
        &self,
        request: Request<SubscriptionRequest>,
    ) -> Result<Response<SubscriptionList>, Status> {
        let req = request.into_inner();
        let scope = req.scope.as_ref().map_or(1, |s| s.virtual_server);
        Ok(Response::new(SubscriptionList {
            registrations: self.0.subscriptions(scope, req.account).await,
        }))
    }
}

#[async_trait]
impl ClientService for PushService {
    async fn frame(&self, inbound: Inbound) -> Actions {
        let outer = ServiceKind::Push.outer_type();
        if inbound.type_id != outer {
            return Actions::new();
        }
        let Ok(envelope) = PushEnvelope::decode(inbound.payload.as_slice()) else {
            return Actions::new();
        };
        let ok = match envelope.body {
            Some(push_envelope::Body::Register(register)) => {
                self.register(
                    inbound.scope,
                    &Registration {
                        scope: None,
                        account: 0,
                        token: register.token,
                        platform: register.platform,
                        channels: Vec::new(),
                    },
                )
                .await;
                true
            }
            Some(push_envelope::Body::Unregister(unregister)) => {
                let _ =
                    sqlx::query("DELETE FROM push_registration WHERE server_id = ? AND token = ?")
                        .bind(i64::from(inbound.scope))
                        .bind(&unregister.token)
                        .execute(self.store.pool())
                        .await;
                true
            }
            _ => false,
        };

        let reply = PushEnvelope {
            body: Some(push_envelope::Body::Ack(PushAck {
                ok,
                detail: String::new(),
            })),
        };
        vec![to_conn(inbound.conn, outer, reply.encode_to_vec())]
    }
}

#[async_trait]
impl Serve for PushService {
    const NAME: &'static str = "push";

    async fn build(ctx: ServiceContext) -> Result<Arc<Self>, ServiceError> {
        let store = ctx.storage().await?;
        store.migrate(SCHEMA).await?;
        Ok(Arc::new(Self {
            store,
            fanout: Fanout::default(),
        }))
    }

    fn routes(self: Arc<Self>) -> tonic::service::Routes {
        let plane = Plane::new(Arc::clone(&self), self.fanout.clone()).into_server();
        tonic::service::Routes::default()
            .add_service(PushServer::new(PushRpc(Arc::clone(&self))))
            .add_service(plane)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn service() -> Arc<PushService> {
        // A name unique per call: `cache=shared` makes same-named in-memory
        // databases visible to every connection that names them, so two tests
        // sharing one name would race on the same `starling_migration` row.
        use std::sync::atomic::{AtomicU64, Ordering};
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let id = NEXT.fetch_add(1, Ordering::Relaxed);
        let store = Store::open(
            &format!("sqlite:file:push-test-{id}?mode=memory&cache=shared"),
            1,
        )
        .await
        .expect("in-memory database");
        store.migrate(SCHEMA).await.expect("schema");
        Arc::new(PushService {
            store,
            fanout: Fanout::default(),
        })
    }

    #[tokio::test]
    async fn re_registering_a_token_replaces_it_rather_than_duplicating_it() {
        // A device that reinstalls sends a new registration for the same token;
        // duplicating would notify it twice for every message.
        let service = service().await;
        for platform in ["android", "ios"] {
            service
                .register(
                    1,
                    &Registration {
                        scope: None,
                        account: 5,
                        token: "device-token".to_owned(),
                        platform: platform.to_owned(),
                        channels: vec![1, 2],
                    },
                )
                .await;
        }
        let subscriptions = service.subscriptions(1, 5).await;
        assert_eq!(subscriptions.len(), 1);
        assert_eq!(
            subscriptions.first().map(|r| r.platform.as_str()),
            Some("ios")
        );
    }

    #[tokio::test]
    async fn a_connected_recipient_is_skipped_rather_than_notified_twice() {
        let service = service().await;
        service
            .register(
                1,
                &Registration {
                    scope: None,
                    account: 5,
                    token: "t".to_owned(),
                    platform: "android".to_owned(),
                    channels: Vec::new(),
                },
            )
            .await;

        let result = PushRpc(Arc::clone(&service))
            .notify(Request::new(Notification {
                scope: None,
                accounts: vec![5],
                title: "t".to_owned(),
                body: "b".to_owned(),
                data: Default::default(),
                skip_accounts: vec![5],
            }))
            .await
            .expect("notify")
            .into_inner();
        assert_eq!(result.skipped, 1);
        assert_eq!(result.delivered, 0);
    }
}
