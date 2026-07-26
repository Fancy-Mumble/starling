//! `onboarding` — the flow a server shows a user on first connection.
//!
//! An operator writes the steps; a client answers them; the answers are stored
//! per account. Optional, so a server that has no flow simply never sends one —
//! there is no "empty flow" a client has to know to skip.

use std::sync::Arc;

use async_trait::async_trait;
use prost::Message as _;
use starling_proto_fancy::fancy::feature::{Flow, OnboardingEnvelope, onboarding_envelope};
use starling_proto_fancy::types::ServiceKind;
use starling_runtime::ids::now_ms;
use starling_runtime::plane::{Actions, ClientService, Fanout, Inbound, Plane, to_conn};
use starling_runtime::serve::{Serve, ServiceContext, ServiceError};
use starling_runtime::storage::{Migration, Store};
use tokio::sync::RwLock;

/// The schema: the flow, and one row per answer.
const SCHEMA: &[Migration<'static>] = &[Migration::new(
    "0001_onboarding",
    &[
        "CREATE TABLE IF NOT EXISTS onboarding_flow (\
             server_id BIGINT PRIMARY KEY, version BIGINT NOT NULL, flow BLOB NOT NULL)",
        "CREATE TABLE IF NOT EXISTS onboarding_response (\
             server_id BIGINT NOT NULL, account_id BIGINT NOT NULL, \
             flow_id VARCHAR(64) NOT NULL, step_id VARCHAR(64) NOT NULL, \
             value TEXT NOT NULL, at_ms BIGINT NOT NULL, \
             PRIMARY KEY (server_id, account_id, flow_id, step_id))",
    ],
)];

/// The service.
#[derive(Debug)]
pub struct OnboardingService {
    store: Store,
    flow: RwLock<Option<Flow>>,
    fanout: Fanout,
}

impl OnboardingService {
    /// Load the configured flow, if there is one.
    async fn load(&self, scope: u32) -> Option<Flow> {
        use sqlx::Row as _;
        let row = sqlx::query("SELECT flow FROM onboarding_flow WHERE server_id = ?")
            .bind(i64::from(scope))
            .fetch_optional(self.store.pool())
            .await
            .ok()??;
        let bytes: Vec<u8> = row.try_get("flow").ok()?;
        Flow::decode(bytes.as_slice()).ok()
    }

    /// Record one answer.
    async fn answer(&self, scope: u32, account: u64, flow_id: &str, step: &str, value: &str) {
        let _ = sqlx::query(
            "INSERT INTO onboarding_response \
                 (server_id, account_id, flow_id, step_id, value, at_ms) VALUES (?, ?, ?, ?, ?, ?) \
             ON CONFLICT (server_id, account_id, flow_id, step_id) DO UPDATE SET \
                 value = excluded.value, at_ms = excluded.at_ms",
        )
        .bind(i64::from(scope))
        .bind(account as i64)
        .bind(flow_id)
        .bind(step)
        .bind(value)
        .bind(now_ms() as i64)
        .execute(self.store.pool())
        .await;
    }
}

#[async_trait]
impl ClientService for OnboardingService {
    async fn frame(&self, inbound: Inbound) -> Actions {
        let outer = ServiceKind::Onboarding.outer_type();
        if inbound.type_id != outer {
            return Actions::new();
        }
        let Ok(envelope) = OnboardingEnvelope::decode(inbound.payload.as_slice()) else {
            return Actions::new();
        };

        match envelope.body {
            Some(onboarding_envelope::Body::Query(_)) => {
                let cached = self.flow.read().await.clone();
                let flow = match cached {
                    Some(flow) => Some(flow),
                    None => self.load(inbound.scope).await,
                };
                // No flow configured means no message: an empty flow would be
                // something every client has to learn to skip.
                let Some(flow) = flow else {
                    return Actions::new();
                };
                let reply = OnboardingEnvelope {
                    body: Some(onboarding_envelope::Body::Flow(flow)),
                };
                vec![to_conn(inbound.conn, outer, reply.encode_to_vec())]
            }
            Some(onboarding_envelope::Body::Response(response)) => {
                self.answer(
                    inbound.scope,
                    u64::from(inbound.session),
                    &response.flow_id,
                    &response.step_id,
                    &response.value,
                )
                .await;
                Actions::new()
            }
            _ => Actions::new(),
        }
    }
}

#[async_trait]
impl Serve for OnboardingService {
    const NAME: &'static str = "onboarding";

    async fn build(ctx: ServiceContext) -> Result<Arc<Self>, ServiceError> {
        let store = ctx.storage().await?;
        store.migrate(SCHEMA).await?;
        Ok(Arc::new(Self {
            store,
            flow: RwLock::new(None),
            fanout: Fanout::default(),
        }))
    }

    fn routes(self: Arc<Self>) -> tonic::service::Routes {
        let plane = Plane::new(Arc::clone(&self), self.fanout.clone()).into_server();
        tonic::service::Routes::default().add_service(plane)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn service() -> Arc<OnboardingService> {
        // A name unique per call: `cache=shared` makes same-named in-memory
        // databases visible to every connection that names them, so two tests
        // sharing one name would race on the same `starling_migration` row.
        use std::sync::atomic::{AtomicU64, Ordering};
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let id = NEXT.fetch_add(1, Ordering::Relaxed);
        let store = Store::open(
            &format!("sqlite:file:onboarding-test-{id}?mode=memory&cache=shared"),
            1,
        )
        .await
        .expect("in-memory database");
        store.migrate(SCHEMA).await.expect("schema");
        Arc::new(OnboardingService {
            store,
            flow: RwLock::new(None),
            fanout: Fanout::default(),
        })
    }

    #[tokio::test]
    async fn a_server_with_no_flow_sends_nothing_at_all() {
        let service = service().await;
        let query = OnboardingEnvelope {
            body: Some(onboarding_envelope::Body::Query(
                starling_proto_fancy::fancy::feature::FlowQuery {},
            )),
        };
        let actions = service
            .frame(Inbound {
                conn: 1,
                session: 2,
                type_id: ServiceKind::Onboarding.outer_type(),
                payload: query.encode_to_vec(),
                gateway: "gw".to_owned(),
                scope: 1,
            })
            .await;
        assert!(actions.is_empty());
    }

    #[tokio::test]
    async fn answering_the_same_step_twice_replaces_the_answer() {
        // A user correcting a consent answer must not leave both on record.
        let service = service().await;
        for value in ["no", "yes"] {
            service.answer(1, 7, "flow", "consent", value).await;
        }
        use sqlx::Row as _;
        let row = sqlx::query("SELECT value FROM onboarding_response WHERE account_id = 7")
            .fetch_one(service.store.pool())
            .await
            .expect("one row");
        assert_eq!(
            row.try_get::<String, _>("value").ok().as_deref(),
            Some("yes")
        );
    }
}
