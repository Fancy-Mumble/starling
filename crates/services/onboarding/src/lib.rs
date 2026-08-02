//! `onboarding` — the flow a server shows a user on first connection.
//!
//! An operator writes the flow; a client answers it; the answers are stored per
//! account. Optional, so a server that has no flow simply never sends one —
//! there is no "empty flow" a client has to know to skip.
//!
//! # What a client is owed
//!
//! Two things, and the second is the one that is easy to forget: the flow, and
//! **whether this user already answered it**. A client that cannot tell "never
//! answered" from "not told yet" has to guess, and the only safe guess is to
//! ask again — which is how an onboarded user gets the questionnaire on every
//! single connect. `FancyOnboardingResponseDeliver` exists to answer that, and
//! is sent even when there is nothing stored, because silence is the ambiguity.
//!
//! # What answers are keyed on
//!
//! The account, never the session. Session ids are per connection and get
//! recycled, so keying on one means a returning user is a stranger and a later
//! user can inherit somebody else's answers. An unregistered guest has no
//! account and therefore cannot be remembered at all — their answers are
//! accepted and dropped rather than stored under something that will not
//! survive the connection.

use std::sync::Arc;

use prost::Message as _;
use starling_proto::proto::tcp::{
    FancyOnboardingConfig, FancyOnboardingResponse, FancyOnboardingResponseDeliver,
    OnboardingEnvelope, onboarding_envelope,
};
use starling_proto_fancy::perm::Perm;
use starling_proto_fancy::types::ServiceKind;
use starling_runtime::ids::now_ms;
use starling_runtime::permit::Permit;
use starling_runtime::plane::{
    Actions, ClientService, Fanout, Inbound, Plane, broadcast_except, to_conn,
};
use starling_runtime::roster::Roster;
use starling_runtime::serve::{Serve, ServiceContext, ServiceError};
use starling_runtime::storage::{Migration, Store};
use tokio::sync::RwLock;

/// The channel an onboarding flow is administered from.
///
/// Editing the flow is a server-wide act, and the root channel is where
/// server-wide authority lives — the same place murmur checks it.
const ROOT_CHANNEL: u32 = 0;

/// The readiness gate that stays closed until the roster has a snapshot.
///
/// A cold roster cannot name the account behind a session, so every answer
/// would be discarded as if it came from a guest.
const VIEW_GATE: &str = "onboarding_roster_warm";

/// The schema: the flow, and one row per account's answers.
///
/// Responses are stored whole rather than one row per question. The client
/// submits a questionnaire in one message stamped with the config revision it
/// was answering, and that revision is what decides whether to ask again —
/// splitting it into rows would lose the thing the decision is made on.
const SCHEMA: &[Migration<'static>] = &[Migration::new(
    "0002_onboarding_epoch1",
    &[
        "CREATE TABLE IF NOT EXISTS onboarding_config (\
             server_id BIGINT PRIMARY KEY, config BLOB NOT NULL, at_ms BIGINT NOT NULL)",
        "CREATE TABLE IF NOT EXISTS onboarding_answers (\
             server_id BIGINT NOT NULL, account_id BIGINT NOT NULL, \
             response BLOB NOT NULL, at_ms BIGINT NOT NULL, \
             PRIMARY KEY (server_id, account_id))",
    ],
)];

/// The service.
#[derive(Debug)]
pub struct OnboardingService {
    store: Store,
    config: RwLock<Option<FancyOnboardingConfig>>,
    roster: Arc<Roster>,
    permit: Permit,
    fanout: Fanout,
}

impl OnboardingService {
    /// The outer type every onboarding frame travels under.
    fn outer() -> u16 {
        ServiceKind::Onboarding.outer_type()
    }

    /// Wrap `body` in the envelope this service owns.
    fn envelope(body: onboarding_envelope::Body) -> Vec<u8> {
        OnboardingEnvelope { body: Some(body) }.encode_to_vec()
    }

    /// The configured flow, reading through to the database on first use.
    async fn config(&self, scope: u32) -> Option<FancyOnboardingConfig> {
        if let Some(cached) = self.config.read().await.clone() {
            return Some(cached);
        }
        use sqlx::Row as _;
        let row = sqlx::query("SELECT config FROM onboarding_config WHERE server_id = ?")
            .bind(i64::from(scope))
            .fetch_optional(self.store.pool())
            .await
            .ok()??;
        let bytes: Vec<u8> = row.try_get("config").ok()?;
        let config = FancyOnboardingConfig::decode(bytes.as_slice()).ok()?;
        *self.config.write().await = Some(config.clone());
        Some(config)
    }

    /// Store a new flow, stamped with the next revision.
    ///
    /// The revision only ever climbs, and is read back from storage first so
    /// that a restart cannot reset it: answers are compared against it, and a
    /// revision that went backwards would make already-answered look newer
    /// than the flow it answered.
    async fn store_config(
        &self,
        scope: u32,
        mut config: FancyOnboardingConfig,
    ) -> FancyOnboardingConfig {
        let previous = self
            .config(scope)
            .await
            .and_then(|c| c.revision)
            .unwrap_or(0);
        config.revision = Some(previous + 1);
        config.updated_at = Some(now_ms());

        let _ = sqlx::query(
            "INSERT INTO onboarding_config (server_id, config, at_ms) VALUES (?, ?, ?) \
             ON CONFLICT (server_id) DO UPDATE SET config = excluded.config, at_ms = excluded.at_ms",
        )
        .bind(i64::from(scope))
        .bind(config.encode_to_vec())
        .bind(now_ms() as i64)
        .execute(self.store.pool())
        .await;

        *self.config.write().await = Some(config.clone());
        config
    }

    /// This account's stored answers, if there are any.
    async fn answers(&self, scope: u32, account: u64) -> Option<FancyOnboardingResponse> {
        use sqlx::Row as _;
        let row = sqlx::query(
            "SELECT response FROM onboarding_answers WHERE server_id = ? AND account_id = ?",
        )
        .bind(i64::from(scope))
        .bind(account as i64)
        .fetch_optional(self.store.pool())
        .await
        .ok()??;
        let bytes: Vec<u8> = row.try_get("response").ok()?;
        FancyOnboardingResponse::decode(bytes.as_slice()).ok()
    }

    /// Record this account's answers, replacing whatever they said before.
    async fn record(&self, scope: u32, account: u64, response: &FancyOnboardingResponse) {
        let _ = sqlx::query(
            "INSERT INTO onboarding_answers (server_id, account_id, response, at_ms) \
                 VALUES (?, ?, ?, ?) \
             ON CONFLICT (server_id, account_id) DO UPDATE SET \
                 response = excluded.response, at_ms = excluded.at_ms",
        )
        .bind(i64::from(scope))
        .bind(account as i64)
        .bind(response.encode_to_vec())
        .bind(now_ms() as i64)
        .execute(self.store.pool())
        .await;
    }

    /// The delivery telling `inbound`'s client what it has on record.
    ///
    /// Always an action, never nothing: an absent delivery is what a client
    /// cannot distinguish from one still in flight.
    async fn deliver_answers(&self, inbound: &Inbound) -> Actions {
        let stored = match self.roster.account_of(inbound.session) {
            Some(account) => self.answers(inbound.scope, account).await,
            // A guest, or a roster that cannot name them yet. Either way there
            // is nothing on record, which is the honest answer.
            None => None,
        };
        vec![to_conn(
            inbound.conn,
            Self::outer(),
            Self::envelope(onboarding_envelope::Body::ResponseDeliver(
                FancyOnboardingResponseDeliver { response: stored },
            )),
        )]
    }
}

impl ClientService for OnboardingService {
    async fn frame(&self, inbound: Inbound) -> Actions {
        if inbound.type_id != Self::outer() {
            return Actions::new();
        }
        let Ok(envelope) = OnboardingEnvelope::decode(inbound.payload.as_slice()) else {
            // An envelope this service cannot read means a client newer than
            // the server; the symptom is a feature that does nothing at all,
            // so it is worth a line.
            tracing::debug!(
                conn = inbound.conn,
                session = inbound.session,
                len = inbound.payload.len(),
                "undecodable OnboardingEnvelope"
            );
            return Actions::new();
        };

        match envelope.body {
            Some(onboarding_envelope::Body::ConfigUpdate(update)) => {
                // Editing the flow is server-wide, so it takes Write on the
                // root channel. Denied on any failure, including the
                // permissions service being unreachable.
                if !self
                    .permit
                    .allows(&inbound, ROOT_CHANNEL, Perm::WRITE.bits())
                    .await
                {
                    tracing::warn!(
                        session = inbound.session,
                        "onboarding config update without root Write; refused"
                    );
                    return Actions::new();
                }
                let Some(config) = update.config else {
                    return Actions::new();
                };
                let stored = self.store_config(inbound.scope, config).await;
                tracing::info!(
                    session = inbound.session,
                    revision = stored.revision,
                    questions = stored.questions.len(),
                    "onboarding flow updated"
                );
                // Everyone gets the new flow, the editor included: they are as
                // subject to it as anybody, and a client that had to special
                // case its own edit would drift from every other client.
                vec![broadcast_except(
                    0,
                    Self::outer(),
                    Self::envelope(onboarding_envelope::Body::Config(stored)),
                )]
            }
            Some(onboarding_envelope::Body::Response(mut response)) => {
                let Some(account) = self.roster.account_of(inbound.session) else {
                    // Nothing durable to key on. Accepting and discarding beats
                    // storing it under a session id that will not survive the
                    // connection and will later belong to somebody else.
                    tracing::debug!(
                        session = inbound.session,
                        "onboarding response from an unregistered session; not stored"
                    );
                    return Actions::new();
                };
                response.user_hash = None;
                response.submitted_at = Some(now_ms());
                self.record(inbound.scope, account, &response).await;
                // Echo it back as the delivery: the client now knows its own
                // answers are on record, from the same message it would have
                // had to ask for.
                vec![to_conn(
                    inbound.conn,
                    Self::outer(),
                    Self::envelope(onboarding_envelope::Body::ResponseDeliver(
                        FancyOnboardingResponseDeliver {
                            response: Some(response),
                        },
                    )),
                )]
            }
            Some(onboarding_envelope::Body::ResponseQuery(_)) => {
                self.deliver_answers(&inbound).await
            }
            // Server -> client only; a client sending one is ignored.
            Some(onboarding_envelope::Body::Config(_))
            | Some(onboarding_envelope::Body::ResponseDeliver(_))
            | None => Actions::new(),
        }
    }
}

impl Serve for OnboardingService {
    const NAME: &'static str = "onboarding";

    async fn build(ctx: ServiceContext) -> Result<Arc<Self>, ServiceError> {
        let store = ctx.storage().await?;
        store.migrate(SCHEMA).await?;
        Ok(Arc::new(Self {
            store,
            config: RwLock::new(None),
            roster: Arc::new(Roster::new()),
            permit: Permit::new(ctx.resolver.clone()),
            fanout: Fanout::default(),
        }))
    }

    async fn run(self: Arc<Self>, ctx: ServiceContext) -> Result<(), ServiceError> {
        let follower = Arc::clone(&self.roster).follow(ctx.clone(), Self::NAME, VIEW_GATE);
        ctx.shutdown.wait().await;
        follower.abort();
        Ok(())
    }

    fn routes(self: Arc<Self>) -> tonic::service::Routes {
        let plane = Plane::new(Arc::clone(&self), self.fanout.clone(), Self::NAME).into_server();
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
            config: RwLock::new(None),
            roster: Arc::new(Roster::new()),
            // A resolver that reaches nothing. These tests exercise storage,
            // and a Permit that cannot ask denies — which is the safe way for
            // it to be wrong if a test ever does reach the ACL path.
            permit: Permit::new(starling_runtime::channel::Resolver::new(
                Arc::new(starling_runtime::config::Config::default()),
                starling_runtime::inproc::Broker::default(),
            )),
            fanout: Fanout::default(),
        })
    }

    #[tokio::test]
    async fn answers_survive_the_session_they_were_given_in() {
        // The bug this replaced keyed answers on the session id, so a reconnect
        // looked like somebody who had never answered.
        let service = service().await;
        let response = FancyOnboardingResponse {
            config_revision: Some(3),
            ..FancyOnboardingResponse::default()
        };
        service.record(1, 7, &response).await;

        let read_back = service.answers(1, 7).await.expect("answers on record");
        assert_eq!(read_back.config_revision, Some(3));
    }

    #[tokio::test]
    async fn answering_twice_replaces_rather_than_accumulates() {
        // A user correcting an answer must not leave both on record.
        let service = service().await;
        for revision in [1, 2] {
            service
                .record(
                    1,
                    7,
                    &FancyOnboardingResponse {
                        config_revision: Some(revision),
                        ..FancyOnboardingResponse::default()
                    },
                )
                .await;
        }
        assert_eq!(
            service.answers(1, 7).await.and_then(|r| r.config_revision),
            Some(2)
        );
    }

    #[tokio::test]
    async fn one_account_cannot_read_anothers_answers() {
        let service = service().await;
        service
            .record(
                1,
                7,
                &FancyOnboardingResponse {
                    config_revision: Some(9),
                    ..FancyOnboardingResponse::default()
                },
            )
            .await;
        assert!(service.answers(1, 8).await.is_none());
    }

    #[tokio::test]
    async fn the_revision_climbs_and_never_resets() {
        // Answers are compared against this number, so a revision that went
        // backwards would make an old answer look like it answered the future.
        let service = service().await;
        let first = service
            .store_config(1, FancyOnboardingConfig::default())
            .await;
        let second = service
            .store_config(1, FancyOnboardingConfig::default())
            .await;
        assert_eq!(first.revision, Some(1));
        assert_eq!(second.revision, Some(2));

        // A restart drops the cache but not the stored revision.
        *service.config.write().await = None;
        let third = service
            .store_config(1, FancyOnboardingConfig::default())
            .await;
        assert_eq!(third.revision, Some(3));
    }

    #[tokio::test]
    async fn a_server_with_no_flow_has_nothing_to_serve() {
        let service = service().await;
        assert!(service.config(1).await.is_none());
    }
}
