//! `onboarding`: the flow a server shows a user on first connection.
//!
//! An operator writes the flow; a client answers it; the answers are stored per
//! account. Optional, so a server that has no flow simply never sends one;
//! there is no "empty flow" a client has to know to skip.
//!
//! # What a client is owed
//!
//! Two things, and the second is the one that is easy to forget: the flow, and
//! **whether this user already answered it**. A client that cannot tell "never
//! answered" from "not told yet" has to guess, and the only safe guess is to
//! ask again, which is how an onboarded user gets the questionnaire on every
//! single connect. A `Response` is sent back even when there is nothing stored
//! (carrying `submitted_at_ms == 0`), because silence is the ambiguity.
//!
//! # What an answer does
//!
//! Each `Step.Choice` names the channels it reveals and the ACL groups it joins
//! the user to. That is the feature: the questionnaire is a way of asking which
//! grants somebody wants, not a survey. [`grants`] applies them, on submission
//! and again whenever a client asks for the flow — see there for why they are
//! read out of the operator's `Flow` and never off the wire.
//!
//! # What answers are keyed on
//!
//! The account, never the session. Session ids are per connection and get
//! recycled, so keying on one means a returning user is a stranger and a later
//! user can inherit somebody else's answers. An unregistered guest has no
//! account and therefore cannot be remembered at all, their answers are
//! accepted and dropped rather than stored under something that will not
//! survive the connection.

pub mod grants;

use std::sync::Arc;

use prost::Message as _;
use starling_proto_fancy::fancy::feature::{
    Flow, OnboardingEnvelope, Response, onboarding_envelope,
};
use starling_proto_fancy::perm::Perm;
use starling_proto_fancy::types::ServiceKind;

use crate::grants::Grants;
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
/// server-wide authority lives, the same place murmur checks it.
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
/// was answering, and that revision is what decides whether to ask again,
/// splitting it into rows would lose the thing the decision is made on.
const SCHEMA: &[Migration<'static>] = &[
    Migration::new(
        "0002_onboarding_epoch1",
        &[
            "CREATE TABLE IF NOT EXISTS onboarding_config (\
                 server_id BIGINT PRIMARY KEY, config BLOB NOT NULL, at_ms BIGINT NOT NULL)",
            "CREATE TABLE IF NOT EXISTS onboarding_answers (\
                 server_id BIGINT NOT NULL, account_id BIGINT NOT NULL, \
                 response BLOB NOT NULL, at_ms BIGINT NOT NULL, \
                 PRIMARY KEY (server_id, account_id))",
        ],
    ),
    // Both blob columns held the epoch-0 `FancyOnboardingConfig` /
    // `FancyOnboardingResponse` from the dead proto2 envelope block; they now
    // hold the canon `Flow` and `Response`, whose field numbers mean different
    // things. Emptied rather than converted: the two shapes disagree on nearly
    // every field, so a "migration" would be guesswork, and a row that decodes
    // into the wrong questionnaire is worse than an operator re-entering one.
    // Answers are re-asked because the flow they answered no longer exists.
    Migration::new(
        "0003_onboarding_canon_encoding",
        &[
            "DELETE FROM onboarding_config",
            "DELETE FROM onboarding_answers",
        ],
    ),
];

/// The service.
#[derive(Debug)]
pub struct OnboardingService {
    store: Store,
    config: RwLock<Option<Flow>>,
    roster: Arc<Roster>,
    permit: Permit,
    grants: Grants,
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
    async fn config(&self, scope: u32) -> Option<Flow> {
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
        let config = Flow::decode(bytes.as_slice()).ok()?;
        *self.config.write().await = Some(config.clone());
        Some(config)
    }

    /// Store a new flow, stamped with the next revision.
    ///
    /// The revision only ever climbs, and is read back from storage first so
    /// that a restart cannot reset it: answers are compared against it, and a
    /// revision that went backwards would make already-answered look newer
    /// than the flow it answered.
    async fn store_config(&self, scope: u32, mut config: Flow, by: &str) -> Flow {
        let previous = self.config(scope).await.map_or(0, |c| c.version);
        config.version = previous + 1;
        config.updated_at_ms = now_ms();
        config.updated_by = by.to_owned();

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
    async fn answers(&self, scope: u32, account: u64) -> Option<Response> {
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
        Response::decode(bytes.as_slice()).ok()
    }

    /// Record this account's answers, replacing whatever they said before.
    async fn record(&self, scope: u32, account: u64, response: &Response) {
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

    /// Make this account's grants real: the flow's defaults, plus whatever
    /// their stored answers earn.
    ///
    /// Called on submission *and* on every query, which is what makes the
    /// grant self-healing. A permissions service that was down when the
    /// questionnaire was answered would otherwise leave the account short of
    /// what it was promised for good, and the user has no way to ask again —
    /// their answers are already on record, so a client has nothing to
    /// re-submit.
    ///
    /// Idempotent all the way down: when nothing is missing, no ACL is written
    /// and no invalidation reaches any connected client.
    ///
    /// Returns what was done, which is how a caller — and a test — tells
    /// "there was nothing to grant" from "we tried and could not".
    async fn apply_grants(&self, scope: u32, account: u64) -> grants::Applied {
        let nothing = grants::Applied {
            changed: 0,
            complete: true,
        };
        let Some(flow) = self.config(scope).await else {
            return nothing;
        };
        if !flow.enabled {
            // The operator's off switch, and it has to mean something beyond
            // "clients stop rendering it": a flow that is off hands out no new
            // permissions. Existing ones are left alone — turning a flow off
            // is not the same act as taking away what it granted, and guessing
            // that it was would revoke access an operator never asked to
            // revoke.
            tracing::debug!(account, "the flow is disabled; no grants applied");
            return nothing;
        }
        let answers = self.answers(scope, account).await.unwrap_or_default();
        let wanted = grants::wanted(&flow, &answers);
        let applied = self.grants.apply(scope, account, &wanted).await;
        if applied.changed > 0 {
            tracing::info!(
                account,
                channels = wanted.channels.len(),
                groups = wanted.groups.len(),
                wrote = applied.changed,
                "onboarding grants applied"
            );
        }
        if !applied.complete {
            // Not fatal, and deliberately not surfaced to the client: the
            // answers are stored, so the next connection retries. But a user
            // who is missing a channel they were told they would get is a
            // support question, and this is the line that answers it.
            tracing::warn!(
                account,
                "some onboarding grants could not be applied; they will be \
                 retried on the next connection"
            );
        }
        applied
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
        // A default `Response` carries `submitted_at_ms == 0`, which is how the
        // canon says "nothing stored", distinct from a stored response whose
        // answers happen to be empty, and the distinction a client needs to
        // decide whether to ask.
        vec![to_conn(
            inbound.conn,
            Self::outer(),
            Self::envelope(onboarding_envelope::Body::Response(
                stored.unwrap_or_default(),
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
            Some(onboarding_envelope::Body::Update(update)) => {
                self.on_flow_update(&inbound, update.flow).await
            }
            Some(onboarding_envelope::Body::Response(response)) => {
                self.on_response(&inbound, response).await
            }
            Some(onboarding_envelope::Body::Query(query)) => {
                self.on_query(&inbound, query.include_answers).await
            }
            // Server -> client only; a client sending one is ignored.
            Some(onboarding_envelope::Body::Flow(_)) | None => Actions::new(),
        }
    }
}

impl OnboardingService {
    /// Replace the questionnaire, and tell everybody the new one.
    ///
    /// Editing the flow is server-wide, so it takes Write on the root channel,
    /// and it is denied on any failure, including the permissions service
    /// being unreachable.
    ///
    /// The edit is recorded against the editor's account and never their
    /// session: a session id is reused by somebody else after they disconnect,
    /// so recording one would eventually attribute the edit to a stranger.
    ///
    /// Everyone gets the new flow, the editor included. They are as subject to
    /// it as anybody, and a client that had to special-case its own edit would
    /// drift from every other client.
    async fn on_flow_update(&self, inbound: &Inbound, flow: Option<Flow>) -> Actions {
        if !self
            .permit
            .allows(inbound, ROOT_CHANNEL, Perm::WRITE.bits())
            .await
        {
            tracing::warn!(
                session = inbound.session,
                "onboarding config update without root Write; refused"
            );
            return Actions::new();
        }
        let Some(config) = flow else {
            return Actions::new();
        };
        let by = self
            .roster
            .account_of(inbound.session)
            .map(|account| account.to_string())
            .unwrap_or_default();
        let stored = self.store_config(inbound.scope, config, &by).await;
        tracing::info!(
            session = inbound.session,
            version = stored.version,
            steps = stored.steps.len(),
            "onboarding flow updated"
        );
        vec![broadcast_except(
            0,
            Self::outer(),
            Self::envelope(onboarding_envelope::Body::Flow(stored)),
        )]
    }

    /// Record a user's answers, apply what they earn, and echo them back.
    ///
    /// A session with no account is answered with nothing: there is nothing
    /// durable to key the answers on, and accepting and discarding beats
    /// storing them under a session id that will not survive the connection
    /// and will later belong to somebody else.
    ///
    /// Both stamps are the server's. The client chooses its answers and
    /// nothing else, because a submission claiming to have been made against a
    /// flow version it was not is how an edited questionnaire looks
    /// already-answered.
    ///
    /// Stored first and granted second, never the other way round: a grant
    /// whose answers were not recorded cannot be re-derived, so it would
    /// survive as a permission nothing in the database explains.
    ///
    /// The echo carries the stamped copy, so the client learns its answers are
    /// on record from the same message it would otherwise have had to ask for.
    async fn on_response(&self, inbound: &Inbound, mut response: Response) -> Actions {
        let Some(account) = self.roster.account_of(inbound.session) else {
            tracing::debug!(
                session = inbound.session,
                "onboarding response from an unregistered session; not stored"
            );
            return Actions::new();
        };
        response.submitted_at_ms = now_ms();
        response.flow_version = self.config(inbound.scope).await.map_or(0, |c| c.version);
        self.record(inbound.scope, account, &response).await;
        let _ = self.apply_grants(inbound.scope, account).await;
        vec![to_conn(
            inbound.conn,
            Self::outer(),
            Self::envelope(onboarding_envelope::Body::Response(response)),
        )]
    }

    /// Send the questionnaire, and optionally the answers already given.
    ///
    /// Asking for the flow is what a user arriving looks like, which is when
    /// `Flow.default_channels` is owed ("granted to everyone who arrives,
    /// whatever they answer") and when a grant that failed last time gets its
    /// retry.
    async fn on_query(&self, inbound: &Inbound, include_answers: bool) -> Actions {
        if let Some(account) = self.roster.account_of(inbound.session) {
            let _ = self.apply_grants(inbound.scope, account).await;
        }
        let mut actions = Actions::new();
        if let Some(flow) = self.config(inbound.scope).await {
            actions.push(to_conn(
                inbound.conn,
                Self::outer(),
                Self::envelope(onboarding_envelope::Body::Flow(flow)),
            ));
        }
        if include_answers {
            actions.extend(self.deliver_answers(inbound).await);
        }
        actions
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
            grants: Grants::new(ctx.resolver.clone()),
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
    use starling_proto_fancy::fancy::feature::{Step, step};

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
        // A resolver that reaches nothing. These tests exercise storage, and a
        // Permit that cannot ask denies, which is the safe way for it to be
        // wrong if a test ever does reach the ACL path. `Grants` shares it, so
        // applying one here writes nothing and reports itself incomplete —
        // which is the behaviour worth having under test anyway.
        let nowhere = starling_runtime::channel::Resolver::new(
            Arc::new(starling_runtime::config::Config::default()),
            starling_runtime::inproc::Broker::default(),
        );
        Arc::new(OnboardingService {
            store,
            config: RwLock::new(None),
            roster: Arc::new(Roster::new()),
            permit: Permit::new(nowhere.clone()),
            grants: Grants::new(nowhere),
            fanout: Fanout::default(),
        })
    }

    #[tokio::test]
    async fn answers_survive_the_session_they_were_given_in() {
        // The bug this replaced keyed answers on the session id, so a reconnect
        // looked like somebody who had never answered.
        let service = service().await;
        let response = Response {
            flow_version: 3,
            ..Response::default()
        };
        service.record(1, 7, &response).await;

        let read_back = service.answers(1, 7).await.expect("answers on record");
        assert_eq!(read_back.flow_version, 3);
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
                    &Response {
                        flow_version: revision,
                        ..Response::default()
                    },
                )
                .await;
        }
        assert_eq!(service.answers(1, 7).await.map(|r| r.flow_version), Some(2));
    }

    #[tokio::test]
    async fn one_account_cannot_read_anothers_answers() {
        let service = service().await;
        service
            .record(
                1,
                7,
                &Response {
                    flow_version: 9,
                    ..Response::default()
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
        let first = service.store_config(1, Flow::default(), "7").await;
        let second = service.store_config(1, Flow::default(), "7").await;
        assert_eq!(first.version, 1);
        assert_eq!(second.version, 2);

        // A restart drops the cache but not the stored revision.
        *service.config.write().await = None;
        let third = service.store_config(1, Flow::default(), "7").await;
        assert_eq!(third.version, 3);
    }

    #[tokio::test]
    async fn a_server_with_no_flow_has_nothing_to_serve() {
        let service = service().await;
        assert!(service.config(1).await.is_none());
    }

    #[tokio::test]
    async fn a_disabled_flow_hands_out_nothing() {
        // The operator's off switch has to mean more than "clients stop
        // rendering it", or a flow turned off still quietly grants channels to
        // everyone who connects.
        let service = service().await;
        let _ = service
            .store_config(
                1,
                Flow {
                    enabled: false,
                    default_channels: vec![7],
                    ..Flow::default()
                },
                "7",
            )
            .await;

        let applied = service.apply_grants(1, 42).await;
        assert_eq!(applied.changed, 0);
        assert!(
            applied.complete,
            "nothing was owed, so nothing is outstanding, this must not read \
             as a failed grant that gets retried forever"
        );
    }

    #[tokio::test]
    async fn a_grant_that_could_not_be_applied_says_so() {
        // The resolver in these tests reaches no permissions service, which is
        // exactly the case that must not pass silently: the user was promised
        // a channel, the ACL was never written, and the only thing standing
        // between that and a support ticket nobody can answer is this flag.
        let service = service().await;
        let _ = service
            .store_config(
                1,
                Flow {
                    enabled: true,
                    default_channels: vec![7],
                    ..Flow::default()
                },
                "7",
            )
            .await;

        let applied = service.apply_grants(1, 42).await;
        assert_eq!(applied.changed, 0);
        assert!(
            !applied.complete,
            "an unreachable permissions service is not success"
        );
    }

    #[tokio::test]
    async fn a_flow_that_grants_nothing_asks_permissions_nothing() {
        // Most servers' flows are informational. Those must not put an ACL read
        // on every connection, which is what an unconditional apply would do.
        let service = service().await;
        let _ = service
            .store_config(
                1,
                Flow {
                    enabled: true,
                    ..Flow::default()
                },
                "7",
            )
            .await;

        let applied = service.apply_grants(1, 42).await;
        assert!(applied.complete && applied.changed == 0);
    }

    #[tokio::test]
    async fn grants_follow_the_stored_answers_not_the_message() {
        // `apply_grants` re-reads what was recorded rather than taking the
        // submission's word for it, which is what makes the retry on the next
        // connection possible at all — by then the message is long gone.
        let service = service().await;
        let _ = service
            .store_config(
                1,
                Flow {
                    enabled: true,
                    steps: vec![Step {
                        id: "interests".to_owned(),
                        choices: vec![step::Choice {
                            id: "dev".to_owned(),
                            channels: vec![7],
                            ..step::Choice::default()
                        }],
                        ..Step::default()
                    }],
                    ..Flow::default()
                },
                "7",
            )
            .await;
        service
            .record(
                1,
                42,
                &Response {
                    answers: vec![starling_proto_fancy::fancy::feature::response::Answer {
                        step_id: "interests".to_owned(),
                        choice_ids: vec!["dev".to_owned()],
                        text: String::new(),
                    }],
                    ..Response::default()
                },
            )
            .await;

        // Reaching the permissions service is what fails, and only a run that
        // found something to grant gets that far.
        assert!(!service.apply_grants(1, 42).await.complete);
        // Another account answered nothing, so there is nothing to reach for.
        assert!(service.apply_grants(1, 43).await.complete);
    }

    #[tokio::test]
    async fn what_an_answer_grants_survives_being_stored() {
        // The reason this service moved off the epoch-0 envelope. An answer is
        // a request for channel visibility and group membership; the shape it
        // used to be stored in could carry a label and nothing else, so a
        // questionnaire that round-tripped intact still granted nothing.
        let service = service().await;
        let flow = Flow {
            flow_id: "welcome".to_owned(),
            steps: vec![Step {
                id: "interests".to_owned(),
                title: "What are you here for?".to_owned(),
                kind: step::Kind::Choice as i32,
                multi_select: true,
                choices: vec![step::Choice {
                    id: "dev".to_owned(),
                    label: "Development".to_owned(),
                    channels: vec![7, 9],
                    groups: vec!["developers".to_owned()],
                    ..step::Choice::default()
                }],
                ..Step::default()
            }],
            ..Flow::default()
        };
        let _ = service.store_config(1, flow, "7").await;

        // Read back through the database, not the cache, or this asserts only
        // that a clone is a clone.
        *service.config.write().await = None;
        let stored = service.config(1).await.expect("the flow is on record");
        let choice = stored
            .steps
            .first()
            .and_then(|step| step.choices.first())
            .expect("the choice survived");
        assert_eq!(choice.channels, vec![7, 9]);
        assert_eq!(choice.groups, vec!["developers".to_owned()]);
        assert!(
            stored.steps[0].multi_select,
            "a multi-select question that round-trips as single-select silently \
             discards every answer but one"
        );
    }
}
