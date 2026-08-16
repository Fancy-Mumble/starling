//! `push`: notifications for clients that are not connected.
//!
//! Optional, and it means it: nobody notices when this is down, because
//! everyone who is connected got the real message over the control plane.
//! Which is also the rule the fan-out follows, a recipient with a live session
//! is skipped, so nobody is notified twice about a message already on screen.
//!
//! Who decides *what* to notify and who decides *how it leaves the building*
//! are deliberately different files. This one owns the first: whose device,
//! which channel, muted or not. [`fcm`] owns the second, and is the only place
//! that knows Google exists.

use std::sync::Arc;

use prost::Message as _;
use starling_proto_fancy::common::Ack;
use starling_proto_fancy::fancy::feature::{PushAck, PushEnvelope, push_envelope};
use starling_proto_fancy::push::push_server::{Push, PushServer};
use starling_proto_fancy::push::{
    LiveList, LiveQuery, Notification, NotifyResult, Registration, SubscriptionList,
    SubscriptionRequest, UnregisterRequest,
};
use starling_proto_fancy::types::ServiceKind;
use starling_runtime::metrics::Counter;
use starling_runtime::plane::{Actions, ClientService, Fanout, Inbound, Plane, to_conn};
use starling_runtime::roster::Roster;
use starling_runtime::serve::{Serve, ServiceContext, ServiceError};
use starling_runtime::storage::{Migration, Store};
use tokio::sync::Semaphore;
use tonic::{Request, Response, Status};

use crate::audience::{Audience, Permitted};
use crate::fcm::{Category, Fcm, Message, Sender, Target};
use crate::oauth::ServiceAccount;

pub mod audience;
pub mod fcm;
pub mod oauth;

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

/// The readiness gate that stays closed until the roster has a snapshot.
///
/// A cold roster cannot name the account behind a session, so every
/// registration would be filed under nobody and every device silently never
/// notified.
const VIEW_GATE: &str = "session-view";

/// How many notifications may be on their way to the provider at once.
///
/// murmur queues without limit onto two worker threads, which turns a burst
/// into unbounded memory rather than into a refusal. This holds the same burst
/// as sockets instead, and says so when it cannot: an optional service that
/// drops loudly is better than one that grows quietly.
const IN_FLIGHT: usize = 64;

/// What the operator configured, once, at start-up.
///
/// murmur's `pushnotify*` switches, plus the topic prefix, read from this
/// service's `options` table. See `starling.example.toml`.
#[derive(Debug, Clone, Default)]
pub struct Settings {
    /// Notify about ordinary channel messages and mentions.
    pub text_messages: bool,
    /// Notify about reactions.
    pub reactions: bool,
    /// Notify about people arriving and leaving.
    pub user_joins: bool,
    /// Send to `<prefix>_server<N>_channel<C>` as well as to registered
    /// devices, for deployments where clients subscribe to FCM topics
    /// themselves and the server never learns a device token.
    ///
    /// Absent is the normal case. A device that both subscribes to the topic
    /// and registers a token is notified twice, which is why this is off unless
    /// an operator asks for it.
    pub topic_prefix: Option<String>,
}

impl Settings {
    /// The murmur defaults: messages yes, the other two no.
    #[must_use]
    pub fn murmur_defaults() -> Self {
        Self {
            text_messages: true,
            reactions: false,
            user_joins: false,
            topic_prefix: None,
        }
    }

    /// Whether this category is one the operator asked to be notified about.
    #[must_use]
    pub const fn notifies(&self, category: Category) -> bool {
        match category {
            // A mention is a text message somebody was named in, and murmur
            // has no separate switch for it: turning off message notifications
            // turns off being told you were named, which is the intent.
            Category::TextMessage | Category::Mention => self.text_messages,
            Category::Reaction => self.reactions,
            Category::Channel => self.user_joins,
        }
    }
}

/// What one [`Notification`] turns into: messages to send, and the reasons the
/// rest were left alone.
///
/// Split out from sending because this is the part worth testing -- who is
/// skipped and why -- and it can then be tested without anybody's network.
#[derive(Debug, Default)]
struct Plan {
    /// What to hand the provider.
    messages: Vec<Message>,
    /// Recipients deliberately not notified: connected, or muted here.
    skipped: u32,
}

/// One connected client's request for live delivery.
///
/// The fork's `LivePushSubscription`, minus its `allowedChannels`: that set is
/// computed once at subscribe time upstream and refreshed only while the user
/// stays connected, so an ACL taken away in between still delivers. Here the
/// permission is asked per message, about the one channel in question, which is
/// both cheaper (one check, not one per channel on the server) and honest about
/// a revocation.
#[derive(Debug, Default, Clone)]
struct LiveSubscription {
    /// The channels this session wants left out.
    muted: std::collections::BTreeSet<u32>,
}

/// The service.
#[derive(Debug)]
pub struct PushService {
    store: Store,
    fanout: Fanout,
    /// Who is behind a session, so a registration is filed under the person
    /// rather than under nobody.
    ///
    /// Every registration used to be stored with `account: 0`, and every lookup
    /// asked for a real account, so nothing was ever found and no device was
    /// ever notified. A push token belongs to a person across reconnects, which
    /// is exactly what a session id is not.
    roster: Arc<Roster>,
    /// What the operator switched on.
    settings: Settings,
    /// Where notifications go, when a provider is configured at all.
    ///
    /// `None` is a supported deployment and the default one: the fan-out still
    /// runs and still answers, and nothing leaves the building.
    provider: Option<Arc<dyn Sender>>,
    /// The cap on sends in flight, so a burst is bounded by [`IN_FLIGHT`].
    permits: Arc<Semaphore>,
    /// Notifications dropped because that cap was reached.
    dropped: Counter,
    /// Who may hear about a channel at all.
    audience: Arc<dyn Audience>,
    /// Live delivery, per `(scope, session)`.
    ///
    /// In memory and nowhere else, exactly as the fork's `QHash`: a
    /// subscription is a property of a connection, and one that survived a
    /// restart would be a subscription belonging to a session id that now
    /// names somebody else.
    live: std::sync::Mutex<std::collections::HashMap<(u32, u32), LiveSubscription>>,
}

impl PushService {
    async fn register(&self, scope: u32, registration: &Registration) {
        let channels = registration
            .muted
            .iter()
            .map(u32::to_string)
            .collect::<Vec<_>>()
            .join(",");
        let result = sqlx::query(
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

        // The caller is acknowledged regardless, so a failure here is a device
        // that believes it is registered and will never be notified.
        match result {
            Ok(_) => tracing::debug!(
                account = registration.account,
                platform = %registration.platform,
                muted = registration.muted.len(),
                "push registration stored"
            ),
            Err(error) => tracing::error!(
                account = registration.account,
                %error,
                "could not store a push registration"
            ),
        }
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
            muted: row
                .try_get::<String, _>("channels")
                .unwrap_or_default()
                .split(',')
                .filter_map(|id| id.parse().ok())
                .collect(),
        })
        .collect()
    }

    /// Record what a connected session wants delivered live.
    ///
    /// Replaces rather than merges, as every mute set here does: a client can
    /// always say "I have stopped muting that one".
    fn live_subscribe(&self, scope: u32, session: u32, muted: &[u32]) {
        let Ok(mut live) = self.live.lock() else {
            return;
        };
        // The session going away is what removes it (`Server.cpp:1838` does the
        // same on disconnect), and [`Self::live_subscribers`] drops whatever the
        // roster no longer knows, so a client that vanishes without a goodbye
        // cannot leave one behind for the next holder of its id.
        let _ = live.insert(
            (scope, session),
            LiveSubscription {
                muted: muted.iter().copied().collect(),
            },
        );
        tracing::debug!(session, muted = muted.len(), "live push subscription");
    }

    /// The sessions to add to a message addressed at `channels`.
    ///
    /// The fork's loop in `msgTextMessage` (`Messages.cpp:2497`), one condition
    /// at a time: not the sender, subscribed, holds `SubscribePush` there, has
    /// not muted it. "Already a recipient" is the caller's to apply, since the
    /// caller is the one holding that list.
    async fn live_subscribers(&self, scope: u32, channels: &[u32], exclude: u32) -> Vec<u32> {
        let candidates: Vec<(u32, LiveSubscription)> = {
            let Ok(mut live) = self.live.lock() else {
                return Vec::new();
            };
            // A subscription outlives its session only until the next message.
            // Only with a warm roster: a cold one knows nobody, and pruning
            // against it would forget every live subscriber on the server.
            if self.roster.is_warm() {
                live.retain(|(_, session), _| self.roster.channel_of(*session).is_some());
            }
            live.iter()
                .filter(|((subscribed_scope, session), _)| {
                    *subscribed_scope == scope && *session != exclude
                })
                .map(|((_, session), subscription)| (*session, subscription.clone()))
                .collect()
        };

        let mut sessions = Vec::new();
        for (session, subscription) in candidates {
            for channel in channels {
                if subscription.muted.contains(channel) {
                    continue;
                }
                // Asked now rather than cached at subscribe time, so a
                // permission taken away while the user is connected stops
                // delivery with the next message rather than with the next
                // reconnect.
                if self
                    .audience
                    .session_may_receive(scope, session, *channel)
                    .await
                {
                    sessions.push(session);
                    break;
                }
            }
        }
        sessions
    }

    /// Every account with a device registered on this server.
    ///
    /// The set a notification that names nobody is fanned out over. Distinct,
    /// because a person with a phone and a tablet is one candidate with two
    /// devices, and the per-device work happens further down.
    async fn registered(&self, scope: u32) -> Vec<u64> {
        use sqlx::Row as _;
        sqlx::query("SELECT DISTINCT account_id FROM push_registration WHERE server_id = ?")
            .bind(i64::from(scope))
            .fetch_all(self.store.pool())
            .await
            .unwrap_or_default()
            .iter()
            .map(|row| row.try_get::<i64, _>("account_id").unwrap_or_default() as u64)
            .collect()
    }

    /// Who this notification is really for, and who is deliberately left alone.
    async fn plan(&self, scope: u32, request: &Notification) -> Plan {
        let category = request
            .data
            .get("category")
            .map_or(Category::default(), |name| Category::parse(name));
        let mut plan = Plan::default();
        if !self.settings.notifies(category) {
            // murmur's `pushnotifyreaction` / `pushnotifyuserjoin` switches:
            // the caller is free to ask, the operator decides which kinds of
            // event are worth a phone buzzing.
            tracing::debug!(?category, "the operator does not notify this category");
            plan.skipped = u32::try_from(request.accounts.len()).unwrap_or(u32::MAX);
            return plan;
        }

        let extra: std::collections::BTreeMap<String, String> = request
            .data
            .iter()
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect();
        let message = |target| Message {
            target,
            title: request.title.clone(),
            body: request.body.clone(),
            category,
            server: scope,
            channel: request.channel,
            data: extra.clone(),
        };

        // A caller that names nobody means "whoever registered a device here",
        // which is the only thing it can mean: `text` knows who is *connected*
        // and this service is the one that knows who is not. murmur's dispatch
        // walks its whole registration table for the same reason.
        let candidates = if request.accounts.is_empty() {
            self.registered(scope).await
        } else {
            request.accounts.clone()
        };

        for account in &candidates {
            // Connected recipients already have the real message; notifying
            // them again is how a phone buzzes for something on screen.
            if request.skip_accounts.contains(account) {
                plan.skipped += 1;
                continue;
            }
            // The gate the fork puts on registration: a notification carries a
            // channel's name and a line of what was said in it, so being told
            // about a channel is a permission and not a consequence of owning
            // a phone. `SubscribePush` is not in the default grant, exactly as
            // upstream, so an operator switching push on grants it too.
            if !self
                .audience
                .may_receive(scope, *account, request.channel)
                .await
            {
                plan.skipped += 1;
                continue;
            }
            // Muted channels are honoured here, and this is the point the whole
            // preference exists for. Every layer below stored it and no layer
            // read it: registrations kept a channel list, the read path
            // returned it, and delivery counted every device regardless, so a
            // user who muted a room was notified from it anyway.
            for registration in self.subscriptions(scope, *account).await {
                if registration.muted.contains(&request.channel) {
                    plan.skipped += 1;
                } else {
                    plan.messages
                        .push(message(Target::Token(registration.token)));
                }
            }
        }

        // Topic mode, murmur's `notifyChannel`: one message for a channel,
        // delivered by Google to whoever subscribed to it. Nobody's mute
        // preference is consulted, because in this mode the server does not
        // know who the recipients are -- which is the trade the operator makes
        // by choosing it.
        if let Some(prefix) = &self.settings.topic_prefix {
            let channel = request.channel;
            plan.messages.push(message(Target::Topic(format!(
                "{prefix}_server{scope}_channel{channel}"
            ))));
        }
        plan
    }

    /// Hand one notification to the provider, without waiting for Google.
    ///
    /// Fire-and-forget, as murmur's module is: `mumble_push_send` queues and
    /// returns, because the alternative is a text message whose latency
    /// includes an OAuth exchange. Returns whether it was accepted for
    /// delivery, which is all this layer can honestly claim.
    fn dispatch(&self, message: Message) -> bool {
        let Some(provider) = self.provider.clone() else {
            // No provider configured. The fan-out decision is still the answer
            // the caller gets; there is simply nowhere for it to go.
            return true;
        };
        let Ok(permit) = Arc::clone(&self.permits).try_acquire_owned() else {
            self.dropped.inc();
            tracing::warn!(
                in_flight = IN_FLIGHT,
                "too many push notifications in flight; dropping one"
            );
            return false;
        };
        drop(tokio::spawn(async move {
            let _permit = permit;
            if let Err(error) = provider.send(message).await {
                // Warn and not error: a stale device token is the common case
                // here, and it is the device's problem to re-register, not an
                // operator's to act on.
                tracing::warn!(%error, "could not deliver a push notification");
            }
        }));
        true
    }
}

/// The gRPC surface, as a type this crate owns.
#[derive(Debug, Clone)]
pub struct PushRpc(Arc<PushService>);

#[tonic::async_trait]
impl Push for PushRpc {
    async fn register(&self, request: Request<Registration>) -> Result<Response<Ack>, Status> {
        let registration = request.into_inner();
        let scope = registration.scope.as_ref().map_or(1, |s| s.instance);
        self.0.register(scope, &registration).await;
        Ok(Response::new(Ack {}))
    }

    async fn unregister(
        &self,
        request: Request<UnregisterRequest>,
    ) -> Result<Response<Ack>, Status> {
        let req = request.into_inner();
        let scope = req.scope.as_ref().map_or(1, |s| s.instance);
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
        let scope = req.scope.as_ref().map_or(1, |s| s.instance);
        let plan = self.0.plan(scope, &req).await;

        // `delivered` is what was accepted for delivery, not what a phone has
        // shown: the provider is asked in the background, and a notification
        // whose round trip a text message waited for would be the wrong trade.
        // What Google then says is in the log and in `starling_push_dropped`.
        let mut delivered = 0;
        let mut failed = 0;
        for message in plan.messages {
            if self.0.dispatch(message) {
                delivered += 1;
            } else {
                failed += 1;
            }
        }
        Ok(Response::new(NotifyResult {
            delivered,
            skipped: plan.skipped,
            failed,
        }))
    }

    async fn subscriptions(
        &self,
        request: Request<SubscriptionRequest>,
    ) -> Result<Response<SubscriptionList>, Status> {
        let req = request.into_inner();
        let scope = req.scope.as_ref().map_or(1, |s| s.instance);
        Ok(Response::new(SubscriptionList {
            registrations: self.0.subscriptions(scope, req.account).await,
        }))
    }

    async fn live_subscribers(
        &self,
        request: Request<LiveQuery>,
    ) -> Result<Response<LiveList>, Status> {
        let req = request.into_inner();
        let scope = req.scope.as_ref().map_or(1, |s| s.instance);
        Ok(Response::new(LiveList {
            sessions: self
                .0
                .live_subscribers(scope, &req.channels, req.exclude_session)
                .await,
        }))
    }
}

impl ClientService for PushService {
    async fn frame(&self, inbound: Inbound) -> Actions {
        let outer = ServiceKind::Push.outer_type();
        if inbound.type_id != outer {
            return Actions::new();
        }
        let Ok(envelope) = PushEnvelope::decode(inbound.payload.as_slice()) else {
            // Dropped silently before: an envelope this service cannot read
            // means a client newer than the server, and the symptom is a
            // feature that does nothing at all.
            tracing::debug!(
                conn = inbound.conn,
                session = inbound.session,
                len = inbound.payload.len(),
                "undecodable PushEnvelope"
            );
            return Actions::new();
        };

        // Live delivery is about a *session*, not a person, so it is answered
        // before the account is looked up: the fork asks only that the sender
        // is authenticated (`msgFancySubscribePush`), and a guest sitting in a
        // channel they may subscribe to is exactly as entitled to see the room
        // as a registered user is.
        if let Some(push_envelope::Body::LiveSubscribe(subscribe)) = &envelope.body {
            self.live_subscribe(inbound.scope, inbound.session, &subscribe.muted);
            let reply = PushEnvelope {
                body: Some(push_envelope::Body::Ack(PushAck {
                    ok: true,
                    detail: String::new(),
                })),
            };
            return vec![to_conn(inbound.conn, outer, reply.encode_to_vec())];
        }

        // A push token belongs to a person, so an unregistered guest has
        // nothing durable to file one under and is refused rather than stored
        // under a session id that will belong to somebody else tomorrow.
        let Some(account) = self.roster.account_of(inbound.session) else {
            tracing::debug!(
                session = inbound.session,
                "push registration from a session with no account; ignored"
            );
            let refusal = PushEnvelope {
                body: Some(push_envelope::Body::Ack(PushAck {
                    ok: false,
                    detail: "push notifications need a registered account".to_owned(),
                })),
            };
            return vec![to_conn(inbound.conn, outer, refusal.encode_to_vec())];
        };
        let ok = match envelope.body {
            Some(push_envelope::Body::Register(register)) => {
                self.register(
                    inbound.scope,
                    &Registration {
                        scope: None,
                        account,
                        token: register.token,
                        platform: register.platform,
                        // Was `Vec::new()`, which threw away what the device
                        // asked for and left it loud until a later subscribe
                        // that nothing handled either.
                        muted: register.muted,
                    },
                )
                .await;
                true
            }
            Some(push_envelope::Body::Subscribe(subscribe)) => {
                // Previously unhandled: it fell through to `ok: false`, so a
                // device muting a channel was told the request failed *and*
                // nothing was stored. The mute is per device, so it is written
                // against every token this account has registered.
                let existing = self.subscriptions(inbound.scope, account).await;
                for registration in existing {
                    self.register(
                        inbound.scope,
                        &Registration {
                            muted: subscribe.muted.clone(),
                            ..registration
                        },
                    )
                    .await;
                }
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

/// The provider named by `options`, when one is named and usable.
///
/// A misconfigured provider is a warning and not a start-up failure, which is
/// murmur's choice too: push is the one service whose absence nobody notices,
/// and refusing to boot a chat server over a Firebase key would be the wrong
/// trade. It is loud enough to find in a log.
fn provider(options: &starling_runtime::ServiceConfig) -> Option<Arc<dyn Sender>> {
    let path = std::path::PathBuf::from(options.options.get("fcm_credentials")?);
    let account = match ServiceAccount::load(&path) {
        Ok(account) => account,
        Err(error) => {
            tracing::error!(%error, "push is configured with credentials it cannot use");
            return None;
        }
    };
    // The configured project wins, and the credentials answer when it is not
    // set: a key belongs to exactly one project, so making an operator repeat
    // it is only an opportunity to get it wrong.
    let Some(project) = options
        .options
        .get("fcm_project")
        .cloned()
        .or_else(|| account.project().map(str::to_owned))
    else {
        tracing::error!("push has FCM credentials that do not name a project; set fcm_project");
        return None;
    };
    tracing::info!(%project, "push notifications go to Firebase Cloud Messaging");
    Some(Arc::new(Fcm::new(project, account)))
}

impl Serve for PushService {
    const NAME: &'static str = "push";

    async fn build(ctx: ServiceContext) -> Result<Arc<Self>, ServiceError> {
        let store = ctx.storage().await?;
        store.migrate(SCHEMA).await?;
        ctx.health.gate(VIEW_GATE);
        let options = ctx.service();
        let defaults = Settings::murmur_defaults();
        Ok(Arc::new(Self {
            store,
            fanout: Fanout::default(),
            roster: Arc::new(Roster::new()),
            settings: Settings {
                text_messages: options
                    .option("notify_text_message")
                    .unwrap_or(defaults.text_messages),
                reactions: options
                    .option("notify_reaction")
                    .unwrap_or(defaults.reactions),
                user_joins: options
                    .option("notify_user_join")
                    .unwrap_or(defaults.user_joins),
                topic_prefix: options.options.get("fcm_topic_prefix").cloned(),
            },
            provider: provider(&options),
            permits: Arc::new(Semaphore::new(IN_FLIGHT)),
            dropped: ctx.metrics.counter("starling_push_dropped"),
            audience: Arc::new(Permitted::new(ctx.resolver.clone())),
            live: std::sync::Mutex::new(std::collections::HashMap::new()),
        }))
    }

    async fn run(self: Arc<Self>, ctx: ServiceContext) -> Result<(), ServiceError> {
        // Follow `session-view`, so a session can be resolved to the account a
        // registration is filed under. Without this the roster stays cold and
        // every device registers as nobody.
        let follower = Arc::clone(&self.roster).follow(ctx.clone(), Self::NAME, VIEW_GATE);
        ctx.shutdown.wait().await;
        follower.abort();
        Ok(())
    }

    fn routes(self: Arc<Self>) -> tonic::service::Routes {
        let plane = Plane::new(Arc::clone(&self), self.fanout.clone(), Self::NAME).into_server();
        tonic::service::Routes::default()
            .add_service(PushServer::new(PushRpc(Arc::clone(&self))))
            .add_service(plane)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::audience::tests::Allowed;

    async fn service() -> Arc<PushService> {
        with_settings(Settings::murmur_defaults()).await
    }

    async fn with_settings(settings: Settings) -> Arc<PushService> {
        with(settings, Arc::new(Allowed::everyone())).await
    }

    async fn with(settings: Settings, audience: Arc<dyn Audience>) -> Arc<PushService> {
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
            roster: Arc::new(Roster::new()),
            store,
            fanout: Fanout::default(),
            settings,
            // No provider: every test here is about who gets notified, which is
            // this crate's decision, and not about whether Google took it.
            provider: None,
            permits: Arc::new(Semaphore::new(IN_FLIGHT)),
            dropped: starling_runtime::Metrics::new().counter("starling_push_dropped"),
            audience,
            live: std::sync::Mutex::new(std::collections::HashMap::new()),
        })
    }

    fn notification(channel: u32, accounts: Vec<u64>) -> Notification {
        Notification {
            channel,
            scope: None,
            accounts,
            title: "alice".to_owned(),
            body: "are you there?".to_owned(),
            data: Default::default(),
            skip_accounts: Vec::new(),
        }
    }

    async fn registered(
        service: &PushService,
        scope: u32,
        account: u64,
        token: &str,
        muted: Vec<u32>,
    ) {
        service
            .register(
                scope,
                &Registration {
                    scope: None,
                    account,
                    token: token.to_owned(),
                    platform: "android".to_owned(),
                    muted,
                },
            )
            .await;
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
                        muted: vec![1, 2],
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
    async fn a_muted_channel_does_not_buzz_the_phone() {
        // The preference was a complete no-op: stored on the registration,
        // returned by the read path, and never compared against anything,
        // because the notification did not say which channel it was about. A
        // user who muted a room was notified from it anyway.
        let service = service().await;
        service
            .register(
                1,
                &Registration {
                    scope: None,
                    account: 5,
                    token: "t".to_owned(),
                    platform: "android".to_owned(),
                    muted: vec![7],
                },
            )
            .await;

        let notify = |channel| {
            let service = Arc::clone(&service);
            async move {
                PushRpc(service)
                    .notify(Request::new(Notification {
                        channel,
                        scope: None,
                        accounts: vec![5],
                        title: "t".to_owned(),
                        body: "b".to_owned(),
                        data: Default::default(),
                        skip_accounts: Vec::new(),
                    }))
                    .await
                    .expect("notify")
                    .into_inner()
            }
        };

        let muted = notify(7).await;
        assert_eq!(muted.delivered, 0, "a muted channel must not be delivered");
        assert_eq!(muted.skipped, 1, "and the skip is counted, not lost");

        let other = notify(9).await;
        assert_eq!(other.delivered, 1, "an unmuted channel still notifies");
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
                    muted: Vec::new(),
                },
            )
            .await;

        let result = PushRpc(Arc::clone(&service))
            .notify(Request::new(Notification {
                channel: 0,
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

    #[tokio::test]
    async fn what_is_sent_is_addressed_to_the_device_and_says_where_it_came_from() {
        // The fan-out decides *who*; this is the part that has to survive the
        // trip to a phone, and a notification that arrives without its channel
        // is one a client cannot open.
        let service = service().await;
        registered(&service, 3, 5, "device-token", Vec::new()).await;

        let plan = service.plan(3, &notification(7, vec![5])).await;
        let [message] = plan.messages.as_slice() else {
            panic!("one registered device, one message: {:?}", plan.messages);
        };
        assert_eq!(message.target, Target::Token("device-token".to_owned()));
        assert_eq!(message.channel, 7);
        // The virtual server, which is what murmur puts in `server_id`: a
        // client connected to two of them has to be able to tell them apart.
        assert_eq!(message.server, 3);
        assert_eq!(message.category, Category::TextMessage);
    }

    #[tokio::test]
    async fn a_category_the_operator_switched_off_notifies_nobody() {
        // murmur's `pushnotifyreaction`, off by default: a phone that buzzes
        // for every thumbs-up is a phone somebody turns notifications off on.
        let service = service().await;
        registered(&service, 1, 5, "t", Vec::new()).await;

        let mut reaction = notification(7, vec![5]);
        let _ = reaction
            .data
            .insert("category".to_owned(), "reaction".to_owned());
        let plan = service.plan(1, &reaction).await;
        assert!(plan.messages.is_empty(), "reactions are off by default");
        assert_eq!(plan.skipped, 1, "and the recipient is counted as skipped");

        let service = with_settings(Settings {
            reactions: true,
            ..Settings::murmur_defaults()
        })
        .await;
        registered(&service, 1, 5, "t", Vec::new()).await;
        let plan = service.plan(1, &reaction).await;
        assert_eq!(plan.messages.len(), 1, "and on when the operator says so");
        assert_eq!(plan.messages[0].category, Category::Reaction);
    }

    #[tokio::test]
    async fn topic_mode_addresses_the_channel_rather_than_a_device() {
        // The deployment where clients subscribe to FCM topics themselves and
        // the server never learns a device token. murmur composes the same name.
        let service = with_settings(Settings {
            topic_prefix: Some("mumble".to_owned()),
            ..Settings::murmur_defaults()
        })
        .await;

        let plan = service.plan(2, &notification(7, Vec::new())).await;
        assert_eq!(
            plan.messages.first().map(|message| &message.target),
            Some(&Target::Topic("mumble_server2_channel7".to_owned())),
            "with no registrations at all, the topic is still addressed"
        );
    }

    #[tokio::test]
    async fn a_notification_that_names_nobody_reaches_everyone_registered() {
        // What `text` sends: it knows who is connected, and this service is the
        // one that knows who is not. Naming the offline recipients would mean
        // the caller enumerating a table it does not own.
        let service = service().await;
        registered(&service, 1, 5, "phone", Vec::new()).await;
        registered(&service, 1, 6, "tablet", Vec::new()).await;

        let mut request = notification(7, Vec::new());
        request.skip_accounts = vec![6];
        let plan = service.plan(1, &request).await;

        assert_eq!(plan.messages.len(), 1, "the connected one is left alone");
        assert_eq!(
            plan.messages.first().map(|message| &message.target),
            Some(&Target::Token("phone".to_owned()))
        );
        assert_eq!(plan.skipped, 1);
    }

    #[tokio::test]
    async fn a_channel_somebody_may_not_subscribe_to_never_reaches_their_phone() {
        // The leak this closes: a notification carries the channel and a line
        // of what was said in it, so without the check, registering a device
        // would read out the parts of a server you cannot see.
        let service = with(
            Settings::murmur_defaults(),
            Arc::new(Allowed::only([(5, 7)])),
        )
        .await;
        registered(&service, 1, 5, "t", Vec::new()).await;

        assert_eq!(
            service
                .plan(1, &notification(7, vec![5]))
                .await
                .messages
                .len(),
            1,
            "the channel they may subscribe to still notifies"
        );

        let elsewhere = service.plan(1, &notification(9, vec![5])).await;
        assert!(
            elsewhere.messages.is_empty(),
            "a channel they may not see must not be announced to them"
        );
        assert_eq!(elsewhere.skipped, 1);
    }

    #[tokio::test]
    async fn a_live_subscriber_hears_a_channel_they_are_not_sitting_in() {
        // The fork's `FancySubscribePush`: live delivery without joining and
        // without a listener, for the channels the subscriber holds
        // `SubscribePush` in.
        let service = with(
            Settings::murmur_defaults(),
            Arc::new(Allowed::sessions([(9, 4)])),
        )
        .await;
        service.live_subscribe(1, 9, &[]);

        assert_eq!(
            service.live_subscribers(1, &[4], 0).await,
            vec![9],
            "a subscriber with the permission is named"
        );
        assert!(
            service.live_subscribers(1, &[5], 0).await.is_empty(),
            "a channel they may not subscribe to is not delivered to them"
        );
    }

    #[tokio::test]
    async fn a_live_subscriber_is_never_added_to_their_own_message() {
        // `subscriber == uSource` in the fork's loop. Without it the sender
        // gets their own message back twice.
        let service = with(
            Settings::murmur_defaults(),
            Arc::new(Allowed::sessions([(9, 4)])),
        )
        .await;
        service.live_subscribe(1, 9, &[]);

        assert!(service.live_subscribers(1, &[4], 9).await.is_empty());
    }

    #[tokio::test]
    async fn a_muted_channel_is_left_out_of_live_delivery_too() {
        // The same exclusion list the fork keeps on the subscription, and the
        // reason the message carries one at all.
        let service = with(
            Settings::murmur_defaults(),
            Arc::new(Allowed::sessions([(9, 4), (9, 5)])),
        )
        .await;
        service.live_subscribe(1, 9, &[4]);

        assert!(service.live_subscribers(1, &[4], 0).await.is_empty());
        assert_eq!(
            service.live_subscribers(1, &[4, 5], 0).await,
            vec![9],
            "one muted channel does not silence a message that also names another"
        );
    }

    #[tokio::test]
    async fn a_subscription_dies_with_the_session_that_made_it() {
        // The fork drops it in `connectionClosed` (`Server.cpp:1838`). Session
        // ids are reused, so one left behind would deliver a private channel to
        // whoever is handed the number next.
        let service = with(
            Settings::murmur_defaults(),
            Arc::new(Allowed::sessions([(9, 4), (10, 4)])),
        )
        .await;
        service.live_subscribe(1, 9, &[]);
        service.live_subscribe(1, 10, &[]);

        // Cold: nothing is known, so nothing is thrown away. Forgetting every
        // subscriber because `session-view` has not answered yet would be the
        // worse failure.
        assert_eq!(service.live_subscribers(1, &[4], 0).await.len(), 2);

        use starling_proto_fancy::sessionview::{Session, Sessions, ViewEvent, view_event};
        let _ = service.roster.apply(ViewEvent {
            event: Some(view_event::Event::Snapshot(Sessions {
                sessions: vec![Session {
                    session: 9,
                    channel: 4,
                    ..Session::default()
                }],
                ..Sessions::default()
            })),
        });

        assert_eq!(
            service.live_subscribers(1, &[4], 0).await,
            vec![9],
            "the session that has gone is dropped, the one still here is kept"
        );
    }

    #[tokio::test]
    async fn a_subscription_belongs_to_one_server_instance() {
        // Session ids are per instance. A subscription that leaked across them
        // would deliver another virtual server's messages to whoever holds the
        // same number here.
        let service = with(
            Settings::murmur_defaults(),
            Arc::new(Allowed::sessions([(9, 4)])),
        )
        .await;
        service.live_subscribe(2, 9, &[]);

        assert!(service.live_subscribers(1, &[4], 0).await.is_empty());
        assert_eq!(service.live_subscribers(2, &[4], 0).await, vec![9]);
    }

    #[tokio::test]
    async fn a_notification_with_no_provider_is_still_answered_honestly() {
        // The default deployment: no credentials, so nothing leaves the
        // building. The caller still learns what the fan-out decided, which is
        // the difference between "nobody wanted it" and "it went nowhere".
        let service = service().await;
        registered(&service, 1, 5, "t", Vec::new()).await;
        let result = PushRpc(Arc::clone(&service))
            .notify(Request::new(notification(7, vec![5])))
            .await
            .expect("notify")
            .into_inner();
        assert_eq!(result.delivered, 1);
        assert_eq!(result.failed, 0);
    }
}
