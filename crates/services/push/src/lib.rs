//! `push`: notifications for clients that are not connected.
//!
//! Optional, and it means it: nobody notices when this is down, because
//! everyone who is connected got the real message over the control plane.
//! Which is also the rule the fan-out follows, a recipient with a live session
//! is skipped, so nobody is notified twice about a message already on screen.

use std::sync::Arc;

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
use starling_runtime::roster::Roster;
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

/// The readiness gate that stays closed until the roster has a snapshot.
///
/// A cold roster cannot name the account behind a session, so every
/// registration would be filed under nobody and every device silently never
/// notified.
const VIEW_GATE: &str = "session-view";

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
            // Muted channels are honoured here, and this is the point the whole
            // preference exists for. Every layer below stored it and no layer
            // read it: registrations kept a channel list, the read path
            // returned it, and delivery counted every device regardless, so a
            // user who muted a room was notified from it anyway.
            for registration in self.0.subscriptions(scope, *account).await {
                if registration.muted.contains(&req.channel) {
                    skipped += 1;
                } else {
                    delivered += 1;
                }
            }
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

impl Serve for PushService {
    const NAME: &'static str = "push";

    async fn build(ctx: ServiceContext) -> Result<Arc<Self>, ServiceError> {
        let store = ctx.storage().await?;
        store.migrate(SCHEMA).await?;
        ctx.health.gate(VIEW_GATE);
        Ok(Arc::new(Self {
            store,
            fanout: Fanout::default(),
            roster: Arc::new(Roster::new()),
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
            roster: Arc::new(Roster::new()),
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
}
