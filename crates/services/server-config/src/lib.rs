//! `server-config`: the settings an operator changes while the server runs.
//!
//! murmur keeps deployment and operational settings in one `Config` table.
//! Starling splits them because they have different lifetimes: endpoints and
//! ports need a restart anyway and live in the TOML, while `bandwidth`,
//! `messagelimit`, `welcometext` and the rest are expected to change live
//! (`docs/CONFIGURATION.md`).
//!
//! It is **essential** for a specific reason: the gateway cannot rate-limit
//! without `messagelimit` and the handshake cannot complete without the config
//! the client is sent. A cold start with this down must reject logins rather
//! than quietly serve on defaults the operator never chose.
//!
//! One actor per server instance, published as a snapshot readers cache, the
//! same pattern metadata uses for membership.
//!
//! # Three layers, and which one wins
//!
//! A setting can be stated in three places, and they are ordered by how
//! deliberate the statement is:
//!
//! 1. [`defaults`] -- murmur's, for a server nobody has configured;
//! 2. `[instances.settings]` in the deployment file, the operator's
//!    starting values;
//! 3. whatever an operator has since changed at run time, which wins.
//!
//! The third layer is stored **with the list of fields it covers** rather than
//! as a whole snapshot. That is the difference between "editing the file
//! changes anything nobody has touched" and "editing the file does nothing
//! whatsoever after the first admin request", which is what a whole-snapshot
//! row would have meant: one `set` of `welcome_text` would have frozen every
//! other setting at the value it happened to have that day.

use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;

use prost::Message as _;
use starling_proto_fancy::common::Scope;
use starling_proto_fancy::common::{Actor, actor};
use starling_proto_fancy::fancy::domain::{
    ConfigValues, LiveryDoc, OperatorTicketReply, OperatorTicketRequest, ServerConfigEnvelope,
    livery_doc, server_config_envelope,
};
use starling_proto_fancy::perm::Perm;
use starling_proto_fancy::serverconfig::server_config_server::{
    ServerConfig as ServerConfigRpc, ServerConfigServer,
};
use starling_proto_fancy::serverconfig::{
    GetRequest, Livery, SetLiveryRequest, SetRequest, Snapshot, VerifyTicketReply,
    VerifyTicketRequest,
};
use starling_proto_fancy::types::ServiceKind;
use starling_runtime::channel::Resolver;
use starling_runtime::config::Config;
use starling_runtime::permit::{Permit, permission_denied};
use starling_runtime::plane::{
    Actions, ClientService, Fanout, Inbound, Plane, broadcast_except, to_conn,
};
use starling_runtime::serve::{Serve, ServiceContext, ServiceError};
use starling_runtime::storage::{Migration, Store};
use tokio::sync::{RwLock, broadcast};
use tonic::{Request, Response, Status};

pub mod import;
pub mod snapshot;
pub mod ticket;

pub use import::import;
// Re-exported so the name still reads as this service's own. It lives in
// `runtime` for the reason `defaults` does: operator-api validates a livery
// and voice hashes one, and a second copy is one copy that eventually
// disagrees.
pub use snapshot::{apply_fields, defaults, redact};
pub use starling_runtime::livery;

/// The schema: one row per server instance, typed columns, no EAV.
pub(crate) const SCHEMA: &[Migration<'static>] = &[
    Migration::new(
        "0001_server_config",
        &["CREATE TABLE IF NOT EXISTS server_config (\
             server_id BIGINT PRIMARY KEY, \
             version BIGINT NOT NULL, \
             settings BLOB NOT NULL)"],
    ),
    Migration::new(
        "0002_server_config_owned_fields",
        &[
            // Which settings an operator has actually set, newline separated.
            // Without it the stored row is a whole snapshot, so the deployment
            // file stops meaning anything the moment anybody uses the admin UI.
            "ALTER TABLE server_config ADD COLUMN owned TEXT NOT NULL DEFAULT ''",
            // Rows that predate the column are whole snapshots an operator
            // owns outright, and there is no way to tell which fields they
            // chose. Claiming all of them keeps an existing deployment behaving
            // exactly as it did; the file takes over each field as it is next
            // reset, rather than silently overriding settings on upgrade.
            "UPDATE server_config SET owned = '*' WHERE owned = ''",
        ],
    ),
    Migration::new(
        "0003_server_livery",
        // Its own table rather than a column on `server_config`: the document
        // has its own version counter, and sharing a row would make one Set
        // bump the other's.
        &["CREATE TABLE IF NOT EXISTS server_livery (\
             server_id BIGINT PRIMARY KEY, \
             version BIGINT NOT NULL, \
             document BLOB NOT NULL)"],
    ),
];

/// Livery is a property of the server, not of a room, so the permission that
/// governs it is checked here — murmur's rule for every administrative write.
const ROOT_CHANNEL: u32 = 0;

/// The stored marker for "this row owns every field".
///
/// Only ever written by the migration above, for rows that predate the column.
const ALL_FIELDS: &str = "*";

/// How many snapshots a lagging subscriber may fall behind. Bounded, because an
/// unbounded inbox turns one slow reader into an OOM.
const WATCH_BUFFER: usize = 32;

/// The service.
#[derive(Debug)]
pub struct ServerConfigService {
    snapshots: RwLock<HashMap<u32, Snapshot>>,
    /// Which settings an operator has set at run time, per server instance.
    ///
    /// Everything else is the deployment file's, or murmur's, and follows the
    /// file when it is edited.
    owned: RwLock<HashMap<u32, BTreeSet<String>>>,
    updates: broadcast::Sender<Snapshot>,
    /// The presentation an operator supplies, per server instance.
    ///
    /// Beside the settings rather than inside them: it is a document with its
    /// own version counter and its own field set, and folding it into
    /// `Snapshot` would mean `SetRequest.fields` carrying dotted paths that the
    /// field-wise merge does not understand.
    liveries: RwLock<HashMap<u32, Livery>>,
    livery_updates: broadcast::Sender<Livery>,
    /// Reaches `userdata`, whose content-addressed blob store holds the livery
    /// artwork. Held rather than taken per call because `frame` is handed an
    /// `Inbound` and no context.
    resolver: Resolver,
    /// Answers "may this session do that", against `permissions`.
    permit: Permit,
    /// Short-lived operator tickets minted for a session with `TicketRequest`;
    /// verified by `operator-api` over `VerifyTicket` when its own configured
    /// authenticator does not recognise a bearer.
    tickets: ticket::TicketStore,
    /// Read once at construction for `operator-api`'s advertised address, the
    /// same way every other value that needs a restart to change is: a
    /// `TicketReply.base_url` that moved mid-deployment would only ever be
    /// noticed by whichever ticket happened to be minted around the reload.
    config: Arc<Config>,
    store: Option<Store>,
    fanout: Fanout,
}

impl ServerConfigService {
    /// The current snapshot for `scope`, or the shipped defaults.
    pub async fn snapshot(&self, scope: u32) -> Snapshot {
        self.snapshots
            .read()
            .await
            .get(&scope)
            .cloned()
            .unwrap_or_else(|| defaults(scope))
    }

    /// Record `snapshot`, noting that the operator now owns `fields`.
    async fn publish(&self, snapshot: Snapshot, fields: &[String]) {
        let scope = snapshot.instance;
        let owned = {
            let mut all = self.owned.write().await;
            let owned = all.entry(scope).or_default();
            owned.extend(fields.iter().cloned());
            owned.clone()
        };
        let _ = self.snapshots.write().await.insert(scope, snapshot.clone());
        if let Some(store) = &self.store
            && let Err(error) = persist(store, &snapshot, &owned).await
        {
            // Reported rather than swallowed: an operator whose change
            // vanishes must not learn about it from the next restart.
            tracing::error!(%error, "could not persist a configuration change");
        }
        let _ = self.updates.send(snapshot);
    }

    /// Re-apply `[instances.settings]` after the deployment file was reloaded.
    ///
    /// The same three layers as [`starting_point`], recomputed: murmur's
    /// defaults, then the file as it now reads, then back on top whatever the
    /// operator has set at run time. The middle layer is the only one that
    /// moved, and the third still wins, so editing the file changes exactly
    /// what nobody has touched -- which is what the boot path already promises
    /// and what an operator plainly means by editing it.
    ///
    /// Published with **no** claimed fields: a value arriving from the file is
    /// not an operator's decision, and recording it as one would freeze it
    /// against every later edit of that file.
    async fn adopt_file(&self, config: &Config, scopes: &[u32]) {
        for scope in scopes {
            let Some(instance) = config.instances.iter().find(|i| i.id == *scope) else {
                // The file no longer mentions this instance. Its settings are
                // left exactly as they are: `[[instances]]` needs a restart to
                // add or remove one, so acting here would apply half of a
                // change whose other half cannot happen yet.
                continue;
            };
            let current = self.snapshot(*scope).await;
            let owned: Vec<String> = self
                .owned
                .read()
                .await
                .get(scope)
                .map(|owned| owned.iter().cloned().collect())
                .unwrap_or_default();

            // A row written before the `owned` column existed carries no record
            // of which fields an operator chose, so all of them are treated as
            // theirs and the file may not reach any of them.
            if owned.iter().any(|field| field == ALL_FIELDS) {
                continue;
            }

            let mut rebuilt = defaults(*scope);
            let named = instance.settings.overlay(&mut rebuilt);
            // Not an operator write, so the counter the gateway reads to tell
            // "nobody has set this" from "somebody set it to zero" must not
            // move (`crates/gateway/src/listener.rs`).
            rebuilt.version = current.version;
            apply_fields(&mut rebuilt, &current, &owned);

            if rebuilt == current {
                continue;
            }
            tracing::info!(
                scope,
                settings = named.join(", "),
                "adopting settings from the reloaded file"
            );
            self.publish(rebuilt, &[]).await;
        }
    }

    /// The livery for `scope`, or an empty one.
    ///
    /// Empty is a real answer, not a missing one: a server that has set no
    /// livery is unbranded, and every caller would otherwise write the same
    /// branch back to a default.
    pub async fn livery(&self, scope: u32) -> Livery {
        self.liveries
            .read()
            .await
            .get(&scope)
            .cloned()
            .unwrap_or_else(|| Livery {
                instance: scope,
                ..Default::default()
            })
    }

    /// Record `livery`, stamping the digest every reader compares against.
    ///
    /// The digest is computed here rather than by the caller so there is one
    /// place it can be wrong, and so a document that reaches a subscriber
    /// always carries the digest for the content beside it.
    async fn publish_livery(&self, mut livery: Livery, actor: Option<Actor>) {
        let scope = livery.instance;
        livery.digest = livery::digest(&livery);
        let _ = self.liveries.write().await.insert(scope, livery.clone());
        if let Some(store) = &self.store
            && let Err(error) = persist_livery(store, &livery).await
        {
            tracing::error!(%error, "could not persist a livery change");
        }
        if let Some(actor) = &actor {
            tracing::info!(?actor, version = livery.version, "livery changed");
        }

        // Connected clients repaint without reconnecting. Pushed without the
        // artwork: most edits change a word, and a client that finds a key it
        // does not hold asks for that one image rather than being sent both on
        // every change.
        let doc = self.livery_doc(&livery, &[]).await;
        let envelope = ServerConfigEnvelope {
            body: Some(server_config_envelope::Body::Livery(LiveryDoc {
                art: Vec::new(),
                ..doc
            })),
        };
        // Session 0 is nobody, which is this codebase's "everyone".
        self.fanout.push(broadcast_except(
            0,
            ServiceKind::ServerConfig.outer_type(),
            envelope.encode_to_vec(),
        ));

        let _ = self.livery_updates.send(livery);
    }
}

/// The stored form of the owned-field set.
///
/// Newline separated, because the set includes `Snapshot.extra` keys, which a
/// service names and an operator types; a newline in one of those is a good
/// deal less likely than a comma.
fn encode_owned(owned: &BTreeSet<String>) -> String {
    owned
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .join("\n")
}

fn decode_owned(stored: &str) -> Vec<String> {
    stored
        .split('\n')
        .filter(|field| !field.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

async fn persist(
    store: &Store,
    snapshot: &Snapshot,
    owned: &BTreeSet<String>,
) -> Result<(), starling_runtime::StoreError> {
    let bytes = snapshot.encode_to_vec();
    sqlx::query(
        "INSERT INTO server_config (server_id, version, settings, owned) VALUES (?, ?, ?, ?) \
         ON CONFLICT (server_id) DO UPDATE SET version = excluded.version, \
         settings = excluded.settings, owned = excluded.owned",
    )
    .bind(i64::from(snapshot.instance))
    .bind(snapshot.version as i64)
    .bind(bytes)
    .bind(encode_owned(owned))
    .execute(store.pool())
    .await
    .map(|_| ())
    .map_err(|error| starling_runtime::StoreError::Query(format!("server_config: {error}")))
}

async fn persist_livery(
    store: &Store,
    livery: &Livery,
) -> Result<(), starling_runtime::StoreError> {
    sqlx::query(
        "INSERT INTO server_livery (server_id, version, document) VALUES (?, ?, ?) \
         ON CONFLICT (server_id) DO UPDATE SET version = excluded.version, \
         document = excluded.document",
    )
    .bind(i64::from(livery.instance))
    .bind(livery.version as i64)
    .bind(livery.encode_to_vec())
    .execute(store.pool())
    .await
    .map(|_| ())
    .map_err(|error| starling_runtime::StoreError::Query(format!("server_livery: {error}")))
}

/// The stored livery for `scope`, if one was ever written.
async fn load_livery(store: &Store, scope: u32) -> Option<Livery> {
    use sqlx::Row as _;
    let row = sqlx::query("SELECT document FROM server_livery WHERE server_id = ?")
        .bind(i64::from(scope))
        .fetch_optional(store.pool())
        .await
        .ok()??;
    let bytes: Vec<u8> = row.try_get("document").ok()?;
    Livery::decode(bytes.as_slice()).ok()
}

/// What was persisted for `scope`: the snapshot, and the fields it owns.
async fn load(store: &Store, scope: u32) -> Option<(Snapshot, Vec<String>)> {
    use sqlx::Row as _;
    let row = sqlx::query("SELECT settings, owned FROM server_config WHERE server_id = ?")
        .bind(i64::from(scope))
        .fetch_optional(store.pool())
        .await
        .ok()??;
    let bytes: Vec<u8> = row.try_get("settings").ok()?;
    let owned: String = row.try_get("owned").unwrap_or_default();
    Snapshot::decode(bytes.as_slice())
        .ok()
        .map(|snapshot| (snapshot, decode_owned(&owned)))
}

/// The gRPC surface, as a type this crate owns.
///
/// tonic's generated trait is foreign and `Arc` is foreign, so the service
/// cannot implement it through an `Arc` directly. A one-field wrapper is the
/// whole of the workaround, and it keeps the RPC methods visibly separate from
/// the service's own.
#[derive(Debug, Clone)]
pub struct ConfigRpc(Arc<ServerConfigService>);

#[tonic::async_trait]
impl ServerConfigRpc for ConfigRpc {
    async fn get(&self, request: Request<GetRequest>) -> Result<Response<Snapshot>, Status> {
        let scope = scope_of(request.into_inner().scope);
        Ok(Response::new(self.0.snapshot(scope).await))
    }

    async fn set(&self, request: Request<SetRequest>) -> Result<Response<Snapshot>, Status> {
        let req = request.into_inner();
        let scope = scope_of(req.scope);
        let mut current = self.0.snapshot(scope).await;
        let Some(values) = req.values else {
            return Ok(Response::new(current));
        };
        // Only the named fields are written, so two operators editing different
        // settings do not overwrite each other.
        apply_fields(&mut current, &values, &req.fields);
        current.version += 1;
        // The same list decides what the operator now owns: a setting they have
        // never touched keeps following the deployment file.
        self.0.publish(current.clone(), &req.fields).await;
        Ok(Response::new(current))
    }

    type WatchStream = tokio_stream::wrappers::ReceiverStream<Result<Snapshot, Status>>;

    async fn watch(
        &self,
        request: Request<GetRequest>,
    ) -> Result<Response<Self::WatchStream>, Status> {
        let scope = scope_of(request.into_inner().scope);
        let (tx, rx) = tokio::sync::mpsc::channel(WATCH_BUFFER);
        // Snapshot first, then deltas: a subscriber that connected after a
        // change must not have to ask for the state it missed.
        let _ = tx.send(Ok(self.0.snapshot(scope).await)).await;

        let mut updates = self.0.updates.subscribe();
        drop(tokio::spawn(async move {
            while let Ok(snapshot) = updates.recv().await {
                if snapshot.instance != scope {
                    continue;
                }
                if tx.send(Ok(snapshot)).await.is_err() {
                    return;
                }
            }
        }));
        Ok(Response::new(tokio_stream::wrappers::ReceiverStream::new(
            rx,
        )))
    }

    async fn get_livery(&self, request: Request<GetRequest>) -> Result<Response<Livery>, Status> {
        let scope = scope_of(request.into_inner().scope);
        Ok(Response::new(self.0.livery(scope).await))
    }

    async fn set_livery(
        &self,
        request: Request<SetLiveryRequest>,
    ) -> Result<Response<Livery>, Status> {
        let req = request.into_inner();
        let scope = scope_of(req.scope);
        let mut current = self.0.livery(scope).await;
        let Some(values) = req.values else {
            return Ok(Response::new(current));
        };

        // Refused rather than partially written. Unlike the settings merge, an
        // unknown key here cannot be another service's knob, so the only thing
        // it can be is a typo, and one whose symptom is a screen that did not
        // change.
        livery::apply_fields(&mut current, &values, &req.fields)
            .map_err(|error| Status::invalid_argument(error.to_string()))?;

        // Validated after the merge, not before: the caller sends only the
        // fields it is changing, so a document is only ever whole here.
        livery::validate(&current).map_err(|error| Status::invalid_argument(error.to_string()))?;

        current.instance = scope;
        current.version += 1;
        self.0.publish_livery(current.clone(), req.actor).await;
        Ok(Response::new(self.0.livery(scope).await))
    }

    type WatchLiveryStream = tokio_stream::wrappers::ReceiverStream<Result<Livery, Status>>;

    async fn watch_livery(
        &self,
        request: Request<GetRequest>,
    ) -> Result<Response<Self::WatchLiveryStream>, Status> {
        let scope = scope_of(request.into_inner().scope);
        let (tx, rx) = tokio::sync::mpsc::channel(WATCH_BUFFER);
        // Current document first, then changes, as `watch` does: a subscriber
        // that attached after a change must not have to ask for what it missed.
        let _ = tx.send(Ok(self.0.livery(scope).await)).await;

        let mut updates = self.0.livery_updates.subscribe();
        drop(tokio::spawn(async move {
            while let Ok(livery) = updates.recv().await {
                if livery.instance != scope {
                    continue;
                }
                if tx.send(Ok(livery)).await.is_err() {
                    return;
                }
            }
        }));
        Ok(Response::new(tokio_stream::wrappers::ReceiverStream::new(
            rx,
        )))
    }

    /// Whether `token` is a ticket this process minted and has not expired.
    ///
    /// Called by `operator-api`, never by a client: a bearer token travels
    /// here exactly as it arrived in `Authorization`, and this is an internal
    /// call between two services that already trust each other's requests,
    /// the same trust `permissions` extends to every caller of `check_session`.
    async fn verify_ticket(
        &self,
        request: Request<VerifyTicketRequest>,
    ) -> Result<Response<VerifyTicketReply>, Status> {
        let token = request.into_inner().token;
        Ok(Response::new(match self.0.tickets.verify(&token) {
            Some((subject, scopes)) => VerifyTicketReply {
                valid: true,
                subject,
                scopes,
            },
            None => VerifyTicketReply::default(),
        }))
    }
}

impl ClientService for ServerConfigService {
    async fn frame(&self, inbound: Inbound) -> Actions {
        let outer = ServiceKind::ServerConfig.outer_type();
        if inbound.type_id != outer {
            return Actions::new();
        }
        let Ok(envelope) = ServerConfigEnvelope::decode(inbound.payload.as_slice()) else {
            // Dropped silently before: an envelope this service cannot read
            // means a client newer than the server, and the symptom is a
            // feature that does nothing at all.
            tracing::debug!(
                conn = inbound.conn,
                session = inbound.session,
                len = inbound.payload.len(),
                "undecodable ServerConfigEnvelope"
            );
            return Actions::new();
        };
        match envelope.body {
            Some(server_config_envelope::Body::Query(_)) => {
                let snapshot = self.snapshot(inbound.scope).await;
                let reply = ServerConfigEnvelope {
                    body: Some(server_config_envelope::Body::Values(ConfigValues {
                        settings: redact(&snapshot),
                        version: snapshot.version,
                    })),
                };
                vec![to_conn(inbound.conn, outer, reply.encode_to_vec())]
            }
            Some(server_config_envelope::Body::LiveryQuery(query)) => {
                let livery = self.livery(inbound.scope).await;
                let doc = self.livery_doc(&livery, &query.have_keys).await;
                let reply = ServerConfigEnvelope {
                    body: Some(server_config_envelope::Body::Livery(doc)),
                };
                vec![to_conn(inbound.conn, outer, reply.encode_to_vec())]
            }
            Some(server_config_envelope::Body::LiveryUpdate(update)) => {
                self.on_livery_update(&inbound, update).await
            }
            Some(server_config_envelope::Body::TicketRequest(request)) => {
                self.on_ticket_request(&inbound, request).await
            }
            // A *settings* update from a client is still refused. Nothing has
            // asked for one, and unlike livery the person sending it is not
            // looking at the thing they are changing.
            _ => Actions::new(),
        }
    }
}

impl ServerConfigService {
    /// An admin changing the livery from a connected client.
    ///
    /// Authorised as murmur authorises every other administrative write:
    /// `Write` on the **root** channel, because livery is a property of the
    /// server rather than of a room. The identity is the session the frame
    /// arrived on, which the handshake established and a client cannot assert.
    ///
    /// Refused loudly. An unauthorised write that is accepted and dropped shows
    /// the admin their change on screen and nothing in any log, which is the
    /// failure `moderation::on_user_remove` records having shipped once.
    async fn on_livery_update(
        &self,
        inbound: &Inbound,
        update: starling_proto_fancy::fancy::domain::LiveryUpdate,
    ) -> Actions {
        if !self
            .permit
            .allows(inbound, ROOT_CHANNEL, Perm::WRITE.bits())
            .await
        {
            tracing::info!(session = inbound.session, "livery write refused");
            return vec![permission_denied(inbound, Perm::WRITE, ROOT_CHANNEL)];
        }

        let Some(values) = update.values else {
            return Actions::new();
        };
        let mut current = self.livery(inbound.scope).await;
        let wire = from_doc(&values);
        if let Err(error) = livery::apply_fields(&mut current, &wire, &update.fields) {
            tracing::info!(session = inbound.session, %error, "livery write names no such field");
            return Actions::new();
        }
        if let Err(error) = livery::validate(&current) {
            tracing::info!(session = inbound.session, %error, "livery write refused as invalid");
            return Actions::new();
        }

        current.instance = inbound.scope;
        current.version += 1;
        // Attributed to the session, which `audit` resolves to an account. The
        // operator API's own file records what *operators* did; this is the
        // other half, and a change made from a client belongs in it.
        self.publish_livery(
            current,
            Some(Actor {
                who: Some(actor::Who::Session(inbound.session)),
            }),
        )
        .await;
        Actions::new()
    }

    /// A connected session asking for an operator credential it can present
    /// to the operator API, for something the control channel does not carry
    /// (an image, today).
    ///
    /// Every scope actually granted is checked by
    /// [`starling_runtime::operator_scope::grant`] against the permission
    /// that already gates the equivalent control-channel action for this
    /// session -- the same authority [`Self::on_livery_update`] checks for a
    /// livery write, generalised. A ticket therefore never grants more than
    /// this session could already do some other way; it is a shorter path to
    /// the same authority, not a new one.
    async fn on_ticket_request(
        &self,
        inbound: &Inbound,
        request: OperatorTicketRequest,
    ) -> Actions {
        let outer = ServiceKind::ServerConfig.outer_type();
        let granted =
            starling_runtime::operator_scope::grant(&self.permit, inbound, &request.scopes).await;

        let reply = if granted.is_empty() {
            OperatorTicketReply {
                denied_reason: "no requested scope is covered by a permission this session holds"
                    .to_owned(),
                ..Default::default()
            }
        } else {
            let subject = format!("session:{}", inbound.session);
            match self.tickets.issue(subject, granted.clone()) {
                Some(issued) => OperatorTicketReply {
                    token: issued.token,
                    granted_scopes: granted,
                    expires_at_ms: issued.expires_at_ms,
                    base_url: operator_api_public_url(&self.config),
                    denied_reason: String::new(),
                },
                None => OperatorTicketReply {
                    denied_reason: "could not generate a credential".to_owned(),
                    ..Default::default()
                },
            }
        };

        let envelope = ServerConfigEnvelope {
            body: Some(server_config_envelope::Body::TicketReply(reply)),
        };
        vec![to_conn(inbound.conn, outer, envelope.encode_to_vec())]
    }

    /// The wire shape of `livery`, carrying the art the caller lacks.
    ///
    /// `have_keys` is what the client already holds, so an operator editing a
    /// motto sends a few hundred bytes rather than the banner again. That is the
    /// whole reason the document carries content keys rather than bytes.
    async fn livery_doc(&self, livery: &Livery, have_keys: &[String]) -> LiveryDoc {
        let palette = |palette: Option<&starling_proto_fancy::serverconfig::livery::Palette>| {
            palette.map(|palette| livery_doc::Palette {
                accent: palette.accent.clone(),
                surface: palette.surface.clone(),
                aura_from: palette.aura_from.clone(),
                aura_to: palette.aura_to.clone(),
            })
        };

        let mut art = Vec::new();
        for key in [&livery.banner_key, &livery.icon_key] {
            if key.is_empty() || have_keys.iter().any(|held| held == key) {
                continue;
            }
            if let Some(bytes) = self.blob(key).await {
                art.push(livery_doc::Art {
                    // Sniffed from the bytes rather than stored alongside them:
                    // it is the same test the client's decoder will apply, and
                    // a claim the bytes do not support is somebody else's bug.
                    content_type: sniff(&bytes).to_owned(),
                    key: key.clone(),
                    bytes,
                });
            }
        }

        LiveryDoc {
            version: livery.version,
            digest: livery.digest.clone(),
            display_name: livery.display_name.clone(),
            tagline: livery.tagline.clone(),
            motd: livery.motd.clone(),
            tags: livery
                .tags
                .iter()
                .map(|tag| livery_doc::Tag {
                    label: tag.label.clone(),
                    tone: tag.tone,
                    href: tag.href.clone(),
                })
                .collect(),
            rules_url: livery.rules_url.clone(),
            banner_key: livery.banner_key.clone(),
            icon_key: livery.icon_key.clone(),
            banner_focus_x: livery.banner_focus_x,
            banner_focus_y: livery.banner_focus_y,
            dark: palette(livery.dark.as_ref()),
            light: palette(livery.light.as_ref()),
            art,
        }
    }

    /// Livery artwork by its content key, from `userdata`'s blob store.
    ///
    /// `None` when the store cannot be reached or the key is not there. A
    /// missing image is a connect screen without a banner, which is a rung of
    /// the ladder rather than a failure, so nothing here refuses the document.
    async fn blob(&self, key: &str) -> Option<Vec<u8>> {
        use starling_proto_fancy::userdata::user_data_client::UserDataClient;

        let hash = unhex(key)?;
        let channel = self.resolver.channel("userdata").ok()?;
        let bytes = UserDataClient::new(channel)
            .get_blob(starling_proto_fancy::userdata::BlobRequest { scope: None, hash })
            .await
            .ok()?
            .into_inner()
            .bytes;
        (!bytes.is_empty()).then_some(bytes)
    }
}

/// The mesh shape of a document that arrived on the wire.
///
/// The mirror of `livery_doc`, and the two planes stay separate types for the
/// reason `PROTOCOL-REDESIGN` §7 gives: neither imports the other's common.
fn from_doc(doc: &LiveryDoc) -> Livery {
    use starling_proto_fancy::serverconfig::livery;

    let palette = |entry: Option<&livery_doc::Palette>| {
        entry.map(|entry| livery::Palette {
            accent: entry.accent.clone(),
            surface: entry.surface.clone(),
            aura_from: entry.aura_from.clone(),
            aura_to: entry.aura_to.clone(),
        })
    };
    Livery {
        display_name: doc.display_name.clone(),
        tagline: doc.tagline.clone(),
        motd: doc.motd.clone(),
        tags: doc
            .tags
            .iter()
            .map(|tag| livery::Tag {
                label: tag.label.clone(),
                tone: tag.tone,
                href: tag.href.clone(),
            })
            .collect(),
        rules_url: doc.rules_url.clone(),
        banner_key: doc.banner_key.clone(),
        icon_key: doc.icon_key.clone(),
        banner_focus_x: doc.banner_focus_x,
        banner_focus_y: doc.banner_focus_y,
        dark: palette(doc.dark.as_ref()),
        light: palette(doc.light.as_ref()),
        ..Default::default()
    }
}

/// The image type these bytes actually are.
fn sniff(bytes: &[u8]) -> &'static str {
    const PNG: &[u8] = &[0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a];
    if bytes.starts_with(PNG) {
        "image/png"
    } else if bytes.starts_with(&[0xff, 0xd8, 0xff]) {
        "image/jpeg"
    } else if bytes.len() > 12 && bytes.starts_with(b"RIFF") && &bytes[8..12] == b"WEBP" {
        "image/webp"
    } else {
        "application/octet-stream"
    }
}

fn unhex(value: &str) -> Option<Vec<u8>> {
    if !value.len().is_multiple_of(2) || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    let bytes = value.as_bytes();
    (0..bytes.len())
        .step_by(2)
        .map(|at| {
            std::str::from_utf8(&bytes[at..at + 2])
                .ok()
                .and_then(|pair| u8::from_str_radix(pair, 16).ok())
        })
        .collect()
}

impl Serve for ServerConfigService {
    const NAME: &'static str = "server-config";

    async fn build(ctx: ServiceContext) -> Result<Arc<Self>, ServiceError> {
        ctx.health.gate("settings loaded");
        let store = match ctx.storage().await {
            Ok(store) => {
                store.migrate(SCHEMA).await?;
                Some(store)
            }
            Err(error) => {
                // Persisting is optional; serving is not. A throwaway server
                // should not need a database to boot.
                tracing::warn!(%error, "running without persisted settings");
                None
            }
        };

        let mut snapshots = HashMap::new();
        let mut owned = HashMap::new();
        for scope in ctx.instances() {
            let (snapshot, fields) = starting_point(&ctx, scope, store.as_ref()).await;
            let _ = snapshots.insert(scope, snapshot);
            let _ = owned.insert(scope, fields);
        }

        let mut liveries = HashMap::new();
        for scope in ctx.instances() {
            let mut stored = match store.as_ref() {
                Some(store) => load_livery(store, scope).await.unwrap_or_default(),
                None => Livery::default(),
            };
            stored.instance = scope;
            stored.digest = livery::digest(&stored);
            let _ = liveries.insert(scope, stored);
        }

        let (updates, _) = broadcast::channel(WATCH_BUFFER);
        let (livery_updates, _) = broadcast::channel(WATCH_BUFFER);
        ctx.health.ready("settings loaded");
        Ok(Arc::new(Self {
            snapshots: RwLock::new(snapshots),
            owned: RwLock::new(owned),
            updates,
            liveries: RwLock::new(liveries),
            livery_updates,
            resolver: ctx.resolver.clone(),
            permit: Permit::new(ctx.resolver.clone()),
            tickets: ticket::TicketStore::default(),
            config: Arc::clone(&ctx.config),
            store,
            fanout: Fanout::default(),
        }))
    }

    fn routes(self: Arc<Self>) -> tonic::service::Routes {
        let plane = Plane::new(Arc::clone(&self), self.fanout.clone(), Self::NAME).into_server();
        tonic::service::Routes::default()
            .add_service(ServerConfigServer::new(ConfigRpc(Arc::clone(&self))))
            .add_service(plane)
    }

    /// Follow the deployment file, so `[instances.settings]` is live.
    ///
    /// This service is where the two configuration layers meet, which makes it
    /// the only place a file edit can reach the operational half without a
    /// restart: the snapshot it republishes is the one every subscriber in the
    /// fleet already caches, so one SIGHUP here changes `max_users` everywhere
    /// that reads it.
    async fn run(self: Arc<Self>, ctx: ServiceContext) -> Result<(), ServiceError> {
        let scopes = ctx.instances();
        let mut configs = ctx.live.subscribe();
        loop {
            tokio::select! {
                () = ctx.shutdown.wait() => return Ok(()),
                changed = configs.changed() => {
                    if changed.is_err() {
                        // The cell outlives every service in practice; if it
                        // did not, there is nothing further to follow.
                        return Ok(());
                    }
                    let config = Arc::clone(&configs.borrow_and_update());
                    self.adopt_file(&config, &scopes).await;
                }
            }
        }
    }
}

/// The settings `scope` starts with, and which of them the operator owns.
///
/// The three layers of the module header, applied in order: murmur's defaults,
/// then the deployment file, then whatever an operator has since set at run
/// time. A field the operator has never touched follows the file, so editing it
/// and restarting does what an operator plainly means by that.
async fn starting_point(
    ctx: &ServiceContext,
    scope: u32,
    store: Option<&Store>,
) -> (Snapshot, BTreeSet<String>) {
    let mut snapshot = defaults(scope);

    if let Some(server) = ctx
        .config
        .instances
        .iter()
        .find(|server| server.id == scope)
    {
        let named = server.settings.overlay(&mut snapshot);
        if !named.is_empty() {
            tracing::debug!(scope, settings = named.join(", "), "settings from the file");
        }
    }

    let persisted = match store {
        Some(store) => load(store, scope).await,
        None => None,
    };
    let Some((persisted, fields)) = persisted else {
        return (snapshot, BTreeSet::new());
    };

    // A row written before the `owned` column existed is a whole snapshot with
    // no record of which fields an operator chose, so it keeps all of them.
    if fields.iter().any(|field| field == ALL_FIELDS) {
        return (persisted, BTreeSet::from([ALL_FIELDS.to_owned()]));
    }
    snapshot.version = persisted.version;
    apply_fields(&mut snapshot, &persisted, &fields);
    (snapshot, fields.into_iter().collect())
}

/// The scope a request names, defaulting to the first server instance.
#[must_use]
pub fn scope_of(scope: Option<Scope>) -> u32 {
    scope.map_or(1, |scope| scope.instance)
}

/// Where a client should present an operator ticket, or empty when this
/// deployment has not said.
///
/// `[services.operator-api].public_url`, never `listen`: a bind address is
/// frequently `127.0.0.1` or a `ClusterIP` nothing outside the pod can reach,
/// and handing that back would read as a working answer until a client tried
/// it. An operator who wants tickets to work at all names the address a
/// client should actually use, the same field `files` and `screenshare`
/// already sign URLs against.
fn operator_api_public_url(config: &Config) -> String {
    config
        .services
        .get("operator-api")
        .and_then(|service| service.public_url.clone())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn service() -> Arc<ServerConfigService> {
        // A resolver that reaches nothing: these tests exercise storage and the
        // merge, and a permission check with no `permissions` service behind it
        // denies, which is what the refusal test wants anyway.
        let config = Arc::new(Config::with_defaults(std::path::Path::new("/run/starling")));
        let resolver = Resolver::new(Arc::clone(&config), starling_runtime::inproc::Broker::new());
        let (updates, _) = broadcast::channel(8);
        let (livery_updates, _) = broadcast::channel(8);
        Arc::new(ServerConfigService {
            snapshots: RwLock::new(HashMap::new()),
            owned: RwLock::new(HashMap::new()),
            updates,
            liveries: RwLock::new(HashMap::new()),
            livery_updates,
            resolver: resolver.clone(),
            permit: Permit::new(resolver),
            tickets: ticket::TicketStore::default(),
            config,
            store: None,
            fanout: Fanout::default(),
        })
    }

    /// A livery query as it arrives from a client.
    fn livery_query(have: &[&str]) -> Inbound {
        Inbound {
            gateway: "test".to_owned(),
            conn: 1,
            session: 1,
            scope: 1,
            type_id: ServiceKind::ServerConfig.outer_type(),
            payload: ServerConfigEnvelope {
                body: Some(server_config_envelope::Body::LiveryQuery(
                    starling_proto_fancy::fancy::domain::LiveryQuery {
                        have_keys: have.iter().map(|key| (*key).to_owned()).collect(),
                    },
                )),
            }
            .encode_to_vec(),
        }
    }

    fn livery_reply(actions: &Actions) -> LiveryDoc {
        let action = actions.first().expect("a reply");
        let starling_proto_fancy::control::server_action::Action::Send(send) =
            action.action.as_ref().expect("an action")
        else {
            panic!("not a send");
        };
        let envelope = ServerConfigEnvelope::decode(send.payload.as_slice()).expect("an envelope");
        match envelope.body {
            Some(server_config_envelope::Body::Livery(doc)) => doc,
            other => panic!("not a livery: {other:?}"),
        }
    }

    #[tokio::test]
    async fn a_client_asking_for_the_livery_is_sent_the_document() {
        let service = service();
        service
            .publish_livery(
                Livery {
                    instance: 1,
                    tagline: "cozy corner".to_owned(),
                    ..Default::default()
                },
                None,
            )
            .await;

        let doc = livery_reply(&service.frame(livery_query(&[])).await);
        assert_eq!(doc.tagline, "cozy corner");
        // The same digest the ping carries, so a client that never saw the ping
        // still has something to cache against.
        assert_eq!(doc.digest, service.livery(1).await.digest);
        assert!(!doc.digest.is_empty());
    }

    #[tokio::test]
    async fn an_unbranded_server_answers_rather_than_going_quiet() {
        // Silence is indistinguishable from a server that is still thinking,
        // and the client would hold its connect screen waiting for it.
        let doc = livery_reply(&service().frame(livery_query(&[])).await);
        assert_eq!(doc.version, 0);
        assert!(doc.digest.is_empty());
        assert!(doc.art.is_empty());
    }

    #[tokio::test]
    async fn art_the_client_already_holds_is_not_sent_again() {
        // The whole reason the document carries content keys and not bytes: an
        // operator editing a motto must not cost the banner a second time.
        let service = service();
        service
            .publish_livery(
                Livery {
                    instance: 1,
                    banner_key: "aa".repeat(20),
                    ..Default::default()
                },
                None,
            )
            .await;

        let held = livery_reply(
            &service
                .frame(livery_query(&["aa".repeat(20).as_str()]))
                .await,
        );
        assert!(held.art.is_empty());
        assert_eq!(held.banner_key, "aa".repeat(20));
    }

    /// A livery write as it arrives from a connected admin.
    fn livery_update(fields: &[&str], values: LiveryDoc) -> Inbound {
        Inbound {
            gateway: "test".to_owned(),
            conn: 1,
            session: 7,
            scope: 1,
            type_id: ServiceKind::ServerConfig.outer_type(),
            payload: ServerConfigEnvelope {
                body: Some(server_config_envelope::Body::LiveryUpdate(
                    starling_proto_fancy::fancy::domain::LiveryUpdate {
                        fields: fields.iter().map(|f| (*f).to_owned()).collect(),
                        values: Some(values),
                    },
                )),
            }
            .encode_to_vec(),
        }
    }

    #[tokio::test]
    async fn a_client_write_without_the_permission_is_refused_out_loud() {
        // The service under test reaches no `permissions`, so the check denies.
        // What matters is that the answer is a PermissionDenied and not silence:
        // a write accepted and dropped shows the admin their change on screen
        // and leaves nothing in any log.
        let service = service();
        let actions = service
            .frame(livery_update(
                &["tagline"],
                LiveryDoc {
                    tagline: "not allowed".to_owned(),
                    ..Default::default()
                },
            ))
            .await;

        assert_eq!(actions.len(), 1, "a refusal has to be sent");
        assert_eq!(service.livery(1).await.tagline, "", "nothing was written");
    }

    #[tokio::test]
    async fn a_settings_update_from_a_client_is_still_ignored() {
        // Livery moved to the client channel; the settings half did not, and
        // this is what keeps the two from drifting into one rule.
        let service = service();
        let inbound = Inbound {
            gateway: "test".to_owned(),
            conn: 1,
            session: 7,
            scope: 1,
            type_id: ServiceKind::ServerConfig.outer_type(),
            payload: ServerConfigEnvelope {
                body: Some(server_config_envelope::Body::Update(
                    starling_proto_fancy::fancy::domain::ConfigUpdate::default(),
                )),
            }
            .encode_to_vec(),
        };
        assert!(service.frame(inbound).await.is_empty());
    }

    #[test]
    fn a_wire_document_converts_to_the_mesh_one_field_for_field() {
        // The two planes keep separate types, so this is the seam where a
        // forgotten field would silently stop being writable from a client.
        let doc = LiveryDoc {
            display_name: "magical.rocks".to_owned(),
            tagline: "cozy".to_owned(),
            motd: "movie night".to_owned(),
            rules_url: "https://x/rules".to_owned(),
            banner_key: "aa".to_owned(),
            icon_key: "bb".to_owned(),
            banner_focus_x: 40,
            banner_focus_y: 35,
            tags: vec![livery_doc::Tag {
                label: "Rules".to_owned(),
                tone: 4,
                href: "https://x".to_owned(),
            }],
            dark: Some(livery_doc::Palette {
                accent: "#8a90ff".to_owned(),
                surface: "#151d38".to_owned(),
                aura_from: "#7d82ff".to_owned(),
                aura_to: "#41b4f9".to_owned(),
            }),
            ..Default::default()
        };
        let mesh = from_doc(&doc);
        assert_eq!(mesh.display_name, "magical.rocks");
        assert_eq!(mesh.tagline, "cozy");
        assert_eq!(mesh.motd, "movie night");
        assert_eq!(mesh.rules_url, "https://x/rules");
        assert_eq!(mesh.banner_key, "aa");
        assert_eq!(mesh.icon_key, "bb");
        assert_eq!(mesh.banner_focus_x, 40);
        assert_eq!(mesh.banner_focus_y, 35);
        assert_eq!(mesh.tags.len(), 1);
        assert_eq!(mesh.tags[0].tone, 4);
        assert_eq!(mesh.dark.as_ref().unwrap().aura_to, "#41b4f9");
        // Never carried in from the wire: they are the server's own.
        assert_eq!(mesh.version, 0);
        assert!(mesh.digest.is_empty());
    }

    #[test]
    fn art_is_typed_from_its_bytes_and_never_from_a_claim() {
        assert_eq!(
            sniff(&[0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a]),
            "image/png"
        );
        assert_eq!(sniff(&[0xff, 0xd8, 0xff, 0xe0]), "image/jpeg");
        assert_eq!(sniff(b"RIFF____WEBPVP8 "), "image/webp");
        assert_eq!(sniff(b"<html>"), "application/octet-stream");
    }

    /// A config whose `[instances.settings]` for server 1 is `settings`.
    fn config_with(settings: starling_runtime::config::ServerSettings) -> Config {
        use starling_runtime::config::Instance;

        let mut config = Config::with_defaults(std::path::Path::new("/run/starling"));
        config.instances = vec![Instance {
            settings,
            ..Instance::default()
        }];
        config
    }

    #[tokio::test]
    async fn a_reloaded_file_reaches_a_setting_nobody_has_touched() {
        use starling_runtime::config::ServerSettings;

        let service = service();
        service.publish(defaults(1), &[]).await;
        assert_ne!(service.snapshot(1).await.max_users, 20);

        service
            .adopt_file(
                &config_with(ServerSettings {
                    max_users: Some(20),
                    ..ServerSettings::default()
                }),
                &[1],
            )
            .await;

        assert_eq!(service.snapshot(1).await.max_users, 20);
    }

    #[tokio::test]
    async fn a_reloaded_file_never_reverts_what_an_operator_set() {
        // The rule the whole owned-field column exists for, now that the file
        // can move underneath a running server: an operator who set
        // `welcome_text` in the admin UI keeps it, and an unrelated edit to the
        // file still applies.
        use starling_runtime::config::ServerSettings;

        let service = service();
        let mut operator = defaults(1);
        operator.welcome_text = "set by an operator".to_owned();
        service
            .publish(operator, &["welcome_text".to_owned()])
            .await;

        service
            .adopt_file(
                &config_with(ServerSettings {
                    welcome_text: Some("set in the file".to_owned()),
                    max_users: Some(20),
                    ..ServerSettings::default()
                }),
                &[1],
            )
            .await;

        let snapshot = service.snapshot(1).await;
        assert_eq!(
            snapshot.welcome_text, "set by an operator",
            "the run-time layer outranks the file"
        );
        assert_eq!(
            snapshot.max_users, 20,
            "a setting nobody claimed still follows the file"
        );
    }

    #[tokio::test]
    async fn dropping_a_setting_from_the_file_returns_it_to_the_default() {
        // Removing a line has to mean something, and the only coherent meaning
        // is the layer below it: murmur's default. Leaving the last value in
        // place would make the file unable to express "never mind".
        use starling_runtime::config::ServerSettings;

        let service = service();
        service.publish(defaults(1), &[]).await;
        service
            .adopt_file(
                &config_with(ServerSettings {
                    max_users: Some(20),
                    ..ServerSettings::default()
                }),
                &[1],
            )
            .await;
        assert_eq!(service.snapshot(1).await.max_users, 20);

        service
            .adopt_file(&config_with(ServerSettings::default()), &[1])
            .await;
        assert_eq!(service.snapshot(1).await.max_users, defaults(1).max_users);
    }

    #[tokio::test]
    async fn adopting_the_file_does_not_claim_the_settings_it_applied() {
        // If it did, the *next* edit of the same key would be ignored: the
        // field would be recorded as an operator's decision and outrank the
        // file it came from.
        use starling_runtime::config::ServerSettings;

        let service = service();
        service.publish(defaults(1), &[]).await;
        let config = config_with(ServerSettings {
            max_users: Some(20),
            ..ServerSettings::default()
        });
        service.adopt_file(&config, &[1]).await;

        assert!(
            service
                .owned
                .read()
                .await
                .get(&1)
                .is_none_or(BTreeSet::is_empty),
            "the file must claim nothing"
        );

        service
            .adopt_file(
                &config_with(ServerSettings {
                    max_users: Some(30),
                    ..ServerSettings::default()
                }),
                &[1],
            )
            .await;
        assert_eq!(
            service.snapshot(1).await.max_users,
            30,
            "a second edit lands"
        );
    }

    #[tokio::test]
    async fn adopting_the_file_does_not_move_the_version_counter() {
        // The gateway reads `version == 0` as "no operator has ever set
        // anything here" and skips applying `message_limit` while it holds.
        // Bumping it from a file reload would make the gateway adopt a limit
        // nobody set through the admin plane.
        use starling_runtime::config::ServerSettings;

        let service = service();
        service.publish(defaults(1), &[]).await;
        let before = service.snapshot(1).await.version;

        service
            .adopt_file(
                &config_with(ServerSettings {
                    max_users: Some(20),
                    ..ServerSettings::default()
                }),
                &[1],
            )
            .await;

        assert_eq!(service.snapshot(1).await.version, before);
    }

    #[tokio::test]
    async fn a_pre_migration_row_is_left_alone_by_the_file() {
        // It owns everything by definition, so there is no field the file may
        // reach without overwriting a decision whose record was never kept.
        use starling_runtime::config::ServerSettings;

        let service = service();
        let mut stored = defaults(1);
        stored.max_users = 5;
        service.publish(stored, &[ALL_FIELDS.to_owned()]).await;

        service
            .adopt_file(
                &config_with(ServerSettings {
                    max_users: Some(20),
                    ..ServerSettings::default()
                }),
                &[1],
            )
            .await;

        assert_eq!(service.snapshot(1).await.max_users, 5);
    }

    #[tokio::test]
    async fn an_instance_the_file_no_longer_names_keeps_its_settings() {
        // Adding or removing an instance needs a restart, so acting on half of
        // that change here would leave a server whose settings moved and whose
        // actors did not.
        use starling_runtime::config::ServerSettings;

        let service = service();
        let mut stored = defaults(2);
        stored.max_users = 7;
        service.publish(stored, &[]).await;

        service
            .adopt_file(&config_with(ServerSettings::default()), &[2])
            .await;

        assert_eq!(service.snapshot(2).await.max_users, 7);
    }

    #[tokio::test]
    async fn adopting_an_unchanged_file_publishes_nothing() {
        // Every publish wakes every subscriber in the fleet; a SIGHUP that
        // changed nothing must not cost a fanout.
        use starling_runtime::config::ServerSettings;

        let service = service();
        service.publish(defaults(1), &[]).await;
        let config = config_with(ServerSettings {
            max_users: Some(20),
            ..ServerSettings::default()
        });
        service.adopt_file(&config, &[1]).await;

        let mut updates = service.updates.subscribe();
        service.adopt_file(&config, &[1]).await;
        assert!(
            updates.try_recv().is_err(),
            "an unchanged file must not republish"
        );
    }

    /// A context whose deployment file configures `settings` for server 1.
    fn ctx_with(settings: starling_runtime::config::ServerSettings) -> ServiceContext {
        use starling_runtime::config::{Config, Instance};

        let mut config = Config::with_defaults(std::path::Path::new("/run/starling"));
        config.instances = vec![Instance {
            settings,
            ..Instance::default()
        }];
        starling_runtime::serve::context(
            ServerConfigService::NAME,
            Arc::new(config),
            starling_runtime::inproc::Broker::new(),
            starling_runtime::shutdown::Shutdown::new(),
            starling_runtime::log::Logger::null(),
        )
    }

    #[tokio::test]
    async fn an_unset_server_instance_reads_the_documented_defaults() {
        // The gateway sizes its buckets from this; a zero would mean no
        // messages at all rather than murmur's 1/s.
        let snapshot = service().snapshot(1).await;
        assert_eq!(snapshot.message_limit, 1);
        assert_eq!(snapshot.message_burst, 5);
        assert!(snapshot.max_users > 0);
    }

    #[tokio::test]
    async fn setting_one_field_leaves_the_others_alone() {
        // Two operators editing different settings must not overwrite each
        // other, which a whole-snapshot write would guarantee they do.
        let service = service();
        let mut values = defaults(1);
        values.welcome_text = "hello".to_owned();
        values.max_users = 1;

        let updated = ServerConfigRpc::set(
            &ConfigRpc(Arc::clone(&service)),
            Request::new(SetRequest {
                scope: Some(Scope { instance: 1 }),
                actor: None,
                fields: vec!["welcome_text".to_owned()],
                values: Some(values),
            }),
        )
        .await
        .expect("set")
        .into_inner();

        assert_eq!(updated.welcome_text, "hello");
        assert_eq!(updated.max_users, defaults(1).max_users);
        assert_eq!(updated.version, 1);
    }

    #[tokio::test]
    async fn a_setting_written_in_the_deployment_file_is_where_a_server_starts() {
        // The gap this closes: the name of a server was configurable in a file
        // and the number of people allowed into it was not, so setting up a
        // server for twenty friends meant an admin API call.
        let settings = starling_runtime::config::ServerSettings {
            max_users: Some(20),
            welcome_text: Some("mind the frogs".to_owned()),
            ..Default::default()
        };
        let (snapshot, owned) = starting_point(&ctx_with(settings), 1, None).await;

        assert_eq!(snapshot.max_users, 20);
        assert_eq!(snapshot.welcome_text, "mind the frogs");
        assert_eq!(
            snapshot.max_bandwidth,
            defaults(1).max_bandwidth,
            "a setting the file never names keeps murmur's default"
        );
        assert!(
            owned.is_empty(),
            "the file's values are a starting point, not the operator's own"
        );
    }

    #[tokio::test]
    async fn an_operator_who_changed_nothing_follows_the_file_when_it_changes() {
        // The failure a whole-snapshot row would have caused: one `set` of
        // `welcome_text` freezes every other setting at whatever it was that
        // day, and editing the file afterwards does nothing forever.
        let service = service();
        let mut values = defaults(1);
        values.welcome_text = "set by an admin".to_owned();
        let _ = ServerConfigRpc::set(
            &ConfigRpc(Arc::clone(&service)),
            Request::new(SetRequest {
                scope: Some(Scope { instance: 1 }),
                actor: None,
                fields: vec!["welcome_text".to_owned()],
                values: Some(values),
            }),
        )
        .await
        .expect("set");

        let owned = service
            .owned
            .read()
            .await
            .get(&1)
            .cloned()
            .unwrap_or_default();
        assert_eq!(
            owned.iter().cloned().collect::<Vec<_>>(),
            vec!["welcome_text".to_owned()],
            "only the field an operator named is theirs"
        );
    }

    #[test]
    fn the_owned_field_set_survives_the_round_trip_through_the_column() {
        let owned: BTreeSet<String> = ["max_users", "welcome_text"]
            .into_iter()
            .map(ToOwned::to_owned)
            .collect();
        assert_eq!(decode_owned(&encode_owned(&owned)).len(), 2);
        // The empty case is the common one, and a naive split yields one empty
        // field name, which `apply_fields` would then warn about on every boot.
        assert!(decode_owned("").is_empty());
    }

    #[tokio::test]
    async fn the_server_password_is_never_read_back() {
        // An operator sets it; nobody reads it. Handing it to a client would
        // make a chat window a credential store.
        let mut snapshot = defaults(1);
        snapshot.password = "hunter2".to_owned();
        let settings = redact(&snapshot);
        assert!(
            !settings.iter().any(|s| s.value.contains("hunter2")),
            "no readable field may carry the password"
        );
        let password = settings
            .iter()
            .find(|s| s.key == "password")
            .expect("the password is named even though it is withheld");
        assert!(password.secret, "it must say it is withheld");
        assert!(password.value.is_empty());
    }

    fn ticket_request(scopes: &[&str]) -> Inbound {
        Inbound {
            gateway: "test".to_owned(),
            conn: 1,
            session: 1,
            scope: 1,
            type_id: ServiceKind::ServerConfig.outer_type(),
            payload: ServerConfigEnvelope {
                body: Some(server_config_envelope::Body::TicketRequest(
                    OperatorTicketRequest {
                        scopes: scopes.iter().map(|scope| (*scope).to_owned()).collect(),
                    },
                )),
            }
            .encode_to_vec(),
        }
    }

    fn ticket_reply(actions: &Actions) -> OperatorTicketReply {
        let action = actions.first().expect("a reply");
        let starling_proto_fancy::control::server_action::Action::Send(send) =
            action.action.as_ref().expect("an action")
        else {
            panic!("not a send");
        };
        let envelope = ServerConfigEnvelope::decode(send.payload.as_slice()).expect("an envelope");
        match envelope.body {
            Some(server_config_envelope::Body::TicketReply(reply)) => reply,
            other => panic!("not a ticket reply: {other:?}"),
        }
    }

    #[tokio::test]
    async fn a_ticket_request_with_no_permissions_service_behind_it_is_denied() {
        // These tests' resolver reaches nothing, so every permission check
        // fails closed -- the same property `Permit`'s own tests assert. A
        // ticket request must fail exactly the same way a livery write does.
        let reply = ticket_reply(
            &service()
                .frame(ticket_request(&["server-config:write"]))
                .await,
        );
        assert!(reply.token.is_empty());
        assert!(reply.granted_scopes.is_empty());
        assert!(!reply.denied_reason.is_empty());
    }

    #[tokio::test]
    async fn a_ticket_request_naming_no_scope_this_table_knows_is_denied() {
        let reply = ticket_reply(&service().frame(ticket_request(&["not-a-real-scope"])).await);
        assert!(reply.token.is_empty());
        assert!(reply.granted_scopes.is_empty());
    }
}
