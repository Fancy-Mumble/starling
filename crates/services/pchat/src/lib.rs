//! `pchat`: persistent chat: a relay and a store, never a decryptor.
//!
//! The end-to-end crypto lives in the client
//! (`vendor/client/crates/mumble-protocol/src/persistent/`), so this service
//! never sees plaintext. What it owns is storage, fan-out, offline queues,
//! key-holder bookkeeping and rate limiting (`docs/PORTING-PLAN.md`, persistent
//! chat).
//!
//! The key is `channel_id ‖ uuidv7`, so the table is physically ordered
//! tenant → channel → time. Both fetch shapes (newest page and scroll-back)
//! are then one backwards range scan, which is what turns murmur's full scan of
//! an unindexed `TEXT` UUID into an index seek (`docs/STORAGE.md` L3).

mod limits;

use std::sync::Arc;

use prost::Message as _;
use starling_proto_fancy::control::ServerAction;
use starling_proto_fancy::fancy::pchat::{
    Ack, Fetch, FetchResponse, Message, PchatEnvelope, Protocol, ack, pchat_envelope,
};
use starling_proto_fancy::fancy::wire::PageInfo;
use starling_proto_fancy::perm::Perm;
use starling_proto_fancy::types::ServiceKind;
use starling_runtime::ids::{Uuid7, now_ms};
use starling_runtime::permit::{Permit, permission_denied};
use starling_runtime::plane::{
    Actions, ClientService, Fanout, Inbound, Plane, to_conn, to_sessions,
};
use starling_runtime::roster::Roster;
use starling_runtime::serve::{Serve, ServiceContext, ServiceError};
use starling_runtime::storage::{Migration, Store};

use crate::limits::{Limits, Op};

/// The readiness gate that stays closed until the roster has a snapshot.
///
/// A pchat service that is up with a cold roster relays nothing, which looks
/// exactly like a chat that has gone quiet. Gating readiness keeps traffic away
/// until it can actually address a channel.
const VIEW_GATE: &str = "session-view";

/// The schema. `expires_at_ms` and its index are here from day one, because
/// retention on a table that grows without bound is a schema property rather
/// than an afterthought (`docs/STORAGE.md` D4).
const SCHEMA: &[Migration<'static>] = &[
    Migration::new(
        "0001_pchat_message",
        &[
            "CREATE TABLE IF NOT EXISTS pchat_message (\
             server_id BIGINT NOT NULL, channel_id BIGINT NOT NULL, id BLOB NOT NULL, \
             sent_at_ms BIGINT NOT NULL, sender BIGINT NOT NULL, epoch INTEGER NOT NULL, \
             ciphertext BLOB NOT NULL, supersedes BLOB NULL, expires_at_ms BIGINT NULL, \
             PRIMARY KEY (server_id, channel_id, id))",
            "CREATE INDEX IF NOT EXISTS ix_pchat_expiry ON pchat_message(server_id, expires_at_ms)",
            // `holder` is the certificate hash, not a session: holding a key is
            // what lets someone read the archive after reconnecting, so the one
            // thing it cannot be keyed on is the connection. Nothing writes this
            // table yet, which is why it is defined right rather than migrated.
            "CREATE TABLE IF NOT EXISTS pchat_holder (\
             server_id BIGINT NOT NULL, channel_id BIGINT NOT NULL, epoch INTEGER NOT NULL, \
             holder BLOB NOT NULL, \
             PRIMARY KEY (server_id, channel_id, epoch, holder))",
        ],
    ),
    // The archive recorded its author as a session id, which is handed out per
    // connection and reused, so a message written last week is attributed to
    // whoever holds that number now. Sessions are the wrong key for anything
    // that outlives a connection (`Roster::accounts` says so in as many words);
    // an archive is the longest-lived thing this server keeps.
    //
    // Nullable and not backfilled: rows written before this column existed have
    // no recoverable author. Left NULL and honestly empty on the wire rather
    // than guessed at, because a wrong attribution in an audit-relevant archive
    // is worse than an absent one.
    Migration::new(
        "0002_pchat_sender_cert",
        &["ALTER TABLE pchat_message ADD COLUMN sender_cert BLOB NULL"],
    ),
    // What a reader needs to decrypt what it fetches back. The archive stored
    // the ciphertext and the epoch *number* but not which key that was, so a
    // channel that forked during a membership change had two epoch 4s and the
    // page came back undecryptable, with nothing to distinguish "wrong key"
    // from "corrupt". Opaque to this service, like the ciphertext beside them.
    Migration::new(
        "0003_pchat_decryption_context",
        &[
            "ALTER TABLE pchat_message ADD COLUMN epoch_fingerprint BLOB NULL",
            "ALTER TABLE pchat_message ADD COLUMN chain_index INTEGER NULL",
            "ALTER TABLE pchat_message ADD COLUMN protocol INTEGER NULL",
        ],
    ),
    // The id the *sender* minted, which is not the same thing as where this
    // server files the row - and the archive used to keep only the latter.
    //
    // A sender seals a message under `AAD = channel ‖ message_id ‖ sent_at_ms`
    // (client `persistent/protocol/fancy_v1/aad.rs`), so an archive that hands
    // back its own id, or its own clock, hands back a ciphertext that nobody -
    // not even the author - can open. murmur never had the problem because it
    // stores what the sender sent (`PchatProtocolHandlers.cpp:58`).
    //
    // The uuid7 `id` stays the primary key and the cursor, because it is what
    // makes a page a backwards range scan (`docs/STORAGE.md` L3); this column
    // is the identity on the wire, and the two are now allowed to differ.
    Migration::new(
        "0004_pchat_client_id",
        &[
            "ALTER TABLE pchat_message ADD COLUMN client_id TEXT NULL",
            "CREATE INDEX IF NOT EXISTS ix_pchat_client_id \
             ON pchat_message(server_id, channel_id, client_id)",
        ],
    ),
];

/// Whether a message of this protocol belongs in the archive at all.
///
/// `signal_v1` keeps **no server-side history**, which is a property of the
/// mode rather than a client's preference: a late joiner must never read what
/// was said before it arrived, and it is inside the channel ACL, so "who may
/// fetch" cannot express the rule. Storing it bought nothing - nothing here
/// redelivers an offline queue, and the only reader of a stored row is
/// `on_fetch` - and cost the one guarantee the mode exists for.
///
/// This reads the protocol the frame declared, so a client that mislabels its
/// own message still gets it archived. That is a client lying about its own
/// history rather than reading somebody else's, and the airtight form - asking
/// `metadata` for the channel's `pchat_protocol` - is a cross-service call this
/// path does not otherwise need.
const fn archivable(protocol: i32) -> bool {
    protocol != Protocol::SignalV1 as i32
}

/// The service.
#[derive(Debug)]
pub struct PchatService {
    store: Store,
    fanout: Fanout,
    /// Asks `permissions` before a channel's archive is written or read.
    ///
    /// The ciphertext is opaque to this service, which is not the same as it
    /// being safe to hand to anyone who asks: the archive still discloses who
    /// spoke in a channel and when, and the ciphertext itself is exactly what
    /// an offline attack needs. `Permit` denies when `permissions` is
    /// unreachable, so a broken dependency closes the archive rather than
    /// opening it.
    permit: Permit,
    /// Who is in which channel, so a relay can be addressed at one.
    roster: Arc<Roster>,
    /// Per-connection budgets.
    limits: Limits,
}

impl PchatService {
    /// Store one ciphertext, returning the id it was filed under.
    async fn store_message(&self, scope: u32, message: &Message) -> Option<Uuid7> {
        let id = Uuid7::now();
        let result = sqlx::query(
            "INSERT INTO pchat_message \
                 (server_id, channel_id, id, sent_at_ms, sender, epoch, ciphertext, \
                  supersedes, sender_cert, epoch_fingerprint, chain_index, protocol, \
                  client_id) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(i64::from(scope))
        .bind(i64::from(message.channel))
        .bind(id.to_vec())
        // The sender's clock, not this server's. It is half of the AAD the
        // message was sealed under, so overwriting it makes the row
        // undecryptable exactly as overwriting the id does. A message that
        // names no time at all still gets one, because a page has to be
        // orderable for a reader.
        .bind(if message.sent_at_ms == 0 {
            now_ms() as i64
        } else {
            message.sent_at_ms as i64
        })
        .bind(i64::from(message.sender))
        .bind(i64::from(message.epoch))
        .bind(message.ciphertext.as_slice())
        .bind(Uuid7::parse(&message.supersedes).map(Uuid7::to_vec))
        .bind((!message.sender_cert.is_empty()).then(|| message.sender_cert.clone()))
        .bind((!message.epoch_fingerprint.is_empty()).then(|| message.epoch_fingerprint.clone()))
        .bind(i64::from(message.chain_index))
        .bind(i64::from(message.protocol))
        .bind((!message.message_id.is_empty()).then(|| message.message_id.clone()))
        .execute(self.store.pool())
        .await;
        match result {
            Ok(_) => Some(id),
            Err(error) => {
                tracing::error!(%error, "could not store a persistent-chat message");
                None
            }
        }
    }

    /// Where a wire id sits in this channel's storage order.
    ///
    /// A cursor arrives as an id a client holds, and what a client holds is the
    /// *sender's* id - so it is looked up rather than parsed. Falling back to
    /// parsing covers rows written before `client_id` existed, whose only
    /// identity is this server's own uuid7.
    async fn cursor_of(&self, scope: u32, channel: u32, wire_id: &str) -> Option<Vec<u8>> {
        use sqlx::Row as _;
        if wire_id.is_empty() {
            return None;
        }
        let found = sqlx::query(
            "SELECT id FROM pchat_message \
             WHERE server_id = ? AND channel_id = ? AND client_id = ?",
        )
        .bind(i64::from(scope))
        .bind(i64::from(channel))
        .bind(wire_id)
        .fetch_optional(self.store.pool())
        .await
        .ok()
        .flatten()
        .and_then(|row| row.try_get::<Vec<u8>, _>("id").ok());

        found.or_else(|| Uuid7::parse(wire_id).map(Uuid7::to_vec))
    }

    /// A page of ciphertexts, newest first.
    async fn fetch(&self, scope: u32, request: &Fetch) -> FetchResponse {
        use sqlx::Row as _;
        let page = request.page.clone().unwrap_or_default();
        let limit = page.page_size(50, 200);
        let before = self
            .cursor_of(scope, request.channel, &page.before_id)
            .await;
        // The protocol predicate is here as well as in `on_message` on purpose:
        // refusing to write only protects a database that has always run this
        // build, and a deployment that upgraded into it still has yesterday's
        // signal_v1 rows on disk. This is what keeps them unreadable without a
        // data migration.
        let sql = if before.is_some() {
            "SELECT id, client_id, sent_at_ms, sender, epoch, ciphertext, sender_cert, epoch_fingerprint, chain_index, protocol FROM pchat_message \
             WHERE server_id = ? AND channel_id = ? AND (protocol IS NULL OR protocol != ?) \
             AND id < ? ORDER BY id DESC LIMIT ?"
        } else {
            "SELECT id, client_id, sent_at_ms, sender, epoch, ciphertext, sender_cert, epoch_fingerprint, chain_index, protocol FROM pchat_message \
             WHERE server_id = ? AND channel_id = ? AND (protocol IS NULL OR protocol != ?) \
             ORDER BY id DESC LIMIT ?"
        };
        let mut query = sqlx::query(sql)
            .bind(i64::from(scope))
            .bind(i64::from(request.channel))
            .bind(i64::from(Protocol::SignalV1 as i32));
        if let Some(cursor) = &before {
            query = query.bind(cursor.as_slice());
        }
        let rows = query
            .bind(i64::from(limit + 1))
            .fetch_all(self.store.pool())
            .await
            .unwrap_or_default();

        // The id a page is addressed by is the one the client will send back as
        // the next cursor, so it has to be the same identity the messages
        // themselves carry.
        let page_info = PageInfo::after(rows.len(), limit, || {
            rows.get(limit as usize - 1)
                .map(wire_id)
                .unwrap_or_default()
        });
        let messages = rows
            .into_iter()
            .take(limit as usize)
            .map(|row| Message {
                message_id: wire_id(&row),
                channel: request.channel,
                sender: row.try_get::<i64, _>("sender").unwrap_or_default() as u32,
                ciphertext: row.try_get("ciphertext").unwrap_or_default(),
                sent_at_ms: row.try_get::<i64, _>("sent_at_ms").unwrap_or_default() as u64,
                supersedes: String::new(),
                epoch: row.try_get::<i64, _>("epoch").unwrap_or_default() as u32,
                // NULL for a row written before the column existed, which is
                // read back as "unattributable" rather than guessed at.
                sender_cert: row.try_get("sender_cert").unwrap_or_default(),
                epoch_fingerprint: row.try_get("epoch_fingerprint").unwrap_or_default(),
                chain_index: row.try_get::<i64, _>("chain_index").unwrap_or_default() as u32,
                protocol: row.try_get::<i64, _>("protocol").unwrap_or_default() as i32,
            })
            .collect();

        FetchResponse {
            channel: request.channel,
            messages,
            page: Some(page_info),
            total_stored: self.count(scope, request.channel).await,
        }
    }

    /// How many messages a channel holds.
    ///
    /// A real `COUNT`, because this table has the index to serve it; on the KV
    /// alternative it would be a maintained counter key
    /// (`docs/STORAGE.md` §5.6).
    async fn count(&self, scope: u32, channel: u32) -> u64 {
        use sqlx::Row as _;
        sqlx::query(
            "SELECT COUNT(*) AS n FROM pchat_message \
             WHERE server_id = ? AND channel_id = ? AND (protocol IS NULL OR protocol != ?)",
        )
        .bind(i64::from(scope))
        .bind(i64::from(channel))
        .bind(i64::from(Protocol::SignalV1 as i32))
        .fetch_optional(self.store.pool())
        .await
        .ok()
        .flatten()
        .and_then(|row| row.try_get::<i64, _>("n").ok())
        .unwrap_or_default() as u64
    }

    /// Drop everything past its retention.
    async fn sweep(&self) {
        let _ = sqlx::query(
            "DELETE FROM pchat_message WHERE expires_at_ms IS NOT NULL AND expires_at_ms < ?",
        )
        .bind(now_ms() as i64)
        .execute(self.store.pool())
        .await;
    }
}

/// The identity a stored row carries on the wire.
///
/// The sender's own id, because that is what its AEAD is sealed against and
/// what every other client files it under - pins, reactions and deletes all
/// name it. Rows written before `client_id` existed, and senders that mint no
/// id at all, fall back to this server's uuid7, which is the only identity
/// those rows have.
fn wire_id(row: &sqlx::any::AnyRow) -> String {
    use sqlx::Row as _;
    row.try_get::<Option<String>, _>("client_id")
        .ok()
        .flatten()
        .filter(|id| !id.is_empty())
        .unwrap_or_else(|| {
            Uuid7::from_slice(&row.try_get::<Vec<u8>, _>("id").unwrap_or_default())
                .map(|id| id.to_string())
                .unwrap_or_default()
        })
}

/// What a relayed body is, for routing and authorisation.
///
/// Every body except `Ack` carries a channel. Reading that field is not
/// "understanding the payload" -- it is the routing address, sitting beside the
/// ciphertext rather than inside it -- so the verbatim relay can be both scoped
/// and authorised without this service learning any crypto.
struct Relay {
    channel: u32,
    /// What the sender must hold in that channel.
    needs: Perm,
    /// Deliver to this one session instead of the channel, when the body names
    /// its recipient.
    unicast: Option<u32>,
    /// The certificate this body claims for its own sender, when it names one.
    ///
    /// Read so the relay can refuse a body claiming somebody else's identity.
    /// The bodies are re-sent verbatim, they carry signatures over their own
    /// encoding, so this cannot be stamped the way `Message.sender_cert` is;
    /// it is checked instead. Absent for bodies that claim no identity.
    claims: Option<Vec<u8>>,
}

impl Relay {
    /// How a client-originated body is routed, or `None` if a client has no
    /// business sending it.
    fn of(body: &pchat_envelope::Body) -> Option<Self> {
        use pchat_envelope::Body;
        let in_channel = |channel, needs| {
            Some(Self {
                channel,
                needs,
                unicast: None,
                claims: None,
            })
        };
        let claiming = |channel, needs, cert: &[u8]| {
            Some(Self {
                channel,
                needs,
                unicast: None,
                claims: Some(cert.to_vec()),
            })
        };
        match body {
            // Sealed key material naming exactly one recipient. Relaying it to
            // the channel handed every member a copy of a message addressed to
            // one of them.
            //
            // No `claims`: this body names its *recipient*, not its sender, and
            // checking a recipient against the sender's certificate would
            // refuse every delivery there is.
            Body::KeyDeliver(deliver) => Some(Self {
                channel: deliver.channel,
                needs: Perm::ENTER,
                unicast: Some(deliver.recipient),
                claims: None,
            }),
            Body::KeyAnnounce(announce) => {
                claiming(announce.channel, Perm::ENTER, &announce.holder_cert)
            }
            Body::KeyRequest(request) => {
                claiming(request.channel, Perm::ENTER, &request.requester_cert)
            }
            Body::HolderReport(report) => in_channel(report.channel, Perm::ENTER),
            Body::HolderQuery(query) => in_channel(query.channel, Perm::ENTER),
            Body::Pin(pin) => in_channel(pin.channel, Perm::TEXT_MESSAGE),
            Body::Delete(delete) => in_channel(delete.channel, Perm::DELETE_MESSAGE),
            // Server-to-client answers. A client that sends one is trying to
            // forge somebody else's history or pin list, and the verbatim relay
            // would have passed it on unaltered.
            Body::FetchResponse(_) | Body::PinList(_) => None,
            // Handled before this point.
            Body::Message(_) | Body::Fetch(_) | Body::Ack(_) => None,
        }
    }
}

impl ClientService for PchatService {
    async fn frame(&self, inbound: Inbound) -> Actions {
        if inbound.type_id != ServiceKind::Pchat.outer_type() {
            return Actions::new();
        }
        let Ok(envelope) = PchatEnvelope::decode(inbound.payload.as_slice()) else {
            // Dropped silently before: an envelope this service cannot read
            // means a client newer than the server, and the symptom is a
            // feature that does nothing at all.
            tracing::debug!(
                conn = inbound.conn,
                session = inbound.session,
                len = inbound.payload.len(),
                "undecodable PchatEnvelope"
            );
            return Actions::new();
        };

        match envelope.body {
            Some(pchat_envelope::Body::Message(message)) => {
                self.on_message(&inbound, message).await
            }
            Some(pchat_envelope::Body::Fetch(request)) => self.on_fetch(&inbound, request).await,
            // A client acknowledging its offline queue. Nothing to relay, and
            // the old catch-all broadcast every one of these to the whole
            // server.
            Some(pchat_envelope::Body::Ack(_)) => Actions::new(),
            Some(body) => self.on_relay(&inbound, &body).await,
            None => Actions::new(),
        }
    }

    async fn closed(&self, conn: u64, _reason: &str) -> Actions {
        // Otherwise the map grows one entry per (connection, operation) for the
        // life of the process.
        self.limits.forget(conn);
        Actions::new()
    }
}

impl PchatService {
    /// Address `payload` at everyone in `channel` except the sender.
    ///
    /// An empty roster produces no action at all rather than a broadcast. That
    /// is the difference between "membership is unknown" and "everyone", and
    /// conflating them is the leak this replaced.
    fn to_channel(&self, inbound: &Inbound, channel: u32, payload: Vec<u8>) -> Actions {
        let members = self.roster.in_channel(channel, inbound.session);
        if members.is_empty() {
            if !self.roster.is_warm() {
                tracing::warn!(
                    channel,
                    "the session-view roster is cold; a pchat relay reached nobody"
                );
            }
            return Actions::new();
        }
        vec![to_sessions(
            members,
            ServiceKind::Pchat.outer_type(),
            payload,
        )]
    }

    /// One acknowledgement, addressed at the connection that asked.
    fn ack(
        &self,
        inbound: &Inbound,
        message_id: &str,
        status: ack::Status,
        detail: &str,
    ) -> ServerAction {
        let envelope = PchatEnvelope {
            body: Some(pchat_envelope::Body::Ack(Ack {
                message_id: message_id.to_owned(),
                status: status as i32,
                detail: detail.to_owned(),
            })),
        };
        to_conn(
            inbound.conn,
            ServiceKind::Pchat.outer_type(),
            envelope.encode_to_vec(),
        )
    }

    /// Store a message and relay it to its channel.
    async fn on_message(&self, inbound: &Inbound, mut message: Message) -> Actions {
        if !self.limits.allow(inbound.conn, Op::Message) {
            return vec![self.ack(
                inbound,
                &message.message_id,
                ack::Status::RateLimited,
                "too many messages",
            )];
        }

        // Checked before the message is stored, not just before it is relayed:
        // an unauthorised write that is refused delivery still leaves a row in
        // somebody else's channel archive, and the sender is the one who chose
        // the channel id.
        if !self
            .permit
            .allows(inbound, message.channel, Perm::TEXT_MESSAGE.bits())
            .await
        {
            return vec![permission_denied(
                inbound,
                Perm::TEXT_MESSAGE,
                message.channel,
            )];
        }

        // Both stamped, and both server-side: whatever the client claimed about
        // its own identity is discarded here, so a message cannot be attributed
        // to somebody else. `sender` addresses the live connection; the
        // certificate is what survives it and what the recipients' key ladder
        // is keyed on.
        message.sender = inbound.session;
        message.sender_cert = self.roster.cert_of(inbound.session).unwrap_or_default();
        // Relayed either way; this decides whether a row outlives the relay.
        let archived = if archivable(message.protocol) {
            let Some(id) = self.store_message(inbound.scope, &message).await else {
                return vec![self.ack(
                    inbound,
                    &message.message_id,
                    ack::Status::Refused,
                    "the message could not be stored",
                )];
            };
            Some(id)
        } else {
            None
        };
        let id = archived.unwrap_or_else(Uuid7::now);

        // The sender's id is left alone. It used to be replaced with `id`, the
        // key this server files the row under, and that made every archive
        // message undecryptable: a sender seals under
        // `AAD = channel ‖ message_id ‖ sent_at_ms`, so a recipient - including
        // the author after a reconnect - authenticated a different id than was
        // sealed and the AEAD refused it. It also split the identity of a
        // message in two, since the author's own copy kept the id it minted
        // while everyone else got this one, so a pin or a reaction named a
        // message the other end did not have. murmur stores what the sender
        // sent for the same reason (`PchatProtocolHandlers.cpp:58`).
        //
        // A sender that minted no id gets this server's, which is the only
        // identity such a message has.
        if message.message_id.is_empty() {
            message.message_id = id.to_string();
        }
        let channel = message.channel;
        // The one line that answers "did the ciphertext ever leave the client",
        // which is the question every silent-encrypted-channel report turns out
        // to be. A client that thinks a channel is unencrypted, or that cannot
        // seal a message, sends nothing at all -- and that is indistinguishable
        // from a broken relay unless the arrival itself is on record. The body
        // stays out of it; a length and a destination are enough.
        tracing::debug!(
            session = inbound.session,
            channel,
            bytes = message.ciphertext.len(),
            protocol = message.protocol,
            archived = archived.is_some(),
            "stored an encrypted message"
        );
        let acknowledgement = self.ack(inbound, &message.message_id, ack::Status::Stored, "");
        let relay = PchatEnvelope {
            body: Some(pchat_envelope::Body::Message(message)),
        };

        let mut actions = vec![acknowledgement];
        actions.extend(self.to_channel(inbound, channel, relay.encode_to_vec()));
        actions
    }

    /// Serve a page of the archive to the asker alone.
    async fn on_fetch(&self, inbound: &Inbound, request: Fetch) -> Actions {
        if !self.limits.allow(inbound.conn, Op::Fetch) {
            return Actions::new();
        }

        // The channel id comes off the wire, so without this a client could
        // page through the stored archive of any channel on the server --
        // including ones it cannot see. murmur gates the same read on Enter
        // (`handlePchatFetch`).
        if !self
            .permit
            .allows(inbound, request.channel, Perm::ENTER.bits())
            .await
        {
            return vec![permission_denied(inbound, Perm::ENTER, request.channel)];
        }

        let page = self.fetch(inbound.scope, &request).await;
        let reply = PchatEnvelope {
            body: Some(pchat_envelope::Body::FetchResponse(page)),
        };
        vec![to_conn(
            inbound.conn,
            ServiceKind::Pchat.outer_type(),
            reply.encode_to_vec(),
        )]
    }

    /// Pass a body this service does not read on to whoever it is addressed to.
    ///
    /// Still verbatim: the bytes are re-sent unaltered, because re-encoding a
    /// body whose meaning this service does not know is how a relay corrupts
    /// things. What changed is that it is now addressed and authorised, both
    /// decided from the channel field beside the payload.
    async fn on_relay(&self, inbound: &Inbound, body: &pchat_envelope::Body) -> Actions {
        let Some(relay) = Relay::of(body) else {
            tracing::debug!(
                session = inbound.session,
                "refused a pchat body a client may not originate"
            );
            return Actions::new();
        };

        if !self.limits.allow(inbound.conn, Op::Manage) {
            return Actions::new();
        }

        // A body that names its own sender must name the connection's own
        // certificate. Without this, anyone in the channel could announce a
        // public key under somebody else's identity and be relayed as them,
        // and key distribution is exactly the place where being believed about
        // who you are is the whole game.
        //
        // Refused rather than corrected: the body is re-sent verbatim because
        // it is signed over its own bytes, so there is nothing to correct
        // without invalidating the signature.
        if let Some(claimed) = &relay.claims {
            let actual = self.roster.cert_of(inbound.session);
            if actual.as_deref() != Some(claimed.as_slice()) {
                tracing::warn!(
                    session = inbound.session,
                    "refused a pchat body claiming an identity that is not the \
                     connection's own"
                );
                return Actions::new();
            }
        }

        if !self
            .permit
            .allows(inbound, relay.channel, relay.needs.bits())
            .await
        {
            return vec![permission_denied(inbound, relay.needs, relay.channel)];
        }

        match relay.unicast {
            Some(recipient) => vec![to_sessions(
                vec![recipient],
                ServiceKind::Pchat.outer_type(),
                inbound.payload.clone(),
            )],
            None => self.to_channel(inbound, relay.channel, inbound.payload.clone()),
        }
    }
}

impl Serve for PchatService {
    const NAME: &'static str = "pchat";

    async fn build(ctx: ServiceContext) -> Result<Arc<Self>, ServiceError> {
        let store = ctx.storage().await?;
        store.migrate(SCHEMA).await?;
        ctx.health.gate(VIEW_GATE);
        Ok(Arc::new(Self {
            store,
            fanout: Fanout::default(),
            permit: Permit::new(ctx.resolver.clone()),
            roster: Arc::new(Roster::new()),
            limits: Limits::new(),
        }))
    }

    fn routes(self: Arc<Self>) -> tonic::service::Routes {
        let plane = Plane::new(Arc::clone(&self), self.fanout.clone(), Self::NAME).into_server();
        tonic::service::Routes::default().add_service(plane)
    }

    async fn run(self: Arc<Self>, ctx: ServiceContext) -> Result<(), ServiceError> {
        let follower = Arc::clone(&self.roster).follow(ctx.clone(), Self::NAME, VIEW_GATE);
        let mut ticker = tokio::time::interval(std::time::Duration::from_secs(300));
        loop {
            tokio::select! {
                _ = ctx.shutdown.wait() => {
                    follower.abort();
                    return Ok(());
                }
                _ = ticker.tick() => self.sweep().await,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use starling_proto_fancy::fancy::pchat::{Delete, KeyAnnounce, KeyDeliver, Pin, PinList};
    use starling_proto_fancy::fancy::wire::Cursor;

    async fn service() -> Arc<PchatService> {
        // A name unique per call: `cache=shared` makes same-named in-memory
        // databases visible to every connection that names them, so two tests
        // sharing one name would race on the same `starling_migration` row.
        use std::sync::atomic::{AtomicU64, Ordering};
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let id = NEXT.fetch_add(1, Ordering::Relaxed);
        let store = Store::open(
            &format!("sqlite:file:pchat-test-{id}?mode=memory&cache=shared"),
            1,
        )
        .await
        .expect("in-memory database");
        store.migrate(SCHEMA).await.expect("schema");
        // Points at a `permissions` nothing is serving, so every check denies.
        // The storage tests below call `store_message`/`fetch` directly and are
        // unaffected; the two that go through `frame` rely on this to assert
        // that an unauthorised client is refused.
        let resolver = starling_runtime::channel::Resolver::new(
            Arc::new(starling_runtime::config::Config::with_defaults(
                std::path::Path::new("/run/starling"),
            )),
            starling_runtime::inproc::Broker::new(),
        );
        Arc::new(PchatService {
            store,
            fanout: Fanout::default(),
            permit: Permit::new(resolver),
            roster: Arc::new(Roster::new()),
            limits: Limits::new(),
        })
    }

    /// The same service with a warm roster, so a relay has somewhere to go.
    ///
    /// Sessions 7, 8 are in channel 4 and session 9 is in channel 9, enough to
    /// tell "the channel" from "everyone".
    /// The certificate behind session 7, as the TLS connection presented it.
    const SPEAKER_CERT: &[u8] = b"\x01\x02speaker-cert";

    async fn service_with_members() -> Arc<PchatService> {
        use starling_proto_fancy::sessionview::{Session, Sessions, ViewEvent, view_event};
        let service = service().await;
        let _ = service.roster.apply(ViewEvent {
            event: Some(view_event::Event::Snapshot(Sessions {
                sessions: vec![
                    Session {
                        session: 7,
                        channel: 4,
                        cert_hash: SPEAKER_CERT.to_vec(),
                        ..Session::default()
                    },
                    Session {
                        session: 8,
                        channel: 4,
                        ..Session::default()
                    },
                    Session {
                        session: 9,
                        channel: 9,
                        ..Session::default()
                    },
                ],
                ..Sessions::default()
            })),
        });
        service
    }

    /// One decoded frame carrying `body`, from session 7 in channel 4.
    fn frame(body: pchat_envelope::Body) -> Inbound {
        Inbound {
            conn: 1,
            session: 7,
            scope: 1,
            type_id: ServiceKind::Pchat.outer_type(),
            gateway: String::new(),
            payload: PchatEnvelope { body: Some(body) }.encode_to_vec(),
        }
    }

    fn message(channel: u32, ciphertext: &[u8]) -> Message {
        Message {
            message_id: String::new(),
            channel,
            sender: 1,
            ciphertext: ciphertext.to_vec(),
            sent_at_ms: 0,
            supersedes: String::new(),
            epoch: 1,
            sender_cert: Vec::new(),
            epoch_fingerprint: Vec::new(),
            chain_index: 0,
            protocol: 0,
        }
    }

    fn fetch(channel: u32, limit: u32) -> Fetch {
        Fetch {
            channel,
            page: Some(Cursor {
                limit,
                ..Cursor::default()
            }),
        }
    }

    #[tokio::test]
    async fn the_archive_keeps_an_identity_that_outlives_the_session() {
        // The archive recorded its author as a session id, which is handed out
        // per connection and reused, so a message written last week is
        // attributed to whoever holds that number today. An archive is the
        // longest-lived thing this server keeps, and a session is the shortest
        // lived name in it.
        //
        // Asserted through storage rather than through `frame`, for the reason
        // `sealed_key_material_is_addressed_to_its_recipient_alone` gives: the
        // test resolver denies every permission, so a frame test would pass on
        // the refusal and prove nothing about what was written.
        let service = service().await;
        let _ = service
            .store_message(
                1,
                &Message {
                    sender_cert: SPEAKER_CERT.to_vec(),
                    ..message(4, b"x")
                },
            )
            .await;

        let page = service.fetch(1, &fetch(4, 10)).await;
        let stored = page.messages.first().expect("the message is on record");
        assert_eq!(
            stored.sender_cert,
            SPEAKER_CERT.to_vec(),
            "the certificate must survive the round trip through the archive"
        );
    }

    #[tokio::test]
    async fn the_archive_gives_back_the_id_and_the_time_the_sender_sealed_under() {
        // The bug this replaced made every archive message undecryptable, and
        // it looked like a delivery failure: the store minted its own uuid7
        // over the sender's id and stamped its own clock over `sent_at_ms`,
        // and both are inside the AAD the message was sealed with
        // (`AAD = channel ‖ message_id ‖ sent_at_ms`). The ciphertext came
        // back intact and the AEAD refused it, for the author as much as for
        // anyone else - which is why "history replay" and "decrypt on the
        // other member" failed together.
        let service = service().await;
        let sealed = Message {
            message_id: "8f14e45f-ea8f-4f2b-b1a4-2f0e1d3c4b5a".to_owned(),
            sent_at_ms: 1_700_000_000_000,
            ..message(4, b"x")
        };
        let _ = service.store_message(1, &sealed).await;

        let page = service.fetch(1, &fetch(4, 10)).await;
        let stored = page.messages.first().expect("the message is on record");
        assert_eq!(
            stored.message_id, sealed.message_id,
            "the archive must hand back the id the sender sealed under"
        );
        assert_eq!(
            stored.sent_at_ms, sealed.sent_at_ms,
            "and the time it sealed under, not this server's clock"
        );
    }

    #[tokio::test]
    async fn a_signal_message_is_never_archived_and_never_served() {
        // signal_v1's whole point is that a late joiner cannot read what was
        // said before it arrived. The joiner is inside the channel ACL by
        // then, so `on_fetch`'s Enter check cannot express the rule - the
        // archive simply must not hold the message.
        //
        // The client also declines to ask, but a client-side skip is an
        // agreement rather than a guarantee: the frame is one a modified peer
        // can still send, and forward secrecy is exactly the property that
        // must not depend on the reader's good manners.
        let service = service().await;
        let _ = service
            .store_message(
                1,
                &Message {
                    protocol: Protocol::SignalV1 as i32,
                    ..message(4, b"said before carol arrived")
                },
            )
            .await;
        assert_eq!(
            service.fetch(1, &fetch(4, 10)).await.messages.len(),
            0,
            "a signal_v1 message must not come back out of the archive"
        );

        // And the same row written by yesterday's build, which stored it
        // before this rule existed. Refusing to write is not enough on a
        // database that upgraded into this version.
        let _ = sqlx::query(
            "INSERT INTO pchat_message \
                 (server_id, channel_id, id, sent_at_ms, sender, epoch, ciphertext, protocol) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(1_i64)
        .bind(4_i64)
        .bind(Uuid7::now().to_vec())
        .bind(1_i64)
        .bind(1_i64)
        .bind(1_i64)
        .bind(b"legacy row".as_slice())
        .bind(i64::from(Protocol::SignalV1 as i32))
        .execute(service.store.pool())
        .await;

        let page = service.fetch(1, &fetch(4, 10)).await;
        assert_eq!(page.messages.len(), 0, "nor one an older build stored");
        assert_eq!(page.total_stored, 0, "and it is not counted either");

        // The mode that *does* keep history still does.
        let _ = service
            .store_message(
                1,
                &Message {
                    protocol: Protocol::FancyV1FullArchive as i32,
                    ..message(4, b"archived on purpose")
                },
            )
            .await;
        assert_eq!(
            service.fetch(1, &fetch(4, 10)).await.messages.len(),
            1,
            "fancy_v1_full_archive is an archive and must still be one"
        );
    }

    #[tokio::test]
    async fn a_page_is_addressed_by_the_same_id_its_messages_carry() {
        // A cursor is an id the client read off a previous page, so it is the
        // sender's - `WHERE id < ?` against the storage key could never match
        // one, and scroll-back silently returned the newest page forever.
        let service = service().await;
        for n in 0..3u8 {
            let _ = service
                .store_message(
                    1,
                    &Message {
                        message_id: format!("0000000{n}-0000-4000-8000-000000000000"),
                        ..message(5, b"x")
                    },
                )
                .await;
        }

        let first = service.fetch(1, &fetch(5, 2)).await;
        let cursor = first.page.expect("a page reports its tail").next_before_id;
        assert_eq!(
            cursor,
            first.messages.last().expect("two messages").message_id,
            "the cursor names the oldest message on the page"
        );

        let second = service
            .fetch(
                1,
                &Fetch {
                    channel: 5,
                    page: Some(Cursor {
                        before_id: cursor,
                        limit: 2,
                        ..Cursor::default()
                    }),
                },
            )
            .await;
        assert_eq!(second.messages.len(), 1, "the page behind the cursor");
        assert!(
            !first
                .messages
                .iter()
                .any(|m| m.message_id == second.messages[0].message_id),
            "a second page must not repeat the first"
        );
    }

    #[tokio::test]
    async fn a_row_written_before_the_column_existed_reads_back_unattributed() {
        // The migration adds the column nullable and does not backfill: those
        // rows have no recoverable author. Empty is the honest answer, and the
        // one thing that must not happen is a decode failure that takes the
        // whole page with it.
        let service = service().await;
        let _ = service.store_message(1, &message(4, b"x")).await;
        let page = service.fetch(1, &fetch(4, 10)).await;
        let stored = page.messages.first().expect("the message is on record");
        assert!(stored.sender_cert.is_empty());
    }

    #[tokio::test]
    async fn a_key_announcement_under_somebody_elses_identity_is_refused() {
        // Key distribution is the one place where being believed about who you
        // are *is* the whole game: announce a public key as somebody else and
        // every member who trusts it seals their next epoch key to you.
        //
        // The body is relayed verbatim because it is signed over its own bytes,
        // so there is nothing to correct; it is refused instead. Session 7's
        // certificate is `SPEAKER_CERT`; this claims a different one.
        let service = service_with_members().await;
        let forged = pchat_envelope::Body::KeyAnnounce(KeyAnnounce {
            channel: 4,
            epoch: 1,
            public_key: vec![1],
            holder_cert: b"somebody-elses-cert".to_vec(),
        });
        assert!(
            service.frame(frame(forged)).await.is_empty(),
            "a body claiming another identity must reach nobody"
        );

        // The same body under its own identity gets as far as the permission
        // check, which the test resolver denies, so this asserts it was *not*
        // stopped by the identity check, which is the distinction that matters.
        let honest = pchat_envelope::Body::KeyAnnounce(KeyAnnounce {
            channel: 4,
            epoch: 1,
            public_key: vec![1],
            holder_cert: SPEAKER_CERT.to_vec(),
        });
        let actions = service.frame(frame(honest)).await;
        assert_eq!(
            actions.len(),
            1,
            "an honest announcement should reach the permission check"
        );
    }

    #[test]
    fn the_identity_comes_off_the_connection_and_not_off_the_wire() {
        // Why the stamp in `on_message` can be trusted: the roster carries what
        // the TLS connection presented, so a client cannot write into somebody
        // else's name however it fills the field. A peer that presented no
        // certificate has no identity here, which is distinct from an empty
        // one and is why `cert_of` filters rather than returning the empty vec.
        use starling_proto_fancy::sessionview::Session;
        let roster = Roster::new();
        roster.upsert(&Session {
            session: 7,
            cert_hash: SPEAKER_CERT.to_vec(),
            ..Session::default()
        });
        roster.upsert(&Session {
            session: 8,
            ..Session::default()
        });

        assert_eq!(roster.cert_of(7).as_deref(), Some(SPEAKER_CERT));
        assert_eq!(roster.cert_of(8), None, "no certificate is not an identity");
        assert_eq!(
            roster.cert_of(99),
            None,
            "an unknown session has none either"
        );

        // The snapshot path, which is how a subscription actually opens, and
        // which this test caught missing the certificates entirely. Getting it
        // only in `upsert` fails closed rather than open (an unknown identity
        // matches nothing, so every announcement is refused), but the feature
        // is dead either way until a session happens to be updated.
        let fresh = Roster::new();
        fresh.replace(vec![Session {
            session: 7,
            cert_hash: SPEAKER_CERT.to_vec(),
            ..Session::default()
        }]);
        assert_eq!(
            fresh.cert_of(7).as_deref(),
            Some(SPEAKER_CERT),
            "a snapshot must carry identities, not just membership"
        );

        // And it goes when the session does: a stale entry would hand the next
        // holder of that number somebody else's identity.
        roster.remove(7);
        assert_eq!(roster.cert_of(7), None);
    }

    #[tokio::test]
    async fn a_stored_message_keeps_its_ciphertext_byte_for_byte() {
        // The server cannot read it and must not touch it: any transformation
        // here is a message the recipient cannot decrypt.
        let service = service().await;
        let _ = service
            .store_message(1, &message(4, b"\x00\xffopaque"))
            .await;
        let page = service.fetch(1, &fetch(4, 10)).await;
        assert_eq!(
            page.messages.first().map(|m| m.ciphertext.clone()),
            Some(b"\x00\xffopaque".to_vec())
        );
    }

    #[tokio::test]
    async fn a_fetch_reports_the_total_so_a_client_can_show_progress() {
        let service = service().await;
        for _ in 0..3 {
            let _ = service.store_message(1, &message(5, b"x")).await;
        }
        let page = service.fetch(1, &fetch(5, 2)).await;
        assert_eq!(page.total_stored, 3);
        let more = page.page.expect("a page always reports its tail");
        assert!(more.more);
        assert!(
            !more.next_before_id.is_empty(),
            "a page with more behind it must say where the next one starts"
        );
    }

    #[tokio::test]
    async fn a_fetch_the_client_may_not_make_returns_no_archive() {
        // The channel id is chosen by the client, so an unchecked fetch paged
        // through the stored archive of any channel on the server.
        let service = service().await;
        let _ = service.store_message(1, &message(4, b"secret")).await;

        let actions = service
            .frame(frame(pchat_envelope::Body::Fetch(fetch(4, 10))))
            .await;

        // Refused, and specifically not a FetchResponse carrying the archive.
        assert_eq!(actions.len(), 1);
        let payload = sent_payload(&actions[0]);
        assert!(
            PchatEnvelope::decode(payload.as_slice())
                .ok()
                .and_then(|envelope| envelope.body)
                .is_none(),
            "a refused fetch must not answer with a pchat body"
        );
    }

    #[tokio::test]
    async fn no_relay_is_ever_a_server_wide_broadcast() {
        // The finding this replaced: a Send naming no conns and no sessions is
        // delivered to every authenticated client on the server, so a message
        // to one channel reached every other.
        let service = service_with_members().await;

        for body in [
            pchat_envelope::Body::Message(message(4, b"x")),
            pchat_envelope::Body::Pin(Pin {
                message_id: "m".to_owned(),
                channel: 4,
                unpin: false,
            }),
            pchat_envelope::Body::KeyAnnounce(KeyAnnounce {
                channel: 4,
                epoch: 1,
                public_key: vec![1],
                holder_cert: SPEAKER_CERT.to_vec(),
            }),
            pchat_envelope::Body::Ack(Ack::default()),
        ] {
            for action in service.frame(frame(body)).await {
                let (_, broadcast) = addressed(&action);
                assert!(!broadcast, "a pchat action must never be server-wide");
            }
        }
    }

    #[tokio::test]
    async fn a_cold_roster_relays_to_nobody_rather_than_everybody() {
        // `service()` leaves the roster cold. Failing open here would be the
        // original leak wearing a fallback.
        let service = service().await;
        let actions = service
            .frame(frame(pchat_envelope::Body::Pin(Pin {
                message_id: "m".to_owned(),
                channel: 4,
                unpin: false,
            })))
            .await;

        for action in &actions {
            let (sessions, broadcast) = addressed(action);
            assert!(!broadcast);
            assert!(sessions.is_empty());
        }
    }

    #[tokio::test]
    async fn a_response_body_from_a_client_is_refused_not_relayed() {
        // FetchResponse and PinList are server-to-client. The verbatim relay
        // passed them on unaltered, which let a client forge somebody else's
        // history.
        let service = service_with_members().await;

        let actions = service
            .frame(frame(pchat_envelope::Body::FetchResponse(FetchResponse {
                channel: 4,
                messages: vec![message(4, b"forged")],
                page: None,
                total_stored: 1,
            })))
            .await;

        assert!(actions.is_empty(), "a forged response must reach nobody");
    }

    #[test]
    fn sealed_key_material_is_addressed_to_its_recipient_alone() {
        // KeyDeliver names one recipient; relaying it to the channel handed
        // every member a copy of a message addressed to one of them.
        //
        // Asserted against `Relay::of` rather than through `frame`, because the
        // test resolver denies every permission, a frame test would pass on
        // the refusal and prove nothing about the addressing.
        let relay = Relay::of(&pchat_envelope::Body::KeyDeliver(KeyDeliver {
            channel: 4,
            epoch: 1,
            recipient: 8,
            sealed_key: vec![9],
            countersignature: Vec::new(),
            recipient_cert: Vec::new(),
        }))
        .expect("KeyDeliver is relayable");

        assert_eq!(relay.unicast, Some(8));
        assert_eq!(relay.channel, 4);
    }

    #[test]
    fn every_relayable_body_names_the_channel_it_is_authorised_against() {
        // The routing table in one assertion: a body whose channel this got
        // wrong would be checked against the wrong ACL and delivered to the
        // wrong people.
        let cases: Vec<(pchat_envelope::Body, Option<(u32, Perm)>)> = vec![
            (
                pchat_envelope::Body::Pin(Pin {
                    message_id: "m".to_owned(),
                    channel: 4,
                    unpin: false,
                }),
                Some((4, Perm::TEXT_MESSAGE)),
            ),
            (
                pchat_envelope::Body::Delete(Delete {
                    channel: 5,
                    message_ids: vec!["m".to_owned()],
                }),
                Some((5, Perm::DELETE_MESSAGE)),
            ),
            (
                pchat_envelope::Body::KeyAnnounce(KeyAnnounce {
                    channel: 6,
                    epoch: 1,
                    public_key: vec![1],
                    holder_cert: SPEAKER_CERT.to_vec(),
                }),
                Some((6, Perm::ENTER)),
            ),
            // Server-to-client: a client may not originate these at all.
            (
                pchat_envelope::Body::FetchResponse(FetchResponse::default()),
                None,
            ),
            (pchat_envelope::Body::PinList(PinList::default()), None),
        ];

        for (body, expected) in cases {
            let got = Relay::of(&body).map(|relay| (relay.channel, relay.needs));
            assert_eq!(got, expected, "routing for {body:?}");
        }
    }

    #[tokio::test]
    async fn a_message_the_client_may_not_send_is_never_stored() {
        // Refusing only the relay would still leave the row in somebody else's
        // channel archive.
        let service = service().await;

        let actions = service
            .frame(frame(pchat_envelope::Body::Message(message(4, b"x"))))
            .await;

        assert_eq!(actions.len(), 1);
        assert_eq!(service.count(1, 4).await, 0);
    }

    /// The payload of a `Send` action, for asserting on what a refusal carries.
    fn sent_payload(action: &ServerAction) -> Vec<u8> {
        match &action.action {
            Some(starling_proto_fancy::control::server_action::Action::Send(send)) => {
                send.payload.clone()
            }
            _ => Vec::new(),
        }
    }

    /// The sessions a `Send` action is addressed at, and whether it is a
    /// server-wide broadcast (no conns and no sessions named).
    fn addressed(action: &ServerAction) -> (Vec<u32>, bool) {
        match &action.action {
            Some(starling_proto_fancy::control::server_action::Action::Send(send)) => (
                send.sessions.clone(),
                send.conns.is_empty() && send.sessions.is_empty(),
            ),
            _ => (Vec::new(), false),
        }
    }
}
