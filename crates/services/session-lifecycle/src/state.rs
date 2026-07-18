//! One state machine per connection.
//!
//! Sharded by connection, so a pod holds whatever it accepted and no two
//! connections share anything but the session-id pool
//! (`docs/diagrams/scaling.puml`).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use starling_proto::proto::tcp;
use starling_proto_fancy::control::Opened;
use starling_runtime::ids::now_ms;

use crate::ids::SessionId;
use crate::session::{SessionAllocator, SessionSource as _};

/// Who a peer turned out to be, once `userdata` has answered.
///
/// A struct rather than the tuple the handshake used to pass around: it now
/// carries two `Vec<u8>` that would otherwise sit side by side unnamed, where
/// swapping a comment for an avatar compiles cleanly and renders a user's
/// biography as a broken image.
#[derive(Debug, Clone, Default)]
pub struct Identity {
    /// The account it holds, or `None` for a guest.
    pub account: Option<u64>,
    /// The name to use — the account's own spelling when there is an account,
    /// so a login as "alice" shows up as the registered "Alice".
    pub name: String,
    /// The account's stored comment, as a content hash. Empty for a guest, who
    /// has no account to have stored one on.
    pub comment_hash: Vec<u8>,
    /// The account's stored avatar, as a content hash. Empty for a guest.
    pub texture_hash: Vec<u8>,
}

/// Everything known about a connection that has not finished the handshake.
#[derive(Debug, Clone, Default)]
pub struct PendingConnection {
    /// The gateway's connection id.
    pub conn: u64,
    /// Which gateway holds it.
    pub gateway: String,
    /// Its virtual server.
    pub scope: u32,
    /// The peer's address, for the log and for a ban check.
    pub address: String,
    /// SHA-1 of the peer's leaf certificate, empty if it presented none.
    pub cert_hash: Vec<u8>,
    /// The chain the peer presented, leaf first, DER-encoded.
    ///
    /// Kept alongside the hash because they serve different readers: the hash
    /// identifies an account or a ban, and this is the only form that can be
    /// shown to a human in the client's Information window.
    pub certificates: Vec<Vec<u8>>,
    /// Whether the chain validated against a configured CA.
    pub strong_cert: bool,
    /// The Mumble version the peer announced.
    pub mumble_version: u64,
    /// The client build it announced, e.g. "Mumble 1.5.735".
    ///
    /// Kept because it is most of what the Information window is *for*: "which
    /// client is this person running" is the first question asked of a user
    /// reporting something nobody else sees.
    pub release: String,
    /// The operating system it announced.
    pub os: String,
    /// That operating system's version.
    pub os_version: String,
    /// The access tokens the peer presented, in `Authenticate`.
    ///
    /// murmur's `ServerUser::qslAccessTokens`. These are what a `#name` ACL
    /// group matches, which is what makes a channel password a channel
    /// password: the operator writes `#hunter2` into the channel's `Enter`
    /// entry, and the token is the client's proof of knowing it.
    ///
    /// **Secret, and treated as one.** They are announced to `session-view`
    /// because that is the only thing `permissions` reads a session through,
    /// and they go nowhere else — no `UserState`, no log line, no operator
    /// response. A password in a log is a password that has leaked.
    ///
    /// Replaceable after the handshake: a client that is told it may not enter
    /// sends a fresh `Authenticate` carrying the token it has since been given
    /// (`vendor/server/src/murmur/Messages.cpp:367`), rather than reconnecting.
    pub tokens: Vec<String>,
    /// Whether the peer offered Opus.
    ///
    /// Read from `Authenticate`, which is where a client announces it
    /// (`vendor/server/src/murmur/Messages.cpp:538`). Not from `CodecVersion`:
    /// that message travels server→client, so waiting for one to arrive means
    /// waiting forever and reporting every client as having no Opus.
    pub opus: bool,
    /// What the peer last reported about its own link, from its `Ping`.
    ///
    /// The client measures these, not the server
    /// (`vendor/server/src/murmur/Messages.cpp:2918`) — round trips it timed,
    /// packets it received, packets it found late or missing. The server's part
    /// is to remember the last set so that *other* clients can be shown them.
    pub reported: ReportedStats,
    /// The Fancy version the peer announced, 0 for a stock client.
    pub fancy_version: u64,
    /// What the peer said it can actually do, from its `Hello`.
    ///
    /// Separate from `fancy_version` for the reason the epoch is separate from
    /// it: a version says which features *exist* in a build, and these say
    /// which of them this connection will accept. Every one is a thing the
    /// server may do *to* a client — compress its stream, replay a gap, send
    /// deltas instead of the full flood — and doing any of them to a peer that
    /// did not ask is a peer that cannot read its own connection.
    ///
    /// So the default is all-false, and silence means the murmur behaviour:
    /// uncompressed, no replay, the whole flood. A stock client never sends a
    /// `Hello` at all and lands here correctly by doing nothing.
    pub capabilities: Capabilities,
    /// What this connection is looking at, when it asked for deltas.
    ///
    /// `None` means the murmur flood: every state change, whether or not the
    /// peer can see the channel it happened in. That stays the default and the
    /// only behaviour a stock client ever gets.
    pub subscription: Option<Subscription>,
    /// The session id, once one has been allocated.
    pub session: u32,
    /// The registered account, once authenticated. `None` for a guest.
    ///
    /// An `Option` and not a `u64` on purpose: the SuperUser's account id is
    /// **0**, so a guest flattened to `0` is indistinguishable from the
    /// administrator, and every reader has to remember a rule it cannot see.
    /// Here the compiler asks the question instead
    /// (`starling_proto_fancy::identity`).
    pub account: Option<u64>,
    /// The account's stored comment, as a content hash. Empty for a guest.
    ///
    /// Read once, at authentication, and carried for the life of the
    /// connection: it is needed in three places that each build a `UserState`
    /// (the peer's own, everyone else's roster entry, and the join broadcast),
    /// and a lookup in each would be three round trips to say what the login
    /// already answered.
    pub comment_hash: Vec<u8>,
    /// The account's stored avatar, as a content hash. Empty for a guest.
    pub texture_hash: Vec<u8>,
    /// The name it authenticated as.
    pub name: String,
    /// Its channel.
    pub channel: u32,
    /// Channels it listens to without being in them.
    ///
    /// Held here rather than read from `metadata` when a `Session` is composed,
    /// because that composition happens on every self-mute and every avatar
    /// change: a gRPC round trip there would put the tree actor's lock on the
    /// path of every push-to-mute keypress. `metadata` remains the authority —
    /// this is the copy it last agreed to.
    pub listening: Vec<u32>,
    /// The gain it set on each listened channel, keyed by channel.
    ///
    /// Sparse, and kept for channels no longer in [`Self::listening`]: murmur
    /// keeps an adjustment across a listener being removed, so that toggling a
    /// room off and on again does not reset a slider the user chose.
    pub listening_volume: HashMap<u32, f32>,
    /// Self-mute.
    pub self_mute: bool,
    /// Self-deafen.
    pub self_deaf: bool,
    /// Muted by a moderator, as distinct from [`Self::self_mute`].
    ///
    /// Separate because they mean different things and are undone by different
    /// people: a user may lift their own self-mute at any time and must not be
    /// able to lift this one.
    pub mute: bool,
    /// Deafened by a moderator.
    pub deaf: bool,
    /// Suppressed by the server for lacking `Speak` in this channel.
    ///
    /// Server-set only. murmur refuses a client that tries to set it
    /// (`vendor/server/src/murmur/Messages.cpp:1135`), because it is the
    /// server's own statement about a permission, not a moderator's decision.
    pub suppress: bool,
    /// Heard over everyone else, and exempt from ducking.
    pub priority_speaker: bool,
    /// When it connected.
    pub connected_at_ms: u64,
    /// When it was last heard from, for the timeout sweep.
    pub last_seen_ms: u64,
}

/// What a client last told the server about its own side of the link.
///
/// What a connection accepts, as it announced in its `Hello`.
///
/// Recorded rather than acted on: the three features these gate are not built
/// (`PROTOCOL-MIGRATION.md` M5). The gate exists first so that each lands behind
/// a flag that is already true or false per connection, instead of arriving
/// with its own ad-hoc way of asking — which is how one of them ends up sent to
/// a peer that never agreed to it.
///
/// Before this, a `Hello` was received and thrown away, so a client announcing
/// `zstd` had no way to tell whether anything heard it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Capabilities {
    /// The control stream may be zstd-compressed.
    pub zstd: bool,
    /// A reconnect may replay from a sequence number instead of re-syncing.
    pub resume: bool,
    /// Channel and user state may be sent as deltas for a declared subscription
    /// rather than as the full murmur flood.
    pub lazy_subscribe: bool,
}

/// The channels a connection asked to be told about.
///
/// murmur sends every user's every state change to everybody, so control
/// fan-out grows with the square of the population: at ten thousand clients and
/// one change each per thirty seconds that is millions of frames a second
/// before anyone speaks. A client that declares what it is actually rendering
/// can be sent only that, which turns the second factor from "everyone" into
/// "everyone looking at this channel".
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Subscription {
    /// The channels this peer is rendering.
    pub channels: Vec<u32>,
    /// Everything, which is the flood by choice rather than by default. A
    /// client that wants it says so, and then it is not a client that quietly
    /// failed to subscribe.
    pub everything: bool,
}

impl Subscription {
    /// Whether a change in `channel` is one this peer asked for.
    #[must_use]
    pub fn covers(&self, channel: u32) -> bool {
        self.everything || self.channels.contains(&channel)
    }
}

/// Every field here is the *client's* measurement. The server cannot compute
/// them: only the client knows when it sent a ping and when the reply came
/// back, and only the client can count what it did not receive. Reporting them
/// is therefore repeating a claim, not making one — which is exactly what
/// murmur does with the same numbers.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct ReportedStats {
    /// Packets the client received intact.
    pub good: u32,
    /// Packets that arrived too late to use.
    pub late: u32,
    /// Packets that never arrived.
    pub lost: u32,
    /// Nonce resyncs the client needed.
    pub resync: u32,
    /// UDP packets the client received.
    pub udp_packets: u32,
    /// TCP packets the client received.
    pub tcp_packets: u32,
    /// Mean UDP round trip, in milliseconds.
    pub udp_ping_avg: f32,
    /// Variance of the UDP round trip.
    pub udp_ping_var: f32,
    /// Mean TCP round trip, in milliseconds.
    pub tcp_ping_avg: f32,
    /// Variance of the TCP round trip.
    pub tcp_ping_var: f32,
}

/// Every connection this process is holding.
#[derive(Debug, Clone)]
pub struct Connections {
    inner: Arc<Mutex<HashMap<u64, PendingConnection>>>,
    sessions: Arc<Mutex<SessionAllocator>>,
}

impl Connections {
    /// A registry with a session pool sized for `max_users`.
    #[must_use]
    pub fn new(max_users: u32) -> Self {
        Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
            sessions: Arc::new(Mutex::new(SessionAllocator::new(max_users))),
        }
    }

    /// Record a new connection.
    pub fn opened(&self, opened: &Opened, gateway: &str) {
        let now = now_ms();
        if let Ok(mut inner) = self.inner.lock() {
            let _ = inner.insert(
                opened.conn,
                PendingConnection {
                    conn: opened.conn,
                    gateway: gateway.to_owned(),
                    scope: opened.virtual_server.max(1),
                    address: opened.peer_addr.clone(),
                    cert_hash: opened.cert_hash.clone(),
                    certificates: opened.certificates.clone(),
                    strong_cert: opened.strong_cert,
                    connected_at_ms: now,
                    last_seen_ms: now,
                    ..PendingConnection::default()
                },
            );
        }
    }

    /// Record what a peer announced in its `Version`.
    pub fn record_version(&self, conn: u64, version: &tcp::Version) {
        if let Ok(mut inner) = self.inner.lock()
            && let Some(pending) = inner.get_mut(&conn)
        {
            pending.mumble_version = version
                .version_v2
                .or_else(|| version.version_v1.map(u64::from))
                .unwrap_or_default();
            pending.release = version.release.clone().unwrap_or_default();
            pending.os = version.os.clone().unwrap_or_default();
            pending.os_version = version.os_version.clone().unwrap_or_default();
            pending.fancy_version = fancy_version(version);
        }
    }

    /// Record whether a peer announced Opus, from its `Authenticate`.
    pub fn record_opus(&self, conn: u64, opus: bool) {
        if let Ok(mut inner) = self.inner.lock()
            && let Some(pending) = inner.get_mut(&conn)
        {
            pending.opus = opus;
        }
    }

    /// Replace the access tokens a peer holds, from its `Authenticate`.
    ///
    /// **Replace, never merge**, as upstream does (`Messages.cpp:378`): the
    /// client sends the whole set it is holding, so merging would make a token
    /// impossible to withdraw — a channel password would keep working for
    /// everyone who had ever typed it, for as long as they stayed connected.
    ///
    /// Answers whether anything actually changed, so the caller can skip
    /// re-announcing and re-pushing permissions for the far commoner case of a
    /// client that sent no tokens and has none.
    pub fn set_tokens(&self, conn: u64, tokens: Vec<String>) -> bool {
        let Ok(mut inner) = self.inner.lock() else {
            return false;
        };
        let Some(pending) = inner.get_mut(&conn) else {
            return false;
        };
        if pending.tokens == tokens {
            return false;
        }
        pending.tokens = tokens;
        true
    }

    /// Record what a peer reported about its own link in a `Ping`.
    pub fn record_reported(&self, conn: u64, reported: ReportedStats) {
        if let Ok(mut inner) = self.inner.lock()
            && let Some(pending) = inner.get_mut(&conn)
        {
            pending.reported = reported;
        }
    }

    /// The connection holding `session`.
    #[must_use]
    pub fn by_session(&self, session: u32) -> Option<PendingConnection> {
        let inner = self.inner.lock().ok()?;
        inner
            .values()
            .find(|pending| pending.session == session && session != 0)
            .cloned()
    }

    /// Allocate a session id for a connection that has authenticated.
    ///
    /// Returns `None` when the pool is exhausted, which refuses the connection
    /// rather than growing — murmur does the same (`Server.cpp:1625`), and an
    /// unbounded pool would mean an unbounded server.
    ///
    /// Takes the whole [`Identity`] rather than its parts: everything the login
    /// established is written onto the record here, and this is the only place
    /// that does it, so a field that arrives at the handshake and never reaches
    /// the record has exactly one place to have been dropped.
    pub fn allocate(&self, conn: u64, identity: &Identity) -> Option<u32> {
        let session = {
            let mut sessions = self.sessions.lock().ok()?;
            sessions.allocate()?.0
        };
        let mut inner = self.inner.lock().ok()?;
        let pending = inner.get_mut(&conn)?;
        pending.session = session;
        pending.account = identity.account;
        pending.name = identity.name.clone();
        pending.comment_hash = identity.comment_hash.clone();
        pending.texture_hash = identity.texture_hash.clone();
        Some(session)
    }

    /// One connection.
    #[must_use]
    pub fn get(&self, conn: u64) -> Option<PendingConnection> {
        self.inner
            .lock()
            .ok()
            .and_then(|inner| inner.get(&conn).cloned())
    }

    /// An authenticated connection that collides with `account`/`name`.
    ///
    /// murmur's predicate, from `Messages.cpp:418` — the same registered
    /// account, *or* the same name compared case-insensitively. Case matters:
    /// without folding, "Alice" and "alice" are two users whom every client
    /// renders as the same person.
    ///
    /// Only authenticated connections are considered. One still mid-handshake
    /// has no name to collide with, and treating it as one would let a peer
    /// that connects and says nothing block a name indefinitely.
    #[must_use]
    pub fn duplicate_of(
        &self,
        conn: u64,
        account: Option<u64>,
        name: &str,
    ) -> Option<PendingConnection> {
        let inner = self.inner.lock().ok()?;
        inner
            .values()
            .find(|other| {
                other.conn != conn
                    && other.session != 0
                    // `is_some`, not `!= 0`: two guests must not be matched to
                    // each other by both holding "no account", and the
                    // administrator must not be excluded by holding account 0.
                    && ((account.is_some() && other.account == account)
                        || other.name.eq_ignore_ascii_case(name))
            })
            .cloned()
    }

    /// Record that a connection is still alive.
    pub fn touch(&self, conn: u64) {
        if let Ok(mut inner) = self.inner.lock()
            && let Some(pending) = inner.get_mut(&conn)
        {
            pending.last_seen_ms = now_ms();
        }
    }

    /// Record what a connection said it accepts.
    ///
    /// Only ever narrowed by the client's own `Hello`; nothing else may widen
    /// it, because every capability is something done *to* that connection.
    pub fn set_capabilities(&self, conn: u64, capabilities: Capabilities) {
        if let Ok(mut inner) = self.inner.lock()
            && let Some(pending) = inner.get_mut(&conn)
        {
            pending.capabilities = capabilities;
        }
    }

    /// What a connection accepts, or nothing at all if it is unknown.
    ///
    /// An unknown connection reads as all-false rather than as an error: the
    /// only safe answer to "may I compress this peer's stream" for a peer that
    /// is not there is no.
    #[must_use]
    pub fn capabilities(&self, conn: u64) -> Capabilities {
        self.inner
            .lock()
            .ok()
            .and_then(|inner| inner.get(&conn).map(|pending| pending.capabilities))
            .unwrap_or_default()
    }

    /// Record what a connection is looking at.
    pub fn set_subscription(&self, conn: u64, subscription: Option<Subscription>) {
        if let Ok(mut inner) = self.inner.lock()
            && let Some(pending) = inner.get_mut(&conn)
        {
            pending.subscription = subscription;
        }
    }

    /// Split the audience for a state change in `channel`.
    ///
    /// Returns `(flood, subscribed)`: the sessions that get the message the way
    /// murmur sends it, and the sessions that asked for deltas and are looking
    /// at the channel it happened in. **A subscriber not looking at `channel`
    /// appears in neither** — that omission is the entire point, and the reason
    /// the fan-out stops growing with the population.
    ///
    /// Sessions with no id yet (mid-handshake) are in neither list: they cannot
    /// be addressed by session, and they get the full state at sync anyway.
    #[must_use]
    #[allow(
        clippy::iter_over_hash_type,
        reason = "membership decides both lists and visit order cannot change \
                  it; the results are sorted before returning, so the output is \
                  deterministic for tests and for a log line either way"
    )]
    pub fn audience(&self, channel: u32) -> (Vec<u32>, Vec<u32>) {
        let Ok(inner) = self.inner.lock() else {
            // A poisoned lock must not silently become "send to nobody": that
            // reads as a quiet server. Empty flood and empty subscribers means
            // the caller falls back to its unaddressed broadcast.
            return (Vec::new(), Vec::new());
        };
        let mut flood = Vec::new();
        let mut subscribed = Vec::new();
        for pending in inner.values() {
            if pending.session == 0 {
                continue;
            }
            match &pending.subscription {
                Some(subscription) if pending.capabilities.lazy_subscribe => {
                    if subscription.covers(channel) {
                        subscribed.push(pending.session);
                    }
                }
                // No subscription, or one from a peer that never announced it
                // could read deltas. Either way it gets what murmur sends.
                _ => flood.push(pending.session),
            }
        }
        // Sorted so the same membership always produces the same lists: a test
        // asserting an audience should not depend on hash order, and neither
        // should a log line somebody is comparing across two runs.
        flood.sort_unstable();
        subscribed.sort_unstable();
        (flood, subscribed)
    }

    /// Record which channel a session is in.
    pub fn set_channel(&self, conn: u64, channel: u32) {
        if let Ok(mut inner) = self.inner.lock()
            && let Some(pending) = inner.get_mut(&conn)
        {
            pending.channel = channel;
        }
    }

    /// Apply the listener change `metadata` has already agreed to.
    ///
    /// Takes the outcome rather than the request: the ceilings are the tree's to
    /// enforce, and applying what was *asked for* here would leave this copy
    /// claiming listeners the authority refused.
    pub fn apply_listeners(
        &self,
        conn: u64,
        added: &[u32],
        removed: &[u32],
        volume: &HashMap<u32, f32>,
    ) {
        let Ok(mut inner) = self.inner.lock() else {
            return;
        };
        let Some(pending) = inner.get_mut(&conn) else {
            return;
        };
        pending
            .listening
            .retain(|channel| !removed.contains(channel));
        for channel in added {
            if !pending.listening.contains(channel) {
                pending.listening.push(*channel);
            }
        }
        // An iterator chain rather than a `for`: nothing here observes the
        // order, and saying so in the shape keeps `iter_over_hash_type` pointed
        // at the loops where order would leak out.
        volume.iter().for_each(|(channel, gain)| {
            // Unity is the absence of an adjustment. Storing it would put an
            // entry in every routing snapshot that changes nothing.
            if (gain - 1.0).abs() < f32::EPSILON {
                let _ = pending.listening_volume.remove(channel);
            } else {
                let _ = pending.listening_volume.insert(*channel, *gain);
            }
        });
    }

    /// Apply a moderator's speak-state change, returning the session it hit.
    ///
    /// The couplings are murmur's (`Messages.cpp:1303`): deafening implies
    /// muting, and un-muting clears deafen. Without them a user can be left
    /// un-muted but still deaf, which every client renders as a contradiction
    /// and no moderator asked for.
    pub fn set_speak_state(
        &self,
        conn: u64,
        mute: Option<bool>,
        deaf: Option<bool>,
        priority_speaker: Option<bool>,
        suppress: Option<bool>,
    ) -> Option<u32> {
        let mut inner = self.inner.lock().ok()?;
        let pending = inner.get_mut(&conn)?;
        if let Some(deaf) = deaf {
            pending.deaf = deaf;
            if deaf {
                pending.mute = true;
            }
        }
        if let Some(mute) = mute {
            pending.mute = mute;
            if !mute {
                pending.deaf = false;
            }
        }
        if let Some(priority) = priority_speaker {
            pending.priority_speaker = priority;
        }
        // Always `None` from a client: murmur refuses one that sets `suppress`
        // however privileged (`Messages.cpp:1135`), because it is the server's
        // own statement that the user lacks `Speak` here rather than anybody's
        // opinion. An operator acting out of band may set it, which is the one
        // caller that passes `Some`.
        if let Some(suppress) = suppress {
            pending.suppress = suppress;
        }
        (pending.session != 0).then_some(pending.session)
    }

    /// Record the account a connection has just been registered as.
    ///
    /// Returns the session it belongs to, so a caller that has to announce the
    /// change does not look the connection up a second time.
    ///
    /// Registration is the **only** moment a live connection's identity moves.
    /// Everywhere else `account` is settled during the handshake and read for
    /// the rest of the connection, which is why this is a named operation
    /// rather than a general setter: what it does is worth finding in a search.
    pub fn set_account(&self, conn: u64, account: u64) -> Option<u32> {
        let mut inner = self.inner.lock().ok()?;
        let pending = inner.get_mut(&conn)?;
        pending.account = Some(account);
        (pending.session != 0).then_some(pending.session)
    }

    /// Record the comment and avatar hashes a connection now carries.
    ///
    /// `None` leaves that hash alone. `Some` replaces it, and an **empty**
    /// vector is how a reset is stored: there is no blob to point at any more.
    ///
    /// This has to exist because `session-view` is fed from the connection
    /// record (`handshake.rs:125`) and nothing else. Storing a blob and writing
    /// its hash to the account row updates the two places a *reconnect* reads,
    /// and leaves every already-connected client's view pointing at the previous
    /// picture for the rest of the session.
    pub fn set_content(
        &self,
        conn: u64,
        comment: Option<Vec<u8>>,
        texture: Option<Vec<u8>>,
    ) -> Option<u32> {
        let mut inner = self.inner.lock().ok()?;
        let pending = inner.get_mut(&conn)?;
        if let Some(comment) = comment {
            pending.comment_hash = comment;
        }
        if let Some(texture) = texture {
            pending.texture_hash = texture;
        }
        (pending.session != 0).then_some(pending.session)
    }

    /// Apply self-mute and self-deafen, returning the session they belong to.
    pub fn set_self_flags(&self, conn: u64, mute: Option<bool>, deaf: Option<bool>) -> Option<u32> {
        let mut inner = self.inner.lock().ok()?;
        let pending = inner.get_mut(&conn)?;
        if let Some(mute) = mute {
            pending.self_mute = mute;
        }
        if let Some(deaf) = deaf {
            pending.self_deaf = deaf;
            // Deafening implies muting, as it does in every Mumble client: a
            // user who cannot hear the room should not be transmitting into it.
            if deaf {
                pending.self_mute = true;
            }
        }
        (pending.session != 0).then_some(pending.session)
    }

    /// Forget a connection, returning its session id to the pool.
    pub fn close(&self, conn: u64) -> Option<u32> {
        let pending = self.inner.lock().ok()?.remove(&conn)?;
        if pending.session != 0 {
            if let Ok(mut sessions) = self.sessions.lock() {
                sessions.release(SessionId(pending.session));
            }
            return Some(pending.session);
        }
        None
    }

    /// Connections that have not been heard from since `cutoff_ms`.
    #[must_use]
    pub fn timed_out(&self, cutoff_ms: u64) -> Vec<u64> {
        self.inner
            .lock()
            .map(|inner| {
                inner
                    .values()
                    .filter(|pending| pending.last_seen_ms < cutoff_ms)
                    .map(|pending| pending.conn)
                    .collect()
            })
            .unwrap_or_default()
    }
}

/// The Fancy extension version a peer announced, or 0.
///
/// Read from the Fancy field rather than inferred from the Mumble version: a
/// fork could ship Mumble 1.6 without the extensions, and announcing the
/// extension is not the same as implementing a capability added later.
#[must_use]
pub fn fancy_version(version: &tcp::Version) -> u64 {
    version.fancy_version.unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_connection_that_announced_nothing_accepts_nothing() {
        // Every capability is something the server does *to* a connection —
        // compress its stream, replay a gap, send deltas instead of the flood.
        // Doing one to a peer that never asked leaves it unable to read its own
        // connection, so silence must mean the murmur behaviour and not a
        // convenient default. A stock client never sends a `Hello` at all.
        let connections = Connections::new(8);
        connections.opened(&opened(1), "gw");
        assert_eq!(connections.capabilities(1), Capabilities::default());

        // And an unknown connection answers the same way rather than erroring:
        // "may I compress this peer" for a peer that is not there is no.
        assert_eq!(connections.capabilities(999), Capabilities::default());
    }

    #[test]
    fn what_a_client_announces_is_kept() {
        // It used to be dropped on the floor, so a client announcing `zstd` had
        // no way to learn whether anything heard it.
        let connections = Connections::new(8);
        connections.opened(&opened(1), "gw");
        connections.set_capabilities(
            1,
            Capabilities {
                zstd: true,
                resume: false,
                lazy_subscribe: true,
            },
        );
        let held = connections.capabilities(1);
        assert!(held.zstd);
        assert!(held.lazy_subscribe);
        assert!(!held.resume, "an unannounced capability stays off");
    }

    /// A connection that announced deltas and is looking at `channels`.
    fn subscriber(connections: &Connections, conn: u64, session: u32, channels: &[u32]) {
        connections.opened(&opened(conn), "gw");
        connections.set_capabilities(
            conn,
            Capabilities {
                lazy_subscribe: true,
                ..Capabilities::default()
            },
        );
        connections.set_subscription(
            conn,
            Some(Subscription {
                channels: channels.to_vec(),
                everything: false,
            }),
        );
        if let Ok(mut inner) = connections.inner.lock()
            && let Some(pending) = inner.get_mut(&conn)
        {
            pending.session = session;
        }
    }

    #[test]
    fn a_subscriber_looking_elsewhere_is_sent_nothing() {
        // The entire saving. murmur sends every state change to everybody, so
        // fan-out grows with the square of the population; the win is not that
        // subscribers get a smaller message, it is that most of them get *no*
        // message. If this ever quietly starts including them, the feature is
        // costing bandwidth to achieve nothing.
        let connections = Connections::new(8);
        subscriber(&connections, 1, 11, &[4]);
        subscriber(&connections, 2, 22, &[9]);

        let (flood, subscribed) = connections.audience(4);
        assert!(flood.is_empty(), "nobody here wants the flood");
        assert_eq!(subscribed, vec![11], "only the peer looking at channel 4");
    }

    #[test]
    fn a_peer_that_did_not_subscribe_still_gets_what_murmur_sends() {
        // The compatibility half: a stock client never subscribes, and must not
        // be quietly cut out of state it is still rendering.
        let connections = Connections::new(8);
        connections.opened(&opened(1), "gw");
        if let Ok(mut inner) = connections.inner.lock()
            && let Some(pending) = inner.get_mut(&1)
        {
            pending.session = 11;
        }
        subscriber(&connections, 2, 22, &[9]);

        let (flood, subscribed) = connections.audience(4);
        assert_eq!(flood, vec![11], "the unsubscribed peer gets everything");
        assert!(subscribed.is_empty());
    }

    #[test]
    fn a_subscription_without_the_capability_is_not_honoured() {
        // Announcing a subscription without announcing that deltas are readable
        // would stop the flood for a client that cannot read what replaces it —
        // a roster that silently stops updating. It falls back to the flood.
        let connections = Connections::new(8);
        connections.opened(&opened(1), "gw");
        connections.set_subscription(
            1,
            Some(Subscription {
                channels: vec![9],
                everything: false,
            }),
        );
        if let Ok(mut inner) = connections.inner.lock()
            && let Some(pending) = inner.get_mut(&1)
        {
            pending.session = 11;
        }

        let (flood, subscribed) = connections.audience(4);
        assert_eq!(flood, vec![11]);
        assert!(subscribed.is_empty());
    }

    #[test]
    fn subscribing_to_everything_is_the_flood_by_choice() {
        // Distinct from not subscribing: the peer reads deltas and asked for all
        // of them, so it is not a client that quietly failed to subscribe.
        let connections = Connections::new(8);
        connections.opened(&opened(1), "gw");
        connections.set_capabilities(
            1,
            Capabilities {
                lazy_subscribe: true,
                ..Capabilities::default()
            },
        );
        connections.set_subscription(
            1,
            Some(Subscription {
                channels: Vec::new(),
                everything: true,
            }),
        );
        if let Ok(mut inner) = connections.inner.lock()
            && let Some(pending) = inner.get_mut(&1)
        {
            pending.session = 11;
        }

        let (flood, subscribed) = connections.audience(4321);
        assert!(flood.is_empty());
        assert_eq!(subscribed, vec![11], "everything covers any channel");
    }

    fn opened(conn: u64) -> Opened {
        Opened {
            conn,
            peer_addr: "127.0.0.1:1234".to_owned(),
            cert_hash: Vec::new(),
            certificates: Vec::new(),
            strong_cert: false,
            virtual_server: 1,
        }
    }

    /// An unregistered peer under `name`: no account, and so no stored profile.
    fn guest(name: &str) -> Identity {
        Identity {
            name: name.to_owned(),
            ..Identity::default()
        }
    }

    #[test]
    fn a_session_id_is_returned_to_the_pool_when_its_connection_ends() {
        // Otherwise a server that has been up for a week runs out of ids while
        // holding ten clients.
        let connections = Connections::new(2);
        connections.opened(&opened(1), "gw");
        let first = connections.allocate(1, &guest("a")).expect("a session id");
        assert_eq!(connections.close(1), Some(first));

        connections.opened(&opened(2), "gw");
        assert!(connections.allocate(2, &guest("b")).is_some());
    }

    #[test]
    fn deafening_yourself_also_mutes_you() {
        // Every Mumble client shows it this way; not doing it leaves a user
        // transmitting into a room they cannot hear.
        let connections = Connections::new(4);
        connections.opened(&opened(1), "gw");
        let _ = connections.allocate(1, &guest("a"));
        let _ = connections.set_self_flags(1, None, Some(true));
        let pending = connections.get(1).expect("the connection");
        assert!(pending.self_mute);
        assert!(pending.self_deaf);
    }

    #[test]
    fn an_exhausted_session_pool_refuses_rather_than_growing() {
        let connections = Connections::new(1);
        for conn in 1..=4 {
            connections.opened(&opened(conn), "gw");
        }
        let mut granted = 0;
        for conn in 1..=4 {
            if connections.allocate(conn, &guest("x")).is_some() {
                granted += 1;
            }
        }
        assert!(granted < 4, "the pool must be bounded");
    }

    #[test]
    fn a_stock_client_announces_no_fancy_version() {
        let stock = tcp::Version {
            version_v2: Some(0x0001_0006_0000),
            ..tcp::Version::default()
        };
        assert_eq!(fancy_version(&stock), 0);
    }

    #[test]
    fn a_name_already_in_use_is_found_whatever_its_case() {
        // Two sessions called "Alice" and "alice" are one person to every
        // client that renders them, so the collision has to be found without
        // regard to case (`Messages.cpp:422`).
        let connections = Connections::new(8);
        connections.opened(&opened(1), "gw");
        let _ = connections.allocate(1, &guest("Alice"));

        connections.opened(&opened(2), "gw");
        let found = connections
            .duplicate_of(2, None, "alice")
            .expect("the same name in another case is the same name");
        assert_eq!(found.conn, 1);
    }

    #[test]
    fn a_connection_does_not_collide_with_itself() {
        // Re-authenticating on one connection must not find its own entry and
        // decide the user is a ghost of themselves.
        let connections = Connections::new(8);
        connections.opened(&opened(1), "gw");
        let _ = connections.allocate(1, &guest("alice"));
        assert!(connections.duplicate_of(1, None, "alice").is_none());
    }

    #[test]
    fn two_guests_are_not_matched_to_each_other_by_both_being_guests() {
        // Both carry `None` for an account. Comparing that as equality would
        // make every guest a duplicate of every other guest and let the first
        // one in lock everybody else out.
        let connections = Connections::new(8);
        connections.opened(&opened(1), "gw");
        let _ = connections.allocate(1, &guest("alice"));

        connections.opened(&opened(2), "gw");
        assert!(connections.duplicate_of(2, None, "bob").is_none());
    }

    #[test]
    fn the_same_account_collides_under_a_different_name() {
        // murmur matches on the account first (`Messages.cpp:422`): one
        // registration is one person, whatever they typed in the name box.
        let connections = Connections::new(8);
        connections.opened(&opened(1), "gw");
        let _ = connections.allocate(
            1,
            &Identity {
                account: Some(7),
                name: "alice".to_owned(),
                ..Identity::default()
            },
        );

        connections.opened(&opened(2), "gw");
        let found = connections
            .duplicate_of(2, Some(7), "someone-else")
            .expect("the same account is the same user");
        assert_eq!(found.conn, 1);
    }

    #[test]
    fn a_connection_still_mid_handshake_holds_no_name() {
        // It has no session yet, so it has not claimed anything. Treating it as
        // a collision would let a peer that connects and never authenticates
        // hold a name indefinitely.
        let connections = Connections::new(8);
        connections.opened(&opened(1), "gw");
        assert!(connections.duplicate_of(2, None, "alice").is_none());
    }

    #[test]
    fn a_session_resolves_back_to_its_connection() {
        // What `UserStats` needs: a client names a session, and the answer has
        // to come from that session's connection state.
        let connections = Connections::new(8);
        connections.opened(&opened(1), "gw");
        let session = connections.allocate(1, &guest("alice")).expect("a session");
        assert_eq!(connections.by_session(session).map(|p| p.conn), Some(1));
    }

    #[test]
    fn session_zero_never_resolves_to_a_connection() {
        // Zero means "not authenticated yet", and every mid-handshake entry
        // carries it — so looking it up must not return an arbitrary one.
        let connections = Connections::new(8);
        connections.opened(&opened(1), "gw");
        assert!(connections.by_session(0).is_none());
    }

    #[test]
    fn the_client_build_is_kept_because_it_is_what_information_shows() {
        let connections = Connections::new(8);
        connections.opened(&opened(1), "gw");
        connections.record_version(
            1,
            &tcp::Version {
                version_v2: Some(0x0001_0005_0000),
                release: Some("Mumble 1.5.735".to_owned()),
                os: Some("Windows".to_owned()),
                os_version: Some("11".to_owned()),
                ..tcp::Version::default()
            },
        );
        let pending = connections.get(1).expect("the connection");
        assert_eq!(pending.release, "Mumble 1.5.735");
        assert_eq!(pending.os, "Windows");
        assert_eq!(pending.os_version, "11");
    }

    #[test]
    fn deafening_someone_also_mutes_them() {
        // murmur's coupling (`Messages.cpp:1303`). Without it a user ends up
        // deaf but not muted, which every client renders as a contradiction.
        let connections = Connections::new(8);
        connections.opened(&opened(1), "gw");
        let _ = connections.allocate(1, &guest("victim"));

        let _ = connections.set_speak_state(1, None, Some(true), None, None);
        let pending = connections.get(1).expect("the connection");
        assert!(pending.deaf);
        assert!(pending.mute, "deafening implies muting");
    }

    #[test]
    fn un_muting_someone_also_un_deafens_them() {
        // The other half of the same coupling: leaving someone un-muted but
        // still deaf means a moderator who lifted a mute has not actually
        // given the user their ears back.
        let connections = Connections::new(8);
        connections.opened(&opened(1), "gw");
        let _ = connections.allocate(1, &guest("victim"));
        let _ = connections.set_speak_state(1, None, Some(true), None, None);

        let _ = connections.set_speak_state(1, Some(false), None, None, None);
        let pending = connections.get(1).expect("the connection");
        assert!(!pending.mute);
        assert!(!pending.deaf, "un-muting clears deafen");
    }

    #[test]
    fn priority_speaker_is_independent_of_mute() {
        // They travel in one message and share one permission, but they are not
        // the same switch: making somebody a priority speaker must not quietly
        // un-mute them.
        let connections = Connections::new(8);
        connections.opened(&opened(1), "gw");
        let _ = connections.allocate(1, &guest("speaker"));
        let _ = connections.set_speak_state(1, Some(true), None, None, None);

        let _ = connections.set_speak_state(1, None, None, Some(true), None);
        let pending = connections.get(1).expect("the connection");
        assert!(pending.priority_speaker);
        assert!(pending.mute, "a priority speaker who was muted stays muted");
    }

    #[test]
    fn registering_a_guest_gives_the_live_connection_its_account() {
        // The connection has to carry the account immediately, not after a
        // reconnect: everything downstream — the ACL evaluation that puts them
        // in `@auth`, the announcement to session-view — reads it from here.
        let connections = Connections::new(8);
        connections.opened(&opened(1), "gw");
        let session = connections.allocate(1, &guest("guest")).expect("a session");
        assert!(
            connections
                .get(1)
                .expect("the connection")
                .account
                .is_none(),
            "a guest starts with no account"
        );

        assert_eq!(connections.set_account(1, 4), Some(session));
        assert_eq!(connections.get(1).expect("the connection").account, Some(4));
    }

    #[test]
    fn registering_the_account_numbered_zero_is_not_read_as_registering_nobody() {
        // Account 0 is the SuperUser and `None` is a guest. Storing the pair as
        // an `Option` is what keeps those apart, and a zero that collapsed to
        // `None` would silently leave the user a guest.
        let connections = Connections::new(8);
        connections.opened(&opened(1), "gw");
        let _ = connections.allocate(1, &guest("someone"));

        let _ = connections.set_account(1, 0);
        assert_eq!(connections.get(1).expect("the connection").account, Some(0));
    }

    #[test]
    fn a_moderator_mute_is_not_the_users_own_self_mute() {
        // Two separate flags on purpose: a user may lift their own self-mute
        // whenever they like, and must not be able to lift a moderator's.
        let connections = Connections::new(8);
        connections.opened(&opened(1), "gw");
        let _ = connections.allocate(1, &guest("victim"));
        let _ = connections.set_speak_state(1, Some(true), None, None, None);

        let _ = connections.set_self_flags(1, Some(false), Some(false));
        let pending = connections.get(1).expect("the connection");
        assert!(!pending.self_mute);
        assert!(
            pending.mute,
            "clearing your own self-mute must not clear a moderator's mute"
        );
    }

    #[test]
    fn a_channel_move_is_recorded_so_the_rest_of_the_server_agrees() {
        // `set_channel` existed and nothing ever called it, so every session
        // read as being in the root however many times it moved — which is
        // what `UserStats` and the same-channel disclosure rule key off.
        let connections = Connections::new(8);
        connections.opened(&opened(1), "gw");
        let session = connections.allocate(1, &guest("alice")).expect("a session");
        assert_eq!(connections.get(1).expect("the connection").channel, 0);

        connections.set_channel(1, 7);
        assert_eq!(connections.get(1).expect("the connection").channel, 7);
        assert_eq!(
            connections
                .by_session(session)
                .expect("the session")
                .channel,
            7,
            "the session view of it has to move too, not just the connection"
        );
    }

    #[test]
    fn a_connection_that_has_gone_quiet_is_reported_as_timed_out() {
        // The sweep this feeds was dead code, which is why a client that
        // vanished without its socket noticing stayed in the tree forever.
        let connections = Connections::new(8);
        connections.opened(&opened(1), "gw");
        let _ = connections.allocate(1, &guest("alice"));

        assert!(
            connections.timed_out(0).is_empty(),
            "a connection just heard from is not timed out"
        );
        assert_eq!(connections.timed_out(now_ms() + 1), vec![1]);
    }
}
