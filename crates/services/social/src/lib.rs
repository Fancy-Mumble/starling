//! `social`: reactions, receipts, typing, polls, watch-together, drawing.
//!
//! One service rather than six, because each of these is a few hundred bytes of
//! state and a fan-out. Six services with one message each would be six
//! deployments, six health checks and six things to configure for no isolation
//! anybody wanted.
//!
//! Everything here is bounded before it is stored. A stroke's point list and a
//! poll's option list both arrive from an unauthenticated peer, and "bound
//! before you allocate" applies to a `Vec` exactly as it does to a frame.
//!
//! # Fan-out addresses a channel, and the server writes the actor
//!
//! Both halves were wrong until 2026-08-09 and both are the same class of bug.
//!
//! A [`Send`] naming no sessions reaches **every** authenticated client on the
//! server, so relaying a reaction with the sender excluded told the whole
//! server who reacted to what in a channel they may not even see. Membership
//! now comes from `session-view` through a [`Roster`], exactly as `text` does,
//! and a cold roster addresses nobody rather than falling back to a broadcast.
//!
//! The actor was whatever the peer wrote. The client leaves it empty (it does
//! not know its own session id at that layer) and murmur fills it in on relay,
//! `Messages.cpp:4094` for typing, `:5432` for polls; a shipped client drops a
//! typing indicator or a poll whose actor is 0, so relaying the peer's bytes
//! verbatim meant the feature did nothing at all. Every actor field is now
//! written from the connection the frame arrived on, which is also the only
//! way it cannot be spoofed.
//!
//! # Polls are relayed, not summarised
//!
//! The service answered a poll and a vote with [`PollState`], its own tally.
//! No client reads that message: the shipped one keeps its own tally from the
//! votes it sees (`ui/src/core/features/chat/poll/model.ts`), and murmur only
//! ever relays (`Messages.cpp:5414`). So the wire is the relay, stamped with
//! the identity the server resolved, and the tally is kept here for what only
//! the server can do: reject a vote in a closed poll, hold a voter to one
//! ballot, and route a vote whose message carries no channel of its own.
//!
//! # Polls are stored; memory is only a cache
//!
//! Polls and ballots lived only in memory until 2026-09-13. The poll card
//! outlives a restart in chat history, so every vote on it after one was
//! dropped, and the [`MAX_POLLS`] eviction did the same to older polls without
//! a restart. Both are now rows, written before the relay and loaded on a cache
//! miss, so an evicted poll is still votable. They are kept for
//! [`POLL_RETENTION_MS`] after the poll closes, or after it was created when it
//! never does, and then swept.
//!
//! [`Send`]: starling_proto_fancy::control::Send

use std::collections::HashMap;
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use prost::Message as _;
use starling_proto_fancy::fancy::social::{
    Poll, PollState, PollVote, Reaction, SocialEnvelope, WatchState, WatchSync, social_envelope,
    watch_sync,
};
use starling_proto_fancy::perm::Perm;
use starling_proto_fancy::types::ServiceKind;
use starling_runtime::permit::Permit;
use starling_runtime::plane::{
    Actions, ClientService, Fanout, Inbound, Plane, to_conn, to_sessions,
};
use starling_runtime::roster::Roster;
use starling_runtime::serve::{Serve, ServiceContext, ServiceError};
use starling_runtime::storage::{Migration, Store};

/// Longest stroke accepted, in points.
///
/// A whiteboard stroke is a few hundred points; an unbounded list from a peer
/// is an allocation attack with a friendly name.
pub const MAX_STROKE_POINTS: usize = 4096;

/// Most options a poll may carry.
pub const MAX_POLL_OPTIONS: usize = 32;

/// Longest emoji accepted, in bytes.
///
/// A grapheme cluster or a shortcode is tens of bytes; murmur caps it at the
/// same 64 (`PersistentChatManager.cpp:1453`) for the same reason, anything
/// larger is garbage that would be relayed verbatim to a whole channel.
pub const MAX_EMOJI_BYTES: usize = 64;

/// Longest poll question and option accepted, in bytes.
///
/// Polls are the one thing here the service keeps, so they are the one thing a
/// peer could grow without limit. Neither bound is a protocol rule; both exist
/// because the memory is the server's.
pub const MAX_POLL_TEXT_BYTES: usize = 512;

/// Longest identifier accepted for a poll or a watch session, in bytes.
///
/// Both are `UUID`s from the client and both end up as `HashMap` keys.
pub const MAX_ID_BYTES: usize = 64;

/// How many polls are cached in memory, across every server instance.
///
/// The oldest is evicted past this. Eviction forgets nothing: the poll is still
/// in storage and a vote on it loads it back.
pub const MAX_POLLS: usize = 512;

/// Milliseconds in a day.
const DAY_MS: u64 = 24 * 60 * 60 * 1_000;

/// How long a poll and its ballots are kept, in milliseconds: 90 days.
///
/// Counted from when the poll closes, or from its creation when it has no
/// deadline. A deadline further out than this is clamped to it, because
/// `closes_at_ms` is the peer's to choose and must not pin a row forever. Past
/// this a vote on the card is refused as a poll the server no longer has.
pub const POLL_RETENTION_MS: u64 = 90 * DAY_MS;

/// How often expired polls are swept.
///
/// Hourly, because retention is measured in days.
const SWEEP_INTERVAL: std::time::Duration = std::time::Duration::from_secs(3_600);

/// Upstream `PermissionDenied`.
const PERMISSION_DENIED: u16 = 12;

/// The schema. Both tables carry the poll's expiry, so the sweep is one
/// indexed `DELETE` each (`docs/STORAGE.md` D4).
///
/// The poll and a ballot's options are stored as their encoded canon messages:
/// neither is ever queried by its fields, and the message is already the
/// schema the client and the relay agree on.
const SCHEMA: &[Migration<'static>] = &[Migration::new(
    "0001_social_poll",
    &[
        "CREATE TABLE IF NOT EXISTS social_poll (\
             server_id BIGINT NOT NULL, poll_id VARCHAR(64) NOT NULL, \
             poll BLOB NOT NULL, created_at_ms BIGINT NOT NULL, \
             expires_at_ms BIGINT NOT NULL, \
             PRIMARY KEY (server_id, poll_id))",
        "CREATE INDEX IF NOT EXISTS ix_social_poll_expiry \
             ON social_poll(server_id, expires_at_ms)",
        // `voter` is the certificate hash where there is one: a session id is
        // recycled, so a ballot keyed on it would belong to a stranger after
        // a restart.
        "CREATE TABLE IF NOT EXISTS social_poll_ballot (\
             server_id BIGINT NOT NULL, poll_id VARCHAR(64) NOT NULL, \
             voter VARCHAR(128) NOT NULL, options BLOB NOT NULL, \
             expires_at_ms BIGINT NOT NULL, \
             PRIMARY KEY (server_id, poll_id, voter))",
        "CREATE INDEX IF NOT EXISTS ix_social_poll_ballot_expiry \
             ON social_poll_ballot(server_id, expires_at_ms)",
    ],
)];

/// The readiness gate that stays closed until the roster has a snapshot.
///
/// A social service that is up with a cold roster relays nothing, which looks
/// exactly like a server where nobody reacts to anything.
const VIEW_GATE: &str = "session-view";

/// One poll, and who has voted in it.
///
/// Ballots are kept per voter rather than as running totals, because a second
/// vote from one voter *replaces* the first; totals cannot be un-counted.
#[derive(Debug, Clone)]
struct PollRecord {
    poll: Poll,
    /// Keyed by [`SocialService::voter_key`].
    ballots: HashMap<String, Vec<u32>>,
    expires_at_ms: u64,
}

/// What became of a vote.
#[derive(Debug, PartialEq)]
enum Ballot {
    /// Counted, and to be relayed as this.
    Counted(PollVote),
    /// No such poll, or one past its retention.
    Unknown,
    /// The poll has closed.
    Closed,
    /// No option the poll has, which no client sends.
    Empty,
    /// Storage could not answer; already logged.
    Failed,
}

impl PollRecord {
    /// The tallies, as the canon reports them.
    fn tallies(&self) -> Vec<u32> {
        let mut tallies = vec![0_u32; self.poll.options.len()];
        // Sorted, so a tally is the same list whichever order the ballots
        // happen to hash into. Addition commutes; the lint is about the two
        // runs of one server disagreeing about anything derived from order.
        let mut voters: Vec<&String> = self.ballots.keys().collect();
        voters.sort_unstable();
        for chosen in voters
            .iter()
            .filter_map(|voter| self.ballots.get(voter.as_str()))
        {
            for option in chosen {
                if let Some(tally) = tallies.get_mut(*option as usize) {
                    *tally += 1;
                }
            }
        }
        tallies
    }

    /// Whether the poll has closed, at `now_ms`.
    const fn closed_at(&self, now_ms: u64) -> bool {
        self.poll.closes_at_ms != 0 && now_ms >= self.poll.closes_at_ms
    }
}

/// Every poll this server is holding, oldest first.
#[derive(Debug, Default)]
struct Polls {
    by_id: HashMap<(u32, String), PollRecord>,
    /// Insertion order, for eviction. A `VecDeque` rather than a sort on
    /// `created_at`: the canon carries no creation time, and arrival order is
    /// what "oldest" means here anyway.
    order: VecDeque<(u32, String)>,
}

impl Polls {
    /// Remember `record`, evicting the oldest poll once [`MAX_POLLS`] is
    /// exceeded.
    fn insert(&mut self, key: (u32, String), record: PollRecord) {
        if self.by_id.insert(key.clone(), record).is_none() {
            self.order.push_back(key);
        }
        while self.order.len() > MAX_POLLS {
            if let Some(oldest) = self.order.pop_front() {
                let _ = self.by_id.remove(&oldest);
            }
        }
    }

    /// Keep only the polls `keep` accepts.
    fn retain(&mut self, mut keep: impl FnMut(&PollRecord) -> bool) {
        self.by_id.retain(|_, record| keep(record));
        let by_id = &self.by_id;
        self.order.retain(|key| by_id.contains_key(key));
    }
}

/// When a poll created at `now_ms` stops being kept. See [`POLL_RETENTION_MS`].
fn poll_expiry(poll: &Poll, now_ms: u64) -> u64 {
    let latest_close = now_ms.saturating_add(POLL_RETENTION_MS);
    let anchor = if poll.closes_at_ms > now_ms {
        poll.closes_at_ms.min(latest_close)
    } else {
        now_ms
    };
    anchor.saturating_add(POLL_RETENTION_MS)
}

/// Apply `vote` from `voter` to `record`, in memory.
fn apply_vote(
    record: &mut PollRecord,
    vote: &PollVote,
    voter: u32,
    voter_key: &str,
    now_ms: u64,
) -> Ballot {
    if record.closed_at(now_ms) {
        return Ballot::Closed;
    }
    let options = record.poll.options.len() as u32;
    let mut chosen: Vec<u32> = vote
        .options
        .iter()
        .copied()
        .filter(|option| *option < options)
        .collect();
    chosen.dedup();
    if !record.poll.multiple {
        chosen.truncate(1);
    }
    if chosen.is_empty() {
        return Ballot::Empty;
    }

    // Replaces rather than adds: one voter, one ballot, which is also what
    // the client's own store does with a second vote from one session.
    let _ = record.ballots.insert(voter_key.to_owned(), chosen.clone());
    Ballot::Counted(PollVote {
        poll_id: vote.poll_id.clone(),
        options: chosen,
        voter,
        channel: record.poll.channel,
    })
}

/// Tell a voter their vote was not counted.
///
/// `PermissionDenied` of type `Text` is the only refusal the canon has. It
/// names no channel on purpose: the client reverts a permanent listen on the
/// channel of any denial that carries one.
fn refuse_vote(inbound: &Inbound, reason: &str) -> Actions {
    let denied = starling_proto::proto::tcp::PermissionDenied {
        session: Some(inbound.session),
        reason: Some(reason.to_owned()),
        r#type: Some(starling_proto::proto::tcp::permission_denied::DenyType::Text as i32),
        ..starling_proto::proto::tcp::PermissionDenied::default()
    };
    vec![to_conn(
        inbound.conn,
        PERMISSION_DENIED,
        denied.encode_to_vec(),
    )]
}

/// One watch-together session, and the connections behind its participants.
///
/// The wire message carries sessions, which is what other clients need. The
/// connections are kept beside it because [`ClientService::closed`] names a
/// connection and the roster may already have forgotten the session by the time
/// it runs -- the same reason `screenshare` matches a share on its connection.
#[derive(Debug, Clone)]
struct WatchRecord {
    state: WatchState,
    /// The connection the host is on.
    host_conn: u64,
    /// The connection each viewer is on.
    viewer_conns: HashMap<u32, u64>,
}

/// The service.
#[derive(Debug)]
pub struct SocialService {
    /// The durable record of every poll; [`Self::polls`] caches it.
    store: Store,
    polls: Mutex<Polls>,
    /// Held across a poll's read, change and write, so two votes cannot
    /// interleave between the cache and storage and leave them disagreeing.
    poll_writes: tokio::sync::Mutex<()>,
    watches: Mutex<HashMap<String, WatchRecord>>,
    /// Who is in which channel, so a relay can be addressed at one.
    roster: Arc<Roster>,
    /// Asks `permissions` before a reaction reaches a channel.
    ///
    /// murmur gates reactions on Enter (`PersistentChatManager.cpp:1400`) and
    /// nothing else here, and this keeps that: a reaction in a channel the
    /// sender cannot enter is both a leak and an unmetered broadcast vector,
    /// while a keystroke-rate typing indicator is not worth a round trip.
    permit: Permit,
    fanout: Fanout,
    /// How many watch sessions are held. See `scripts/canon-gauges.json`.
    ///
    /// The map is keyed by a client-supplied string, so this is the number that
    /// says whether [`SocialService::closed`] is doing its job.
    watches_gauge: starling_runtime::pressure::Gauge,
}

impl SocialService {
    /// Everyone in `channel`, including `sender` when they are in it.
    ///
    /// The default for anything a sender must see their own copy of: the
    /// shipped client has no optimistic update for a reaction, it renders what
    /// the server delivers, so excluding the sender means their own pill never
    /// appears (`ui/src/core/features/chat/reaction/useReactions.ts`).
    fn channel_including(&self, channel: u32) -> Vec<u32> {
        self.addressed(self.roster.in_channel(channel, 0))
    }

    /// Everyone in `channel` except `sender`.
    fn channel_excluding(&self, channel: u32, sender: u32) -> Vec<u32> {
        self.addressed(self.roster.in_channel(channel, sender))
    }

    /// Warn once per empty fan-out when the reason is a cold roster.
    ///
    /// Membership that is merely unknown looks identical to an empty channel
    /// at the call site, and only one of the two is a fault.
    fn addressed(&self, sessions: Vec<u32>) -> Vec<u32> {
        if sessions.is_empty() && !self.roster.is_warm() {
            tracing::warn!("the session-view roster is cold; a social relay reached nobody");
        }
        sessions
    }

    /// One relay, addressed at `sessions`.
    ///
    /// Empty means "nobody is there", never "everybody": a `Send` naming no
    /// sessions is delivered to the whole server, which is the leak this
    /// service used to have.
    fn relay(sessions: Vec<u32>, body: social_envelope::Body) -> Actions {
        if sessions.is_empty() {
            return Actions::new();
        }
        let envelope = SocialEnvelope { body: Some(body) };
        vec![to_sessions(
            sessions,
            ServiceKind::Social.outer_type(),
            envelope.encode_to_vec(),
        )]
    }

    /// Record a poll, or refuse it.
    ///
    /// Refusal is silent by design: every rejection here is a peer sending
    /// something no client produces.
    ///
    /// A poll id seen before replaces that poll and clears its ballots, as it
    /// always has in memory; storage now does the same.
    async fn create(&self, scope: u32, mut poll: Poll, creator: u32, now_ms: u64) -> Option<Poll> {
        if poll.poll_id.is_empty() || poll.poll_id.len() > MAX_ID_BYTES {
            return None;
        }
        poll.options.truncate(MAX_POLL_OPTIONS);
        poll.options
            .retain(|option| !option.is_empty() && option.len() <= MAX_POLL_TEXT_BYTES);
        if poll.options.is_empty() || poll.question.len() > MAX_POLL_TEXT_BYTES {
            return None;
        }
        // The identity is the server's to write, never the peer's.
        poll.creator = creator;

        let record = PollRecord {
            poll: poll.clone(),
            ballots: HashMap::new(),
            expires_at_ms: poll_expiry(&poll, now_ms),
        };
        let _serial = self.poll_writes.lock().await;
        // Relayed and cached even when the write fails: the poll still works
        // until a restart, which is no worse than before it was stored.
        if let Err(error) = self.write_poll(scope, &record, now_ms).await {
            tracing::error!(%error, scope, poll = %poll.poll_id, "could not store a poll");
        }
        self.polls
            .lock()
            .ok()?
            .insert((scope, poll.poll_id.clone()), record);
        Some(poll)
    }

    /// Apply a vote, and say what became of it.
    ///
    /// A counted vote is the *normalised* one: the voter stamped, the poll's
    /// channel filled in (the canon vote carries none, and the client needs
    /// one to route the vote to its card), out-of-range options dropped and a
    /// single-choice poll held to one option. Relaying the peer's own bytes
    /// instead would let one client show a tally another never counts.
    async fn vote(&self, scope: u32, vote: &PollVote, voter: u32, now_ms: u64) -> Ballot {
        let key = (scope, vote.poll_id.clone());
        let _serial = self.poll_writes.lock().await;
        if !self.cached(&key, now_ms) {
            match self.load(scope, &vote.poll_id, now_ms).await {
                Ok(Some(record)) => {
                    if let Ok(mut polls) = self.polls.lock() {
                        polls.insert(key.clone(), record);
                    }
                }
                Ok(None) => return Ballot::Unknown,
                Err(error) => {
                    tracing::error!(%error, scope, poll = %vote.poll_id, "could not load a poll");
                    return Ballot::Failed;
                }
            }
        }

        let voter_key = self.voter_key(voter);
        let (ballot, expires_at_ms) = {
            let Ok(mut polls) = self.polls.lock() else {
                return Ballot::Failed;
            };
            let Some(record) = polls.by_id.get_mut(&key) else {
                return Ballot::Unknown;
            };
            (
                apply_vote(record, vote, voter, &voter_key, now_ms),
                record.expires_at_ms,
            )
        };
        if let Ballot::Counted(counted) = &ballot {
            let written = self
                .write_ballot(scope, counted, &voter_key, expires_at_ms)
                .await;
            if let Err(error) = written {
                tracing::error!(%error, scope, poll = %vote.poll_id, "could not store a ballot");
            }
        }
        ballot
    }

    /// Whether `key` is cached and still inside its retention.
    fn cached(&self, key: &(u32, String), now_ms: u64) -> bool {
        self.polls
            .lock()
            .ok()
            .and_then(|polls| {
                polls
                    .by_id
                    .get(key)
                    .map(|record| record.expires_at_ms > now_ms)
            })
            .unwrap_or(false)
    }

    /// Who a ballot belongs to: the certificate hash, or the session for a
    /// peer that presented none.
    ///
    /// The certificate is what makes a ballot the same person's after they
    /// reconnect or the server restarts. A guest has nothing durable, so their
    /// ballot is only as good as the session id it was cast from.
    fn voter_key(&self, session: u32) -> String {
        match self.roster.cert_of(session) {
            Some(cert) if !cert.is_empty() => {
                cert.iter().map(|byte| format!("{byte:02x}")).collect()
            }
            _ => format!("session:{session}"),
        }
    }

    /// Store `record` as the whole of its poll, replacing any earlier ballots.
    async fn write_poll(
        &self,
        scope: u32,
        record: &PollRecord,
        now_ms: u64,
    ) -> Result<(), sqlx::Error> {
        let mut tx = self.store.pool().begin().await?;
        let _ = sqlx::query(
            "INSERT INTO social_poll (server_id, poll_id, poll, created_at_ms, expires_at_ms) \
             VALUES (?, ?, ?, ?, ?) \
             ON CONFLICT (server_id, poll_id) DO UPDATE SET poll = excluded.poll, \
             created_at_ms = excluded.created_at_ms, expires_at_ms = excluded.expires_at_ms",
        )
        .bind(i64::from(scope))
        .bind(&record.poll.poll_id)
        .bind(record.poll.encode_to_vec())
        .bind(now_ms as i64)
        .bind(record.expires_at_ms as i64)
        .execute(&mut *tx)
        .await?;
        let _ = sqlx::query("DELETE FROM social_poll_ballot WHERE server_id = ? AND poll_id = ?")
            .bind(i64::from(scope))
            .bind(&record.poll.poll_id)
            .execute(&mut *tx)
            .await?;
        tx.commit().await
    }

    /// Store one voter's ballot, replacing their earlier one.
    async fn write_ballot(
        &self,
        scope: u32,
        vote: &PollVote,
        voter_key: &str,
        expires_at_ms: u64,
    ) -> Result<(), sqlx::Error> {
        let options = PollVote {
            options: vote.options.clone(),
            ..PollVote::default()
        };
        sqlx::query(
            "INSERT INTO social_poll_ballot (server_id, poll_id, voter, options, expires_at_ms) \
             VALUES (?, ?, ?, ?, ?) \
             ON CONFLICT (server_id, poll_id, voter) DO UPDATE SET options = excluded.options",
        )
        .bind(i64::from(scope))
        .bind(&vote.poll_id)
        .bind(voter_key)
        .bind(options.encode_to_vec())
        .bind(expires_at_ms as i64)
        .execute(self.store.pool())
        .await
        .map(|_| ())
    }

    /// A poll and its ballots from storage, unless it is gone or expired.
    async fn load(
        &self,
        scope: u32,
        poll_id: &str,
        now_ms: u64,
    ) -> Result<Option<PollRecord>, sqlx::Error> {
        use sqlx::Row as _;

        let Some(row) = sqlx::query(
            "SELECT poll, expires_at_ms FROM social_poll \
             WHERE server_id = ? AND poll_id = ? AND expires_at_ms > ?",
        )
        .bind(i64::from(scope))
        .bind(poll_id)
        .bind(now_ms as i64)
        .fetch_optional(self.store.pool())
        .await?
        else {
            return Ok(None);
        };
        let bytes: Vec<u8> = row.try_get("poll")?;
        let Ok(poll) = Poll::decode(bytes.as_slice()) else {
            tracing::warn!(scope, poll = poll_id, "a stored poll does not decode");
            return Ok(None);
        };
        let expires_at_ms = row.try_get::<i64, _>("expires_at_ms")? as u64;

        let rows = sqlx::query(
            "SELECT voter, options FROM social_poll_ballot WHERE server_id = ? AND poll_id = ?",
        )
        .bind(i64::from(scope))
        .bind(poll_id)
        .fetch_all(self.store.pool())
        .await?;
        let mut ballots = HashMap::with_capacity(rows.len());
        for row in rows {
            let voter: String = row.try_get("voter")?;
            let options: Vec<u8> = row.try_get("options")?;
            if let Ok(ballot) = PollVote::decode(options.as_slice()) {
                let _ = ballots.insert(voter, ballot.options);
            }
        }
        Ok(Some(PollRecord {
            poll,
            ballots,
            expires_at_ms,
        }))
    }

    /// Delete every poll and ballot in `scope` past its retention, and drop
    /// them from the cache. Returns how many polls went.
    async fn sweep(&self, scope: u32, now_ms: u64) -> u64 {
        let result: Result<u64, sqlx::Error> = async {
            let mut tx = self.store.pool().begin().await?;
            let _ = sqlx::query(
                "DELETE FROM social_poll_ballot WHERE server_id = ? AND expires_at_ms <= ?",
            )
            .bind(i64::from(scope))
            .bind(now_ms as i64)
            .execute(&mut *tx)
            .await?;
            let polls =
                sqlx::query("DELETE FROM social_poll WHERE server_id = ? AND expires_at_ms <= ?")
                    .bind(i64::from(scope))
                    .bind(now_ms as i64)
                    .execute(&mut *tx)
                    .await?
                    .rows_affected();
            tx.commit().await?;
            Ok(polls)
        }
        .await;
        if let Ok(mut cache) = self.polls.lock() {
            cache.retain(|record| record.expires_at_ms > now_ms);
        }
        match result {
            Ok(swept) => swept,
            Err(error) => {
                // Reported rather than swallowed: a retention sweep that has
                // stopped working looks exactly like one with nothing to do.
                tracing::error!(%error, scope, "the poll retention sweep failed");
                0
            }
        }
    }

    /// One sweep per interval, across every server instance, until aborted.
    async fn sweep_forever(self: Arc<Self>, scopes: Vec<u32>) {
        loop {
            tokio::time::sleep(SWEEP_INTERVAL).await;
            for scope in &scopes {
                let swept = self.sweep(*scope, starling_runtime::ids::now_ms()).await;
                if swept > 0 {
                    tracing::debug!(scope, polls = swept, "expired polls deleted");
                }
            }
        }
    }

    /// Record a poll and relay it to its channel, creator included, so
    /// everyone holds the server-stamped poll rather than two versions of it.
    async fn on_poll(&self, inbound: &Inbound, poll: Poll) -> Actions {
        let channel = poll.channel;
        let now_ms = starling_runtime::ids::now_ms();
        let Some(stamped) = self
            .create(inbound.scope, poll, inbound.session, now_ms)
            .await
        else {
            return Actions::new();
        };
        let sessions = self.channel_including(channel);
        Self::relay(sessions, social_envelope::Body::Poll(stamped))
    }

    /// Count a vote and relay it, or tell the voter why it was not counted.
    async fn on_vote(&self, inbound: &Inbound, vote: &PollVote) -> Actions {
        let now_ms = starling_runtime::ids::now_ms();
        match self
            .vote(inbound.scope, vote, inbound.session, now_ms)
            .await
        {
            Ballot::Counted(stamped) => {
                let sessions = self.channel_including(stamped.channel);
                Self::relay(sessions, social_envelope::Body::Vote(stamped))
            }
            Ballot::Unknown => {
                tracing::info!(
                    session = inbound.session,
                    scope = inbound.scope,
                    poll = %vote.poll_id,
                    "vote refused: no such poll, or it is past its retention"
                );
                refuse_vote(inbound, "That poll no longer exists on this server.")
            }
            Ballot::Closed => {
                tracing::debug!(
                    session = inbound.session,
                    poll = %vote.poll_id,
                    "vote refused: the poll has closed"
                );
                refuse_vote(inbound, "That poll has closed.")
            }
            Ballot::Empty => {
                tracing::debug!(
                    session = inbound.session,
                    poll = %vote.poll_id,
                    "vote dropped: it names no option the poll has"
                );
                Actions::new()
            }
            Ballot::Failed => Actions::new(),
        }
    }

    /// The tally, for a caller that wants the server's own count.
    ///
    /// Not on the wire: no shipped client reads [`PollState`], and a message
    /// nobody decodes is bytes on every vote for nothing. It is the answer a
    /// query would return the day the canon grows one, and it is what the
    /// tests assert on. Reads the cache only, so a poll not voted on since a
    /// restart or an eviction answers `None`.
    #[must_use]
    pub fn state(&self, scope: u32, poll_id: &str, now_ms: u64) -> Option<PollState> {
        let polls = self.polls.lock().ok()?;
        let record = polls.by_id.get(&(scope, poll_id.to_owned()))?;
        Some(PollState {
            tallies: record.tallies(),
            poll: Some(record.poll.clone()),
            closed: record.closed_at(now_ms),
        })
    }

    /// Whether a reaction may be relayed at all.
    ///
    /// Emoji bounds first because they cost nothing, then Enter, which is a
    /// round trip.
    ///
    /// Every refusal says why. The canon has no answer to send back, so a
    /// refused reaction is indistinguishable from a lost one at the client,
    /// and the only place the difference can exist is this log. murmur writes
    /// the same lines (`PersistentChatManager.cpp:1401`, `:1454`).
    async fn may_react(&self, inbound: &Inbound, reaction: &Reaction) -> bool {
        if reaction.message_id.is_empty() || reaction.message_id.len() > MAX_ID_BYTES {
            tracing::debug!(
                session = inbound.session,
                len = reaction.message_id.len(),
                "reaction refused: no usable message id"
            );
            return false;
        }
        let emoji = match reaction
            .emoji
            .as_ref()
            .and_then(|emoji| emoji.kind.as_ref())
        {
            Some(starling_proto_fancy::fancy::wire::emoji::Kind::Unicode(grapheme)) => grapheme,
            Some(starling_proto_fancy::fancy::wire::emoji::Kind::Shortcode(code)) => code,
            None => {
                tracing::debug!(
                    session = inbound.session,
                    "reaction refused: no emoji in the message"
                );
                return false;
            }
        };
        if emoji.is_empty() || emoji.len() > MAX_EMOJI_BYTES {
            tracing::debug!(
                session = inbound.session,
                len = emoji.len(),
                "reaction refused: the emoji is empty or oversized"
            );
            return false;
        }
        let allowed = self
            .permit
            .allows(inbound, reaction.channel, Perm::ENTER.bits())
            .await;
        if !allowed {
            // Includes an unreachable `permissions`: the guard fails closed, so
            // a denial here is not by itself proof the client lacked the right.
            tracing::debug!(
                session = inbound.session,
                channel = reaction.channel,
                "reaction refused: no Enter permission for that channel"
            );
        }
        allowed
    }

    /// Start or update a watch-together session.
    fn watch(&self, sync: &WatchSync, actor: u32, conn: u64) -> Option<WatchState> {
        if sync.session_id.is_empty() || sync.session_id.len() > MAX_ID_BYTES {
            return None;
        }
        let mut watches = self.watches.lock().ok()?;
        let kind = watch_sync::Kind::try_from(sync.kind).unwrap_or(watch_sync::Kind::State);
        let record = watches
            .entry(sync.session_id.clone())
            .or_insert_with(|| WatchRecord {
                state: WatchState {
                    session_id: sync.session_id.clone(),
                    channel: sync.channel,
                    host: actor,
                    viewers: Vec::new(),
                    url: sync.url.clone(),
                    position_s: sync.position_s,
                    playing: sync.playing,
                },
                host_conn: conn,
                viewer_conns: HashMap::new(),
            });
        let state = &mut record.state;

        match kind {
            watch_sync::Kind::Start => {
                state.host = actor;
                state.url = sync.url.clone();
                record.host_conn = conn;
            }
            watch_sync::Kind::Join => {
                if !state.viewers.contains(&actor) {
                    state.viewers.push(actor);
                }
                let _ = record.viewer_conns.insert(actor, conn);
            }
            watch_sync::Kind::Leave => {
                state.viewers.retain(|viewer| *viewer != actor);
                let _ = record.viewer_conns.remove(&actor);
            }
            watch_sync::Kind::State => {
                // Only the host drives. Accepting a position from a viewer
                // would let one late buffer drag everybody else back.
                if state.host != actor {
                    return None;
                }
                state.position_s = sync.position_s;
                state.playing = sync.playing;
            }
            // A transfer is explicit and observable: a silent one desyncs every
            // viewer, because they keep obeying somebody who is no longer host.
            watch_sync::Kind::TransferHost => {
                if state.host != actor {
                    return None;
                }
                state.host = sync.new_host;
                // The new host's connection, if they were watching as a viewer.
                // Unknown otherwise, and a host whose connection is unknown is
                // one whose disconnect cannot end the session, so the entry
                // would outlive them. `u64::MAX` is no connection, which the
                // sweep below treats as already gone.
                record.host_conn = record
                    .viewer_conns
                    .get(&sync.new_host)
                    .copied()
                    .unwrap_or(u64::MAX);
            }
            watch_sync::Kind::End => {
                let ended = state.clone();
                let _ = watches.remove(&sync.session_id);
                self.watches_gauge.observe(watches.len() as u64);
                return Some(ended);
            }
        }
        let updated = state.clone();
        self.watches_gauge.observe(watches.len() as u64);
        Some(updated)
    }

    /// Drop everything `conn` was holding, and say what the channel should see.
    ///
    /// The host leaving ends the session, exactly as an explicit `End` does; a
    /// viewer leaving is the `Leave` they did not get to send. Without this the
    /// map only ever shrank on an explicit `End`, so a client could mint an
    /// entry per 64-byte id it invented and every one of them outlived it.
    fn forget_conn(&self, conn: u64) -> Vec<(u32, WatchState)> {
        let Ok(mut watches) = self.watches.lock() else {
            return Vec::new();
        };
        let mut changed = Vec::new();
        watches.retain(|_, record| {
            if record.host_conn == conn {
                changed.push((record.state.channel, record.state.clone()));
                return false;
            }
            let Some((viewer, _)) = record
                .viewer_conns
                .iter()
                .find(|(_, held)| **held == conn)
                .map(|(viewer, held)| (*viewer, *held))
            else {
                return true;
            };
            let _ = record.viewer_conns.remove(&viewer);
            record.state.viewers.retain(|other| *other != viewer);
            changed.push((record.state.channel, record.state.clone()));
            true
        });
        self.watches_gauge.observe(watches.len() as u64);
        changed
    }
}

impl ClientService for SocialService {
    async fn closed(&self, conn: u64, _reason: &str) -> Actions {
        // The one client-facing service that did not implement this. Its watch
        // map is keyed by a *client-supplied* 64-byte string and only shrank on
        // an explicit `End`, so a client could mint unlimited entries and every
        // one of them outlived the connection that made it.
        let mut actions = Actions::new();
        for (channel, state) in self.forget_conn(conn) {
            let sessions = self.channel_including(channel);
            actions.extend(Self::relay(
                sessions,
                social_envelope::Body::WatchState(state),
            ));
        }
        actions
    }

    async fn frame(&self, inbound: Inbound) -> Actions {
        let outer = ServiceKind::Social.outer_type();
        if inbound.type_id != outer {
            return Actions::new();
        }
        let Ok(envelope) = SocialEnvelope::decode(inbound.payload.as_slice()) else {
            // Dropped silently before: an envelope this service cannot read
            // means a client newer than the server, and the symptom is a
            // feature that does nothing at all.
            tracing::debug!(
                conn = inbound.conn,
                session = inbound.session,
                len = inbound.payload.len(),
                "undecodable SocialEnvelope"
            );
            return Actions::new();
        };

        match envelope.body {
            // Relayed to the channel *and* the sender: the client renders what
            // the server delivers rather than what it sent.
            Some(social_envelope::Body::Reaction(mut reaction)) => {
                if !self.may_react(&inbound, &reaction).await {
                    return Actions::new();
                }
                let sessions = self.channel_including(reaction.channel);
                reaction.actor = inbound.session;
                // The durable half of the identity, and the one a receiver
                // keys on: a session id is recycled, a certificate is the
                // person. Empty for a peer that presented none.
                reaction.actor_cert = self.roster.cert_of(inbound.session).unwrap_or_default();
                Self::relay(sessions, social_envelope::Body::Reaction(reaction))
            }
            // Everyone but the sender, who knows they are typing. murmur is
            // explicit about the exclusion (`Messages.cpp:4098`).
            Some(social_envelope::Body::Typing(mut typing)) => {
                let sessions = self.channel_excluding(typing.channel, inbound.session);
                typing.actor = inbound.session;
                Self::relay(sessions, social_envelope::Body::Typing(typing))
            }
            Some(social_envelope::Body::Receipt(mut receipt)) => {
                let sessions = self.channel_including(receipt.channel);
                receipt.actor = inbound.session;
                // The durable half of the identity, as with a reaction: a
                // receiver keys read watermarks per reader, and a session id
                // is recycled. Empty for a peer that presented none.
                receipt.actor_cert = self.roster.cert_of(inbound.session).unwrap_or_default();
                // Stamped too: receivers order watermark updates by this, and
                // the sender's clock is the one guaranteed to disagree with
                // everybody else's.
                receipt.at_ms = starling_runtime::ids::now_ms();
                // Same reason pchat logs "stored an encrypted message": a
                // client that never sends a watermark is indistinguishable
                // from a relay that dropped it, unless the arrival is on
                // record.
                tracing::debug!(
                    session = inbound.session,
                    channel = receipt.channel,
                    readers = sessions.len(),
                    "relayed a read watermark"
                );
                Self::relay(sessions, social_envelope::Body::Receipt(receipt))
            }
            Some(social_envelope::Body::Poll(poll)) => self.on_poll(&inbound, poll).await,
            Some(social_envelope::Body::Vote(vote)) => self.on_vote(&inbound, &vote).await,
            Some(social_envelope::Body::Watch(sync)) => {
                let Some(state) = self.watch(&sync, inbound.session, inbound.conn) else {
                    return Actions::new();
                };
                let sessions = self.channel_including(state.channel);
                Self::relay(sessions, social_envelope::Body::WatchState(state))
            }
            Some(social_envelope::Body::Stroke(mut stroke)) => {
                let sessions = self.channel_excluding(stroke.channel, inbound.session);
                stroke.actor = inbound.session;
                // Bounded before it is relayed. Flat x,y pairs, hence twice.
                stroke.points.truncate(MAX_STROKE_POINTS * 2);
                Self::relay(sessions, social_envelope::Body::Stroke(stroke))
            }
            Some(social_envelope::Body::Clear(mut clear)) => {
                let sessions = self.channel_excluding(clear.channel, inbound.session);
                clear.actor = inbound.session;
                Self::relay(sessions, social_envelope::Body::Clear(clear))
            }
            // Server-to-client bodies, and an envelope with nothing in it.
            // Answering would mean echoing a client's own claim about state
            // only the server holds.
            Some(social_envelope::Body::PollState(_) | social_envelope::Body::WatchState(_))
            | None => Actions::new(),
        }
    }
}

impl Serve for SocialService {
    const NAME: &'static str = "social";

    async fn build(ctx: ServiceContext) -> Result<Arc<Self>, ServiceError> {
        ctx.health.gate(VIEW_GATE);
        let store = ctx.storage().await?;
        store.migrate(SCHEMA).await?;
        Ok(Arc::new(Self {
            store,
            polls: Mutex::new(Polls::default()),
            poll_writes: tokio::sync::Mutex::new(()),
            watches: Mutex::new(HashMap::new()),
            roster: Arc::new(Roster::new()),
            // No declared ceiling: nothing caps the number of watch sessions a
            // server may hold, so this reports a count rather than a
            // percentage. What it is for is the shape over time -- a count that
            // does not come back down when everybody disconnects is the leak.
            watches_gauge: ctx.pressure.gauge("watches", 0),
            permit: Permit::new(ctx.resolver),
            fanout: Fanout::default(),
        }))
    }

    async fn run(self: Arc<Self>, ctx: ServiceContext) -> Result<(), ServiceError> {
        let follower = Arc::clone(&self.roster).follow(ctx.clone(), Self::NAME, VIEW_GATE);
        let sweeper = tokio::spawn(Arc::clone(&self).sweep_forever(ctx.instances()));
        ctx.shutdown.wait().await;
        sweeper.abort();
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
    use starling_proto_fancy::control::server_action;
    use starling_proto_fancy::fancy::social::{DrawStroke, ReadReceipt, Typing};
    use starling_proto_fancy::sessionview::Session;

    /// The server instance every test uses.
    const SCOPE: u32 = 1;
    /// The channel Alice and Bob are both in.
    const CHANNEL: u32 = 4;

    /// An empty in-memory database with the schema applied. Named uniquely per
    /// call: `cache=shared` makes same-named in-memory databases visible to
    /// every connection that names them.
    async fn memory_store() -> Store {
        use std::sync::atomic::{AtomicU64, Ordering};
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let id = NEXT.fetch_add(1, Ordering::Relaxed);
        let store = Store::open(
            &format!("sqlite:file:social-test-{id}?mode=memory&cache=shared"),
            1,
        )
        .await
        .expect("in-memory database");
        store.migrate(SCHEMA).await.expect("schema");
        store
    }

    /// A service whose roster holds `sessions`, all in [`CHANNEL`].
    ///
    /// The roster is warm, because a cold one addresses nobody and every
    /// assertion below would pass vacuously.
    async fn service(sessions: &[u32]) -> Arc<SocialService> {
        on_store(memory_store().await, sessions)
    }

    /// As [`service`], on `store`: a second call on the same store is the
    /// service after a restart, with nothing in memory.
    fn on_store(store: Store, sessions: &[u32]) -> Arc<SocialService> {
        let roster = Roster::new();
        roster.replace(
            sessions
                .iter()
                .map(|session| Session {
                    session: *session,
                    channel: CHANNEL,
                    ..Session::default()
                })
                .collect(),
        );
        Arc::new(SocialService {
            store,
            polls: Mutex::new(Polls::default()),
            poll_writes: tokio::sync::Mutex::new(()),
            watches: Mutex::new(HashMap::new()),
            watches_gauge: starling_runtime::pressure::Pressure::new().gauge("watches", 0),
            roster: Arc::new(roster),
            // Points at a `permissions` nothing is serving, so every check
            // denies. Only reactions ask, and the reaction test says so.
            permit: Permit::new(starling_runtime::channel::Resolver::new(
                Arc::new(starling_runtime::config::Config::with_defaults(
                    std::path::Path::new("/run/starling"),
                )),
                starling_runtime::inproc::Broker::new(),
            )),
            fanout: Fanout::default(),
        })
    }

    fn frame(session: u32, envelope: &SocialEnvelope) -> Inbound {
        Inbound {
            conn: 1,
            session,
            type_id: ServiceKind::Social.outer_type(),
            payload: envelope.encode_to_vec(),
            gateway: "gw".to_owned(),
            scope: SCOPE,
        }
    }

    fn poll(id: &str, multiple: bool) -> SocialEnvelope {
        SocialEnvelope {
            body: Some(social_envelope::Body::Poll(Poll {
                poll_id: id.to_owned(),
                channel: CHANNEL,
                question: "which?".to_owned(),
                options: vec!["a".to_owned(), "b".to_owned()],
                multiple,
                closes_at_ms: 0,
                creator: 0,
            })),
        }
    }

    /// The one `Send` in `actions`, as its sessions and decoded envelope.
    fn sent(actions: &Actions) -> (Vec<u32>, SocialEnvelope) {
        assert_eq!(actions.len(), 1, "expected exactly one action");
        let Some(server_action::Action::Send(send)) = &actions[0].action else {
            panic!("expected a Send");
        };
        assert!(
            send.conns.is_empty(),
            "a social relay is addressed at sessions, not connections"
        );
        assert!(
            !send.sessions.is_empty(),
            "a Send naming no sessions reaches the whole server"
        );
        let mut sessions = send.sessions.clone();
        sessions.sort_unstable();
        (
            sessions,
            SocialEnvelope::decode(send.payload.as_slice()).expect("a social envelope"),
        )
    }

    #[tokio::test]
    async fn a_typing_indicator_carries_the_actor_the_server_resolved() {
        // The client cannot fill this in and leaves it 0; a shipped client
        // drops an indicator whose actor is 0, so the feature did nothing.
        let service = service(&[7, 8]).await;
        let envelope = SocialEnvelope {
            body: Some(social_envelope::Body::Typing(Typing {
                channel: CHANNEL,
                actor: 0,
                typing: true,
            })),
        };
        let actions = service.frame(frame(7, &envelope)).await;
        let (sessions, relayed) = sent(&actions);

        assert_eq!(sessions, vec![8], "everyone in the channel but the typist");
        let Some(social_envelope::Body::Typing(typing)) = relayed.body else {
            panic!("expected a typing relay");
        };
        assert_eq!(typing.actor, 7, "the server writes the actor");
    }

    #[tokio::test]
    async fn a_read_receipt_names_its_reader_by_certificate_and_the_servers_clock() {
        // `actor` is a session id, recycled per connection, and a receiver
        // keys read watermarks per reader - without the certificate every
        // reader collapses into one, exactly as reactions did. The timestamp
        // orders watermark updates at the receiver, so it has to come from
        // the one clock every receiver shares.
        let service = service(&[7, 8]).await;
        service.roster.upsert(&Session {
            session: 7,
            channel: CHANNEL,
            cert_hash: b"reader-cert".to_vec(),
            ..Session::default()
        });
        let envelope = SocialEnvelope {
            body: Some(social_envelope::Body::Receipt(ReadReceipt {
                channel: CHANNEL,
                message_id: "m-9".to_owned(),
                actor: 0,
                at_ms: 0,
                actor_cert: b"a-claimed-identity".to_vec(),
            })),
        };
        let actions = service.frame(frame(7, &envelope)).await;
        let (sessions, relayed) = sent(&actions);

        assert_eq!(sessions, vec![7, 8], "the author reads their own tick too");
        let Some(social_envelope::Body::Receipt(receipt)) = relayed.body else {
            panic!("expected a receipt relay");
        };
        assert_eq!(receipt.actor, 7, "the server writes the actor");
        assert_eq!(
            receipt.actor_cert,
            b"reader-cert".to_vec(),
            "the certificate is the connection's own, not the claim"
        );
        assert!(
            receipt.at_ms > 0,
            "the server stamps when the read was reported"
        );
        assert_eq!(
            receipt.message_id, "m-9",
            "the watermark itself is untouched"
        );
    }

    #[tokio::test]
    async fn a_relay_never_reaches_a_channel_the_sender_is_not_in() {
        // The bug this whole file changed shape for: an unaddressed Send goes
        // to every authenticated client on the server.
        let service = service(&[7, 8]).await;
        let envelope = SocialEnvelope {
            body: Some(social_envelope::Body::Typing(Typing {
                channel: CHANNEL + 1,
                actor: 0,
                typing: true,
            })),
        };
        assert!(
            service.frame(frame(7, &envelope)).await.is_empty(),
            "nobody is in that channel, so the relay must reach nobody"
        );
    }

    #[tokio::test]
    async fn a_poll_is_relayed_to_its_channel_including_its_creator() {
        // murmur relays to the sender too, so everyone holds one
        // server-stamped poll rather than two versions of it.
        let service = service(&[7, 8]).await;
        let actions = service.frame(frame(7, &poll("p1", false))).await;
        let (sessions, relayed) = sent(&actions);

        assert_eq!(sessions, vec![7, 8]);
        let Some(social_envelope::Body::Poll(poll)) = relayed.body else {
            panic!("expected the poll itself, which is what a client reads");
        };
        assert_eq!(poll.creator, 7, "the server writes the creator");
    }

    #[tokio::test]
    async fn a_vote_is_relayed_with_the_channel_the_poll_was_created_in() {
        // The vote message carries no channel of its own, and the client drops
        // one it cannot route, so the server fills it in from the poll.
        let service = service(&[7, 8]).await;
        let _ = service.frame(frame(7, &poll("p1", false))).await;

        let ballot = SocialEnvelope {
            body: Some(social_envelope::Body::Vote(PollVote {
                poll_id: "p1".to_owned(),
                options: vec![1],
                voter: 0,
                channel: 0,
            })),
        };
        let actions = service.frame(frame(8, &ballot)).await;
        let (sessions, relayed) = sent(&actions);

        assert_eq!(sessions, vec![7, 8], "the voter sees their own vote too");
        let Some(social_envelope::Body::Vote(vote)) = relayed.body else {
            panic!("expected the vote itself");
        };
        assert_eq!(vote.voter, 8, "the server writes the voter");
        assert_eq!(vote.channel, CHANNEL, "and the channel the poll is in");
        assert_eq!(vote.options, vec![1]);
    }

    #[tokio::test]
    async fn a_single_choice_poll_counts_one_vote_even_when_several_are_sent() {
        // Otherwise "single choice" is a label rather than a rule.
        let service = service(&[7, 8]).await;
        let _ = service.frame(frame(7, &poll("p1", false))).await;
        let Ballot::Counted(vote) = service.vote(SCOPE, &ballot("p1", vec![0, 1]), 8, 0).await
        else {
            panic!("a vote applies");
        };
        assert_eq!(vote.options, vec![0]);
        let state = service.state(SCOPE, "p1", 0).expect("the poll is held");
        assert_eq!(state.tallies, vec![1, 0]);
    }

    #[tokio::test]
    async fn a_second_ballot_replaces_the_first_rather_than_adding_to_it() {
        // A running total cannot be un-counted, which is why ballots are kept
        // per voter.
        let service = service(&[7, 8]).await;
        let _ = service.frame(frame(7, &poll("p1", false))).await;
        for option in [0_u32, 1] {
            assert!(matches!(
                service.vote(SCOPE, &ballot("p1", vec![option]), 8, 0).await,
                Ballot::Counted(_)
            ));
        }
        let state = service.state(SCOPE, "p1", 0).expect("the poll is held");
        assert_eq!(state.tallies, vec![0, 1], "one voter, one ballot");
    }

    #[tokio::test]
    async fn a_vote_in_a_closed_poll_is_refused() {
        let service = service(&[7, 8]).await;
        let mut envelope = poll("p1", false);
        if let Some(social_envelope::Body::Poll(ref mut poll)) = envelope.body {
            poll.closes_at_ms = 1_000;
        }
        let _ = service.frame(frame(7, &envelope)).await;
        assert_eq!(
            service.vote(SCOPE, &ballot("p1", vec![0]), 8, 2_000).await,
            Ballot::Closed,
            "a closed poll takes no more votes"
        );
    }

    #[tokio::test]
    async fn a_vote_for_an_option_that_does_not_exist_is_dropped() {
        // The tally is indexed by the option number a peer sends.
        let service = service(&[7, 8]).await;
        let _ = service.frame(frame(7, &poll("p1", true))).await;
        assert_eq!(
            service.vote(SCOPE, &ballot("p1", vec![99]), 8, 0).await,
            Ballot::Empty
        );
    }

    #[tokio::test]
    async fn a_reaction_without_the_enter_permission_reaches_nobody() {
        // The `permissions` service is unreachable in these tests, and an
        // unreachable check denies. murmur gates reactions the same way.
        let service = service(&[7, 8]).await;
        let envelope = SocialEnvelope {
            body: Some(social_envelope::Body::Reaction(Reaction {
                channel: CHANNEL,
                message_id: "m1".to_owned(),
                emoji: Some(starling_proto_fancy::fancy::wire::Emoji {
                    kind: Some(starling_proto_fancy::fancy::wire::emoji::Kind::Unicode(
                        "\u{1f44d}".to_owned(),
                    )),
                }),
                actor: 0,
                actor_cert: Vec::new(),
                remove: false,
            })),
        };
        assert!(service.frame(frame(7, &envelope)).await.is_empty());
    }

    #[tokio::test]
    async fn only_the_host_may_drive_a_watch_session() {
        // A viewer's position would drag everyone back to their buffer.
        let service = service(&[7, 8]).await;
        let start = WatchSync {
            session_id: "w1".to_owned(),
            channel: CHANNEL,
            kind: watch_sync::Kind::Start as i32,
            url: "https://example.org/v".to_owned(),
            position_s: 0.0,
            playing: true,
            actor: 0,
            new_host: 0,
        };
        let _ = service.watch(&start, 5, 100).expect("host starts");

        let seek = WatchSync {
            kind: watch_sync::Kind::State as i32,
            position_s: 90.0,
            ..start
        };
        assert!(
            service.watch(&seek, 6, 101).is_none(),
            "a viewer cannot seek"
        );
        let driven = service.watch(&seek, 5, 100).expect("the host can");
        assert!((driven.position_s - 90.0).abs() < f64::EPSILON);
    }

    /// Defect 8: `social` never implemented `closed`.
    #[tokio::test]
    async fn a_disconnect_takes_every_watch_that_connection_minted() {
        let service = service(&[7, 8]).await;

        // One client, a hundred ids it made up. The map is keyed by this
        // string, so this is the whole of the attack: no permission is needed
        // and nothing but an explicit `End` used to remove an entry.
        for id in 0..100 {
            let sync = WatchSync {
                session_id: format!("mint-{id}"),
                channel: CHANNEL,
                kind: watch_sync::Kind::Start as i32,
                url: "https://example.org/v".to_owned(),
                position_s: 0.0,
                playing: true,
                actor: 0,
                new_host: 0,
            };
            let _ = service.watch(&sync, 7, 42).expect("the host starts one");
        }
        assert_eq!(
            service.watches.lock().expect("watches").len(),
            100,
            "the set-up itself must be what the client can do today"
        );

        let _ = service.closed(42, "gone").await;

        assert!(
            service.watches.lock().expect("watches").is_empty(),
            "every entry a closed connection minted must go with it"
        );
    }

    /// Defect 8: a viewer leaving is not the same event as a host leaving.
    #[tokio::test]
    async fn a_viewer_disconnecting_leaves_the_session_up_without_them() {
        let service = service(&[7, 8]).await;
        let start = WatchSync {
            session_id: "w1".to_owned(),
            channel: CHANNEL,
            kind: watch_sync::Kind::Start as i32,
            url: "https://example.org/v".to_owned(),
            position_s: 0.0,
            playing: true,
            actor: 0,
            new_host: 0,
        };
        let _ = service.watch(&start, 7, 100).expect("the host starts");
        let joined = service
            .watch(
                &WatchSync {
                    kind: watch_sync::Kind::Join as i32,
                    ..start
                },
                8,
                101,
            )
            .expect("a viewer joins");
        assert_eq!(joined.viewers, vec![8]);

        let actions = service.closed(101, "gone").await;

        let watches = service.watches.lock().expect("watches");
        let record = watches.get("w1").expect("the session outlives its viewer");
        assert!(
            record.state.viewers.is_empty(),
            "the departed viewer must be dropped from the state"
        );
        assert!(
            record.viewer_conns.is_empty(),
            "and from the connections behind it"
        );
        assert!(
            !actions.is_empty(),
            "the channel must be told, the way an explicit Leave tells it"
        );
    }

    #[tokio::test]
    async fn a_stroke_from_a_peer_is_bounded_before_it_is_relayed() {
        let service = service(&[7, 8]).await;
        let envelope = SocialEnvelope {
            body: Some(social_envelope::Body::Stroke(DrawStroke {
                channel: CHANNEL,
                actor: 0,
                colour: "#fff".to_owned(),
                width: 2.0,
                points: vec![0.0; MAX_STROKE_POINTS * 4],
            })),
        };
        let actions = service.frame(frame(7, &envelope)).await;
        let (sessions, relayed) = sent(&actions);

        assert_eq!(sessions, vec![8], "the artist already has their own stroke");
        let Some(social_envelope::Body::Stroke(stroke)) = relayed.body else {
            panic!("expected a stroke relay");
        };
        assert_eq!(stroke.points.len(), MAX_STROKE_POINTS * 2);
        assert_eq!(stroke.actor, 7);
    }

    #[test]
    fn the_poll_table_evicts_rather_than_growing_without_limit() {
        // Fed by clients, so it is bounded like everything else here.
        let mut polls = Polls::default();
        for id in 0..(MAX_POLLS + 8) {
            polls.insert(
                (SCOPE, id.to_string()),
                PollRecord {
                    poll: Poll::default(),
                    ballots: HashMap::new(),
                    expires_at_ms: u64::MAX,
                },
            );
        }
        assert_eq!(polls.by_id.len(), MAX_POLLS);
        assert!(
            !polls.by_id.contains_key(&(SCOPE, "0".to_owned())),
            "the oldest poll is the one that goes"
        );
    }

    fn ballot(id: &str, options: Vec<u32>) -> PollVote {
        PollVote {
            poll_id: id.to_owned(),
            options,
            voter: 0,
            channel: 0,
        }
    }

    fn vote_frame(id: &str, option: u32) -> SocialEnvelope {
        SocialEnvelope {
            body: Some(social_envelope::Body::Vote(ballot(id, vec![option]))),
        }
    }

    #[tokio::test]
    async fn a_poll_and_its_ballots_survive_a_restart() {
        // The card is still in chat history after a restart, so a vote on it
        // has to find the poll and every ballot cast before.
        let store = memory_store().await;
        let before = on_store(store.clone(), &[7, 8]);
        let _ = before.frame(frame(7, &poll("p1", false))).await;
        let _ = sent(&before.frame(frame(8, &vote_frame("p1", 1))).await);

        let after = on_store(store, &[7, 8]);
        let actions = after.frame(frame(7, &vote_frame("p1", 0))).await;
        let (sessions, relayed) = sent(&actions);
        assert_eq!(sessions, vec![7, 8]);
        let Some(social_envelope::Body::Vote(vote)) = relayed.body else {
            panic!("expected the vote itself");
        };
        assert_eq!(
            vote.channel, CHANNEL,
            "the channel comes from the stored poll"
        );
        assert_eq!(
            after.state(SCOPE, "p1", 0).expect("loaded").tallies,
            vec![1, 1],
            "the ballot cast before the restart still counts"
        );

        // And the voter from before is still held to one ballot.
        let _ = sent(&after.frame(frame(8, &vote_frame("p1", 0))).await);
        assert_eq!(
            after.state(SCOPE, "p1", 0).expect("held").tallies,
            vec![2, 0]
        );
    }

    #[tokio::test]
    async fn a_closed_poll_stays_closed_after_a_restart() {
        let store = memory_store().await;
        let now = starling_runtime::ids::now_ms();
        let mut envelope = poll("p1", false);
        if let Some(social_envelope::Body::Poll(ref mut poll)) = envelope.body {
            poll.closes_at_ms = now + 1_000;
        }
        let _ = on_store(store.clone(), &[7, 8])
            .frame(frame(7, &envelope))
            .await;

        let after = on_store(store, &[7, 8]);
        assert_eq!(
            after
                .vote(SCOPE, &ballot("p1", vec![0]), 8, now + 2_000)
                .await,
            Ballot::Closed
        );
    }

    #[tokio::test]
    async fn a_poll_evicted_from_the_cache_is_still_votable() {
        // Eviction bounds memory; it used to forget the poll as well.
        let service = service(&[7, 8]).await;
        for id in 0..=MAX_POLLS {
            let _ = service.frame(frame(7, &poll(&id.to_string(), false))).await;
        }
        assert!(
            service.state(SCOPE, "0", 0).is_none(),
            "evicted from memory"
        );
        let (_, relayed) = sent(&service.frame(frame(8, &vote_frame("0", 1))).await);
        assert!(matches!(relayed.body, Some(social_envelope::Body::Vote(_))));
    }

    #[tokio::test]
    async fn a_vote_on_a_poll_the_server_does_not_have_is_refused_to_the_voter() {
        // It was dropped without a word, which looks like a relay that lost it.
        let service = service(&[7, 8]).await;
        let actions = service.frame(frame(8, &vote_frame("nope", 0))).await;
        assert_eq!(actions.len(), 1, "one refusal, and no relay");
        let Some(server_action::Action::Send(send)) = &actions[0].action else {
            panic!("expected a Send");
        };
        assert_eq!(send.conns, vec![1], "to the voter's connection only");
        assert!(send.sessions.is_empty());
        let denied = starling_proto::proto::tcp::PermissionDenied::decode(send.payload.as_slice())
            .expect("a PermissionDenied");
        assert_eq!(
            denied.r#type,
            Some(starling_proto::proto::tcp::permission_denied::DenyType::Text as i32)
        );
        assert_eq!(
            denied.channel_id, None,
            "a channel would make the client drop its listen there"
        );
        assert!(denied.reason.is_some_and(|reason| !reason.is_empty()));
    }

    #[tokio::test]
    async fn the_sweep_forgets_a_poll_past_its_retention() {
        let store = memory_store().await;
        let service = on_store(store.clone(), &[7, 8]);
        let Some(social_envelope::Body::Poll(created)) = poll("p1", false).body else {
            panic!("a poll");
        };
        let _ = service.create(SCOPE, created, 7, 0).await.expect("created");
        let _ = service.vote(SCOPE, &ballot("p1", vec![0]), 8, 0).await;

        assert_eq!(service.sweep(SCOPE, POLL_RETENTION_MS - 1).await, 0);
        assert_eq!(service.sweep(SCOPE, POLL_RETENTION_MS).await, 1);
        assert!(
            service.state(SCOPE, "p1", 0).is_none(),
            "gone from the cache"
        );
        assert_eq!(
            on_store(store, &[7, 8])
                .vote(SCOPE, &ballot("p1", vec![0]), 8, POLL_RETENTION_MS)
                .await,
            Ballot::Unknown,
            "and from storage"
        );
    }

    #[test]
    fn a_far_off_deadline_cannot_keep_a_poll_forever() {
        let poll = Poll {
            closes_at_ms: u64::MAX,
            ..Poll::default()
        };
        assert_eq!(poll_expiry(&poll, 0), 2 * POLL_RETENTION_MS);
        let open = Poll::default();
        assert_eq!(poll_expiry(&open, 5), 5 + POLL_RETENTION_MS);
    }
}
