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
use starling_runtime::plane::{Actions, ClientService, Fanout, Inbound, Plane, to_sessions};
use starling_runtime::roster::Roster;
use starling_runtime::serve::{Serve, ServiceContext, ServiceError};

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

/// How many polls are remembered per server instance.
///
/// The oldest is evicted past this. A poll nobody can vote in any more is a
/// display artefact the clients already hold; keeping every poll a server has
/// ever seen would be an unbounded map fed by clients.
pub const MAX_POLLS: usize = 512;

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
    ballots: HashMap<u32, Vec<u32>>,
}

impl PollRecord {
    /// The tallies, as the canon reports them.
    fn tallies(&self) -> Vec<u32> {
        let mut tallies = vec![0_u32; self.poll.options.len()];
        // Sorted, so a tally is the same list whichever order the ballots
        // happen to hash into. Addition commutes; the lint is about the two
        // runs of one server disagreeing about anything derived from order.
        let mut voters: Vec<&u32> = self.ballots.keys().collect();
        voters.sort_unstable();
        for chosen in voters.iter().filter_map(|voter| self.ballots.get(voter)) {
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
}

/// The service.
#[derive(Debug)]
pub struct SocialService {
    polls: Mutex<Polls>,
    watches: Mutex<HashMap<String, WatchState>>,
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
    /// something no client produces, and the canon has no refusal message to
    /// answer with.
    fn create(&self, scope: u32, mut poll: Poll, creator: u32) -> Option<Poll> {
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
        };
        self.polls
            .lock()
            .ok()?
            .insert((scope, poll.poll_id.clone()), record);
        Some(poll)
    }

    /// Apply a vote, returning it as it should be relayed.
    ///
    /// The returned vote is the *normalised* one: the voter stamped, the
    /// poll's channel filled in (the canon vote carries none, and the client
    /// needs one to route the vote to its card), out-of-range options dropped
    /// and a single-choice poll held to one option. Relaying the peer's own
    /// bytes instead would let one client show a tally another never counts.
    fn vote(&self, scope: u32, vote: &PollVote, voter: u32, now_ms: u64) -> Option<PollVote> {
        let mut polls = self.polls.lock().ok()?;
        let record = polls.by_id.get_mut(&(scope, vote.poll_id.clone()))?;
        if record.closed_at(now_ms) {
            return None;
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
            return None;
        }

        // Replaces rather than adds: one voter, one ballot, which is also what
        // the client's own store does with a second vote from one session.
        let _ = record.ballots.insert(voter, chosen.clone());
        Some(PollVote {
            poll_id: vote.poll_id.clone(),
            options: chosen,
            voter,
            channel: record.poll.channel,
        })
    }

    /// The tally, for a caller that wants the server's own count.
    ///
    /// Not on the wire: no shipped client reads [`PollState`], and a message
    /// nobody decodes is bytes on every vote for nothing. It is the answer a
    /// query would return the day the canon grows one, and it is what the
    /// tests assert on.
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
    fn watch(&self, sync: &WatchSync, actor: u32) -> Option<WatchState> {
        if sync.session_id.is_empty() || sync.session_id.len() > MAX_ID_BYTES {
            return None;
        }
        let mut watches = self.watches.lock().ok()?;
        let kind = watch_sync::Kind::try_from(sync.kind).unwrap_or(watch_sync::Kind::State);
        let state = watches
            .entry(sync.session_id.clone())
            .or_insert_with(|| WatchState {
                session_id: sync.session_id.clone(),
                channel: sync.channel,
                host: actor,
                viewers: Vec::new(),
                url: sync.url.clone(),
                position_s: sync.position_s,
                playing: sync.playing,
            });

        match kind {
            watch_sync::Kind::Start => {
                state.host = actor;
                state.url = sync.url.clone();
            }
            watch_sync::Kind::Join => {
                if !state.viewers.contains(&actor) {
                    state.viewers.push(actor);
                }
            }
            watch_sync::Kind::Leave => state.viewers.retain(|viewer| *viewer != actor),
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
            }
            watch_sync::Kind::End => {
                let ended = state.clone();
                let _ = watches.remove(&sync.session_id);
                return Some(ended);
            }
        }
        Some(state.clone())
    }
}

impl ClientService for SocialService {
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
            // Including the creator, so everyone in the channel holds the
            // server-stamped poll rather than two versions of it.
            Some(social_envelope::Body::Poll(poll)) => {
                let channel = poll.channel;
                let Some(stamped) = self.create(inbound.scope, poll, inbound.session) else {
                    return Actions::new();
                };
                let sessions = self.channel_including(channel);
                Self::relay(sessions, social_envelope::Body::Poll(stamped))
            }
            Some(social_envelope::Body::Vote(vote)) => {
                let Some(stamped) = self.vote(
                    inbound.scope,
                    &vote,
                    inbound.session,
                    starling_runtime::ids::now_ms(),
                ) else {
                    return Actions::new();
                };
                let sessions = self.channel_including(stamped.channel);
                Self::relay(sessions, social_envelope::Body::Vote(stamped))
            }
            Some(social_envelope::Body::Watch(sync)) => {
                let Some(state) = self.watch(&sync, inbound.session) else {
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
        Ok(Arc::new(Self {
            polls: Mutex::new(Polls::default()),
            watches: Mutex::new(HashMap::new()),
            roster: Arc::new(Roster::new()),
            permit: Permit::new(ctx.resolver),
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
    use starling_proto_fancy::control::server_action;
    use starling_proto_fancy::fancy::social::{DrawStroke, ReadReceipt, Typing};
    use starling_proto_fancy::sessionview::Session;

    /// The server instance every test uses.
    const SCOPE: u32 = 1;
    /// The channel Alice and Bob are both in.
    const CHANNEL: u32 = 4;

    /// A service whose roster holds `sessions`, all in [`CHANNEL`].
    ///
    /// The roster is warm, because a cold one addresses nobody and every
    /// assertion below would pass vacuously.
    fn service(sessions: &[u32]) -> Arc<SocialService> {
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
            polls: Mutex::new(Polls::default()),
            watches: Mutex::new(HashMap::new()),
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
        let service = service(&[7, 8]);
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
        let service = service(&[7, 8]);
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
        let service = service(&[7, 8]);
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
        let service = service(&[7, 8]);
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
        let service = service(&[7, 8]);
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
        let service = service(&[7, 8]);
        let _ = service.frame(frame(7, &poll("p1", false))).await;
        let vote = service
            .vote(
                SCOPE,
                &PollVote {
                    poll_id: "p1".to_owned(),
                    options: vec![0, 1],
                    voter: 0,
                    channel: 0,
                },
                8,
                0,
            )
            .expect("a vote applies");
        assert_eq!(vote.options, vec![0]);
        let state = service.state(SCOPE, "p1", 0).expect("the poll is held");
        assert_eq!(state.tallies, vec![1, 0]);
    }

    #[tokio::test]
    async fn a_second_ballot_replaces_the_first_rather_than_adding_to_it() {
        // A running total cannot be un-counted, which is why ballots are kept
        // per voter.
        let service = service(&[7, 8]);
        let _ = service.frame(frame(7, &poll("p1", false))).await;
        for option in [0_u32, 1] {
            let _ = service
                .vote(
                    SCOPE,
                    &PollVote {
                        poll_id: "p1".to_owned(),
                        options: vec![option],
                        voter: 0,
                        channel: 0,
                    },
                    8,
                    0,
                )
                .expect("a vote applies");
        }
        let state = service.state(SCOPE, "p1", 0).expect("the poll is held");
        assert_eq!(state.tallies, vec![0, 1], "one voter, one ballot");
    }

    #[tokio::test]
    async fn a_vote_in_a_closed_poll_is_refused() {
        let service = service(&[7, 8]);
        let mut envelope = poll("p1", false);
        if let Some(social_envelope::Body::Poll(ref mut poll)) = envelope.body {
            poll.closes_at_ms = 1_000;
        }
        let _ = service.frame(frame(7, &envelope)).await;
        assert!(
            service
                .vote(
                    SCOPE,
                    &PollVote {
                        poll_id: "p1".to_owned(),
                        options: vec![0],
                        voter: 0,
                        channel: 0,
                    },
                    8,
                    2_000
                )
                .is_none(),
            "a closed poll takes no more votes"
        );
    }

    #[tokio::test]
    async fn a_vote_for_an_option_that_does_not_exist_is_dropped() {
        // The tally is indexed by the option number a peer sends.
        let service = service(&[7, 8]);
        let _ = service.frame(frame(7, &poll("p1", true))).await;
        assert!(
            service
                .vote(
                    SCOPE,
                    &PollVote {
                        poll_id: "p1".to_owned(),
                        options: vec![99],
                        voter: 0,
                        channel: 0,
                    },
                    8,
                    0
                )
                .is_none()
        );
    }

    #[tokio::test]
    async fn a_reaction_without_the_enter_permission_reaches_nobody() {
        // The `permissions` service is unreachable in these tests, and an
        // unreachable check denies. murmur gates reactions the same way.
        let service = service(&[7, 8]);
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
        let service = service(&[7, 8]);
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
        let _ = service.watch(&start, 5).expect("host starts");

        let seek = WatchSync {
            kind: watch_sync::Kind::State as i32,
            position_s: 90.0,
            ..start
        };
        assert!(service.watch(&seek, 6).is_none(), "a viewer cannot seek");
        let driven = service.watch(&seek, 5).expect("the host can");
        assert!((driven.position_s - 90.0).abs() < f64::EPSILON);
    }

    #[tokio::test]
    async fn a_stroke_from_a_peer_is_bounded_before_it_is_relayed() {
        let service = service(&[7, 8]);
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
                },
            );
        }
        assert_eq!(polls.by_id.len(), MAX_POLLS);
        assert!(
            !polls.by_id.contains_key(&(SCOPE, "0".to_owned())),
            "the oldest poll is the one that goes"
        );
    }
}
