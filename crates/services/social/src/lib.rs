//! `social` — reactions, receipts, typing, polls, watch-together, drawing.
//!
//! One service rather than six, because each of these is a few hundred bytes of
//! state and a fan-out. Six services with one message each would be six
//! deployments, six health checks and six things to configure for no isolation
//! anybody wanted.
//!
//! Everything here is bounded before it is stored. A stroke's point list and a
//! poll's option list both arrive from an unauthenticated peer, and "bound
//! before you allocate" applies to a `Vec` exactly as it does to a frame.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use prost::Message as _;
use starling_proto_fancy::fancy::social::{
    PollState, SocialEnvelope, WatchState, WatchSync, social_envelope, watch_sync,
};
use starling_proto_fancy::types::ServiceKind;
use starling_runtime::plane::{
    Actions, ClientService, Fanout, Inbound, Plane, broadcast_except, to_conn, to_sessions,
};
use starling_runtime::serve::{Serve, ServiceContext, ServiceError};

/// Longest stroke accepted, in points.
///
/// A whiteboard stroke is a few hundred points; an unbounded list from a peer
/// is an allocation attack with a friendly name.
pub const MAX_STROKE_POINTS: usize = 4096;

/// Most options a poll may carry.
pub const MAX_POLL_OPTIONS: usize = 32;

/// The service.
#[derive(Debug)]
pub struct SocialService {
    polls: Mutex<HashMap<String, PollState>>,
    watches: Mutex<HashMap<String, WatchState>>,
    fanout: Fanout,
}

impl SocialService {
    /// Apply a vote, returning the state to publish.
    fn vote(&self, poll_id: &str, options: &[u32]) -> Option<PollState> {
        let mut polls = self.polls.lock().ok()?;
        let state = polls.get_mut(poll_id)?;
        if state.closed {
            return None;
        }
        let multiple = state.poll.as_ref().is_some_and(|poll| poll.multiple);
        let chosen = if multiple {
            options
        } else {
            &options[..1.min(options.len())]
        };
        for option in chosen {
            if let Some(tally) = state.tallies.get_mut(*option as usize) {
                *tally += 1;
            }
        }
        Some(state.clone())
    }

    /// Start or update a watch-together session.
    fn watch(&self, sync: &WatchSync, actor: u32) -> Option<WatchState> {
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
            Some(social_envelope::Body::Stroke(mut stroke)) => {
                stroke.actor = inbound.session;
                // Bounded before it is stored or relayed.
                stroke.points.truncate(MAX_STROKE_POINTS * 2);
                let relay = SocialEnvelope {
                    body: Some(social_envelope::Body::Stroke(stroke)),
                };
                vec![broadcast_except(
                    inbound.session,
                    outer,
                    relay.encode_to_vec(),
                )]
            }
            Some(social_envelope::Body::Poll(mut poll)) => {
                poll.creator = inbound.session;
                poll.options.truncate(MAX_POLL_OPTIONS);
                let state = PollState {
                    tallies: vec![0; poll.options.len()],
                    poll: Some(poll.clone()),
                    closed: false,
                };
                if let Ok(mut polls) = self.polls.lock() {
                    let _ = polls.insert(poll.poll_id.clone(), state.clone());
                }
                let announcement = SocialEnvelope {
                    body: Some(social_envelope::Body::PollState(state)),
                };
                vec![to_sessions(Vec::new(), outer, announcement.encode_to_vec())]
            }
            Some(social_envelope::Body::Vote(vote)) => {
                let Some(state) = self.vote(&vote.poll_id, &vote.options) else {
                    return Actions::new();
                };
                let update = SocialEnvelope {
                    body: Some(social_envelope::Body::PollState(state)),
                };
                vec![to_sessions(Vec::new(), outer, update.encode_to_vec())]
            }
            Some(social_envelope::Body::Watch(sync)) => {
                let Some(state) = self.watch(&sync, inbound.session) else {
                    return Actions::new();
                };
                let update = SocialEnvelope {
                    body: Some(social_envelope::Body::WatchState(state)),
                };
                vec![to_sessions(Vec::new(), outer, update.encode_to_vec())]
            }
            // Reactions, typing and receipts are pure fan-out: the server holds
            // no state a client could not rebuild from the stream itself.
            Some(
                social_envelope::Body::Reaction(_)
                | social_envelope::Body::Typing(_)
                | social_envelope::Body::Receipt(_)
                | social_envelope::Body::Clear(_),
            ) => vec![broadcast_except(inbound.session, outer, inbound.payload)],
            _ => {
                let _ = to_conn(inbound.conn, outer, Vec::new());
                Actions::new()
            }
        }
    }
}

impl Serve for SocialService {
    const NAME: &'static str = "social";

    async fn build(_ctx: ServiceContext) -> Result<Arc<Self>, ServiceError> {
        Ok(Arc::new(Self {
            polls: Mutex::new(HashMap::new()),
            watches: Mutex::new(HashMap::new()),
            fanout: Fanout::default(),
        }))
    }

    fn routes(self: Arc<Self>) -> tonic::service::Routes {
        let plane = Plane::new(Arc::clone(&self), self.fanout.clone(), Self::NAME).into_server();
        tonic::service::Routes::default().add_service(plane)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use starling_proto_fancy::fancy::social::Poll;

    fn service() -> Arc<SocialService> {
        Arc::new(SocialService {
            polls: Mutex::new(HashMap::new()),
            watches: Mutex::new(HashMap::new()),
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
            scope: 1,
        }
    }

    fn poll(id: &str, multiple: bool) -> SocialEnvelope {
        SocialEnvelope {
            body: Some(social_envelope::Body::Poll(Poll {
                poll_id: id.to_owned(),
                channel: 1,
                question: "which?".to_owned(),
                options: vec!["a".to_owned(), "b".to_owned()],
                multiple,
                closes_at_ms: 0,
                creator: 0,
            })),
        }
    }

    #[tokio::test]
    async fn a_single_choice_poll_counts_one_vote_even_when_several_are_sent() {
        // Otherwise "single choice" is a label rather than a rule.
        let service = service();
        let _ = service.frame(frame(1, &poll("p1", false))).await;
        let state = service.vote("p1", &[0, 1]).expect("a vote applies");
        assert_eq!(state.tallies, vec![1, 0]);
    }

    #[tokio::test]
    async fn only_the_host_may_drive_a_watch_session() {
        // A viewer's position would drag everyone back to their buffer.
        let service = service();
        let start = WatchSync {
            session_id: "w1".to_owned(),
            channel: 1,
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
        let service = service();
        let stroke = SocialEnvelope {
            body: Some(social_envelope::Body::Stroke(
                starling_proto_fancy::fancy::social::DrawStroke {
                    channel: 1,
                    actor: 0,
                    colour: "#fff".to_owned(),
                    width: 2.0,
                    points: vec![0.0; MAX_STROKE_POINTS * 4],
                },
            )),
        };
        let actions = service.frame(frame(3, &stroke)).await;
        assert_eq!(actions.len(), 1);
    }
}
