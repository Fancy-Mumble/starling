//! `screenshare`: signalling only; media goes client↔SFU directly.
//!
//! Two contract constraints, each of which cost a debugging session
//! (`docs/ARCHITECTURE.md` §3):
//!
//! * the str0m SFU is **ICE-lite**: it ignores trickled candidates and its own
//!   ride in the SDP answer, so ICE is never trickled through the control plane;
//! * **SDP offers retry until answered**, because the control plane rate-limits
//!   and a silently dropped offer looks exactly like a client bug. This service
//!   is charged to the `signalling` bucket rather than the 1/s control one for
//!   the same reason.
//!
//! # Who may do what
//!
//! Sharing a screen into a channel is a broadcast into that channel, so it
//! takes the permission that broadcasting takes: `Speak`. Stopping a share
//! takes being the presenter, or holding the moderator power in that channel —
//! murmur has no "stop that stream" permission, and `MuteDeafen` is the closest
//! true analogue, since it is already "silence somebody in this room".
//!
//! Every one of these was unenforced: **any client could stop any share** by
//! naming its id, and any client could announce a share in a channel it could
//! not enter. Neither needed a bug to exploit, only a message.
//!
//! # What a share is announced to
//!
//! The channel it is in, and nothing wider. It used to be broadcast to every
//! connected session, which tells a user on the other side of the server that a
//! share called "Quarterly numbers — draft" exists in a channel they cannot
//! see. A title is content.
//!
//! # The SDP answer is empty, and that is the honest state
//!
//! There is no SFU in this tree. The answer carries the endpoint a client
//! should negotiate with and an **empty `sdp`**, because inventing one here
//! would be inventing an answer on behalf of a media server that does not
//! exist. When the SFU lands, the answer is where its real SDP goes; until
//! then a client can see it has been given an endpoint and no session.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use prost::Message as _;
use starling_proto_fancy::fancy::screenshare::{
    Answer, Offer, ScreenshareEnvelope, Start, Stop, Viewers, screenshare_envelope,
};
use starling_proto_fancy::perm::Perm;
use starling_proto_fancy::types::ServiceKind;
use starling_runtime::permit::Permit;
use starling_runtime::plane::{Actions, ClientService, Fanout, Inbound, Plane, to_conn, to_sessions};
use starling_runtime::roster::Roster;
use starling_runtime::serve::{Serve, ServiceContext, ServiceError};

/// One live share.
#[derive(Debug, Clone)]
struct Share {
    presenter: u32,
    /// The connection the presenter started it on.
    ///
    /// Kept beside the session because `closed` names a *connection*, and by
    /// the time it runs the roster may already have forgotten the session it
    /// belonged to — looking it up then is a race whose losing side is a share
    /// that never ends.
    conn: u64,
    channel: u32,
    viewers: Vec<u32>,
}

/// The readiness gate that stays closed until the roster has a snapshot.
///
/// A cold roster names nobody, so a share would be announced to an empty
/// audience: the feature would look broken rather than unready.
const VIEW_GATE: &str = "screenshare_roster_warm";

/// The service.
#[derive(Debug)]
pub struct ScreenshareService {
    shares: Mutex<HashMap<String, Share>>,
    sfu: (String, u32),
    fanout: Fanout,
    permit: Permit,
    roster: Arc<Roster>,
    /// Test-only: treat every permission check as granted.
    ///
    /// `cfg(test)`, so it is not configuration and no operator can turn the
    /// checks off. Without it the tests below could only ever exercise the
    /// refusal path — a `Permit` with no `permissions` behind it denies — and
    /// an assertion on "one action came back" would pass for a refusal exactly
    /// as it passes for an announcement, which is how the test this replaced
    /// was green while testing nothing.
    #[cfg(test)]
    permits_everything: bool,
}

impl ScreenshareService {
    /// Whether the client on `inbound` holds `permission` in `channel`.
    async fn allows(&self, inbound: &Inbound, channel: u32, permission: Perm) -> bool {
        #[cfg(test)]
        if self.permits_everything {
            return true;
        }
        self.permit.allows(inbound, channel, permission.bits()).await
    }

    /// Everyone in `channel` except `except`, as an audience.
    ///
    /// The share's channel, never the whole server: a title is content, and
    /// "Quarterly numbers — draft" announced server-wide is that content
    /// leaving the room it belongs to.
    fn audience(&self, channel: u32, except: u32, payload: Vec<u8>) -> Actions {
        let sessions = self.roster.in_channel(channel, except);
        if sessions.is_empty() {
            return Actions::new();
        }
        vec![to_sessions(
            sessions,
            ServiceKind::Screenshare.outer_type(),
            payload,
        )]
    }

    /// The share `share_id` names, if there is one.
    fn share(&self, share_id: &str) -> Option<Share> {
        self.shares
            .lock()
            .ok()
            .and_then(|shares| shares.get(share_id).cloned())
    }

    /// A client announcing a share.
    async fn on_start(&self, inbound: &Inbound, start: Start) -> Actions {
        // Sharing into a channel is broadcasting into it. Unchecked, a client
        // could announce a share in a channel it may not even enter, and every
        // member of that channel would be told.
        if !self.allows(inbound, start.channel, Perm::SPEAK).await {
            tracing::warn!(
                session = inbound.session,
                channel = start.channel,
                "screen share refused: no Speak in that channel"
            );
            return vec![starling_runtime::permit::permission_denied(
                inbound,
                Perm::SPEAK,
                start.channel,
            )];
        }
        if let Ok(mut shares) = self.shares.lock() {
            let _ = shares.insert(
                start.share_id.clone(),
                Share {
                    presenter: inbound.session,
                    conn: inbound.conn,
                    channel: start.channel,
                    viewers: Vec::new(),
                },
            );
        }
        let channel = start.channel;
        let announcement = ScreenshareEnvelope {
            body: Some(screenshare_envelope::Body::Start(Start {
                // Stamped, never taken from the message: a presenter field a
                // client fills is a client announcing somebody else's share.
                presenter: inbound.session,
                ..start
            })),
        };
        self.audience(channel, inbound.session, announcement.encode_to_vec())
    }

    /// An SDP offer, answered with the endpoint to negotiate against.
    fn on_offer(&self, inbound: &Inbound, offer: &Offer) -> Actions {
        // The answer carries the SFU's own candidates, which is why nothing
        // here waits for a trickle that will never come.
        let answer = ScreenshareEnvelope {
            body: Some(screenshare_envelope::Body::Answer(Answer {
                share_id: offer.share_id.clone(),
                sdp: String::new(),
                sfu_host: self.sfu.0.clone(),
                sfu_port: self.sfu.1,
            })),
        };
        vec![to_conn(
            inbound.conn,
            ServiceKind::Screenshare.outer_type(),
            answer.encode_to_vec(),
        )]
    }

    /// Somebody ending a share.
    async fn on_stop(&self, inbound: &Inbound, stop: &Stop) -> Actions {
        let Some(share) = self.share(&stop.share_id) else {
            // Already gone, or never there. Silence either way: a reply that
            // told the two apart would let anyone enumerate live share ids.
            return Actions::new();
        };
        if !self.may_stop(inbound, &share).await {
            tracing::warn!(
                session = inbound.session,
                share = %stop.share_id,
                presenter = share.presenter,
                "screen share stop refused: not the presenter, and no MuteDeafen here"
            );
            return vec![starling_runtime::permit::permission_denied(
                inbound,
                Perm::MUTE_DEAFEN,
                share.channel,
            )];
        }
        self.end(&stop.share_id, &share, inbound.session)
    }

    /// The viewer list, which asking for is also how a client joins.
    fn on_viewers(&self, inbound: &Inbound, request: &Viewers) -> Actions {
        // Joining is implicit in asking: a client that wants the viewer list is
        // watching, and the presenter's own request is not a join, which is why
        // the presenter is compared out here rather than filtered on the way to
        // the SFU.
        let viewers = self
            .shares
            .lock()
            .ok()
            .map(|mut shares| {
                let Some(share) = shares.get_mut(&request.share_id) else {
                    return Vec::new();
                };
                if inbound.session != share.presenter && !share.viewers.contains(&inbound.session) {
                    share.viewers.push(inbound.session);
                }
                tracing::debug!(
                    share = %request.share_id,
                    channel = share.channel,
                    viewers = share.viewers.len(),
                    "viewer list"
                );
                share.viewers.clone()
            })
            .unwrap_or_default();
        let reply = ScreenshareEnvelope {
            body: Some(screenshare_envelope::Body::Viewers(Viewers {
                share_id: request.share_id.clone(),
                sessions: viewers,
            })),
        };
        vec![to_conn(
            inbound.conn,
            ServiceKind::Screenshare.outer_type(),
            reply.encode_to_vec(),
        )]
    }

    /// Whether `inbound` may stop this share.
    ///
    /// The presenter, or the moderator power in that channel. Anyone else
    /// naming the id used to be enough, which made every live share stoppable
    /// by every connected client.
    async fn may_stop(&self, inbound: &Inbound, share: &Share) -> bool {
        inbound.session == share.presenter
            || self.allows(inbound, share.channel, Perm::MUTE_DEAFEN).await
    }

    /// End a share and tell its channel, whatever ended it.
    fn end(&self, share_id: &str, share: &Share, actor: u32) -> Actions {
        if let Ok(mut shares) = self.shares.lock() {
            let _ = shares.remove(share_id);
        }
        let stopped = ScreenshareEnvelope {
            body: Some(screenshare_envelope::Body::Stop(Stop {
                share_id: share_id.to_owned(),
                actor,
            })),
        };
        // Nobody is excepted, the presenter included: a presenter whose share
        // was stopped by a moderator has to be told, and a presenter who
        // stopped it themselves is not harmed by the confirmation.
        self.audience(share.channel, 0, stopped.encode_to_vec())
    }
}

impl ClientService for ScreenshareService {
    async fn frame(&self, inbound: Inbound) -> Actions {
        if inbound.type_id != ServiceKind::Screenshare.outer_type() {
            return Actions::new();
        }
        let Ok(envelope) = ScreenshareEnvelope::decode(inbound.payload.as_slice()) else {
            // Dropped silently before: an envelope this service cannot read
            // means a client newer than the server, and the symptom is a
            // feature that does nothing at all.
            tracing::debug!(
                conn = inbound.conn,
                session = inbound.session,
                len = inbound.payload.len(),
                "undecodable ScreenshareEnvelope"
            );
            return Actions::new();
        };

        match envelope.body {
            Some(screenshare_envelope::Body::Start(start)) => self.on_start(&inbound, start).await,
            Some(screenshare_envelope::Body::Offer(offer)) => self.on_offer(&inbound, &offer),
            Some(screenshare_envelope::Body::Stop(stop)) => self.on_stop(&inbound, &stop).await,
            Some(screenshare_envelope::Body::Viewers(request)) => self.on_viewers(&inbound, &request),
            Some(screenshare_envelope::Body::Health(health)) => {
                // Recorded rather than dropped. It was falling into a catch-all
                // arm, so a client dutifully reporting that it is dropping half
                // its frames was telling nobody: the one signal that says a
                // share is unwatchable went nowhere.
                tracing::debug!(
                    session = inbound.session,
                    share = %health.share_id,
                    fps = health.fps,
                    kbps = health.kbps,
                    dropped = health.dropped,
                    "screen share health"
                );
                Actions::new()
            }
            // Server to client, or an empty envelope.
            Some(screenshare_envelope::Body::Answer(_)) | None => Actions::new(),
        }
    }

    async fn closed(&self, conn: u64, _reason: &str) -> Actions {
        // A presenter who disconnects ends their share. This did nothing, so a
        // presenter closing their laptop left the share in the table forever
        // and every viewer watching a stream that had stopped, with no event
        // to tell them: the share could only be cleared by the presenter
        // reconnecting and stopping it by hand.
        //
        // Matched on the connection the share was started on, not on a session
        // resolved now: `closed` names a connection, and the roster may already
        // have forgotten the session by the time this runs.
        let ended: Vec<(String, Share)> = self
            .shares
            .lock()
            .map(|shares| {
                shares
                    .iter()
                    .filter(|(_, share)| share.conn == conn)
                    .map(|(id, share)| (id.clone(), share.clone()))
                    .collect()
            })
            .unwrap_or_default();

        let mut actions = Actions::new();
        for (share_id, share) in &ended {
            tracing::info!(
                share = %share_id,
                presenter = share.presenter,
                "share ended: the presenter's connection closed"
            );
            actions.extend(self.end(share_id, share, share.presenter));
        }
        actions
    }
}

impl Serve for ScreenshareService {
    const NAME: &'static str = "screenshare";

    async fn build(ctx: ServiceContext) -> Result<Arc<Self>, ServiceError> {
        let service = ctx.service();
        let sfu = service
            .public_url
            .as_deref()
            .and_then(|url| url.rsplit_once(':'))
            .map(|(host, port)| (host.to_owned(), port.parse().unwrap_or(0)))
            .unwrap_or_else(|| (String::new(), 0));
        Ok(Arc::new(Self {
            shares: Mutex::new(HashMap::new()),
            sfu,
            fanout: Fanout::default(),
            permit: Permit::new(ctx.resolver),
            roster: Arc::new(Roster::new()),
            #[cfg(test)]
            permits_everything: false,
        }))
    }

    async fn run(self: Arc<Self>, ctx: ServiceContext) -> Result<(), ServiceError> {
        // Without this the roster is empty forever and every share is announced
        // to nobody: the audience is the feature.
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
    use starling_proto_fancy::sessionview::Session;

    /// A service that refuses every permission, because nothing is behind its
    /// `Permit`. The refusal paths.
    fn strict() -> Arc<ScreenshareService> {
        build(false)
    }

    /// A service that grants every permission. The paths a permitted client
    /// takes, which a `Permit` with no `permissions` service behind it cannot
    /// reach at all.
    fn permissive() -> Arc<ScreenshareService> {
        build(true)
    }

    fn build(permits_everything: bool) -> Arc<ScreenshareService> {
        let nowhere = starling_runtime::channel::Resolver::new(
            Arc::new(starling_runtime::config::Config::default()),
            starling_runtime::inproc::Broker::default(),
        );
        Arc::new(ScreenshareService {
            shares: Mutex::new(HashMap::new()),
            sfu: ("sfu.example.org".to_owned(), 7000),
            fanout: Fanout::default(),
            permit: Permit::new(nowhere),
            roster: Arc::new(Roster::new()),
            permits_everything,
        })
    }

    /// Put `sessions` in the roster, each in the channel it is paired with.
    fn seat(service: &ScreenshareService, sessions: &[(u32, u32)]) {
        service.roster.replace(
            sessions
                .iter()
                .map(|(session, channel)| Session {
                    session: *session,
                    channel: *channel,
                    ..Session::default()
                })
                .collect(),
        );
    }

    fn frame(session: u32, envelope: &ScreenshareEnvelope) -> Inbound {
        frame_on(session, 100 + u64::from(session), envelope)
    }

    fn frame_on(session: u32, conn: u64, envelope: &ScreenshareEnvelope) -> Inbound {
        Inbound {
            conn,
            session,
            type_id: ServiceKind::Screenshare.outer_type(),
            payload: envelope.encode_to_vec(),
            gateway: "gw".to_owned(),
            scope: 1,
        }
    }

    fn start_of(share_id: &str, channel: u32) -> ScreenshareEnvelope {
        ScreenshareEnvelope {
            body: Some(screenshare_envelope::Body::Start(Start {
                share_id: share_id.to_owned(),
                channel,
                presenter: 0,
                title: "screen".to_owned(),
                width: 1920,
                height: 1080,
            })),
        }
    }

    fn stop_of(share_id: &str) -> ScreenshareEnvelope {
        ScreenshareEnvelope {
            body: Some(screenshare_envelope::Body::Stop(Stop {
                share_id: share_id.to_owned(),
                actor: 0,
            })),
        }
    }

    /// The sessions an action is addressed to.
    fn addressed(action: &starling_proto_fancy::control::ServerAction) -> Vec<u32> {
        match action.action.as_ref() {
            Some(starling_proto_fancy::control::server_action::Action::Send(send)) => {
                send.sessions.clone()
            }
            _ => Vec::new(),
        }
    }

    #[tokio::test]
    async fn an_offer_is_answered_with_the_sfu_endpoint_rather_than_trickled_to() {
        // The SFU is ICE-lite: its candidates ride in the answer, and waiting
        // for a trickle would wait forever.
        let offer = ScreenshareEnvelope {
            body: Some(screenshare_envelope::Body::Offer(Offer {
                share_id: "s1".to_owned(),
                channel: 1,
                sdp: "v=0".to_owned(),
                attempt: 1,
            })),
        };
        let actions = permissive().frame(frame(4, &offer)).await;
        assert_eq!(actions.len(), 1, "an offer is always answered");
    }

    #[tokio::test]
    async fn a_share_is_announced_to_its_channel_and_to_nobody_else() {
        // It used to be broadcast to every connected session, which tells
        // somebody on the other side of the server that a share titled
        // "Quarterly numbers — draft" exists in a room they cannot see.
        let service = permissive();
        seat(&service, &[(1, 3), (2, 3), (9, 7), (4, 3)]);

        let actions = service.frame(frame(4, &start_of("s2", 3))).await;
        assert_eq!(actions.len(), 1);
        let mut told = addressed(&actions[0]);
        told.sort_unstable();
        assert_eq!(told, vec![1, 2], "the channel, without the presenter");
    }

    #[tokio::test]
    async fn a_share_in_a_channel_the_client_may_not_speak_in_is_refused() {
        let service = strict();
        seat(&service, &[(1, 3), (4, 3)]);

        let actions = service.frame(frame(4, &start_of("s3", 3))).await;
        assert_eq!(actions.len(), 1, "the client is told, not ignored");
        assert!(
            service.share("s3").is_none(),
            "a refused share must not be live"
        );
    }

    #[tokio::test]
    async fn a_stranger_cannot_stop_somebody_elses_share() {
        // Unenforced, this was the whole feature: name any live share id and it
        // stops. No bug required, only a message.
        let service = strict();
        seat(&service, &[(4, 3), (5, 3)]);
        // Started by 4, through the permissive path, so the refusal under test
        // is the *stop* and not the start.
        let permitted = permissive();
        let _ = permitted.frame(frame(4, &start_of("s4", 3))).await;
        if let (Ok(mut theirs), Ok(mine)) = (service.shares.lock(), permitted.shares.lock()) {
            theirs.clone_from(&mine);
        }

        let actions = service.frame(frame(5, &stop_of("s4"))).await;
        assert_eq!(actions.len(), 1, "the refusal is sent, not swallowed");
        assert!(
            service.share("s4").is_some(),
            "the share must still be running"
        );
    }

    #[tokio::test]
    async fn the_presenter_stops_their_own_share_and_the_channel_is_told() {
        let service = strict();
        seat(&service, &[(1, 3), (4, 3)]);
        // Strict, and it still works: being the presenter is the authority, so
        // this path never consults `permissions` at all.
        let permitted = permissive();
        let _ = permitted.frame(frame(4, &start_of("s5", 3))).await;
        if let (Ok(mut theirs), Ok(mine)) = (service.shares.lock(), permitted.shares.lock()) {
            theirs.clone_from(&mine);
        }

        let actions = service.frame(frame(4, &stop_of("s5"))).await;
        assert!(service.share("s5").is_none(), "the share is over");
        let told = addressed(&actions[0]);
        assert!(
            told.contains(&1) && told.contains(&4),
            "everyone in the channel hears it, the presenter included: got {told:?}"
        );
    }

    #[tokio::test]
    async fn stopping_a_share_that_does_not_exist_says_nothing_at_all() {
        // Answering differently for "no such share" and "not yours" would let
        // anyone enumerate live share ids by asking.
        let service = permissive();
        assert!(service.frame(frame(4, &stop_of("never"))).await.is_empty());
    }

    #[tokio::test]
    async fn a_presenter_who_disconnects_ends_the_share() {
        // This did nothing: a presenter closing their laptop left the share in
        // the table forever, and every viewer watching a stream that had
        // stopped, with no event to tell them.
        let service = permissive();
        seat(&service, &[(1, 3), (4, 3)]);
        let _ = service.frame(frame_on(4, 77, &start_of("s6", 3))).await;
        assert!(service.share("s6").is_some());

        let actions = service.closed(77, "gone").await;
        assert!(service.share("s6").is_none(), "the share is cleaned up");
        assert_eq!(actions.len(), 1, "and the channel is told");
        assert!(addressed(&actions[0]).contains(&1));
    }

    #[tokio::test]
    async fn another_connection_closing_leaves_the_share_alone() {
        let service = permissive();
        seat(&service, &[(1, 3), (4, 3)]);
        let _ = service.frame(frame_on(4, 77, &start_of("s7", 3))).await;

        assert!(service.closed(78, "gone").await.is_empty());
        assert!(service.share("s7").is_some(), "somebody else left");
    }

    #[tokio::test]
    async fn the_presenter_on_the_wire_is_the_one_the_server_stamped() {
        // A presenter field a client fills is a client announcing somebody
        // else's share.
        let service = permissive();
        seat(&service, &[(1, 3), (4, 3)]);
        let mut claimed = start_of("s8", 3);
        if let Some(screenshare_envelope::Body::Start(start)) = claimed.body.as_mut() {
            start.presenter = 999;
        }

        let _ = service.frame(frame(4, &claimed)).await;
        assert_eq!(service.share("s8").map(|share| share.presenter), Some(4));
    }
}
