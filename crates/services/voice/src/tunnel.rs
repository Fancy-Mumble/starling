//! Audio over TCP: the path for a client whose UDP does not work.
//!
//! Every connection starts here and stays until one of its datagrams
//! authenticates, and a client behind a restrictive firewall never leaves — so
//! this is not a degraded mode to be tolerated, it is how a substantial fraction
//! of a real server's users are heard at all.
//!
//! # Why this addresses a session and not a connection
//!
//! Connection ids are the gateway's, minted from a counter that starts at 1 in
//! each pod (`gateway/src/listener.rs`). Sessions are the server's. Addressing
//! by session is therefore the only form that stays correct when a second
//! gateway is attached — the pod holding that session delivers, the others drop
//! it, and no service has to know which is which (`runtime/src/plane.rs`).

use bytes::Bytes;
use starling_proto_fancy::control::{Send, server_action};
use starling_runtime::plane::Fanout;

use crate::ports::{FrameSink, Stuck};

/// Upstream `UDPTunnel`: a control message whose payload is one audio frame.
const UDP_TUNNEL: u16 = 1;

/// One peer's tunnel, pointed at whichever gateway is holding it.
#[derive(Debug, Clone)]
pub struct GatewayTunnel {
    fanout: Fanout,
    session: u32,
}

impl GatewayTunnel {
    /// A tunnel that delivers to `session` through `fanout`.
    #[must_use]
    pub const fn new(fanout: Fanout, session: u32) -> Self {
        Self { fanout, session }
    }
}

impl FrameSink for GatewayTunnel {
    /// Hand one already-framed control message to the gateway.
    ///
    /// The header comes back off because the two sides frame at different
    /// layers: [`FrameSink`] is defined over control messages — which is what
    /// makes the router's transport-blindness testable — while a `Send` carries
    /// the type and the payload apart and the gateway reassembles them
    /// (`gateway/src/attach.rs`). Slicing `Bytes` copies nothing, so the round
    /// trip costs one header write per frame and buys a routing core that never
    /// mentions gRPC.
    ///
    /// Never blocks and never fails: the queue that can actually be full is the
    /// per-client audio lane inside the gateway, which drops its oldest frame
    /// and counts it. Reporting [`Stuck`] from here would report on the
    /// broadcast to *every* gateway, which is not this peer's backlog.
    fn try_send(&self, frame: Bytes) -> Result<(), Stuck> {
        let payload = frame
            .get(starling_proto::codec::HEADER_SIZE..)
            .ok_or(Stuck)?
            .to_vec();

        self.fanout
            .push(starling_proto_fancy::control::ServerAction {
                action: Some(server_action::Action::Send(Send {
                    conns: Vec::new(),
                    sessions: vec![self.session],
                    r#type: u32::from(UDP_TUNNEL),
                    payload,
                    // The audio lane, where lateness is worse than loss: a backed-up
                    // client drops its oldest frame instead of stalling the socket
                    // it shares with every control message (`gateway/connection.rs`).
                    audio: true,
                    except: Vec::new(),
                })),
            });
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use starling_proto::ControlMessage;

    /// What the router hands a sink: a framed `UDPTunnel`.
    fn framed(audio: &[u8]) -> Bytes {
        starling_proto::codec::encode(&ControlMessage::UdpTunnel(Bytes::copy_from_slice(audio)))
    }

    #[test]
    fn a_tunnelled_frame_reaches_the_gateway_as_a_udp_tunnel_for_one_session() {
        let fanout = Fanout::new(8);
        let mut gateway = fanout.subscribe();

        GatewayTunnel::new(fanout, 7)
            .try_send(framed(b"opus"))
            .expect("the tunnel never refuses");

        let action = gateway.try_recv().expect("the gateway was pushed to");
        let Some(server_action::Action::Send(send)) = action.action else {
            panic!("expected a Send");
        };
        assert_eq!(send.sessions, vec![7], "audio must be addressed by session");
        assert!(send.conns.is_empty(), "a connection id is pod-local");
        assert_eq!(send.r#type, u32::from(UDP_TUNNEL));
        assert_eq!(
            send.payload, b"opus",
            "the control header must not be sent twice"
        );
        assert!(send.audio, "tunnelled audio belongs on the audio lane");
    }

    #[test]
    fn two_peers_are_addressed_separately() {
        // The tunnel is per client, not per listener: each recipient is sealed
        // and delivered on its own.
        let fanout = Fanout::new(8);
        let mut gateway = fanout.subscribe();

        for session in [3, 4] {
            GatewayTunnel::new(fanout.clone(), session)
                .try_send(framed(b"x"))
                .expect("never refuses");
        }

        let addressed: Vec<_> = (0..2)
            .filter_map(|_| gateway.try_recv().ok())
            .filter_map(|action| match action.action {
                Some(server_action::Action::Send(send)) => Some(send.sessions),
                _ => None,
            })
            .collect();
        assert_eq!(addressed, vec![vec![3], vec![4]]);
    }

    #[test]
    fn a_frame_too_short_to_hold_a_header_is_refused_rather_than_truncated() {
        // Cannot happen from the router, which always frames. It must not panic
        // if it ever does: this is the audio path.
        let fanout = Fanout::new(8);
        assert!(
            GatewayTunnel::new(fanout, 1)
                .try_send(Bytes::from_static(b"\x00\x01"))
                .is_err()
        );
    }
}
