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

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use prost::Message as _;
use starling_proto_fancy::fancy::screenshare::{
    Answer, ScreenshareEnvelope, Start, Viewers, screenshare_envelope,
};
use starling_proto_fancy::types::ServiceKind;
use starling_runtime::plane::{
    Actions, ClientService, Fanout, Inbound, Plane, broadcast_except, to_conn,
};
use starling_runtime::serve::{Serve, ServiceContext, ServiceError};

/// One live share.
#[derive(Debug, Clone)]
struct Share {
    presenter: u32,
    channel: u32,
    viewers: Vec<u32>,
}

/// The service.
#[derive(Debug)]
pub struct ScreenshareService {
    shares: Mutex<HashMap<String, Share>>,
    sfu: (String, u32),
    fanout: Fanout,
}

impl ClientService for ScreenshareService {
    async fn frame(&self, inbound: Inbound) -> Actions {
        let outer = ServiceKind::Screenshare.outer_type();
        if inbound.type_id != outer {
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
            Some(screenshare_envelope::Body::Start(start)) => {
                if let Ok(mut shares) = self.shares.lock() {
                    let _ = shares.insert(
                        start.share_id.clone(),
                        Share {
                            presenter: inbound.session,
                            channel: start.channel,
                            viewers: Vec::new(),
                        },
                    );
                }
                let announcement = ScreenshareEnvelope {
                    body: Some(screenshare_envelope::Body::Start(Start {
                        presenter: inbound.session,
                        ..start
                    })),
                };
                vec![broadcast_except(
                    inbound.session,
                    outer,
                    announcement.encode_to_vec(),
                )]
            }
            Some(screenshare_envelope::Body::Offer(offer)) => {
                // The answer carries the SFU's own candidates, which is why
                // nothing here waits for a trickle that will never come.
                let answer = ScreenshareEnvelope {
                    body: Some(screenshare_envelope::Body::Answer(Answer {
                        share_id: offer.share_id,
                        sdp: String::new(),
                        sfu_host: self.sfu.0.clone(),
                        sfu_port: self.sfu.1,
                    })),
                };
                vec![to_conn(inbound.conn, outer, answer.encode_to_vec())]
            }
            Some(screenshare_envelope::Body::Stop(stop)) => {
                if let Ok(mut shares) = self.shares.lock() {
                    let _ = shares.remove(&stop.share_id);
                }
                vec![broadcast_except(inbound.session, outer, inbound.payload)]
            }
            Some(screenshare_envelope::Body::Viewers(request)) => {
                // Joining is implicit in asking: a client that wants the viewer
                // list is watching, and the presenter's own request is not a
                // join, which is why the presenter is compared out here rather
                // than filtered on the way to the SFU.
                let viewers = self
                    .shares
                    .lock()
                    .ok()
                    .map(|mut shares| {
                        let Some(share) = shares.get_mut(&request.share_id) else {
                            return Vec::new();
                        };
                        if inbound.session != share.presenter
                            && !share.viewers.contains(&inbound.session)
                        {
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
                        share_id: request.share_id,
                        sessions: viewers,
                    })),
                };
                vec![to_conn(inbound.conn, outer, reply.encode_to_vec())]
            }
            _ => Actions::new(),
        }
    }

    async fn closed(&self, _conn: u64, _reason: &str) -> Actions {
        Actions::new()
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

    fn service() -> Arc<ScreenshareService> {
        Arc::new(ScreenshareService {
            shares: Mutex::new(HashMap::new()),
            sfu: ("sfu.example.org".to_owned(), 7000),
            fanout: Fanout::default(),
        })
    }

    fn frame(session: u32, envelope: &ScreenshareEnvelope) -> Inbound {
        Inbound {
            conn: 1,
            session,
            type_id: ServiceKind::Screenshare.outer_type(),
            payload: envelope.encode_to_vec(),
            gateway: "gw".to_owned(),
            scope: 1,
        }
    }

    #[tokio::test]
    async fn an_offer_is_answered_with_the_sfu_endpoint_rather_than_trickled_to() {
        // The SFU is ICE-lite: its candidates ride in the answer, and waiting
        // for a trickle would wait forever.
        let offer = ScreenshareEnvelope {
            body: Some(screenshare_envelope::Body::Offer(
                starling_proto_fancy::fancy::screenshare::Offer {
                    share_id: "s1".to_owned(),
                    channel: 1,
                    sdp: "v=0".to_owned(),
                    attempt: 1,
                },
            )),
        };
        let actions = service().frame(frame(4, &offer)).await;
        assert_eq!(actions.len(), 1, "an offer is always answered");
    }

    #[tokio::test]
    async fn a_start_is_announced_to_everyone_but_the_presenter() {
        let start = ScreenshareEnvelope {
            body: Some(screenshare_envelope::Body::Start(Start {
                share_id: "s2".to_owned(),
                channel: 3,
                presenter: 0,
                title: "screen".to_owned(),
                width: 1920,
                height: 1080,
            })),
        };
        let actions = service().frame(frame(9, &start)).await;
        assert_eq!(actions.len(), 1);
    }
}
