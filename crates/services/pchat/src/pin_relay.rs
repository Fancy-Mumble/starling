//! A pin as it arrives, is kept, and is told: to the channel at once, and to
//! whoever fetches the channel's history later.
//!
//! It used to be relayed to who was there and kept nowhere, so somebody who
//! came later, or reconnected, never learned of it, and nothing said who
//! pinned it or when.

use prost::Message as _;
use starling_proto_fancy::control::ServerAction;
use starling_proto_fancy::fancy::pchat::{Message, PchatEnvelope, Pin, PinList, pchat_envelope};
use starling_proto_fancy::types::ServiceKind;
use starling_runtime::ids::now_ms;
use starling_runtime::permit::permission_denied;
use starling_runtime::plane::{Actions, Inbound, to_conn, to_views};

use crate::limits::Op;
use crate::{PchatService, Relay, pins};

impl PchatService {
    /// Stamp a pin with who and when, keep it where messages are kept, and
    /// tell the channel, the pinner included.
    pub(crate) async fn on_pin(&self, inbound: &Inbound, body: &pchat_envelope::Body) -> Actions {
        let (Some(relay), pchat_envelope::Body::Pin(pin)) = (Relay::of(body), body) else {
            return Actions::new();
        };
        if !self.limits.allow(inbound.conn, Op::Manage) {
            return Actions::new();
        }
        if !self
            .permit
            .allows(inbound, relay.channel, relay.needs.bits())
            .await
        {
            return vec![permission_denied(inbound, relay.needs, relay.channel)];
        }

        let pin = Pin {
            pinner: 0,
            pinner_cert: self.roster.cert_of(inbound.session).unwrap_or_default(),
            pinner_name: self.roster.name_of(inbound.session).unwrap_or_default(),
            pinned_at_ms: now_ms(),
            ..pin.clone()
        };
        self.keep_pin(inbound.scope, &pin).await;

        let members = self.members(inbound, pin.channel, relay.echoes);
        to_views(members, ServiceKind::Pchat.outer_type(), |viewer| {
            let named = Pin {
                pinner: self.roster.seen_by(viewer, inbound.session),
                ..pin.clone()
            };
            PchatEnvelope {
                body: Some(pchat_envelope::Body::Pin(named)),
            }
            .encode_to_vec()
        })
    }

    /// Keep or drop `pin` on the row it names, in a channel that keeps its
    /// messages. A pin on a message this channel does not hold is told and not
    /// kept: there is nothing for it to be a property of.
    async fn keep_pin(&self, scope: u32, pin: &Pin) {
        if !pins::keeps(self.modes.get(pin.channel)) {
            return;
        }
        let row = self
            .named_rows(scope, pin.channel, std::slice::from_ref(&pin.message_id))
            .await
            .ok()
            .and_then(|mut rows| rows.pop().flatten());
        let Some(row) = row else {
            tracing::debug!(
                channel = pin.channel,
                "a pin names no stored message; not kept"
            );
            return;
        };
        let kept = if pin.unpin {
            self.pins.drop_pin(scope, pin.channel, &row.id).await
        } else {
            self.pins.keep(scope, &row.id, pin).await
        };
        if let Err(error) = kept {
            tracing::error!(%error, channel = pin.channel, "a pin could not be kept");
        }
    }

    /// What is pinned in `channel`, for the reader on `inbound` alone.
    ///
    /// Sent with the first page of a channel's history, which is how a client
    /// asks for it: whoever opens the channel is told, whenever they come.
    /// `None` for a channel that keeps no messages, and so no pins.
    pub(crate) async fn pin_list(&self, inbound: &Inbound, channel: u32) -> Option<ServerAction> {
        if !pins::keeps(self.modes.get(channel)) {
            return None;
        }
        let mut kept = self.pins.list(inbound.scope, channel).await;
        for pin in &mut kept {
            // The pinner by session only while they are here, named as this
            // reader knows them.
            pin.pinner = self
                .roster
                .sessions_with_cert(&pin.pinner_cert)
                .first()
                .map_or(0, |&session| self.roster.seen_by(inbound.session, session));
        }
        let list = PinList {
            channel,
            // For a client that reads only this: which messages, no more.
            pinned: kept
                .iter()
                .map(|pin| Message {
                    message_id: pin.message_id.clone(),
                    channel,
                    ..Message::default()
                })
                .collect(),
            pins: kept,
        };
        let envelope = PchatEnvelope {
            body: Some(pchat_envelope::Body::PinList(list)),
        };
        Some(to_conn(
            inbound.conn,
            ServiceKind::Pchat.outer_type(),
            envelope.encode_to_vec(),
        ))
    }
}
