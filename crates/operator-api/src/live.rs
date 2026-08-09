//! The live channel's transports.
//!
//! Two ways in, one channel behind them: a WebSocket, and WebTransport over
//! HTTP/3. Both carry the same JSON, so a consumer written against one reads
//! the other unchanged and this file is the only place that knows there are
//! two.
//!
//! **WebSocket is the one that works everywhere.** WebTransport needs the
//! deployment to terminate QUIC, reverse proxies do not generally forward
//! Extended CONNECT over HTTP/3, so it is off unless configured, and the
//! WebSocket is what a proxied deployment uses.
//!
//! # Why the channel is bidirectional
//!
//! A subscriber does not only listen. It can put an entry in a user's context
//! menu and be told when somebody chooses it, and that registration has to
//! live exactly as long as the connection that will service it: an entry whose
//! owner has gone is a menu item that does nothing. Tying the two together
//! means a disconnect cleans up after itself.

use std::sync::Arc;

use axum::extract::State;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use futures_util::{SinkExt as _, StreamExt as _};
use serde::Deserialize;
use starling_proto_fancy::common::Scope;
use tokio::sync::broadcast::error::RecvError;

use crate::OperatorApi;
use crate::events::{Event, OWNER, encode};

/// What a subscriber may send up the channel.
///
/// Tagged like the events themselves, so one `switch` on `event` handles both
/// directions in a consumer.
#[derive(Debug, Deserialize)]
// Tagged on `command`, not `action`: an addContext carries a field
// called `action` (the entry's name), and a tag of the same name would
// collide with it.
#[serde(tag = "command", rename_all = "camelCase")]
enum Command {
    /// Add a context-menu entry, serviced by this connection.
    AddContext {
        action: String,
        text: String,
        /// A bitwise OR of the upstream context bits: 1 server, 2 channel,
        /// 4 user.
        #[serde(default)]
        context: u32,
    },
    /// Withdraw an entry this connection added.
    RemoveContext { action: String },
    /// A keepalive. Answered with `pong`, so a consumer behind an idle-timeout
    /// proxy can keep the connection open without sending a real command.
    Ping,
}

/// Upgrade to a WebSocket, once the caller has been identified and recorded.
///
/// Authorisation happens **before** the upgrade: a socket that opens and then
/// closes on the first frame is indistinguishable, to most clients, from a
/// network fault, and an operator debugging a bad token deserves a 401.
pub async fn websocket(
    State(api): State<Arc<OperatorApi>>,
    headers: HeaderMap,
    upgrade: WebSocketUpgrade,
) -> Result<Response, (StatusCode, String)> {
    let subject = crate::routes::admit_live(&api, &headers, "GET /v1/events")?;
    Ok(upgrade.on_upgrade(move |socket| serve(socket, api, subject)))
}

/// One subscriber, for as long as it stays connected.
async fn serve(socket: WebSocket, api: Arc<OperatorApi>, subject: String) {
    let mut events = api.events().subscribe();
    let (mut sink, mut stream) = socket.split();

    // Registered entries, so they can be withdrawn when this connection ends.
    // Without this a disconnect leaves a menu item nothing will ever service.
    let mut registered: Vec<String> = Vec::new();

    tracing::info!(subject, "a live subscriber attached");

    // Told on arrival, not only at the moment the bridge attaches. `started` is
    // published once and this channel is not a replay, so without this a
    // subscriber that connects to an already-running server is never told the
    // state below it is readable, which is the only thing `started` says.
    if api.events().is_live()
        && sink
            .send(Message::Text(
                encode(&Event::Started { server_id: 1 }).into(),
            ))
            .await
            .is_err()
    {
        return;
    }

    loop {
        tokio::select! {
            // Outbound: events to the subscriber.
            received = events.recv() => match received {
                Ok(event) => {
                    if sink.send(Message::Text(encode(&event).into())).await.is_err() {
                        break;
                    }
                }
                Err(RecvError::Lagged(missed)) => {
                    // Told rather than hidden: a consumer that knows it missed
                    // events can re-read /v1/sessions and /v1/channels, and one
                    // that does not will act on a state it believes is current.
                    tracing::warn!(subject, missed, "a live subscriber fell behind");
                    let notice = format!(
                        r#"{{"event":"lagged","missed":{missed}}}"#
                    );
                    if sink.send(Message::Text(notice.into())).await.is_err() {
                        break;
                    }
                }
                Err(RecvError::Closed) => break,
            },

            // Inbound: commands from the subscriber.
            received = stream.next() => match received {
                Some(Ok(Message::Text(text))) => {
                    if let Some(reply) = run_command(&api, &text, &mut registered).await
                        && sink.send(Message::Text(reply.into())).await.is_err()
                    {
                        break;
                    }
                }
                Some(Ok(Message::Close(_))) | None => break,
                // Ping/Pong are answered by axum; binary frames are not part of
                // this protocol and are ignored rather than closing the socket.
                Some(Ok(_)) => {}
                Some(Err(error)) => {
                    tracing::debug!(subject, %error, "a live subscriber's socket failed");
                    break;
                }
            },
        }
    }

    withdraw_entries(&api, &registered).await;
    tracing::info!(subject, "a live subscriber detached");
}

/// Parse one command line and run it, returning what to send back.
///
/// Shared with the WebTransport channel so the two transports cannot drift
/// into accepting different commands or answering them differently.
pub(crate) async fn run_command(
    api: &OperatorApi,
    text: &str,
    registered: &mut Vec<String>,
) -> Option<String> {
    match serde_json::from_str::<Command>(text) {
        Ok(command) => apply(api, command, registered).await,
        // Answered rather than ignored. A command silently dropped because of
        // a typo looks exactly like one the server chose not to honour.
        Err(error) => {
            Some(serde_json::json!({ "event": "error", "reason": error.to_string() }).to_string())
        }
    }
}

/// Run one command, returning what to send back if anything.
async fn apply(
    api: &OperatorApi,
    command: Command,
    registered: &mut Vec<String>,
) -> Option<String> {
    use starling_proto_fancy::contextactions::context_actions_client::ContextActionsClient;
    use starling_proto_fancy::contextactions::{AddRequest, Entry, RemoveRequest};

    match command {
        Command::Ping => Some(r#"{"event":"pong"}"#.to_owned()),

        Command::AddContext {
            action,
            text,
            context,
        } => {
            let channel = api.resolver().channel("context-actions").ok()?;
            let result = ContextActionsClient::new(channel)
                .add(AddRequest {
                    scope: Some(Scope { instance: 1 }),
                    actor: None,
                    entry: Some(Entry {
                        action: action.clone(),
                        text,
                        owner: OWNER.to_owned(),
                        context,
                    }),
                })
                .await;

            Some(match result {
                Ok(_) => {
                    registered.push(action.clone());
                    serde_json::json!({ "event": "contextAdded", "action": action }).to_string()
                }
                Err(status) => serde_json::json!({
                    "event": "error",
                    "reason": status.message(),
                })
                .to_string(),
            })
        }

        Command::RemoveContext { action } => {
            let channel = api.resolver().channel("context-actions").ok()?;
            let result = ContextActionsClient::new(channel)
                .remove(RemoveRequest {
                    scope: Some(Scope { instance: 1 }),
                    actor: None,
                    owner: OWNER.to_owned(),
                    action: action.clone(),
                })
                .await;

            registered.retain(|held| held != &action);
            Some(match result {
                Ok(_) => {
                    serde_json::json!({ "event": "contextRemoved", "action": action }).to_string()
                }
                Err(status) => serde_json::json!({
                    "event": "error",
                    "reason": status.message(),
                })
                .to_string(),
            })
        }
    }
}

/// Withdraw everything this connection registered.
///
/// Shared with the WebTransport channel: a session ending must clean up after
/// itself the same way whichever transport carried it.
pub(crate) async fn withdraw_entries(api: &OperatorApi, registered: &[String]) {
    use starling_proto_fancy::contextactions::RemoveRequest;
    use starling_proto_fancy::contextactions::context_actions_client::ContextActionsClient;

    if registered.is_empty() {
        return;
    }
    let Ok(channel) = api.resolver().channel("context-actions") else {
        tracing::warn!(
            entries = registered.len(),
            "could not reach context-actions to withdraw a departed subscriber's entries"
        );
        return;
    };

    let mut client = ContextActionsClient::new(channel);
    for action in registered {
        let _ = client
            .remove(RemoveRequest {
                scope: Some(Scope { instance: 1 }),
                actor: None,
                owner: OWNER.to_owned(),
                action: action.clone(),
            })
            .await;
    }
}

/// Serialise an event for a transport that carries bytes rather than text.
///
/// Used by the WebTransport channel, which writes datagram or stream payloads;
/// the encoding is the same JSON so the two cannot drift.
#[must_use]
pub fn encode_bytes(event: &Event) -> Vec<u8> {
    encode(event).into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_command_is_recognised_by_its_action_name() {
        let command: Command = serde_json::from_str(
            r#"{"command":"addContext","action":"kick","text":"Kick","context":4}"#,
        )
        .expect("parsed");
        match command {
            Command::AddContext {
                action, context, ..
            } => {
                assert_eq!(action, "kick");
                // 4 is the user menu, as upstream numbers the contexts.
                assert_eq!(context, 4);
            }
            _ => panic!("expected an addContext command"),
        }
    }

    #[test]
    fn a_ping_is_a_command_so_an_idle_proxy_does_not_close_the_channel() {
        let command: Command = serde_json::from_str(r#"{"command":"ping"}"#).expect("parsed");
        assert!(matches!(command, Command::Ping));
    }

    #[test]
    fn an_unknown_command_is_an_error_rather_than_silence() {
        // A consumer that sends a command the server does not know must be
        // told; silently dropping it looks like a refusal.
        assert!(serde_json::from_str::<Command>(r#"{"command":"detonate"}"#).is_err());
    }
}
