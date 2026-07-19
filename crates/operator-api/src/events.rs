//! The live event channel: what changed, as it changes.
//!
//! Every other route here answers what the server *is*. This one reports what
//! happened to it, so an external system, a channel viewer, a user manager, a
//! bot, follows the server instead of polling it.
//!
//! # Why the events are named the way they are
//!
//! `userConnected`, `channelStateChanged` and the rest are the method names of
//! the C++ server's `ServerCallback` (`vendor/server`'s `MumbleServer.ice`).
//! Nothing here speaks Ice (`docs/GAP-ANALYSIS.md` S6) but the systems being
//! pointed at this channel were written against those names, and a
//! gratuitously different vocabulary would make every one of them rewrite a
//! `switch` to gain nothing.
//!
//! # Why a bridge rather than a passthrough
//!
//! The services already publish changes, but in a shape built for state
//! reconciliation: `session-view` and `metadata` both report an **upsert**,
//! which is a create and an update collapsed into one. That is right for a
//! subscriber rebuilding a view and wrong for one reacting to arrivals, "a
//! user appeared" and "a user moved" call for different behaviour, and a
//! consumer cannot recover the distinction from an upsert alone.
//!
//! So this tracks which ids it has seen and splits the upsert back apart.
//! Doing it here keeps a wire format several services depend on from being
//! reshaped around one consumer's notification semantics.

use std::collections::HashSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use serde::Serialize;
use starling_proto_fancy::common::Scope;
use tokio::sync::broadcast;

/// How many events a subscriber may fall behind by before it loses the oldest.
///
/// Bounded because an unbounded queue turns one stalled websocket into an OOM.
/// A subscriber that exceeds it is told, so it can go and re-read the state it
/// missed rather than silently believing it is current.
const BACKLOG: usize = 1024;

/// A connected user, as an event reports them.
///
/// Exactly what `session-view` composes, and therefore exactly what is known
/// about a session. Latency, bandwidth and client version are absent because
/// nothing composes them into the live view.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct UserJson {
    /// The session id, unique for as long as the connection lasts.
    pub session: u32,
    /// The name the user is connected under.
    pub name: String,
    /// The channel they are in.
    pub channel: u32,
    /// The account, or `null` for an unregistered guest.
    ///
    /// Null rather than a sentinel, matching what `/v1/sessions` already
    /// serves. Account `0` is the SuperUser, so a guest written as `0` would
    /// read as the administrator.
    pub user_id: Option<u64>,
    /// Muted by a moderator.
    pub mute: bool,
    /// Deafened by a moderator.
    pub deaf: bool,
    /// Muted by themselves.
    pub self_mute: bool,
    /// Deafened by themselves.
    pub self_deaf: bool,
    /// Suppressed by the server rather than by a moderator.
    pub suppress: bool,
    /// Heard over others when speaking.
    pub priority_speaker: bool,
    /// When the connection was established.
    pub connected_at_ms: u64,
}

/// A channel, as an event reports it.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ChannelJson {
    /// The channel id. `0` is the root.
    pub id: u32,
    /// The parent channel; `0` for one directly under the root, and for the
    /// root itself, which has none.
    pub parent: u32,
    /// The channel name.
    pub name: String,
    /// The description, as it would be rendered.
    pub description: String,
    /// Sort position among its siblings.
    pub position: i32,
    /// The occupancy limit, `0` for none.
    pub max_users: u32,
    /// Channels linked to this one, so speech carries between them.
    pub links: Vec<u32>,
    /// Hidden from users who cannot see it. Unpacked from the flags bitfield.
    pub hidden: bool,
    /// Vanishes when the last member leaves.
    pub temporary: bool,
}

/// A text message, as an event reports it.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct TextMessageJson {
    /// The message text.
    pub body: String,
    /// Channels it was addressed to.
    pub channels: Vec<u32>,
    /// Sessions it was addressed to directly.
    pub sessions: Vec<u32>,
    /// Channels whose whole subtree it was addressed to.
    pub tree: Vec<u32>,
    /// When it was sent.
    pub sent_at_ms: u64,
    /// False when the server itself sent it, through `POST /v1/messages`.
    ///
    /// Worth distinguishing: a watcher that reacts to messages would otherwise
    /// answer the server's own announcements, including ones it caused.
    pub from_client: bool,
}

/// One event on the live channel.
///
/// Tagged with `event`; a consumer switches on that one field. The names are
/// the C++ server's callback names, for the reason given at the top of this
/// module.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(tag = "event", rename_all = "camelCase")]
pub enum Event {
    /// A user finished connecting.
    UserConnected {
        /// Their state as of the moment they appeared.
        user: UserJson,
    },
    /// A user disconnected.
    UserDisconnected {
        /// Their last known state. They are already gone, so nothing can look
        /// this up afterwards, which is why it is carried here.
        user: UserJson,
    },
    /// A user moved, was renamed, muted, deafened or suppressed.
    ///
    /// Only when something in [`UserJson`] actually differs: `session-view`
    /// republishes on any composed change, including ones this projection does
    /// not carry, and an event for those is one a consumer cannot act on.
    UserStateChanged {
        /// Their new state.
        user: UserJson,
    },
    /// A message was delivered.
    UserTextMessage {
        /// The sender, as far as the `text` service knows them.
        user: UserJson,
        /// What was sent, and to whom.
        message: TextMessageJson,
    },
    /// A channel was created.
    ChannelCreated {
        /// The new channel.
        channel: ChannelJson,
    },
    /// A channel was removed, along with its subchannels.
    ChannelRemoved {
        /// Its last known state, for the reason `userDisconnected` carries one.
        channel: ChannelJson,
    },
    /// A channel was renamed, moved, or had its description or limits changed.
    ChannelStateChanged {
        /// Its new state.
        channel: ChannelJson,
    },

    /// The server's state became readable, and this channel is live.
    ///
    /// Virtual servers are configuration here; there is nothing to boot at
    /// runtime. So this fires when the bridge attaches, which is what a
    /// consumer wants it for either way: the moment it is worth asking.
    Started {
        /// Which virtual server.
        server_id: u32,
    },
    /// The server's state stopped being readable.
    ///
    /// A shutdown and a dropped subscription are reported the same way: from a
    /// consumer's side they are indistinguishable, and both mean the same
    /// thing, what you are holding is now stale.
    Stopped {
        /// Which virtual server.
        server_id: u32,
    },

    /// A user chose a context-menu entry registered over this channel.
    ContextAction {
        /// The entry's name, as it was registered.
        action: String,
        /// Who registered it.
        owner: String,
        /// The session that invoked it.
        actor_session: u32,
        /// The user it was invoked on, `0` when not a user-menu entry.
        session: u32,
        /// The channel it was invoked on, `0` when not a channel-menu entry.
        channel: u32,
    },
}

/// The hub every subscriber reads from.
///
/// One per process, fed by one bridge task per upstream service. Subscribers
/// are cheap: they are receivers on a broadcast channel, so a thousand of them
/// cost one copy of each event, not a thousand gRPC subscriptions.
#[derive(Debug, Clone)]
pub struct EventHub {
    tx: broadcast::Sender<Event>,
    /// Whether the state below the bridges is currently readable.
    ///
    /// Kept because `started` is published once, when the bridges attach, and
    /// this channel is deliberately not a replay, so a subscriber connecting
    /// afterwards would otherwise never learn the channel is live, which is the
    /// one thing `started` exists to tell it.
    live: Arc<AtomicBool>,
    /// How many bridges currently hold a subscription.
    ///
    /// The channel is live only at [`BRIDGES`] (every one of them) and that
    /// is the whole point of counting. `live` used to be set by the session
    /// bridge alone, so `started` went out while the channel bridge was still
    /// attaching: a channel created in that window produced no event at all,
    /// and a subscriber that had done what `started` invites it to do waited
    /// for something nobody was listening for. Intermittent by nature, and
    /// indistinguishable from a lost event.
    attached: Arc<AtomicUsize>,
}

/// How many bridges must hold a subscription for the channel to be live.
///
/// The count of `spawn_bridges`, and the two must agree: one too high and
/// `started` never fires, one too low and it fires early, which is the bug the
/// counter exists to prevent.
const BRIDGES: usize = 4;

impl Default for EventHub {
    fn default() -> Self {
        Self::new()
    }
}

impl EventHub {
    /// An empty hub with no bridges running yet.
    #[must_use]
    pub fn new() -> Self {
        Self {
            tx: broadcast::channel(BACKLOG).0,
            live: Arc::new(AtomicBool::new(false)),
            attached: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// Whether the state below the bridges is readable right now.
    ///
    /// A transport sends a joining subscriber its own `started` when this is
    /// true, so "the channel is live" does not depend on having been connected
    /// at the moment the bridges happened to attach.
    #[must_use]
    pub fn is_live(&self) -> bool {
        self.live.load(Ordering::Relaxed)
    }

    /// One bridge has its subscription; `started` goes out when the last does.
    ///
    /// Called after the stream is open rather than before, because the promise
    /// being made is that events from here on are observed, a bridge that has
    /// asked for a stream and not yet received one is still dropping them.
    fn bridge_attached(&self, scope: Scope) {
        if self.attached.fetch_add(1, Ordering::Relaxed) + 1 == BRIDGES {
            self.live.store(true, Ordering::Relaxed);
            self.publish(Event::Started {
                server_id: scope.virtual_server,
            });
        }
    }

    /// One bridge lost its subscription; `stopped` goes out as the first does.
    ///
    /// The channel stops being live the moment *any* bridge drops, for the
    /// same reason it only starts when all of them are up: a subscriber cannot
    /// tell which half of the server it is no longer hearing about.
    fn bridge_detached(&self, scope: Scope) {
        if self.attached.fetch_sub(1, Ordering::Relaxed) == BRIDGES {
            self.live.store(false, Ordering::Relaxed);
            self.publish(Event::Stopped {
                server_id: scope.virtual_server,
            });
        }
    }

    /// Everything published from now on.
    ///
    /// Deliberately not a replay: this is a notification channel, and what the
    /// state *is* has its own routes. A consumer that wants both reads
    /// `/v1/sessions` and `/v1/channels` first, then follows the stream.
    #[must_use]
    pub fn subscribe(&self) -> broadcast::Receiver<Event> {
        self.tx.subscribe()
    }

    /// Publish. A send with no subscriber is dropped, not an error.
    pub fn publish(&self, event: Event) {
        let _ = self.tx.send(event);
    }

    /// Start every bridge task. Returns immediately; the tasks run until
    /// shutdown and reconnect on their own.
    pub fn spawn_bridges(&self, resolver: starling_runtime::channel::Resolver) {
        let scope = Scope { virtual_server: 1 };
        drop(tokio::spawn(bridge_sessions(
            self.clone(),
            resolver.clone(),
            scope,
        )));
        drop(tokio::spawn(bridge_channels(
            self.clone(),
            resolver.clone(),
            scope,
        )));
        drop(tokio::spawn(bridge_text(
            self.clone(),
            resolver.clone(),
            scope,
        )));
        drop(tokio::spawn(bridge_context(self.clone(), resolver, scope)));
    }
}

/// How long to wait before re-attaching a dropped subscription.
///
/// A fixed delay rather than a backoff: these are in-cluster gRPC streams, and
/// the failure being retried is a service restart, which resolves in seconds or
/// not at all.
const REATTACH: std::time::Duration = std::time::Duration::from_secs(2);

/// How long one attempt to attach a subscription may take.
///
/// Without this a bridge can wait forever inside the call that opens the
/// stream, a dial that hangs rather than refusing never returns, so the retry
/// below is never reached and the live channel silently never starts. That
/// failure logs nothing at all, which makes it the worst of the ones available.
const ATTACH: std::time::Duration = std::time::Duration::from_secs(5);

/// Run one attach attempt, turning a hang into a refusal that can be retried.
async fn attaching<T>(
    what: &str,
    attempt: impl Future<Output = Result<T, tonic::Status>>,
) -> Result<T, tonic::Status> {
    match tokio::time::timeout(ATTACH, attempt).await {
        Ok(result) => result,
        Err(_) => Err(tonic::Status::deadline_exceeded(format!(
            "{what} did not answer within {}s",
            ATTACH.as_secs()
        ))),
    }
}

/// `session-view` → `userConnected` / `userStateChanged` / `userDisconnected`.
async fn bridge_sessions(
    hub: EventHub,
    resolver: starling_runtime::channel::Resolver,
    scope: Scope,
) {
    use starling_proto_fancy::sessionview::SubscribeRequest;
    use starling_proto_fancy::sessionview::session_view_client::SessionViewClient;
    use starling_proto_fancy::sessionview::view_event::Event as ViewEvent;

    loop {
        // Reset per attach. A new subscription opens with a snapshot, and the
        // set has to be rebuilt from it, carrying the old one across a
        // reconnect would report everybody who joined while it was down as
        // already known, which is exactly the arrival a consumer wanted.
        let mut known: HashSet<u32> = HashSet::new();
        let mut last: std::collections::HashMap<u32, UserJson> = std::collections::HashMap::new();

        let stream = match resolver.channel("session-view") {
            Ok(channel) => {
                attaching(
                    "session-view",
                    SessionViewClient::new(channel).subscribe(SubscribeRequest {
                        scope: Some(scope),
                        subscriber: "operator-api/events".to_owned(),
                    }),
                )
                .await
            }
            Err(error) => {
                tracing::warn!(%error, "session-view is unreachable; retrying");
                tokio::time::sleep(REATTACH).await;
                continue;
            }
        };

        let mut stream = match stream {
            Ok(response) => {
                hub.bridge_attached(scope);
                response.into_inner()
            }
            Err(status) => {
                tracing::warn!(%status, "could not subscribe to session-view; retrying");
                tokio::time::sleep(REATTACH).await;
                continue;
            }
        };

        while let Ok(Some(event)) = stream.message().await {
            match event.event {
                Some(ViewEvent::Snapshot(sessions)) => {
                    // Seeded silently. Everyone already connected when the
                    // bridge attached is not an arrival, and reporting them as
                    // one would make every restart look like a join flood.
                    known.clear();
                    last.clear();
                    for session in sessions.sessions {
                        let _ = known.insert(session.session);
                        let _ = last.insert(session.session, user_json(&session));
                    }
                }
                Some(ViewEvent::Upsert(session)) => {
                    let user = user_json(&session);
                    if known.insert(session.session) {
                        hub.publish(Event::UserConnected { user: user.clone() });
                    } else if last.get(&session.session) != Some(&user) {
                        // Only when something actually changed. `session-view`
                        // republishes on any composed change, including ones
                        // this projection does not carry, and a consumer that
                        // reacts to every upsert would act on nothing.
                        hub.publish(Event::UserStateChanged { user: user.clone() });
                    }
                    let _ = last.insert(session.session, user);
                }
                Some(ViewEvent::Gone(gone)) => {
                    let _ = known.remove(&gone.session);
                    // The last state seen, because the session is already gone
                    // and cannot be looked up to describe what just left.
                    if let Some(user) = last.remove(&gone.session) {
                        hub.publish(Event::UserDisconnected { user });
                    }
                }
                _ => {}
            }
        }

        hub.bridge_detached(scope);
        tracing::warn!("the session-view subscription ended; re-attaching");
        tokio::time::sleep(REATTACH).await;
    }
}

/// `metadata` → `channelCreated` / `channelStateChanged` / `channelRemoved`.
async fn bridge_channels(
    hub: EventHub,
    resolver: starling_runtime::channel::Resolver,
    scope: Scope,
) {
    use starling_proto_fancy::metadata::TreeRequest;
    use starling_proto_fancy::metadata::metadata_client::MetadataClient;
    use starling_proto_fancy::metadata::tree_event::Event as TreeEvent;

    loop {
        let mut known: HashSet<u32> = HashSet::new();
        let mut last: std::collections::HashMap<u32, ChannelJson> =
            std::collections::HashMap::new();

        let Ok(channel) = resolver.channel("metadata") else {
            tracing::warn!("metadata is unreachable; retrying");
            tokio::time::sleep(REATTACH).await;
            continue;
        };
        let mut client = MetadataClient::new(channel);

        // Seeded from the tree before watching, because `Watch` sends changes
        // and not a snapshot: without this every existing channel's first edit
        // would be reported as a creation.
        if let Ok(tree) = client.get_tree(TreeRequest { scope: Some(scope) }).await {
            for c in tree.into_inner().channels {
                let json = channel_json(&c);
                let _ = known.insert(c.id);
                let _ = last.insert(c.id, json);
            }
        }

        let mut stream =
            match attaching("metadata", client.watch(TreeRequest { scope: Some(scope) })).await {
                Ok(response) => {
                    hub.bridge_attached(scope);
                    response.into_inner()
                }
                Err(status) => {
                    tracing::warn!(%status, "could not watch metadata; retrying");
                    tokio::time::sleep(REATTACH).await;
                    continue;
                }
            };

        while let Ok(Some(event)) = stream.message().await {
            match event.event {
                Some(TreeEvent::Upsert(c)) => {
                    let json = channel_json(&c);
                    if known.insert(c.id) {
                        hub.publish(Event::ChannelCreated {
                            channel: json.clone(),
                        });
                    } else if last.get(&c.id) != Some(&json) {
                        hub.publish(Event::ChannelStateChanged {
                            channel: json.clone(),
                        });
                    }
                    let _ = last.insert(c.id, json);
                }
                Some(TreeEvent::Removed(id)) => {
                    let _ = known.remove(&id);
                    if let Some(channel) = last.remove(&id) {
                        hub.publish(Event::ChannelRemoved { channel });
                    }
                }
                _ => {}
            }
        }

        hub.bridge_detached(scope);
        tracing::warn!("the metadata subscription ended; re-attaching");
        tokio::time::sleep(REATTACH).await;
    }
}

/// `text` → `userTextMessage`.
async fn bridge_text(hub: EventHub, resolver: starling_runtime::channel::Resolver, scope: Scope) {
    use starling_proto_fancy::text::WatchRequest;
    use starling_proto_fancy::text::text_client::TextClient;

    loop {
        let stream = match resolver.channel("text") {
            Ok(channel) => {
                attaching(
                    "text",
                    TextClient::new(channel).watch(WatchRequest {
                        scope: Some(scope),
                        subscriber: "operator-api/events".to_owned(),
                    }),
                )
                .await
            }
            Err(error) => {
                tracing::warn!(%error, "text is unreachable; retrying");
                tokio::time::sleep(REATTACH).await;
                continue;
            }
        };

        let mut stream = match stream {
            Ok(response) => {
                hub.bridge_attached(scope);
                response.into_inner()
            }
            Err(status) => {
                tracing::warn!(%status, "could not watch text; retrying");
                tokio::time::sleep(REATTACH).await;
                continue;
            }
        };

        while let Ok(Some(message)) = stream.message().await {
            hub.publish(Event::UserTextMessage {
                // What `text` knows about the sender. A consumer wanting the
                // rest joins on `session`.
                user: UserJson {
                    session: message.sender_session,
                    name: message.sender_name,
                    channel: message.channels.first().copied().unwrap_or_default(),
                    user_id: starling_proto_fancy::identity::account(
                        message.sender_registered,
                        message.sender_account,
                    ),
                    mute: false,
                    deaf: false,
                    self_mute: false,
                    self_deaf: false,
                    suppress: false,
                    priority_speaker: false,
                    connected_at_ms: 0,
                },
                message: TextMessageJson {
                    body: message.body,
                    channels: message.channels,
                    sessions: message.sessions,
                    tree: message.tree,
                    sent_at_ms: message.sent_at_ms,
                    from_client: message.from_client,
                },
            });
        }

        hub.bridge_detached(scope);
        tracing::warn!("the text subscription ended; re-attaching");
        tokio::time::sleep(REATTACH).await;
    }
}

/// `context-actions` → `contextAction`.
async fn bridge_context(
    hub: EventHub,
    resolver: starling_runtime::channel::Resolver,
    scope: Scope,
) {
    use starling_proto_fancy::contextactions::WatchRequest;
    use starling_proto_fancy::contextactions::context_actions_client::ContextActionsClient;

    loop {
        let stream = match resolver.channel("context-actions") {
            Ok(channel) => {
                attaching(
                    "context-actions",
                    ContextActionsClient::new(channel).watch(WatchRequest {
                        scope: Some(scope),
                        // Every entry this API registers is owned by the API,
                        // not by the operator who added it: operators come and
                        // go and the menu entry outlives the request.
                        owner: OWNER.to_owned(),
                    }),
                )
                .await
            }
            Err(error) => {
                tracing::warn!(%error, "context-actions is unreachable; retrying");
                tokio::time::sleep(REATTACH).await;
                continue;
            }
        };

        let mut stream = match stream {
            Ok(response) => {
                hub.bridge_attached(scope);
                response.into_inner()
            }
            Err(status) => {
                tracing::warn!(%status, "could not watch context-actions; retrying");
                tokio::time::sleep(REATTACH).await;
                continue;
            }
        };

        while let Ok(Some(trigger)) = stream.message().await {
            hub.publish(Event::ContextAction {
                action: trigger.action,
                owner: trigger.owner,
                actor_session: trigger.actor_session,
                session: trigger.session,
                channel: trigger.channel,
            });
        }

        hub.bridge_detached(scope);
        tracing::warn!("the context-actions subscription ended; re-attaching");
        tokio::time::sleep(REATTACH).await;
    }
}

/// The owner every entry registered through this API belongs to.
pub const OWNER: &str = "operator-api";

fn user_json(s: &starling_proto_fancy::sessionview::Session) -> UserJson {
    UserJson {
        session: s.session,
        name: s.name.clone(),
        channel: s.channel,
        // Through `identity`, never `account` alone: an unregistered guest and
        // the SuperUser are both account 0, and only `registered` tells them
        // apart.
        user_id: starling_proto_fancy::identity::account(s.registered, s.account),
        mute: s.mute,
        deaf: s.deaf,
        self_mute: s.self_mute,
        self_deaf: s.self_deaf,
        suppress: s.suppress,
        priority_speaker: s.priority_speaker,
        connected_at_ms: s.connected_at_ms,
    }
}

/// `Channel.flags` bits, from `metadata`'s `tree_actor.rs`.
const CHANNEL_HIDDEN: u32 = 1;
const CHANNEL_TEMPORARY: u32 = 2;

fn channel_json(c: &starling_proto_fancy::metadata::Channel) -> ChannelJson {
    ChannelJson {
        id: c.id,
        parent: c.parent.unwrap_or(0),
        name: c.name.clone(),
        description: c.description.clone(),
        position: c.position,
        max_users: c.max_users,
        links: c.links.clone(),
        hidden: c.flags & CHANNEL_HIDDEN != 0,
        temporary: c.flags & CHANNEL_TEMPORARY != 0,
    }
}

/// Shared by both transports: what a subscriber is sent, as a JSON line.
///
/// One function so the WebSocket and WebTransport channels cannot drift into
/// serialising the same event two different ways.
#[must_use]
pub fn encode(event: &Event) -> String {
    serde_json::to_string(event).unwrap_or_else(|error| {
        // Serialising these types cannot fail; they are plain data with no
        // maps, non-string keys or custom impls, but a panic on the event path
        // would take the whole channel down for every subscriber.
        tracing::error!(%error, "an event could not be serialised");
        String::from(r#"{"event":"error","reason":"unserialisable"}"#)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn user(session: u32, channel: u32) -> UserJson {
        UserJson {
            session,
            name: "someone".to_owned(),
            channel,
            user_id: None,
            mute: false,
            deaf: false,
            self_mute: false,
            self_deaf: false,
            suppress: false,
            priority_speaker: false,
            connected_at_ms: 0,
        }
    }

    #[test]
    fn an_event_names_itself_the_way_the_cpp_server_named_its_callback() {
        // The systems pointed at this channel switch on this string, and they
        // were written against those names. It is the contract.
        let json = encode(&Event::UserConnected { user: user(1, 0) });
        assert!(json.contains(r#""event":"userConnected""#), "{json}");

        let json = encode(&Event::ChannelStateChanged {
            channel: ChannelJson {
                id: 1,
                parent: 0,
                name: "General".to_owned(),
                description: String::new(),
                position: 0,
                max_users: 0,
                links: Vec::new(),
                hidden: false,
                temporary: false,
            },
        });
        assert!(json.contains(r#""event":"channelStateChanged""#), "{json}");
    }

    #[test]
    fn an_unregistered_guest_has_no_account_rather_than_account_zero() {
        // Account 0 is the SuperUser. A guest written as 0 would read as the
        // administrator, which is the one confusion this must never allow.
        let json = encode(&Event::UserConnected { user: user(3, 0) });
        assert!(json.contains(r#""user_id":null"#), "{json}");

        let mut registered = user(4, 0);
        registered.user_id = Some(0);
        let json = encode(&Event::UserConnected { user: registered });
        assert!(json.contains(r#""user_id":0"#), "{json}");
    }

    #[test]
    fn a_subscriber_receives_what_is_published_after_it_subscribed() {
        let hub = EventHub::new();
        let mut first = hub.subscribe();
        hub.publish(Event::Started { server_id: 1 });
        assert_eq!(
            first.try_recv().expect("delivered"),
            Event::Started { server_id: 1 }
        );

        // And not what came before it: this is a notification channel, not a
        // replay, so a late subscriber must not be handed history it would
        // then act on twice.
        let mut late = hub.subscribe();
        assert!(late.try_recv().is_err());
    }

    #[test]
    fn publishing_with_nobody_listening_is_not_an_error() {
        // The bridges run whether or not anything is subscribed, and a server
        // whose event path failed when unobserved would fail exactly when
        // nobody could see why.
        let hub = EventHub::new();
        hub.publish(Event::Stopped { server_id: 1 });
    }
}
