//! `context-actions`: the menu entries a plugin adds, and the triggers back.
//!
//! The server never learns what an action *does*. It carries the plugin's own
//! identifier alongside each entry, so a trigger routes back to the plugin that
//! registered it without anything here understanding the feature, the same
//! opacity rule the plugin host follows (`docs/STORAGE.md` L6).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use prost::Message as _;
use starling_proto::proto::tcp;
use starling_proto_fancy::common::Ack;
use starling_proto_fancy::contextactions::context_actions_server::{
    ContextActions, ContextActionsServer,
};
use starling_proto_fancy::contextactions::{AddRequest, RemoveRequest, Trigger, WatchRequest};
use starling_proto_fancy::fancy::feature::{
    ContextActionsEnvelope, Menu, MenuEntry, context_actions_envelope,
};
use starling_proto_fancy::types::ServiceKind;
use starling_runtime::ids::now_ms;
use starling_runtime::plane::{Actions, ClientService, Fanout, Inbound, Plane, to_conn};
use starling_runtime::serve::{Serve, ServiceContext, ServiceError};
use tokio::sync::broadcast;
use tonic::{Request, Response, Status};

/// Upstream `ContextActionModify`.
const CONTEXT_ACTION_MODIFY: u16 = 16;
/// Upstream `ContextAction`.
const CONTEXT_ACTION: u16 = 17;

/// How many triggers a `Watch` subscriber may fall behind by.
const TRIGGER_BACKLOG: usize = 256;

/// The service.
#[derive(Debug)]
pub struct ContextActionsService {
    /// Keyed by action name, which is therefore unique across owners.
    ///
    /// That constraint predates the gRPC surface, the client half has always
    /// keyed on it, and a trigger arrives naming only the action, so a second
    /// owner reusing a name would make the routing ambiguous rather than
    /// merely crowded.
    entries: Mutex<HashMap<String, MenuEntry>>,
    fanout: Fanout,
    /// Triggers, for `Watch` subscribers. Bounded and lossy, like [`Fanout`].
    triggers: broadcast::Sender<Trigger>,
}

impl ContextActionsService {
    /// Every entry a client should be shown.
    fn menu(&self) -> Menu {
        Menu {
            entries: self
                .entries
                .lock()
                .map(|entries| entries.values().cloned().collect())
                .unwrap_or_default(),
            removed: Vec::new(),
        }
    }

    /// Register or replace an entry.
    pub fn add(&self, entry: MenuEntry) {
        if let Ok(mut entries) = self.entries.lock() {
            let _ = entries.insert(entry.action.clone(), entry);
        }
    }

    /// Remove an entry, which is what a plugin being disabled does to its own.
    pub fn remove(&self, action: &str) {
        if let Ok(mut entries) = self.entries.lock() {
            let _ = entries.remove(action);
        }
    }

    /// Which plugin owns an action, if any does.
    #[must_use]
    pub fn owner(&self, action: &str) -> Option<String> {
        self.entries
            .lock()
            .ok()
            .and_then(|entries| entries.get(action).map(|entry| entry.plugin.clone()))
    }
}

impl ClientService for ContextActionsService {
    async fn frame(&self, inbound: Inbound) -> Actions {
        let outer = ServiceKind::ContextActions.outer_type();
        match inbound.type_id {
            CONTEXT_ACTION => {
                let Ok(action) = tcp::ContextAction::decode(inbound.payload.as_slice()) else {
                    tracing::debug!(conn = inbound.conn, "undecodable ContextAction");
                    return Actions::new();
                };
                // An action nobody registered is dropped rather than relayed:
                // forwarding it would let a client invent menu entries for
                // plugins that never offered them.
                if self.owner(&action.action).is_none() {
                    // The user clicked a menu entry and nothing happened, which
                    // is indistinguishable from a broken plugin without this.
                    tracing::debug!(
                        session = inbound.session,
                        action = %action.action,
                        "context action for an unregistered entry dropped"
                    );
                    return Actions::new();
                }
                tracing::debug!(
                    session = inbound.session,
                    action = %action.action,
                    "context action triggered"
                );
                // Routed to the owner, and only to it. `owner` returning None
                // was already handled above, so this cannot attribute a
                // trigger to nobody.
                let owner = self.owner(&action.action).unwrap_or_default();
                let _ = self.triggers.send(Trigger {
                    action: action.action.clone(),
                    owner,
                    actor_session: inbound.session,
                    session: action.session.unwrap_or_default(),
                    channel: action.channel_id.unwrap_or_default(),
                    at_ms: now_ms(),
                });
                Actions::new()
            }
            CONTEXT_ACTION_MODIFY => Actions::new(),
            id if id == outer => {
                let Ok(envelope) = ContextActionsEnvelope::decode(inbound.payload.as_slice())
                else {
                    tracing::debug!(conn = inbound.conn, "undecodable ContextActionsEnvelope");
                    return Actions::new();
                };
                match envelope.body {
                    Some(context_actions_envelope::Body::Menu(_)) => {
                        let reply = ContextActionsEnvelope {
                            body: Some(context_actions_envelope::Body::Menu(self.menu())),
                        };
                        vec![to_conn(inbound.conn, outer, reply.encode_to_vec())]
                    }
                    _ => Actions::new(),
                }
            }
            _ => Actions::new(),
        }
    }
}

/// The gRPC surface, as a type this crate owns.
#[derive(Debug, Clone)]
pub struct ContextActionsRpc(Arc<ContextActionsService>);

#[tonic::async_trait]
impl ContextActions for ContextActionsRpc {
    async fn add(&self, request: Request<AddRequest>) -> Result<Response<Ack>, Status> {
        let Some(entry) = request.into_inner().entry else {
            return Err(Status::invalid_argument("no entry was described"));
        };
        if entry.action.trim().is_empty() {
            return Err(Status::invalid_argument("an entry needs an action name"));
        }
        if entry.owner.trim().is_empty() {
            // Without an owner a trigger has nowhere to go, and the entry would
            // sit in every user's menu doing nothing.
            return Err(Status::invalid_argument("an entry needs an owner"));
        }

        self.0.add(MenuEntry {
            action: entry.action,
            text: entry.text,
            plugin: entry.owner,
            context: entry.context,
        });
        Ok(Response::new(Ack {}))
    }

    async fn remove(&self, request: Request<RemoveRequest>) -> Result<Response<Ack>, Status> {
        let req = request.into_inner();
        // An owner may only remove its own. Without this check any caller could
        // unregister a plugin's menu entries by naming them.
        match self.0.owner(&req.action) {
            Some(owner) if owner == req.owner => {
                self.0.remove(&req.action);
                Ok(Response::new(Ack {}))
            }
            // Already gone is success: removing what is not there leaves the
            // world in the state the caller asked for.
            None => Ok(Response::new(Ack {})),
            Some(_) => Err(Status::permission_denied(
                "that action belongs to another owner",
            )),
        }
    }

    type WatchStream = tokio_stream::wrappers::ReceiverStream<Result<Trigger, Status>>;

    async fn watch(
        &self,
        request: Request<WatchRequest>,
    ) -> Result<Response<Self::WatchStream>, Status> {
        let owner = request.into_inner().owner;
        if owner.trim().is_empty() {
            return Err(Status::invalid_argument("a watcher must name its owner"));
        }
        let mut triggers = self.0.triggers.subscribe();
        let (tx, rx) = tokio::sync::mpsc::channel(TRIGGER_BACKLOG);

        drop(tokio::spawn(async move {
            loop {
                match triggers.recv().await {
                    Ok(trigger) => {
                        // Filtered here rather than with one channel per owner:
                        // a trigger for somebody else must not reach this
                        // stream, because its mere arrival would disclose that
                        // the other entry exists.
                        if trigger.owner != owner {
                            continue;
                        }
                        if tx.send(Ok(trigger)).await.is_err() {
                            break;
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(missed)) => {
                        tracing::warn!(owner, missed, "a context-action watcher fell behind");
                    }
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }
        }));

        Ok(Response::new(tokio_stream::wrappers::ReceiverStream::new(
            rx,
        )))
    }
}

impl Serve for ContextActionsService {
    const NAME: &'static str = "context-actions";

    async fn build(_ctx: ServiceContext) -> Result<Arc<Self>, ServiceError> {
        Ok(Arc::new(Self {
            entries: Mutex::new(HashMap::new()),
            fanout: Fanout::default(),
            triggers: broadcast::channel(TRIGGER_BACKLOG).0,
        }))
    }

    fn routes(self: Arc<Self>) -> tonic::service::Routes {
        let plane = Plane::new(Arc::clone(&self), self.fanout.clone(), Self::NAME).into_server();
        tonic::service::Routes::default()
            .add_service(ContextActionsServer::new(ContextActionsRpc(Arc::clone(
                &self,
            ))))
            .add_service(plane)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn service() -> Arc<ContextActionsService> {
        Arc::new(ContextActionsService {
            entries: Mutex::new(HashMap::new()),
            fanout: Fanout::default(),
            triggers: broadcast::channel(TRIGGER_BACKLOG).0,
        })
    }

    #[test]
    fn an_entry_carries_the_plugin_that_owns_it() {
        // Without it a trigger has nowhere to route back to, and the server
        // would have to know what the action means.
        let service = service();
        service.add(MenuEntry {
            action: "kick-to-lobby".to_owned(),
            text: "Send to lobby".to_owned(),
            plugin: "moderation-helper".to_owned(),
            context: 1,
        });
        assert_eq!(
            service.owner("kick-to-lobby").as_deref(),
            Some("moderation-helper")
        );
    }

    #[tokio::test]
    async fn a_trigger_for_an_unregistered_action_is_dropped() {
        let actions = service()
            .frame(Inbound {
                conn: 1,
                session: 2,
                type_id: CONTEXT_ACTION,
                payload: tcp::ContextAction {
                    action: "invented".to_owned(),
                    ..tcp::ContextAction::default()
                }
                .encode_to_vec(),
                gateway: "gw".to_owned(),
                scope: 1,
            })
            .await;
        assert!(actions.is_empty());
    }

    #[test]
    fn removing_an_entry_takes_it_out_of_the_menu() {
        let service = service();
        service.add(MenuEntry {
            action: "a".to_owned(),
            plugin: "p".to_owned(),
            ..MenuEntry::default()
        });
        service.remove("a");
        assert!(service.menu().entries.is_empty());
    }

    /// An `AddRequest` for `owner`, with the given action name.
    fn add_request(owner: &str, action: &str) -> Request<AddRequest> {
        Request::new(AddRequest {
            scope: None,
            actor: None,
            entry: Some(starling_proto_fancy::contextactions::Entry {
                action: action.to_owned(),
                text: "Do the thing".to_owned(),
                owner: owner.to_owned(),
                context: 4,
            }),
        })
    }

    #[tokio::test]
    async fn one_owner_cannot_remove_another_owners_entry() {
        // Otherwise any operator holding the scope could unregister a plugin's
        // menu entries simply by knowing their names.
        let rpc = ContextActionsRpc(service());
        let _ = rpc
            .add(add_request("plugin-a", "shared-name"))
            .await
            .expect("added");

        let refused = rpc
            .remove(Request::new(RemoveRequest {
                scope: None,
                actor: None,
                owner: "plugin-b".to_owned(),
                action: "shared-name".to_owned(),
            }))
            .await;

        assert_eq!(
            refused.expect_err("removal is refused").code(),
            tonic::Code::PermissionDenied
        );
        assert_eq!(rpc.0.owner("shared-name").as_deref(), Some("plugin-a"));
    }

    #[tokio::test]
    async fn removing_an_entry_that_is_already_gone_succeeds() {
        // Removal states an intended end state, and that state already holds.
        let rpc = ContextActionsRpc(service());
        let _ = rpc
            .remove(Request::new(RemoveRequest {
                scope: None,
                actor: None,
                owner: "anyone".to_owned(),
                action: "never-registered".to_owned(),
            }))
            .await
            .expect("removing nothing is not an error");
    }

    #[tokio::test]
    async fn an_entry_without_an_owner_is_refused() {
        // A trigger for it would have nowhere to go, so the entry would sit in
        // every menu doing nothing.
        let rpc = ContextActionsRpc(service());
        let refused = rpc.add(add_request("", "orphan")).await;
        assert_eq!(
            refused.expect_err("refused").code(),
            tonic::Code::InvalidArgument
        );
    }

    #[tokio::test]
    async fn a_trigger_reaches_the_owner_and_names_who_invoked_it() {
        let service = service();
        let rpc = ContextActionsRpc(Arc::clone(&service));
        let _ = rpc
            .add(add_request("user-manager", "kick-nicely"))
            .await
            .expect("added");
        let mut triggers = service.triggers.subscribe();

        let _ = service
            .frame(Inbound {
                conn: 1,
                session: 7,
                type_id: CONTEXT_ACTION,
                payload: tcp::ContextAction {
                    action: "kick-nicely".to_owned(),
                    session: Some(42),
                    channel_id: Some(3),
                }
                .encode_to_vec(),
                gateway: "gw".to_owned(),
                scope: 1,
            })
            .await;

        let trigger = triggers.try_recv().expect("a trigger was published");
        assert_eq!(trigger.owner, "user-manager");
        assert_eq!(trigger.action, "kick-nicely");
        // Who clicked, and who it was clicked on: an entry in the user menu is
        // meaningless without the second.
        assert_eq!(trigger.actor_session, 7);
        assert_eq!(trigger.session, 42);
        assert_eq!(trigger.channel, 3);
    }
}
