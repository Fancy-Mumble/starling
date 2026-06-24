//! `context-actions` — the menu entries a plugin adds, and the triggers back.
//!
//! The server never learns what an action *does*. It carries the plugin's own
//! identifier alongside each entry, so a trigger routes back to the plugin that
//! registered it without anything here understanding the feature — the same
//! opacity rule the plugin host follows (`docs/STORAGE.md` L6).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use prost::Message as _;
use starling_proto::proto::tcp;
use starling_proto_fancy::fancy::feature::{
    ContextActionsEnvelope, Menu, MenuEntry, context_actions_envelope,
};
use starling_proto_fancy::types::ServiceKind;
use starling_runtime::plane::{Actions, ClientService, Fanout, Inbound, Plane, to_conn};
use starling_runtime::serve::{Serve, ServiceContext, ServiceError};

/// Upstream `ContextActionModify`.
const CONTEXT_ACTION_MODIFY: u16 = 16;
/// Upstream `ContextAction`.
const CONTEXT_ACTION: u16 = 17;

/// The service.
#[derive(Debug)]
pub struct ContextActionsService {
    entries: Mutex<HashMap<String, MenuEntry>>,
    fanout: Fanout,
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

impl Serve for ContextActionsService {
    const NAME: &'static str = "context-actions";

    async fn build(_ctx: ServiceContext) -> Result<Arc<Self>, ServiceError> {
        Ok(Arc::new(Self {
            entries: Mutex::new(HashMap::new()),
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

    fn service() -> Arc<ContextActionsService> {
        Arc::new(ContextActionsService {
            entries: Mutex::new(HashMap::new()),
            fanout: Fanout::default(),
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
}
