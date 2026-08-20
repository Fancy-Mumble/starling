//! The plugin-facing context: one [`HostBridge`], namespaced per plugin.
//!
//! A plugin is handed a [`PluginContext`] trait object and calls back into the
//! server through it. Everything except configuration is forwarded to the
//! bridge unchanged; configuration is *scoped*, so a plugin asking for `"port"`
//! reads `plugin.<name>.port` and cannot see, or name, another plugin's
//! settings. That scoping is the whole reason this type exists rather than
//! handing the bridge straight to the plugin.
//!
//! Cross-plugin wiring is therefore impossible from inside a plugin by
//! construction, and possible only in whatever sits above the host.

// The `#[sabi_trait]`-generated forwarder for `PluginContext` calls the
// deprecated `send_plugin_data`, which would otherwise warn on every build of
// this file. The deprecation is aimed at plugin authors, not at the host that
// has to keep relaying the message shipped clients still send.
#![allow(
    deprecated,
    reason = "the host implements the deprecated legacy relay it still has to carry"
)]

use std::sync::Arc;

use abi_stable::std_types::{RErr, RNone, ROk, ROption, RSlice, RSome, RStr, RString, RVec};
use mumble_plugin_api::{
    ChannelId, PluginContext, PluginError, PluginMessageOut, PluginResult, ServerId, SessionId,
};

use crate::bridge::{HostBridge, NewChannel, OutboundMessage};

/// Wrap a bridge failure as the error type plugins see.
fn failed(message: String) -> PluginResult<()> {
    RErr(PluginError::Other(RString::from(message)))
}

/// One plugin's view of the server.
#[derive(Debug)]
pub struct ScopedContext {
    bridge: Arc<dyn HostBridge>,
    /// `plugin.<name>`, prepended to every configuration key the plugin names.
    config_prefix: String,
}

impl ScopedContext {
    /// A context scoping configuration reads to `config_prefix`.
    pub fn new(bridge: Arc<dyn HostBridge>, config_prefix: impl Into<String>) -> Self {
        Self {
            bridge,
            config_prefix: config_prefix.into(),
        }
    }
}

impl PluginContext for ScopedContext {
    fn send_plugin_data(
        &self,
        server_id: ServerId,
        target_session: SessionId,
        data_id: RStr<'_>,
        data: RSlice<'_, u8>,
    ) -> PluginResult<()> {
        match self.bridge.send_plugin_data(
            server_id,
            target_session,
            data_id.as_str(),
            data.as_slice(),
        ) {
            Ok(()) => ROk(()),
            Err(error) => failed(error),
        }
    }

    fn is_session_active(&self, server_id: ServerId, session: SessionId) -> bool {
        self.bridge.is_session_active(server_id, session)
    }

    fn user_has_channel_access(
        &self,
        server_id: ServerId,
        session: SessionId,
        channel: ChannelId,
    ) -> bool {
        self.bridge
            .user_has_channel_access(server_id, session, channel)
    }

    fn has_permission(
        &self,
        server_id: ServerId,
        session: SessionId,
        channel: ChannelId,
        permission_flags: u32,
    ) -> bool {
        self.bridge
            .has_permission(server_id, session, channel, permission_flags)
    }

    fn current_channel(&self, server_id: ServerId, session: SessionId) -> ROption<ChannelId> {
        self.bridge
            .current_channel(server_id, session)
            .map_or(RNone, RSome)
    }

    fn get_config(&self, key: RStr<'_>) -> ROption<RString> {
        let scoped = format!("{}.{}", self.config_prefix, key.as_str());
        self.bridge
            .get_config(&scoped)
            .map_or(RNone, |value| RSome(RString::from(value)))
    }

    fn send_plugin_message(&self, msg: PluginMessageOut) -> PluginResult<()> {
        let targets: Vec<SessionId> = msg.target_sessions.iter().copied().collect();
        let message = OutboundMessage {
            server_id: msg.server_id,
            plugin_name: msg.plugin_name.as_str(),
            payload_type: msg.payload_type.as_str(),
            payload: msg.payload.as_slice(),
            target_sessions: &targets,
            channel_id: msg.channel_id.into_option(),
        };
        match self.bridge.send_plugin_message(&message) {
            Ok(()) => ROk(()),
            Err(error) => failed(error),
        }
    }

    fn sessions_in_channel(&self, server_id: ServerId, channel: ChannelId) -> RVec<SessionId> {
        RVec::from(self.bridge.sessions_in_channel(server_id, channel))
    }

    fn all_sessions(&self, server_id: ServerId) -> RVec<SessionId> {
        RVec::from(self.bridge.all_sessions(server_id))
    }

    fn find_session_by_name(&self, server_id: ServerId, name: RStr<'_>) -> ROption<SessionId> {
        self.bridge
            .find_session_by_name(server_id, name.as_str())
            .map_or(RNone, RSome)
    }

    fn send_request_response(
        &self,
        server_id: ServerId,
        response_type: RStr<'_>,
        request_id: RStr<'_>,
        target_session: SessionId,
        payload: RSlice<'_, u8>,
    ) -> PluginResult<()> {
        match self.bridge.send_request_response(
            server_id,
            response_type.as_str(),
            request_id.as_str(),
            target_session,
            payload.as_slice(),
        ) {
            Ok(()) => ROk(()),
            Err(error) => failed(error),
        }
    }

    fn create_channel(
        &self,
        server_id: ServerId,
        parent: ChannelId,
        name: RStr<'_>,
        hidden: bool,
        registered_can_manage: bool,
        detached: bool,
        pchat_protocol: u32,
        expiry_mode: u32,
        expiry_duration_secs: u32,
        invitee_uids: RSlice<'_, u32>,
    ) -> ROption<ChannelId> {
        let spec = NewChannel {
            parent,
            name: name.as_str(),
            hidden,
            registered_can_manage,
            detached,
            pchat_protocol,
            expiry_mode,
            expiry_duration_secs,
            invitee_uids: invitee_uids.as_slice(),
        };
        self.bridge
            .create_channel(server_id, &spec)
            .map_or(RNone, RSome)
    }

    fn grant_channel_access(&self, server_id: ServerId, channel: ChannelId, user_id: u32) -> bool {
        self.bridge
            .grant_channel_access(server_id, channel, user_id)
    }

    fn revoke_channel_access(&self, server_id: ServerId, channel: ChannelId, user_id: u32) -> bool {
        self.bridge
            .revoke_channel_access(server_id, channel, user_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// A bridge that records the keys it was asked for.
    #[derive(Debug, Default)]
    struct Recorder {
        asked: Mutex<Vec<String>>,
    }

    impl HostBridge for Recorder {
        fn get_config(&self, key: &str) -> Option<String> {
            if let Ok(mut asked) = self.asked.lock() {
                asked.push(key.to_owned());
            }
            Some("value".to_owned())
        }
        fn set_config(&self, _key: &str, _value: &str) -> Result<(), String> {
            Ok(())
        }
        fn delete_config_prefix(&self, _prefix: &str) -> Result<(), String> {
            Ok(())
        }
        fn send_plugin_data(
            &self,
            _server_id: ServerId,
            _target_session: SessionId,
            _data_id: &str,
            _data: &[u8],
        ) -> Result<(), String> {
            Ok(())
        }
        fn send_plugin_message(&self, _message: &OutboundMessage<'_>) -> Result<(), String> {
            Ok(())
        }
        fn is_session_active(&self, _server_id: ServerId, _session: SessionId) -> bool {
            false
        }
        fn user_has_channel_access(
            &self,
            _server_id: ServerId,
            _session: SessionId,
            _channel: ChannelId,
        ) -> bool {
            false
        }
        fn has_permission(
            &self,
            _server_id: ServerId,
            _session: SessionId,
            _channel: ChannelId,
            _flags: u32,
        ) -> bool {
            false
        }
        fn current_channel(&self, _server_id: ServerId, _session: SessionId) -> Option<ChannelId> {
            None
        }
    }

    #[test]
    fn a_plugin_reads_its_own_namespace_and_cannot_name_anothers() {
        // The plugin asks for "port"; what reaches the server is
        // `plugin.fancy-friends.port`. A plugin that wrote the fully-qualified
        // key of a *different* plugin would still only reach its own namespace,
        // because the prefix is prepended rather than trusted from the caller.
        let recorder = Arc::new(Recorder::default());
        let ctx = ScopedContext::new(
            Arc::clone(&recorder) as Arc<dyn HostBridge>,
            "plugin.fancy-friends",
        );

        let _ = ctx.get_config(RStr::from_str("port"));
        let _ = ctx.get_config(RStr::from_str("plugin.fancy-audit.secret"));

        let asked = recorder.asked.lock().expect("not poisoned").clone();
        assert_eq!(
            asked,
            vec![
                "plugin.fancy-friends.port".to_owned(),
                "plugin.fancy-friends.plugin.fancy-audit.secret".to_owned(),
            ],
            "every read is prefixed, so no key escapes the plugin's namespace"
        );
    }

    #[test]
    fn a_bridge_that_offers_nothing_answers_no_rather_than_yes() {
        // The defaults matter: a half-implemented bridge must degrade to "the
        // host does not offer that", never to an accidental grant.
        let ctx = ScopedContext::new(
            Arc::new(Recorder::default()) as Arc<dyn HostBridge>,
            "plugin.x",
        );
        assert!(ctx.all_sessions(1).is_empty());
        assert!(!ctx.grant_channel_access(1, 2, 3));
        assert_eq!(
            ctx.create_channel(
                1,
                0,
                RStr::from_str("x"),
                false,
                false,
                false,
                0,
                0,
                0,
                RSlice::from_slice(&[]),
            ),
            RNone
        );
    }
}
