//! What the host needs from the server it runs inside.
//!
//! In the C++ server this was a struct of C function pointers the server filled
//! in and the host called through, with a `user_data` void pointer threaded
//! behind every call. Here it is a trait, which is the same contract without
//! the raw pointers, the NUL-termination dance or the manual free on every
//! returned string.
//!
//! The split is what keeps this crate ignorant of Starling. The host knows how
//! to find a plugin binary, load it, and hand it events; it does not know what
//! a channel is or how to reach one. Everything in that second category is a
//! method here, and `starling-plugins` implements them.
//!
//! # Everything is synchronous
//!
//! Plugin hooks are synchronous ([`mumble_plugin_api::MumblePlugin`] says so),
//! and a plugin calls back in from whatever thread it likes. So these methods
//! are synchronous too, and an implementation over an async server blocks
//! inside them. That is the right place for the blocking to happen: the caller
//! is a plugin worker thread or the blocking pool, never a runtime worker.

use mumble_plugin_api::{ChannelId, ServerId, SessionId};

/// The properties of a channel a plugin asks the host to create.
///
/// Grouped into a struct rather than eleven parameters, which is also how the
/// plugin-facing trait's own `create_channel` reads once the host is done with
/// it. Every field is a standard, content-agnostic channel property forwarded
/// verbatim; the host ascribes no meaning to any of them.
#[derive(Debug, Clone, Copy)]
pub struct NewChannel<'a> {
    /// Parent to create under. Ignored when [`Self::detached`] is set.
    pub parent: ChannelId,
    /// Channel name. Doubles as the identity for find-or-create.
    pub name: &'a str,
    /// Only users with `SeeChannel` are told it exists.
    pub hidden: bool,
    /// A shared container the authenticated group may see, traverse and create
    /// sub-channels in, while `@all` is denied `SeeChannel`.
    pub registered_can_manage: bool,
    /// Parentless and never shown in the channel tree.
    pub detached: bool,
    /// Persistent-chat protocol selector; 0 for none.
    pub pchat_protocol: u32,
    /// Auto-expiry mode; 0 for none.
    pub expiry_mode: u32,
    /// Auto-expiry duration in seconds.
    pub expiry_duration_secs: u32,
    /// When non-empty, makes it private: `@all` is denied and these registered
    /// users are granted.
    pub invitee_uids: &'a [u32],
}

/// One outbound plugin message the host asks the server to deliver.
///
/// Delivery is to [`Self::target_sessions`] when it is non-empty, otherwise to
/// every member of [`Self::channel_id`]. Naming neither is a no-op, not an
/// error: a plugin addressing nobody has said nothing.
#[derive(Debug, Clone, Copy)]
pub struct OutboundMessage<'a> {
    /// Server instance the message is bound for.
    pub server_id: ServerId,
    /// Which plugin is speaking. The server stamps it on the envelope.
    pub plugin_name: &'a str,
    /// Plugin-defined inner message type.
    pub payload_type: &'a str,
    /// Opaque payload bytes. The server never parses these.
    pub payload: &'a [u8],
    /// Explicit recipients.
    pub target_sessions: &'a [SessionId],
    /// Channel-scoped fan-out, used only when `target_sessions` is empty.
    pub channel_id: Option<ChannelId>,
}

/// The server, as the host sees it.
///
/// Methods that a minimal embedding need not implement carry defaults matching
/// the plugin-facing trait's own defaults, so an incomplete bridge degrades to
/// "the host does not offer that" rather than to a wrong answer.
pub trait HostBridge: std::fmt::Debug + Send + Sync + 'static {
    /// Read one configuration value by its full key.
    ///
    /// Plugin-scoped keys arrive here already prefixed with `plugin.<name>.`;
    /// the scoping is done by [`ScopedContext`](crate::ScopedContext), not
    /// here.
    fn get_config(&self, key: &str) -> Option<String>;

    /// Write one configuration value, durably.
    fn set_config(&self, key: &str, value: &str) -> Result<(), String>;

    /// Drop every key under `prefix`. Used when a plugin is uninstalled.
    fn delete_config_prefix(&self, prefix: &str) -> Result<(), String>;

    /// Deliver a legacy `PluginDataTransmission` to one session.
    fn send_plugin_data(
        &self,
        server_id: ServerId,
        target_session: SessionId,
        data_id: &str,
        data: &[u8],
    ) -> Result<(), String>;

    /// Deliver a generic plugin message.
    fn send_plugin_message(&self, message: &OutboundMessage<'_>) -> Result<(), String>;

    /// Read one key from `plugin`'s own storage.
    ///
    /// The name is supplied by the host, never by the plugin, which is what
    /// makes the namespace unforgeable.
    ///
    /// The default has no storage, for a bridge that offers none.
    fn kv_get(&self, plugin: &str, server_id: ServerId, key: &[u8]) -> Option<Vec<u8>> {
        let _ = (plugin, server_id, key);
        None
    }

    /// Every pair in `[start, end)` of `plugin`'s storage, in key order.
    fn kv_scan(
        &self,
        plugin: &str,
        server_id: ServerId,
        start: &[u8],
        end: &[u8],
        limit: u32,
        reverse: bool,
    ) -> Vec<(Vec<u8>, Vec<u8>)> {
        let _ = (plugin, server_id, start, end, limit, reverse);
        Vec::new()
    }

    /// Apply a batch of writes to `plugin`'s storage, atomically.
    fn kv_write(
        &self,
        plugin: &str,
        server_id: ServerId,
        ops: &[(Vec<u8>, Option<Vec<u8>>)],
    ) -> Result<(), String> {
        let _ = (plugin, server_id, ops);
        Err("this host offers no plugin storage".to_owned())
    }

    /// Open a writable slot for one object in `plugin`'s namespace.
    ///
    /// Returns the key it will be stored under, the URL to send the bytes to,
    /// the method, and when that URL stops working.
    fn object_reserve(
        &self,
        plugin: &str,
        server_id: ServerId,
        filename: &str,
        content_type: &str,
        size: u64,
        public: bool,
    ) -> Option<(String, String, String, u64)> {
        let _ = (plugin, server_id, filename, content_type, size, public);
        None
    }

    /// A short-lived signed URL to read one of `plugin`'s objects.
    fn object_url(&self, plugin: &str, server_id: ServerId, key: &str) -> Option<String> {
        let _ = (plugin, server_id, key);
        None
    }

    /// Point one of `plugin`'s names at `key`, as a new revision.
    fn name_put(
        &self,
        plugin: &str,
        server_id: ServerId,
        name: &str,
        key: &str,
        keep: u64,
    ) -> Result<u64, String> {
        let _ = (plugin, server_id, name, key, keep);
        Err("this host offers no plugin storage".to_owned())
    }

    /// What one of `plugin`'s names currently answers with: revision, key,
    /// and when it was made.
    fn name_latest(
        &self,
        plugin: &str,
        server_id: ServerId,
        name: &str,
    ) -> Option<(u64, String, u64)> {
        let _ = (plugin, server_id, name);
        None
    }

    /// A name's revisions, newest first.
    fn name_revisions(
        &self,
        plugin: &str,
        server_id: ServerId,
        name: &str,
        limit: u32,
    ) -> Vec<(u64, String, u64)> {
        let _ = (plugin, server_id, name, limit);
        Vec::new()
    }

    /// Every name `plugin` has stored, each with its latest revision.
    fn name_list(&self, plugin: &str, server_id: ServerId) -> Vec<(String, u64, String, u64)> {
        let _ = (plugin, server_id);
        Vec::new()
    }

    /// Forget one of `plugin`'s names and every revision of it.
    fn name_forget(&self, plugin: &str, server_id: ServerId, name: &str) -> Result<(), String> {
        let _ = (plugin, server_id, name);
        Err("this host offers no plugin storage".to_owned())
    }

    /// Whether `session` is connected right now.
    fn is_session_active(&self, server_id: ServerId, session: SessionId) -> bool;

    /// Whether `session` may enter `channel`.
    fn user_has_channel_access(
        &self,
        server_id: ServerId,
        session: SessionId,
        channel: ChannelId,
    ) -> bool;

    /// Whether `session` holds every permission in the raw `flags` bitmask on
    /// `channel`.
    fn has_permission(
        &self,
        server_id: ServerId,
        session: SessionId,
        channel: ChannelId,
        flags: u32,
    ) -> bool;

    /// The channel `session` is in.
    fn current_channel(&self, server_id: ServerId, session: SessionId) -> Option<ChannelId>;

    /// Everyone joined to `channel`.
    fn sessions_in_channel(&self, server_id: ServerId, channel: ChannelId) -> Vec<SessionId> {
        let _ = (server_id, channel);
        Vec::new()
    }

    /// Everyone connected to `server_id`.
    fn all_sessions(&self, server_id: ServerId) -> Vec<SessionId> {
        let _ = server_id;
        Vec::new()
    }

    /// The session using `name`, matched exactly.
    fn find_session_by_name(&self, server_id: ServerId, name: &str) -> Option<SessionId> {
        let _ = (server_id, name);
        None
    }

    /// Hand a server-originated request's result back to whoever asked.
    fn send_request_response(
        &self,
        server_id: ServerId,
        response_type: &str,
        request_id: &str,
        target_session: SessionId,
        payload: &[u8],
    ) -> Result<(), String> {
        let _ = (
            server_id,
            response_type,
            request_id,
            target_session,
            payload,
        );
        Ok(())
    }

    /// Create `spec` under its parent, or return the existing child of that
    /// parent already carrying the name. Idempotent by name.
    fn create_channel(&self, server_id: ServerId, spec: &NewChannel<'_>) -> Option<ChannelId> {
        let _ = (server_id, spec);
        None
    }

    /// Grant a registered user access to a private channel.
    fn grant_channel_access(&self, server_id: ServerId, channel: ChannelId, user_id: u32) -> bool {
        let _ = (server_id, channel, user_id);
        false
    }

    /// Revoke it again. Idempotent.
    fn revoke_channel_access(&self, server_id: ServerId, channel: ChannelId, user_id: u32) -> bool {
        let _ = (server_id, channel, user_id);
        false
    }
}
