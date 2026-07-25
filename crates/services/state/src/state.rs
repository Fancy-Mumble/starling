//! The authoritative server state (Facade).
//!
//! Assembles the model's stores behind one owner and hands out **trait**
//! references, so a handler that only reads channels takes `&dyn ChannelStore`
//! and never learns which implementation is behind it (`DESIGN.md` §1).
//!
//! Owned exclusively by [`ServerCore`](crate::ServerCore) and mutated only from
//! its task, so nothing here needs synchronisation. It holds no sockets and no
//! senders, which is what lets handler tests construct one directly.

use std::net::SocketAddr;

use starling_gate::{Gate, MumbleVersion};
use starling_model::{
    AllowAll, ChannelId, ChannelStore, ChannelTree, Permissions, SessionId, UserRegistry, Users,
};

use crate::connection::Connections;
use std::collections::HashMap;

use starling_api::ConnId;
use starling_api::ServerConfig;
use starling_api::{Connection, Limits, Sessions, Settings, Shout, VoiceTargetSlot, World};
use starling_crypto::{
    CompatibilityFirst, CompatibilityFirstProfiles, ProfileError, ProfileFactory, SecurityPolicy,
    SecuritySuite, VoiceProfile,
};

/// Everything the server knows.
#[derive(Debug)]
pub struct ServerState {
    /// Resolved configuration.
    pub config: ServerConfig,
    connections: Connections,
    channels: Box<dyn ChannelStore + Send + Sync>,
    users: Box<dyn UserRegistry + Send + Sync>,
    permissions: Box<dyn Permissions>,
    security: Box<dyn SecurityPolicy>,
    /// Which framing and cipher each client version earns.
    ///
    /// Alongside `security` rather than inside it: one negotiates the TLS
    /// control channel, the other the UDP voice path, and a deployment can
    /// reasonably want a strict floor on one and not the other.
    profiles: Box<dyn ProfileFactory>,
    /// Every session's registered whisper and shout slots.
    ///
    /// Here rather than in `starling-voice` because the slots decide who hears
    /// whom, which is this service's subject. The voice path is told the result
    /// through the same rebuilt view that carries channel membership.
    voice_targets: HashMap<(SessionId, u8), VoiceTargetSlot>,
}

/// The highest whisper or shout slot a client may register.
///
/// The audio header's target field is five bits: 0 is normal speech, 31 is the
/// server loopback, and the thirty in between are the client's to fill.
const MAX_VOICE_TARGET: u8 = 30;

impl ServerState {
    /// Build the initial state: a root channel named after `register_name`, no
    /// users, and a session pool sized from `max_users`.
    #[must_use]
    pub fn new(config: ServerConfig) -> Self {
        let connections = Connections::new(config.limits.max_users);
        let channels = ChannelTree::new(config.register_name.clone());
        Self {
            config,
            connections,
            voice_targets: HashMap::new(),
            channels: Box::new(channels),
            users: Box::new(Users::new()),
            // Phase 2 swaps this for the real ACL evaluator; no handler changes.
            permissions: Box::new(AllowAll),
            // Never refuses anyone, so stock Mumble clients keep working.
            security: Box::new(CompatibilityFirst),
            profiles: Box::new(CompatibilityFirstProfiles),
        }
    }

    /// Replace a collaborator (Strategy).
    ///
    /// The composition root uses these to install Phase 2's SQL-backed stores
    /// and real permission evaluator without `ServerState` knowing either type.
    #[must_use]
    pub fn with_permissions(mut self, permissions: Box<dyn Permissions>) -> Self {
        self.permissions = permissions;
        self
    }

    /// Install a different channel store. See [`Self::with_permissions`].
    #[must_use]
    pub fn with_channels(mut self, channels: Box<dyn ChannelStore + Send + Sync>) -> Self {
        self.channels = channels;
        self
    }

    /// Install a different user registry. See [`Self::with_permissions`].
    #[must_use]
    pub fn with_users(mut self, users: Box<dyn UserRegistry + Send + Sync>) -> Self {
        self.users = users;
        self
    }

    /// Install a different voice-profile factory. See [`Self::with_permissions`].
    ///
    /// `ModernOnlyProfiles` refuses any client that cannot do
    /// `XChaCha20-Poly1305`, for a deployment that controls its client fleet
    /// and would rather turn a legacy client away than carry OCB2 for it.
    #[must_use]
    pub fn with_profiles(mut self, profiles: Box<dyn ProfileFactory>) -> Self {
        self.profiles = profiles;
        self
    }

    /// Install a different security policy. See [`Self::with_permissions`].
    ///
    /// This negotiates the TLS control channel; [`Self::with_profiles`] does the
    /// UDP voice path. A deployment can reasonably want a strict floor on one
    /// and not the other.
    #[must_use]
    pub fn with_security(mut self, security: Box<dyn SecurityPolicy>) -> Self {
        self.security = security;
        self
    }

    /// The security policy.
    #[must_use]
    pub fn security(&self) -> &dyn SecurityPolicy {
        self.security.as_ref()
    }

    // -- Collaborators, as traits -------------------------------------

    /// The channel tree, mutably.
    pub fn channels_mut(&mut self) -> &mut dyn ChannelStore {
        self.channels.as_mut()
    }

    // -- Connections ---------------------------------------------------

    /// Register a newly accepted connection.
    pub fn add_connection(&mut self, id: ConnId, addr: SocketAddr) {
        self.connections.add(id, addr);
    }

    /// The connection carrying a session, if it is still open.
    #[must_use]
    pub fn conn_for_session(&self, session: SessionId) -> Option<ConnId> {
        self.connections.conn_for(session)
    }

    /// Drop a connection and everything derived from it.
    ///
    /// Returns the session it held, so the caller can broadcast `UserRemove`.
    pub fn remove_connection(&mut self, conn: ConnId) -> Option<SessionId> {
        let session = self.connections.remove(conn)?;
        let _ = self.users.remove(session);
        Some(session)
    }

    /// How many session ids remain.
    #[must_use]
    pub fn sessions_available(&self) -> usize {
        self.connections.sessions_available()
    }

    // -- Derived queries -----------------------------------------------

    /// Sessions that should receive a broadcast to `channel`.
    #[must_use]
    pub fn channel_members(&self, channel: ChannelId) -> Vec<SessionId> {
        self.users.in_channel(channel)
    }
}

impl Sessions for ServerState {
    fn set_voice_target(
        &mut self,
        session: SessionId,
        slot: u8,
        targets: &[starling_proto::proto::tcp::voice_target::Target],
    ) -> bool {
        // 0 is normal speech and 31 is the server loopback. Neither can be
        // reassigned, and clamping would silently point the client somewhere
        // it never asked for.
        if slot == 0 || slot > MAX_VOICE_TARGET {
            return false;
        }

        let mut registered = VoiceTargetSlot::default();
        for target in targets {
            registered
                .sessions
                .extend(target.session.iter().copied().map(SessionId));
            if let Some(channel) = target.channel_id {
                registered.shouts.push(Shout {
                    channel: ChannelId(channel),
                    // Absent means false, which is also protobuf 3's default —
                    // stated rather than relied on, because the two agreeing is
                    // a coincidence of this schema.
                    links: target.links.unwrap_or(false),
                    children: target.children.unwrap_or(false),
                });
            }
        }

        // An empty registration clears the slot. That is how a client releases
        // a target it no longer wants, not a malformed request.
        if registered.is_empty() {
            let _ = self.voice_targets.remove(&(session, slot));
        } else {
            let _ = self.voice_targets.insert((session, slot), registered);
        }
        true
    }

    fn voice_target(&self, session: SessionId, slot: u8) -> Option<&VoiceTargetSlot> {
        self.voice_targets.get(&(session, slot))
    }

    fn voice_targets(&self) -> Vec<(SessionId, u8, &VoiceTargetSlot)> {
        self.voice_targets
            .iter()
            .map(|((session, slot), target)| (*session, *slot, target))
            .collect()
    }

    fn suite_for(&self, conn: ConnId) -> Option<Box<dyn SecuritySuite>> {
        let capabilities = Sessions::connection(self, conn)?.capabilities();
        self.security.negotiate(&capabilities)
    }

    fn voice_profile(&self, conn: ConnId) -> Option<Result<VoiceProfile, ProfileError>> {
        let connection = Sessions::connection(self, conn)?;
        let announced = connection.version;
        Some(self.profiles.build(
            MumbleVersion::new(announced.major, announced.minor, announced.patch),
            Gate::for_peer(connection.fancy_version),
        ))
    }

    fn connection(&self, id: ConnId) -> Option<&Connection> {
        self.connections.get(id)
    }

    fn is_authenticated(&self, id: ConnId) -> bool {
        self.connections.is_authenticated(id)
    }

    fn session_of(&self, id: ConnId) -> Option<SessionId> {
        self.connections.session_of(id)
    }

    fn is_full(&self) -> bool {
        self.users.len() as u32 >= self.config.limits.max_users
    }

    fn connection_mut(&mut self, id: ConnId) -> Option<&mut Connection> {
        self.connections.get_mut(id)
    }

    fn assign_session(&mut self, conn: ConnId) -> Option<SessionId> {
        self.connections.assign_session(conn)
    }
}

impl World for ServerState {
    fn channels(&self) -> &dyn ChannelStore {
        self.channels.as_ref()
    }

    fn users(&self) -> &dyn UserRegistry {
        self.users.as_ref()
    }

    fn users_mut(&mut self) -> &mut dyn UserRegistry {
        self.users.as_mut()
    }

    fn permissions(&self) -> &dyn Permissions {
        self.permissions.as_ref()
    }
}

impl Settings for ServerState {
    fn limits(&self) -> &Limits {
        &self.config.limits
    }

    fn password_accepted(&self, candidate: &str) -> bool {
        self.config.password_matches(candidate)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use starling_api::Limits;
    use starling_api::{Sessions, World};
    use starling_model::{ROOT_CHANNEL, User};

    fn addr() -> SocketAddr {
        "127.0.0.1:1234".parse().expect("valid test address")
    }

    fn state() -> ServerState {
        ServerState::new(ServerConfig {
            register_name: "Test Server".into(),
            limits: Limits {
                max_users: 4,
                ..Default::default()
            },
            ..Default::default()
        })
    }

    #[test]
    fn the_root_channel_is_named_after_register_name() {
        let s = state();
        assert_eq!(
            s.channels().get(ROOT_CHANNEL).expect("root exists").name,
            "Test Server"
        );
    }

    #[test]
    fn removing_a_connection_also_removes_its_user() {
        let mut s = state();
        s.add_connection(ConnId(1), addr());
        let session = s.assign_session(ConnId(1)).expect("pool has ids");
        s.users_mut()
            .insert(User::new(session, "alice", ROOT_CHANNEL));

        assert_eq!(s.remove_connection(ConnId(1)), Some(session));
        assert!(s.users().is_empty(), "the user outlived its connection");
        assert_eq!(s.conn_for_session(session), None);
    }

    #[test]
    fn is_full_tracks_users_not_connections() {
        let mut s = state(); // max_users = 4
        for i in 0..4 {
            s.users_mut()
                .insert(User::new(SessionId(i + 1), format!("u{i}"), ROOT_CHANNEL));
        }
        assert!(s.is_full());
    }

    #[test]
    fn collaborators_can_be_replaced_without_touching_callers() {
        // The seam Phase 2 depends on.
        #[derive(Debug)]
        struct DenyAll;
        impl Permissions for DenyAll {
            fn effective(
                &self,
                _: Option<starling_model::UserId>,
                _: ChannelId,
            ) -> starling_model::Perm {
                starling_model::Perm::NONE
            }
        }

        let s = state().with_permissions(Box::new(DenyAll));
        assert!(
            !s.permissions()
                .allows(None, ROOT_CHANNEL, starling_model::Perm::SPEAK)
        );
    }

    #[test]
    fn channel_members_reflects_moves() {
        let mut s = state();
        let lobby = s
            .channels_mut()
            .insert(ROOT_CHANNEL, "Lobby")
            .expect("root exists");
        s.users_mut()
            .insert(User::new(SessionId(1), "alice", ROOT_CHANNEL));

        assert_eq!(s.channel_members(ROOT_CHANNEL), vec![SessionId(1)]);
        let _ = s.users_mut().move_to(SessionId(1), lobby);
        assert_eq!(s.channel_members(lobby), vec![SessionId(1)]);
        assert!(s.channel_members(ROOT_CHANNEL).is_empty());
    }
}
