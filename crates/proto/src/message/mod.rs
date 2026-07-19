//! The TCP control-channel message enum.

mod kind;

pub use kind::TcpMessageType;

use bytes::Bytes;

use crate::proto::tcp;

/// A decoded (or ready-to-encode) control-channel message.
///
/// # Why `Opaque` exists
///
/// The Fancy fork defines ~70 extension messages (ids 100–171, 200–201). A
/// staged port cannot implement them all at once, but the *framing* layer must
/// be complete and correct from day one, otherwise an unimplemented message
/// desynchronises the stream and takes the whole connection down.
///
/// [`ControlMessage::Opaque`] keeps the frame intact and the stream in sync
/// while the semantics are still missing. Each porting phase replaces a slice of
/// `Opaque` ids with real variants; nothing else has to change.
#[derive(Debug, Clone)]
pub enum ControlMessage {
    /// See [`TcpMessageType::Version`].
    Version(tcp::Version),
    /// Tunnelled UDP audio: the raw UDP packet, *not* a protobuf message.
    ///
    /// `Mumble.proto` does define a `UDPTunnel` message, but its own comment
    /// says it is "Not used. Not even for tunneling UDP through TCP", the
    /// payload is the UDP packet verbatim. Both murmur and the FancyMumble
    /// client treat it that way.
    UdpTunnel(Bytes),
    /// See [`TcpMessageType::Authenticate`].
    Authenticate(tcp::Authenticate),
    /// See [`TcpMessageType::Ping`].
    Ping(tcp::Ping),
    /// See [`TcpMessageType::Reject`].
    Reject(tcp::Reject),
    /// See [`TcpMessageType::ServerSync`].
    ServerSync(tcp::ServerSync),
    /// See [`TcpMessageType::ChannelRemove`].
    ChannelRemove(tcp::ChannelRemove),
    /// See [`TcpMessageType::ChannelState`].
    ChannelState(tcp::ChannelState),
    /// See [`TcpMessageType::UserRemove`].
    UserRemove(tcp::UserRemove),
    /// See [`TcpMessageType::UserState`].
    UserState(tcp::UserState),
    /// See [`TcpMessageType::BanList`].
    BanList(tcp::BanList),
    /// See [`TcpMessageType::TextMessage`].
    TextMessage(tcp::TextMessage),
    /// See [`TcpMessageType::PermissionDenied`].
    PermissionDenied(tcp::PermissionDenied),
    /// See [`TcpMessageType::Acl`].
    Acl(tcp::Acl),
    /// See [`TcpMessageType::QueryUsers`].
    QueryUsers(tcp::QueryUsers),
    /// See [`TcpMessageType::CryptSetup`].
    CryptSetup(tcp::CryptSetup),
    /// See [`TcpMessageType::ContextActionModify`].
    ContextActionModify(tcp::ContextActionModify),
    /// See [`TcpMessageType::ContextAction`].
    ContextAction(tcp::ContextAction),
    /// See [`TcpMessageType::UserList`].
    UserList(tcp::UserList),
    /// See [`TcpMessageType::VoiceTarget`].
    VoiceTarget(tcp::VoiceTarget),
    /// See [`TcpMessageType::PermissionQuery`].
    PermissionQuery(tcp::PermissionQuery),
    /// See [`TcpMessageType::CodecVersion`].
    CodecVersion(tcp::CodecVersion),
    /// See [`TcpMessageType::UserStats`].
    UserStats(tcp::UserStats),
    /// See [`TcpMessageType::RequestBlob`].
    RequestBlob(tcp::RequestBlob),
    /// See [`TcpMessageType::ServerConfig`].
    ServerConfig(tcp::ServerConfig),
    /// See [`TcpMessageType::SuggestConfig`].
    SuggestConfig(tcp::SuggestConfig),
    /// See [`TcpMessageType::PluginDataTransmission`].
    PluginDataTransmission(tcp::PluginDataTransmission),

    /// A well-framed message whose type this build does not decode.
    ///
    /// Carried verbatim so the stream stays in sync. See the type-level docs.
    Opaque {
        /// The wire type id from the frame header.
        type_id: u16,
        /// The undecoded payload.
        payload: Bytes,
    },
}

impl ControlMessage {
    /// The wire type id this message is framed with.
    #[must_use]
    pub fn type_id(&self) -> u16 {
        use ControlMessage::*;
        match self {
            Version(_) => TcpMessageType::Version.id(),
            UdpTunnel(_) => TcpMessageType::UdpTunnel.id(),
            Authenticate(_) => TcpMessageType::Authenticate.id(),
            Ping(_) => TcpMessageType::Ping.id(),
            Reject(_) => TcpMessageType::Reject.id(),
            ServerSync(_) => TcpMessageType::ServerSync.id(),
            ChannelRemove(_) => TcpMessageType::ChannelRemove.id(),
            ChannelState(_) => TcpMessageType::ChannelState.id(),
            UserRemove(_) => TcpMessageType::UserRemove.id(),
            UserState(_) => TcpMessageType::UserState.id(),
            BanList(_) => TcpMessageType::BanList.id(),
            TextMessage(_) => TcpMessageType::TextMessage.id(),
            PermissionDenied(_) => TcpMessageType::PermissionDenied.id(),
            Acl(_) => TcpMessageType::Acl.id(),
            QueryUsers(_) => TcpMessageType::QueryUsers.id(),
            CryptSetup(_) => TcpMessageType::CryptSetup.id(),
            ContextActionModify(_) => TcpMessageType::ContextActionModify.id(),
            ContextAction(_) => TcpMessageType::ContextAction.id(),
            UserList(_) => TcpMessageType::UserList.id(),
            VoiceTarget(_) => TcpMessageType::VoiceTarget.id(),
            PermissionQuery(_) => TcpMessageType::PermissionQuery.id(),
            CodecVersion(_) => TcpMessageType::CodecVersion.id(),
            UserStats(_) => TcpMessageType::UserStats.id(),
            RequestBlob(_) => TcpMessageType::RequestBlob.id(),
            ServerConfig(_) => TcpMessageType::ServerConfig.id(),
            SuggestConfig(_) => TcpMessageType::SuggestConfig.id(),
            PluginDataTransmission(_) => TcpMessageType::PluginDataTransmission.id(),
            Opaque { type_id, .. } => *type_id,
        }
    }

    /// A short, stable name for logs and metrics.
    #[must_use]
    pub fn name(&self) -> &'static str {
        TcpMessageType::from_id(self.type_id()).map_or("Opaque", TcpMessageType::name)
    }

    /// The decoded message type, or `None` for [`Self::Opaque`].
    #[must_use]
    pub fn kind(&self) -> Option<TcpMessageType> {
        TcpMessageType::from_id(self.type_id())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn type_id_agrees_with_the_message_type_table() {
        // A variant wired to the wrong id would be framed as a different
        // message and silently mis-dispatched.
        assert_eq!(
            ControlMessage::Version(tcp::Version::default()).type_id(),
            TcpMessageType::Version.id()
        );
        assert_eq!(
            ControlMessage::TextMessage(tcp::TextMessage::default()).type_id(),
            TcpMessageType::TextMessage.id()
        );
        assert_eq!(
            ControlMessage::PluginDataTransmission(tcp::PluginDataTransmission::default())
                .type_id(),
            TcpMessageType::PluginDataTransmission.id()
        );
    }

    #[test]
    fn an_opaque_message_keeps_the_id_it_was_framed_with() {
        let msg = ControlMessage::Opaque {
            type_id: 120,
            payload: Bytes::new(),
        };
        assert_eq!(msg.type_id(), 120);
        assert_eq!(msg.name(), "Opaque");
        assert_eq!(msg.kind(), None);
    }

    #[test]
    fn a_decoded_message_reports_its_kind() {
        let msg = ControlMessage::Ping(tcp::Ping::default());
        assert_eq!(msg.kind(), Some(TcpMessageType::Ping));
        assert_eq!(msg.name(), "Ping");
    }

    #[test]
    fn udp_tunnel_is_named_after_the_proto() {
        assert_eq!(ControlMessage::UdpTunnel(Bytes::new()).name(), "UDPTunnel");
    }
}
