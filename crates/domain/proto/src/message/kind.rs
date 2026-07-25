//! The TCP message-type-id table.
//!
//! Ids are transcribed from `vendor/server/src/MumbleProtocol.h` and
//! cross-checked against the client's `mumble-protocol/src/message.rs`. Ids
//! 0–26 are stock Mumble; 100+ are Fancy Mumble extensions; 200+ are the plugin
//! channel.

/// The 16-bit message type ids carried in the TCP frame header.
///
/// Only the variants Starling decodes into typed messages are listed. Every
/// other id is carried as [`ControlMessage::Opaque`](super::ControlMessage) —
/// see that type's docs for why that is the right shape for a staged port.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum TcpMessageType {
    /// Protocol version exchange. Sent by the server immediately after the TLS
    /// handshake completes, before anything is read.
    Version = 0,
    /// Tunnelled UDP audio. The payload is a *raw UDP packet*, not protobuf.
    UdpTunnel = 1,
    /// Client credentials. Drives the whole session-establishment sequence.
    Authenticate = 2,
    /// Keepalive plus UDP crypt statistics.
    Ping = 3,
    /// Server's refusal to establish a session.
    Reject = 4,
    /// End of the session-establishment sequence.
    ServerSync = 5,
    /// Channel deletion.
    ChannelRemove = 6,
    /// Channel creation or property change.
    ChannelState = 7,
    /// User left, was kicked, or was banned.
    UserRemove = 8,
    /// User joined or changed state.
    UserState = 9,
    /// Ban list query or replacement.
    BanList = 10,
    /// Chat message.
    TextMessage = 11,
    /// Explanation for a refused action.
    PermissionDenied = 12,
    /// Channel ACL query or replacement.
    Acl = 13,
    /// Registered-user lookup by id or name.
    QueryUsers = 14,
    /// UDP crypto key and nonce exchange, and nonce resynchronisation.
    CryptSetup = 15,
    /// Server-defined context menu entries.
    ContextActionModify = 16,
    /// Client invoked a context menu entry.
    ContextAction = 17,
    /// Registered-user list.
    UserList = 18,
    /// Whisper/shout target definition.
    VoiceTarget = 19,
    /// Permission bits for a channel.
    PermissionQuery = 20,
    /// Negotiated audio codec.
    CodecVersion = 21,
    /// Detailed per-user connection statistics.
    UserStats = 22,
    /// Request for a texture or comment the client only holds a hash for.
    RequestBlob = 23,
    /// Server limits and feature flags.
    ServerConfig = 24,
    /// Settings the server suggests the client adopt.
    SuggestConfig = 25,
    /// Opaque client-plugin payload relayed between users.
    PluginDataTransmission = 26,
}

impl TcpMessageType {
    /// Map a wire type id to a known message type.
    ///
    /// Returns `None` for ids Starling does not decode (Fancy extensions and
    /// plugin messages in this build), which the codec carries opaquely.
    #[must_use]
    pub fn from_id(id: u16) -> Option<Self> {
        use TcpMessageType::*;
        Some(match id {
            0 => Version,
            1 => UdpTunnel,
            2 => Authenticate,
            3 => Ping,
            4 => Reject,
            5 => ServerSync,
            6 => ChannelRemove,
            7 => ChannelState,
            8 => UserRemove,
            9 => UserState,
            10 => BanList,
            11 => TextMessage,
            12 => PermissionDenied,
            13 => Acl,
            14 => QueryUsers,
            15 => CryptSetup,
            16 => ContextActionModify,
            17 => ContextAction,
            18 => UserList,
            19 => VoiceTarget,
            20 => PermissionQuery,
            21 => CodecVersion,
            22 => UserStats,
            23 => RequestBlob,
            24 => ServerConfig,
            25 => SuggestConfig,
            26 => PluginDataTransmission,
            _ => return None,
        })
    }

    /// The wire type id for this message type.
    #[must_use]
    pub fn id(self) -> u16 {
        self as u16
    }

    /// A short, stable name for logs and metrics.
    ///
    /// Matches the `.proto` message name rather than the Rust variant, so a log
    /// line can be grepped straight against `Mumble.proto`.
    #[must_use]
    pub fn name(self) -> &'static str {
        use TcpMessageType::*;
        match self {
            Version => "Version",
            UdpTunnel => "UDPTunnel",
            Authenticate => "Authenticate",
            Ping => "Ping",
            Reject => "Reject",
            ServerSync => "ServerSync",
            ChannelRemove => "ChannelRemove",
            ChannelState => "ChannelState",
            UserRemove => "UserRemove",
            UserState => "UserState",
            BanList => "BanList",
            TextMessage => "TextMessage",
            PermissionDenied => "PermissionDenied",
            Acl => "ACL",
            QueryUsers => "QueryUsers",
            CryptSetup => "CryptSetup",
            ContextActionModify => "ContextActionModify",
            ContextAction => "ContextAction",
            UserList => "UserList",
            VoiceTarget => "VoiceTarget",
            PermissionQuery => "PermissionQuery",
            CodecVersion => "CodecVersion",
            UserStats => "UserStats",
            RequestBlob => "RequestBlob",
            ServerConfig => "ServerConfig",
            SuggestConfig => "SuggestConfig",
            PluginDataTransmission => "PluginDataTransmission",
        }
    }

    /// Every message type this build decodes, for exhaustiveness tests.
    pub const ALL: &'static [Self] = &[
        Self::Version,
        Self::UdpTunnel,
        Self::Authenticate,
        Self::Ping,
        Self::Reject,
        Self::ServerSync,
        Self::ChannelRemove,
        Self::ChannelState,
        Self::UserRemove,
        Self::UserState,
        Self::BanList,
        Self::TextMessage,
        Self::PermissionDenied,
        Self::Acl,
        Self::QueryUsers,
        Self::CryptSetup,
        Self::ContextActionModify,
        Self::ContextAction,
        Self::UserList,
        Self::VoiceTarget,
        Self::PermissionQuery,
        Self::CodecVersion,
        Self::UserStats,
        Self::RequestBlob,
        Self::ServerConfig,
        Self::SuggestConfig,
        Self::PluginDataTransmission,
    ];
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_id_round_trips_through_from_id() {
        for kind in TcpMessageType::ALL {
            assert_eq!(
                TcpMessageType::from_id(kind.id()),
                Some(*kind),
                "{kind:?} did not round-trip"
            );
        }
    }

    #[test]
    fn ids_match_the_cpp_header() {
        // Wire-visible constants. Spot-check the boundaries of the stock range.
        assert_eq!(TcpMessageType::Version.id(), 0);
        assert_eq!(TcpMessageType::Authenticate.id(), 2);
        assert_eq!(TcpMessageType::TextMessage.id(), 11);
        assert_eq!(TcpMessageType::PluginDataTransmission.id(), 26);
    }

    #[test]
    fn ids_are_unique() {
        let mut ids: Vec<_> = TcpMessageType::ALL.iter().map(|k| k.id()).collect();
        let count = ids.len();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), count, "two message types share an id");
    }

    #[test]
    fn all_lists_every_id_in_the_stock_range() {
        // Guards against a variant being added to the enum but not to ALL,
        // which would silently weaken every test that iterates it.
        assert_eq!(TcpMessageType::ALL.len(), 27);
        for id in 0..=26u16 {
            assert!(
                TcpMessageType::ALL.iter().any(|k| k.id() == id),
                "id {id} is missing from ALL"
            );
        }
    }

    #[test]
    fn fancy_extension_ids_are_not_decoded_by_this_build() {
        // 100+ are Fancy extensions, 200+ the plugin channel. They must come
        // back as None so the codec carries them opaquely.
        for id in [100, 120, 144, 168, 200, 201, 9999] {
            assert_eq!(TcpMessageType::from_id(id), None, "id {id}");
        }
    }

    #[test]
    fn names_are_unique_and_non_empty() {
        let mut names: Vec<_> = TcpMessageType::ALL.iter().map(|k| k.name()).collect();
        assert!(names.iter().all(|n| !n.is_empty()));
        let count = names.len();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), count, "two message types share a name");
    }

    #[test]
    fn names_match_the_proto_not_the_rust_variant() {
        // So a log line greps straight against Mumble.proto.
        assert_eq!(TcpMessageType::Acl.name(), "ACL");
        assert_eq!(TcpMessageType::UdpTunnel.name(), "UDPTunnel");
    }
}
