//! Keying the voice path, during the handshake.
//!
//! The server generates every byte: the AES-128 key and both nonces. The client
//! contributes nothing, which is what makes this a distribution rather than a
//! negotiation — and why it is safe to do in one message with no round trip.
//!
//! # Which cipher, and who decides
//!
//! Not this module. `ProfileFactory` maps the two versions a peer announced onto
//! the framing and cipher it earns, and this asks it once. That is the Abstract
//! Factory doing its job: a peer is assembled purpose-built for its client, and
//! nothing downstream re-derives capabilities from a version number.
//!
//! The material differs by cipher — OCB2 wants a 16-byte AES key and two IVs,
//! `XChaCha20-Poly1305` a 32-byte master secret and two salts — so `VoiceSecrets`
//! is an enum rather than three byte vectors and a tag that could disagree with
//! them.
//!
//! # Why the server picks the client's nonce too
//!
//! It looks wrong: the client will encrypt under a counter the server chose.
//! murmur does it because the *counter* is not a secret — it goes on the wire,
//! one byte at a time, in every packet. What matters is that the pair
//! (key, nonce) is never reused, and one party choosing both is the simplest way
//! to guarantee that.
//!
//! # Why this is sent even to a client that will never use UDP
//!
//! `CryptSetup` is what makes a Mumble client open its UDP socket at all. A
//! client that never receives one falls back to tunnelling forever — which
//! works, and costs every frame a TCP round trip through a congestion-controlled
//! stream that was never meant to carry 50 packets a second.

use starling_api::{Authority, ConnId, Effects, Recipients, VoiceKeying, VoiceUpdate};
use starling_crypto::VoiceSecrets;
use starling_proto::proto::tcp;
use starling_proto::ControlMessage;
use tracing::{info, warn};

/// Send a peer its voice keys, and give the voice service the same material.
///
/// Returns no effects if key generation fails, which leaves the peer with a
/// working control connection and no voice. That is the right degradation: the
/// alternative is refusing the login over an entropy failure the user cannot
/// act on.
pub(crate) fn crypt_setup(state: &dyn Authority, conn: ConnId) -> Effects {
    let Some(session) = state.session_of(conn) else {
        return Effects::none();
    };
    let Some(connection) = state.connection(conn) else {
        return Effects::none();
    };

    let host = connection.addr.ip();

    // One call, and every version rule lives behind it. Deciding the framing and
    // the cipher separately here would duplicate the factory's rules and lose
    // the one that is easy to forget: a legacy-framed peer gets OCB2 however new
    // its Fancy version claims to be, because the legacy packet type *is* the
    // codec and has nowhere to name a cipher.
    let profile = match state.voice_profile(conn) {
        Some(Ok(profile)) => profile,
        Some(Err(refused)) => {
            // A configured `ModernOnlyProfiles` declining to serve this client.
            // Not a disconnect: the control connection is fine, and the operator
            // who opted in to refusing knows what they asked for.
            warn!(%conn, %session, %refused, "no voice profile for this client");
            return Effects::none();
        }
        None => return Effects::none(),
    };

    // `None` means the transport encrypts for us, so there is nothing to key
    // and nothing to send. No transport does yet; when QUIC does, this is where
    // it stops generating keys nobody will use.
    let Some(choice) = profile.cipher_choice() else {
        return Effects::none();
    };
    let Ok(secrets) = VoiceSecrets::generate(choice) else {
        // Counted through the log rather than failing the login: a peer cannot
        // do anything about the server's entropy, and a control connection
        // without voice is better than no connection.
        warn!(%conn, %session, "voice keys could not be generated; peer will have no audio");
        return Effects::none();
    };

    let (key, client_nonce, server_nonce) = secrets.to_wire();
    // At `info`, and naming the cipher: an operator needs to be able to tell
    // from the log alone whether a connection got the modern suite or fell back
    // to OCB2, because both carry audio perfectly and only one is safe from a
    // four-day forgery search. The name comes from the spec rather than the
    // enum's `Debug` so it is a stable string something can assert on.
    info!(
        %conn,
        %session,
        format = ?profile.format(),
        cipher = profile.cipher().map_or("none", starling_crypto::VoiceCipherSpec::name),
        "voice path keyed"
    );

    let mut fx = Effects::none();
    let _ = fx.send(
        Recipients::Session(session),
        ControlMessage::CryptSetup(tcp::CryptSetup {
            key: Some(key),
            client_nonce: Some(client_nonce),
            server_nonce: Some(server_nonce),
        }),
    );
    let _ = fx.voice(VoiceUpdate::Attach(Box::new(VoiceKeying {
        conn,
        session,
        host,
        format: profile.format(),
        secrets,
    })));
    fx
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::ServerState;
    use starling_api::{Effect, ServerConfig, Sessions};
    use starling_crypto::VoiceSecrets;
    use starling_proto::Version;

    /// A state with one authenticated connection.
    fn authenticated() -> (ServerState, ConnId) {
        let mut state = ServerState::new(ServerConfig::default());
        let conn = ConnId(1);
        state.add_connection(conn, "203.0.113.7:50000".parse().expect("address"));
        if let Some(connection) = state.connection_mut(conn) {
            connection.version = Version::new(1, 5, 0);
        }
        let _ = state.assign_session(conn).expect("session");
        (state, conn)
    }

    /// The `CryptSetup` a run of the handler produced, if any.
    fn crypt_message(fx: &Effects) -> Option<tcp::CryptSetup> {
        fx.as_slice().iter().find_map(|effect| match effect {
            Effect::Send { msg, .. } => match msg.as_ref() {
                ControlMessage::CryptSetup(setup) => Some(setup.clone()),
                _ => None,
            },
            _ => None,
        })
    }

    /// The keying handed to the voice path, if any.
    fn keying(fx: &Effects) -> Option<VoiceKeying> {
        fx.as_slice().iter().find_map(|effect| match effect {
            Effect::Voice(VoiceUpdate::Attach(keying)) => Some(*keying.clone()),
            _ => None,
        })
    }

    /// A connection announcing a Mumble version and optionally a Fancy one.
    fn peer(mumble: Version, fancy: Option<(u16, u16, u16)>) -> (ServerState, ConnId) {
        let (mut state, conn) = authenticated();
        if let Some(connection) = state.connection_mut(conn) {
            connection.version = mumble;
            connection.fancy_version = fancy.map(|(major, minor, patch)| {
                starling_gate::FancyVersion::new(major, minor, patch).to_wire()
            });
        }
        (state, conn)
    }

    #[test]
    fn an_authenticated_peer_is_sent_every_field() {
        // A client that receives a partial `CryptSetup` never opens its UDP
        // socket, and the failure looks like "UDP just does not work here".
        let (state, conn) = authenticated();
        let setup = crypt_message(&crypt_setup(&state, conn)).expect("CryptSetup sent");

        assert_eq!(
            setup.key.as_ref().map(Vec::len),
            Some(starling_crypto::OCB2_KEY_LEN)
        );
        assert_eq!(
            setup.client_nonce.as_ref().map(Vec::len),
            Some(starling_crypto::OCB2_KEY_LEN)
        );
        assert_eq!(
            setup.server_nonce.as_ref().map(Vec::len),
            Some(starling_crypto::OCB2_KEY_LEN)
        );
    }

    #[test]
    fn a_stock_client_is_keyed_for_ocb2() {
        // No Fancy version announced at all — the overwhelming majority of
        // clients, forever. Anything but OCB2 here is a client that cannot
        // decrypt a single packet.
        let (state, conn) = peer(Version::new(1, 5, 0), None);
        let keying = keying(&crypt_setup(&state, conn)).expect("keying");
        assert!(matches!(keying.secrets, VoiceSecrets::Legacy(_)));
    }

    #[test]
    fn an_old_fancy_client_is_keyed_for_ocb2() {
        // Fancy, but before the modern cipher existed. The gate's whole job.
        let (state, conn) = peer(Version::new(1, 5, 0), Some((0, 3, 9)));
        let keying = keying(&crypt_setup(&state, conn)).expect("keying");
        assert!(matches!(keying.secrets, VoiceSecrets::Legacy(_)));
    }

    #[test]
    fn a_modern_fancy_client_is_keyed_for_xchacha() {
        // The upgrade path, and the reason any of this exists.
        let (state, conn) = peer(Version::new(1, 5, 0), Some((0, 4, 0)));
        let keying = keying(&crypt_setup(&state, conn)).expect("keying");
        assert!(
            matches!(keying.secrets, VoiceSecrets::Modern(_)),
            "a Fancy 0.4 client was downgraded to OCB2"
        );
    }

    #[test]
    fn a_legacy_framed_client_is_downgraded_even_on_a_modern_fancy_version() {
        // The rule that is easy to forget and impossible to recover from: the
        // legacy packet type *is* the codec, so there is nowhere to name a
        // cipher. A Fancy 0.4 client on Mumble 1.4 must still get OCB2.
        let (state, conn) = peer(Version::new(1, 4, 0), Some((0, 4, 0)));
        let keying = keying(&crypt_setup(&state, conn)).expect("keying");
        assert_eq!(keying.format, starling_gate::UdpFormat::Legacy);
        assert!(
            matches!(keying.secrets, VoiceSecrets::Legacy(_)),
            "a legacy-framed peer was given a cipher its framing cannot name"
        );
    }

    #[test]
    fn a_real_fancy_client_gets_the_modern_cipher_end_to_end() {
        // The whole selection path, from the version a shipping client actually
        // announces to the bytes that reach it. `mumble-protocol` is at 0.4.0,
        // so this is not a hypothetical: it is what the next connection does.
        //
        // The client reads the cipher from the *length* of what arrives, so
        // that length is the contract between the two repositories.
        let (state, conn) = peer(Version::new(1, 5, 0), Some((0, 4, 0)));
        let fx = crypt_setup(&state, conn);
        let setup = crypt_message(&fx).expect("CryptSetup sent");

        assert_eq!(
            setup.key.as_ref().map(Vec::len),
            Some(32),
            "a 0.4.0 client was not given a modern key, so it will select OCB2"
        );
        assert!(matches!(
            keying(&fx).expect("keying").secrets,
            VoiceSecrets::Modern(_)
        ));
    }

    #[test]
    fn the_modern_key_is_twice_as_long_on_the_wire() {
        // 32 bytes of master secret against 16 of AES key. The client reads
        // these lengths as a cross-check on what it thinks it negotiated.
        let (state, conn) = peer(Version::new(1, 5, 0), Some((0, 4, 0)));
        let setup = crypt_message(&crypt_setup(&state, conn)).expect("CryptSetup sent");
        assert_eq!(setup.key.as_ref().map(Vec::len), Some(32));
        assert_eq!(setup.client_nonce.as_ref().map(Vec::len), Some(16));
        assert_eq!(setup.server_nonce.as_ref().map(Vec::len), Some(16));
    }

    #[test]
    fn the_voice_path_is_given_the_same_material() {
        // If these ever diverge, the handshake looks perfect and no packet
        // authenticates — which is why they come from one draw, not two.
        for fancy in [None, Some((0, 4, 0))] {
            let (state, conn) = peer(Version::new(1, 5, 0), fancy);
            let fx = crypt_setup(&state, conn);
            let setup = crypt_message(&fx).expect("CryptSetup sent");
            let keying = keying(&fx).expect("voice keying produced");

            let (key, client, server) = keying.secrets.to_wire();
            assert_eq!(setup.key, Some(key), "{fancy:?}");
            assert_eq!(setup.client_nonce, Some(client), "{fancy:?}");
            assert_eq!(setup.server_nonce, Some(server), "{fancy:?}");
        }
    }

    #[test]
    fn the_three_values_are_distinct() {
        // Reusing one for two purposes is the classic key-reuse bug, and it
        // would still pass a round-trip test because both sides would agree.
        for fancy in [None, Some((0, 4, 0))] {
            let (state, conn) = peer(Version::new(1, 5, 0), fancy);
            let keying = keying(&crypt_setup(&state, conn)).expect("keying");
            let (key, client, server) = keying.secrets.to_wire();

            assert_ne!(key, client, "{fancy:?}");
            assert_ne!(key, server, "{fancy:?}");
            assert_ne!(client, server, "{fancy:?}");
        }
    }

    #[test]
    fn two_peers_get_different_keys() {
        // Per-connection, never shared. A shared key would let any peer decrypt
        // any other's audio straight off the wire.
        let (state, conn) = authenticated();
        let first = keying(&crypt_setup(&state, conn)).expect("keying");
        let second = keying(&crypt_setup(&state, conn)).expect("keying");
        assert_ne!(first.secrets.to_wire().0, second.secrets.to_wire().0);
    }

    #[test]
    fn the_keying_names_the_session_and_the_host() {
        let (state, conn) = authenticated();
        let keying = keying(&crypt_setup(&state, conn)).expect("keying");

        assert_eq!(Some(keying.session), state.session_of(conn));
        assert_eq!(
            Some(keying.host),
            state.connection(conn).map(|c| c.addr.ip()),
            "the attribution hint does not match where the peer connected from"
        );
    }

    #[test]
    fn the_framing_follows_the_announced_mumble_version() {
        // The axis that is not the cipher: a 1.4 client gets the legacy layout
        // whatever else it announces, and a 1.5 one gets protobuf.
        for (version, expected) in [
            (Version::new(1, 4, 0), starling_gate::UdpFormat::Legacy),
            (Version::new(1, 5, 0), starling_gate::UdpFormat::Protobuf),
            (Version::new(1, 6, 2), starling_gate::UdpFormat::Protobuf),
        ] {
            let (state, conn) = peer(version, None);
            let keying = keying(&crypt_setup(&state, conn)).expect("keying");
            assert_eq!(keying.format, expected, "{version:?}");
        }
    }

    #[test]
    fn an_unauthenticated_connection_is_told_nothing() {
        // Key material must never be discussed with a peer that has not proved
        // who it is; murmur guards the same message with `Authenticated`.
        let (mut state, _) = authenticated();
        let stranger = ConnId(999);
        state.add_connection(stranger, "127.0.0.1:1".parse().expect("address"));

        assert!(crypt_setup(&state, stranger).is_empty());
    }

    #[test]
    fn an_unknown_connection_is_harmless() {
        let (state, _) = authenticated();
        assert!(crypt_setup(&state, ConnId(12_345)).is_empty());
    }
}
