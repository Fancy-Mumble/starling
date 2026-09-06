//! Fuzz certificate-chain parsing.
//!
//! `AcceptAnyClientCertificate` is wired by design -- Mumble identifies users
//! by a self-signed certificate they generate -- so `PeerCertificate::from_chain`
//! runs on unauthenticated input on **every** connection, before anything has
//! been proved about the peer.
//!
//! ```text
//! cargo +nightly fuzz run peer_cert
//! ```

#![no_main]

use libfuzzer_sys::fuzz_target;
use starling_crypto::peer_cert::PeerCertificate;

fuzz_target!(|data: &[u8]| {
    // A chain, not one certificate: the split is arbitrary because a peer's is
    // too, and the leaf/issuer distinction is what `from_chain` is about.
    let split = data.first().map_or(0, |first| usize::from(*first)) % data.len().max(1);
    let (leaf, rest) = data.split_at(split.min(data.len()));

    let chain: Vec<rustls::pki_types::CertificateDer<'static>> = vec![
        rustls::pki_types::CertificateDer::from(leaf.to_vec()),
        rustls::pki_types::CertificateDer::from(rest.to_vec()),
    ];
    let _ = PeerCertificate::from_chain(&chain);

    // And the single-certificate case, which is what almost every real client
    // presents.
    let _ = PeerCertificate::from_chain(&[rustls::pki_types::CertificateDer::from(data.to_vec())]);
});
