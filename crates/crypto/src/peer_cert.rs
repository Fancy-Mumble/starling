//! Asking a client for its certificate, and identifying it by the result.
//!
//! # Why the server asks at all
//!
//! In Mumble a certificate *is* the identity. A registered account is bound to
//! the SHA-1 of the certificate that registered it, bans can be issued against
//! one, and a client that presents the right certificate is admitted without a
//! password (`vendor/server/src/murmur/Messages.cpp:418`). None of that is
//! reachable unless the server requests a certificate during the TLS handshake
//! and a server built with rustls's `with_no_client_auth()` never does, so
//! every peer arrives anonymous and none of those mechanisms can ever fire.
//!
//! # Why it accepts a certificate that chains to nothing
//!
//! Mumble clients generate their own self-signed certificate on first run.
//! There is no CA, and there is not meant to be: the trust model is
//! **trust-on-first-use over a stable fingerprint**, the same one the client
//! applies to the server (`crate::identity`). Refusing an unchained
//! certificate would refuse every Mumble client in existence.
//!
//! So the verifier below accepts any well-formed certificate and treats the
//! hash as an *identifier*, not as proof of a trusted third party's opinion.
//! What it must not do is let that be mistaken for validation, which is what
//! [`PeerCertificate::strong`] is for: it is set only when a chain verified
//! against a configured CA, and it is the only thing an operator should key a
//! privilege off.
//!
//! # What is still checked
//!
//! Accepting any *issuer* is not accepting anything at all. The handshake
//! signature is still verified against the presented key, by rustls, using the
//! provider's own algorithms, so a peer must actually hold the private key for
//! the certificate it offers. Without that a client could claim any hash it
//! liked by copying somebody else's public certificate, and certificate
//! identity would be worse than none.

use std::sync::Arc;

use rustls::DigitallySignedStruct;
use rustls::client::danger::HandshakeSignatureValid;
use rustls::crypto::{CryptoProvider, verify_tls12_signature, verify_tls13_signature};
use rustls::pki_types::{CertificateDer, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{DistinguishedName, SignatureScheme};
use sha1::{Digest as _, Sha1};

/// What a peer presented, reduced to what the rest of the server needs.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PeerCertificate {
    /// SHA-1 of the leaf certificate, in DER.
    ///
    /// murmur's `qsHash` (`vendor/server/src/murmur/Server.cpp:1686`), which it
    /// stores hex-encoded. Kept as raw bytes here because that is what the
    /// account and ban tables compare against; hex is a wire and display
    /// concern, applied at the edges.
    ///
    /// SHA-1 and not something stronger because this value is a **compatibility
    /// key**: it has to equal what every existing Mumble client, murmur
    /// database and ban list already computed. Its collision resistance is not
    /// what protects the account, holding the private key is, and that is
    /// checked during the handshake.
    pub hash: Vec<u8>,
    /// The chain as presented, leaf first, DER-encoded.
    ///
    /// Kept so the client's Information window can show the certificate it is
    /// talking to; a hash alone cannot be rendered.
    pub chain: Vec<Vec<u8>>,
    /// Whether the chain validated against a configured certificate authority.
    ///
    /// False for the self-signed certificate a stock Mumble client generates,
    /// which is the ordinary case and not a problem. It is `murmur`'s
    /// `bVerified`, and the only field here that carries an assurance rather
    /// than an identifier.
    pub strong: bool,
}

impl PeerCertificate {
    /// Read a peer's chain into the parts the server keeps.
    ///
    /// `None` when the peer presented nothing, which is allowed: a client
    /// without a certificate is a guest, exactly as it is under murmur.
    #[must_use]
    pub fn from_chain(chain: &[CertificateDer<'static>]) -> Option<Self> {
        let leaf = chain.first()?;
        Some(Self {
            hash: Sha1::digest(leaf.as_ref()).to_vec(),
            chain: chain.iter().map(|der| der.as_ref().to_vec()).collect(),
            // Nothing here validates a chain, so nothing here may claim to.
            // A deployment that configures a CA sets this on the way past.
            strong: false,
        })
    }

    /// The hash as murmur writes it: lower-case hex.
    #[must_use]
    pub fn hex(&self) -> String {
        self.hash.iter().map(|byte| format!("{byte:02x}")).collect()
    }
}

/// Requests a certificate, accepts any, and proves the peer holds its key.
///
/// See the module documentation for why "accepts any" is the correct policy
/// here rather than a weakening of one.
#[derive(Debug)]
pub struct AcceptAnyClientCertificate {
    provider: Arc<CryptoProvider>,
    /// Empty: an empty hint list tells a client to send whatever certificate it
    /// has, which is what is wanted when there is no CA to name.
    hints: Vec<DistinguishedName>,
}

impl AcceptAnyClientCertificate {
    /// A verifier over `provider`'s signature algorithms.
    #[must_use]
    pub fn new(provider: Arc<CryptoProvider>) -> Arc<Self> {
        Arc::new(Self {
            provider,
            hints: Vec::new(),
        })
    }
}

impl ClientCertVerifier for AcceptAnyClientCertificate {
    fn offer_client_auth(&self) -> bool {
        true
    }

    /// Optional, deliberately.
    ///
    /// Mumble has always allowed a client with no certificate to connect as a
    /// guest. Requiring one would turn certificate support into a hard break
    /// for every user who has not made one.
    fn client_auth_mandatory(&self) -> bool {
        false
    }

    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &self.hints
    }

    /// Accepts any issuer; see the module documentation.
    ///
    /// The certificate is still parsed by rustls before this is reached, and
    /// the peer must still prove possession of the private key in the two
    /// signature checks below, so "accepted" means "identified", not
    /// "unauthenticated".
    fn verify_client_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        // rustls's own implementation, not a hand-written one: this is the
        // check that makes the hash mean anything, and it is the last place
        // that should have bespoke cryptography in it.
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn der(bytes: &[u8]) -> CertificateDer<'static> {
        CertificateDer::from(bytes.to_vec())
    }

    #[test]
    fn a_peer_that_presented_nothing_is_not_an_error() {
        // Mumble allows a client with no certificate; it is a guest, not a
        // failure, and treating it as one would refuse ordinary users.
        assert_eq!(PeerCertificate::from_chain(&[]), None);
    }

    #[test]
    fn the_hash_is_sha1_of_the_leaf_as_murmur_computes_it() {
        // The value has to equal what every existing client, murmur database
        // and ban list already holds, so the algorithm is not a free choice.
        // SHA-1 of "abc" is the published test vector below.
        let peer = PeerCertificate::from_chain(&[der(b"abc")]).expect("a leaf was presented");
        assert_eq!(peer.hex(), "a9993e364706816aba3e25717850c26c9cd0d89d");
        assert_eq!(peer.hash.len(), 20);
    }

    #[test]
    fn the_leaf_is_hashed_not_the_whole_chain() {
        // murmur takes `certs.first()`. Hashing an intermediate as well would
        // produce a value no existing deployment could match.
        let with_intermediate =
            PeerCertificate::from_chain(&[der(b"abc"), der(b"issuer")]).expect("a leaf");
        let leaf_only = PeerCertificate::from_chain(&[der(b"abc")]).expect("a leaf");
        assert_eq!(with_intermediate.hash, leaf_only.hash);
        assert_eq!(with_intermediate.chain.len(), 2, "the chain is still kept");
    }

    #[test]
    fn a_chain_is_never_reported_as_strong_by_reading_it_alone() {
        // `strong` is an assurance, and nothing in this file validates one.
        // Defaulting it to true would let an operator grant privilege on the
        // strength of a self-signed certificate anybody can mint.
        let peer = PeerCertificate::from_chain(&[der(b"abc")]).expect("a leaf");
        assert!(!peer.strong);
    }

    #[test]
    fn the_verifier_requests_a_certificate_without_demanding_one() {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let verifier = AcceptAnyClientCertificate::new(provider);
        assert!(
            verifier.offer_client_auth(),
            "not asking is what made every peer anonymous"
        );
        assert!(
            !verifier.client_auth_mandatory(),
            "demanding one locks out every user who has not made a certificate"
        );
        assert!(
            verifier.root_hint_subjects().is_empty(),
            "an empty hint list asks the client for whatever it has"
        );
    }
}
