//! The TLS version floor.

/// The oldest TLS version a peer may negotiate.
///
/// rustls implements **only** TLS 1.2 and 1.3, so even
/// [`TlsFloor::Tls12`] is stricter than murmur, which accepts
/// `TlsV1_0OrLater` (`Server.cpp:1660`). There is deliberately no variant for
/// TLS 1.0 or 1.1: they are broken, and offering the option would invite
/// somebody to select it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub enum TlsFloor {
    /// TLS 1.2 or 1.3. Required for stock Mumble clients, some of which are
    /// built against OpenSSL versions predating TLS 1.3.
    #[default]
    Tls12,
    /// TLS 1.3 only. Forward secrecy and AEAD are mandatory, the downgrade and
    /// renegotiation surface is gone, and there are no configurable cipher
    /// suites left to get wrong.
    Tls13,
}

/// The single-version list for [`TlsFloor::Tls13`].
///
/// A `static` rather than an inline slice literal so it can be returned with a
/// `'static` lifetime, matching `rustls::ALL_VERSIONS`.
static TLS13_ONLY: &[&rustls::SupportedProtocolVersion] = &[&rustls::version::TLS13];

impl TlsFloor {
    /// The rustls protocol versions this floor permits.
    #[must_use]
    pub fn versions(self) -> &'static [&'static rustls::SupportedProtocolVersion] {
        match self {
            Self::Tls12 => rustls::ALL_VERSIONS,
            Self::Tls13 => TLS13_ONLY,
        }
    }

    /// A short label for logs and the admin API.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Tls12 => "TLS 1.2+",
            Self::Tls13 => "TLS 1.3",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_floor_admits_stock_clients() {
        // Raising the default to 1.3 would lock out stock Mumble clients built
        // against older OpenSSL, which the acceptance rule forbids.
        assert_eq!(TlsFloor::default(), TlsFloor::Tls12);
    }

    #[test]
    fn tls13_permits_exactly_one_version() {
        let versions = TlsFloor::Tls13.versions();
        assert_eq!(versions.len(), 1);
        assert_eq!(versions[0].version, rustls::ProtocolVersion::TLSv1_3);
    }

    #[test]
    fn tls12_permits_more_than_tls13_does() {
        assert!(TlsFloor::Tls12.versions().len() > TlsFloor::Tls13.versions().len());
    }

    #[test]
    fn no_floor_admits_anything_below_tls12() {
        // rustls does not implement TLS 1.0/1.1 at all; this asserts that we
        // never regain the ability to offer them.
        for floor in [TlsFloor::Tls12, TlsFloor::Tls13] {
            for version in floor.versions() {
                assert!(
                    matches!(
                        version.version,
                        rustls::ProtocolVersion::TLSv1_2 | rustls::ProtocolVersion::TLSv1_3
                    ),
                    "{floor:?} admitted {:?}",
                    version.version
                );
            }
        }
    }

    #[test]
    fn floors_order_from_permissive_to_strict() {
        // So "take the stricter of two" is a max().
        assert!(TlsFloor::Tls13 > TlsFloor::Tls12);
    }
}
