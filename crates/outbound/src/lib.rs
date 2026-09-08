//! `starling-outbound`: the one HTTP client that talks to hosts we do not own.
//!
//! Two services make requests to a host somebody outside the deployment named:
//! `link-preview` fetches the page behind a link somebody pasted, and `gifs`
//! calls a media provider's search API and, when the operator asks for it, the
//! CDN behind the results. Both need the same guard, and services may not link
//! each other (`docs/ARCHITECTURE.md` §4) - so it lives here, below both, in
//! the tier that holds `gate` and `crypto`.
//!
//! **It is one crate rather than two copies precisely because of the deny
//! list.** `fetch.rs` says it already: there must not be a second list of
//! private ranges to keep in step with the first. A copy of this file in a
//! second service is that second list, and the way it fails is that one of the
//! two gets the fix for the next bypass.
//!
//! The guard is a deny list of destinations no legitimate outbound target ever
//! lives on: loopback, link-local, and the private ranges that hold a cloud
//! metadata service.

pub mod fetch;
/// A loopback server to fetch from, for the tests of whatever is fetching.
///
/// Behind the same gate as [`Fetcher::against_loopback`], and shipped with
/// neither.
#[cfg(any(test, feature = "loopback"))]
pub mod testing;

#[cfg(any(test, feature = "loopback"))]
pub use fetch::connect_any;
pub use fetch::{
    DEFAULT_USER_AGENT, FetchError, Fetcher, Image, Json, Limits, Page, connect_public, join,
};

/// Why a URL will not be fetched.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// Not `http` or `https`.
    Scheme,
    /// A host that resolves (or is written as) an address inside the
    /// deployment rather than out on the internet.
    PrivateAddress,
    /// No host at all.
    Malformed,
}

impl Refusal {
    /// What the client is told.
    #[must_use]
    pub const fn reason(self) -> &'static str {
        match self {
            Self::Scheme => "only http and https links are previewed",
            Self::PrivateAddress => "that address is inside the server's network",
            Self::Malformed => "that is not a URL",
        }
    }
}

/// Whether `url` may be fetched.
///
/// # Errors
///
/// [`Refusal`] naming which rule it broke, so a client can say something more
/// useful than "no preview".
pub fn vet(url: &str) -> Result<(), Refusal> {
    let rest = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .ok_or(Refusal::Scheme)?;
    let authority = rest
        .split('/')
        .next()
        .map(|authority| authority.split('@').next_back().unwrap_or(authority))
        .filter(|authority| !authority.is_empty())
        .ok_or(Refusal::Malformed)?;
    // An IPv6 literal is bracketed precisely so its own colons cannot be
    // mistaken for the port separator, `[::1]:8080`. Stripping the port by
    // splitting on the first `:` instead treats `[::1]` as the malformed host
    // `[`, which is not a recognised address and so was never checked against
    // the private-range deny list, a bracketed loopback or link-local
    // literal would sail straight through.
    let host = if let Some(literal) = authority.strip_prefix('[') {
        literal.split(']').next().unwrap_or(literal)
    } else {
        authority.split(':').next().unwrap_or(authority)
    };
    if host.is_empty() {
        return Err(Refusal::Malformed);
    }

    if is_private(host) {
        return Err(Refusal::PrivateAddress);
    }
    Ok(())
}

/// Whether a host names something inside the deployment.
///
/// Textual rather than resolved, deliberately: this is the first gate, and the
/// second is [`fetch`] refusing to connect to a private address. Both, not
/// either, a DNS name can resolve to 169.254.169.254 whatever it looks like.
fn is_private(host: &str) -> bool {
    if host.eq_ignore_ascii_case("localhost") || host.ends_with(".localhost") {
        return true;
    }
    let Ok(address) = host.parse::<std::net::IpAddr>() else {
        // A name, not an address. It passes this gate and is caught by the
        // connect-time check.
        return false;
    };
    is_private_addr(address)
}

/// Whether an address is inside the deployment.
///
/// The one predicate, used by the URL check *and* by the resolver check, so
/// there is no second list of ranges to keep in step with this one.
pub(crate) fn is_private_addr(address: std::net::IpAddr) -> bool {
    match address {
        std::net::IpAddr::V4(v4) => {
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_unspecified()
                // 169.254.169.254 is the cloud metadata service, and the single
                // most valuable SSRF target there is.
                || v4.octets()[..2] == [169, 254]
                // Carrier-grade NAT (100.64.0.0/10) and the benchmarking range
                // (198.18.0.0/15): neither is the public internet, and both are
                // routable inside a deployment. Both are written as the ranges
                // they are, 198.18.0.0/15 spans 198.18 *and* 198.19, and
                // reading it as a /16 leaves half of it fetchable.
                || v4.octets()[0] == 100 && (64..128).contains(&v4.octets()[1])
                || v4.octets()[0] == 198 && (18..20).contains(&v4.octets()[1])
        }
        std::net::IpAddr::V6(v6) => {
            // An IPv4-mapped address is an IPv4 address wearing a hat:
            // `::ffff:127.0.0.1` connects to loopback, and a check that reads
            // only the v6 predicates lets it through. This was the hole.
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_private_addr(std::net::IpAddr::V4(v4));
            }
            v6.is_loopback()
                || v6.is_unspecified()
                // fc00::/7, the unique-local range, and fe80::/10, link-local.
                // The v6 equivalents of everything above, and until now the v6
                // arm checked neither.
                || (v6.segments()[0] & 0xfe00) == 0xfc00
                || (v6.segments()[0] & 0xffc0) == 0xfe80
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_cloud_metadata_address_is_refused() {
        // The single most valuable SSRF target in any cloud deployment.
        assert_eq!(
            vet("http://169.254.169.254/latest/meta-data/"),
            Err(Refusal::PrivateAddress)
        );
    }

    #[test]
    fn loopback_and_private_ranges_are_refused() {
        for url in [
            "http://127.0.0.1/admin",
            "http://localhost:8080/",
            "http://10.0.0.5/",
            "http://192.168.1.1/",
            "http://[::1]/",
        ] {
            assert!(vet(url).is_err(), "{url} must be refused");
        }
    }

    #[test]
    fn an_ipv4_address_wearing_an_ipv6_hat_is_still_loopback() {
        // `::ffff:127.0.0.1` is an IPv4-mapped IPv6 address: it connects to
        // 127.0.0.1, and a check that reads only the v6 predicates
        // (`is_loopback`, `is_unspecified`) says it is public. It was the hole.
        for url in [
            "http://[::ffff:127.0.0.1]/",
            "http://[::ffff:169.254.169.254]/latest/meta-data/",
            "http://[::ffff:10.0.0.1]/",
        ] {
            assert_eq!(
                vet(url),
                Err(Refusal::PrivateAddress),
                "{url} must be refused"
            );
        }
    }

    #[test]
    fn the_ipv6_private_ranges_are_refused_as_well_as_the_ipv4_ones() {
        // fc00::/7 is where a deployment's own machines live on v6, and
        // fe80::/10 is the link. Neither was checked.
        for url in ["http://[fd00::1]/", "http://[fe80::1]/"] {
            assert_eq!(
                vet(url),
                Err(Refusal::PrivateAddress),
                "{url} must be refused"
            );
        }
    }

    #[test]
    fn carrier_grade_nat_and_the_benchmark_range_are_not_the_internet() {
        assert_eq!(vet("http://100.64.0.1/"), Err(Refusal::PrivateAddress));
        assert_eq!(vet("http://198.18.0.1/"), Err(Refusal::PrivateAddress));
        // The neighbours of both, which are ordinary public addresses and must
        // stay fetchable, a guard that is too wide is a feature that does not
        // work, and nobody reports it as a security bug.
        assert!(vet("http://100.63.255.255/").is_ok());
        assert!(vet("http://100.128.0.1/").is_ok());
        assert_eq!(vet("http://198.19.255.255/"), Err(Refusal::PrivateAddress));
        assert!(vet("http://198.20.0.1/").is_ok());
    }

    #[test]
    fn a_non_http_scheme_is_refused_rather_than_attempted() {
        assert_eq!(vet("file:///etc/passwd"), Err(Refusal::Scheme));
        assert_eq!(vet("gopher://example.org/"), Err(Refusal::Scheme));
    }

    #[test]
    fn an_ordinary_public_url_passes() {
        assert!(vet("https://example.org/article").is_ok());
    }

    #[test]
    fn credentials_in_the_authority_do_not_hide_the_host() {
        // http://example.org@127.0.0.1/ is a classic filter bypass.
        assert_eq!(
            vet("http://example.org@127.0.0.1/"),
            Err(Refusal::PrivateAddress)
        );
    }
}
