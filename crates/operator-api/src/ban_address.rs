//! An address an operator bans, as the ban table stores it.
//!
//! Mumble keeps every ban address as sixteen bytes, an IPv4 one v6-mapped
//! (`::ffff:a.b.c.d`), and counts the mask over all sixteen: one IPv4 address
//! is 128, an IPv4 /24 is 120 (`vendor/server`, `HostAddress::match`; the
//! stock client's ban editor adds 96 for IPv4). A login is compared in that
//! form (`moderation`, `covers`). This API stored an IPv4 address as its four
//! octets under a /32, which matches no address at all, so every IPv4 ban
//! written through it turned nobody away.
//!
//! An operator writes the prefix in the address's own terms, 24 for an IPv4
//! /24, which is what anybody types; it is turned into the stored count here.

/// Bits in a stored address.
const STORED_BITS: u32 = 128;
/// What an IPv4 address's own bits are counted after in the mapped form.
const V4_MAPPED_OFFSET: u32 = 96;

/// `(address, prefix_len)` as stored, or why `text` cannot be banned.
pub(crate) fn stored(text: &str, prefix_len: Option<u32>) -> Result<(Vec<u8>, u32), String> {
    match text.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(v4)) => {
            let own = prefix_len.unwrap_or(32);
            if own > 32 {
                return Err(format!("prefix_len {own} is longer than an IPv4 address"));
            }
            Ok((
                v4.to_ipv6_mapped().octets().to_vec(),
                V4_MAPPED_OFFSET + own,
            ))
        }
        Ok(std::net::IpAddr::V6(v6)) => {
            let own = prefix_len.unwrap_or(STORED_BITS);
            if own > STORED_BITS {
                return Err(format!("prefix_len {own} is longer than an IPv6 address"));
            }
            Ok((v6.octets().to_vec(), own))
        }
        Err(_) => Err(format!("{text:?} is not an IP address")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_ipv4_address_is_stored_mapped_under_all_128_bits() {
        let (address, prefix) = stored("127.0.0.1", None).expect("valid");
        assert_eq!(address.len(), 16);
        assert_eq!(&address[10..], &[0xff, 0xff, 127, 0, 0, 1]);
        assert_eq!(prefix, 128);
    }

    #[test]
    fn an_ipv4_prefix_is_written_in_its_own_terms() {
        assert_eq!(stored("10.0.0.0", Some(24)).expect("valid").1, 120);
        assert!(stored("10.0.0.0", Some(33)).is_err());
    }

    #[test]
    fn an_ipv6_address_keeps_its_bytes_and_counts_its_own_bits() {
        let (address, prefix) = stored("2001:db8::1", Some(64)).expect("valid");
        assert_eq!(address[..2], [0x20, 0x01]);
        assert_eq!(prefix, 64);
        assert_eq!(stored("2001:db8::1", None).expect("valid").1, 128);
    }

    #[test]
    fn something_that_is_not_an_address_is_refused() {
        assert!(stored("example.org", None).is_err());
    }
}
