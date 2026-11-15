//! Which local address the SFU's media socket binds.
//!
//! The service's own `media_listen` option when it names one, and otherwise
//! the address the gateway listens on, which voice follows as well: a server
//! the operator put on loopback keeps its media plane on loopback, and one on
//! every interface keeps it there. It used to bind every interface whatever
//! the deployment said.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

/// The address to bind, from `media_listen` and the gateway's `listen_tcp`.
pub(crate) fn media_bind(media_listen: Option<&str>, gateway_listen: &str) -> IpAddr {
    if let Some(option) = media_listen {
        match option.trim().parse::<IpAddr>() {
            Ok(ip) => return ip,
            Err(_) => tracing::warn!(
                media_listen = option,
                "media_listen is not an address; binding where the gateway listens"
            ),
        }
    }
    gateway_listen
        .parse::<SocketAddr>()
        .map_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED), |listen| listen.ip())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_server_on_loopback_keeps_its_media_on_loopback() {
        assert_eq!(
            media_bind(None, "127.0.0.1:64940"),
            "127.0.0.1".parse::<IpAddr>().unwrap()
        );
        assert_eq!(
            media_bind(None, "[::1]:64940"),
            "::1".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn the_services_own_setting_wins() {
        assert_eq!(
            media_bind(Some("10.0.0.5"), "127.0.0.1:64940"),
            "10.0.0.5".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn every_interface_stays_every_interface_and_nonsense_falls_back() {
        assert_eq!(
            media_bind(None, "0.0.0.0:64738"),
            IpAddr::V4(Ipv4Addr::UNSPECIFIED)
        );
        assert_eq!(
            media_bind(Some("not an address"), "127.0.0.1:1"),
            "127.0.0.1".parse::<IpAddr>().unwrap()
        );
    }
}
