//! Binding a wildcard address so it actually means "everywhere".
//!
//! `0.0.0.0` is IPv4 only. A socket bound to it never receives an IPv6 datagram,
//! and the operating system drops those before any code here runs — no error, no
//! packet, nothing to log.
//!
//! That is how this arrived: a client resolved `localhost` to `::1` for its
//! voice socket, sent every audio frame to `[::1]:64738`, and a server bound to
//! `0.0.0.0:64738` sat in silence. The server's logs were clean, the client
//! believed UDP was working, and no counter anywhere moved.
//!
//! # The rule
//!
//! A **wildcard** host means every interface, and every interface includes IPv6.
//! So a wildcard binds `[::]` with `IPV6_V6ONLY` off, which accepts both families
//! on one socket. Anything else is an address the operator chose deliberately and
//! is bound exactly as written — `192.0.2.7` must not silently start accepting
//! IPv6 as well.
//!
//! # Why this is not `UdpSocket::bind`
//!
//! Neither `std` nor `tokio` exposes `IPV6_V6ONLY`, and its default differs by
//! platform: off on most Linux distributions, **on** for Windows and OpenBSD.
//! Relying on the default would give a server that works on the developer's
//! machine and not on the deployment's, which is the failure this module exists
//! to remove.

use std::io;
use std::net::SocketAddr;

use socket2::{Domain, Protocol, Socket, Type};

/// Whether `addr` asks for every interface rather than a particular one.
///
/// Both wildcards count: an operator writing `0.0.0.0` means "all of them" just
/// as much as one writing `[::]`, and neither should be read as "IPv4 only".
#[must_use]
pub(crate) fn is_wildcard(addr: SocketAddr) -> bool {
    match addr {
        SocketAddr::V4(v4) => v4.ip().is_unspecified(),
        SocketAddr::V6(v6) => v6.ip().is_unspecified(),
    }
}

/// The address to actually bind for `addr`.
///
/// A wildcard becomes the IPv6 wildcard, which — with `IPV6_V6ONLY` off — carries
/// both families. Everything else is returned unchanged.
#[must_use]
pub(crate) fn resolve(addr: SocketAddr) -> SocketAddr {
    if is_wildcard(addr) {
        SocketAddr::from((std::net::Ipv6Addr::UNSPECIFIED, addr.port()))
    } else {
        addr
    }
}

/// Bind a UDP socket that hears both address families when asked to.
///
/// # Errors
///
/// Whatever the OS says: the port is taken, or the address is not local. A
/// system with IPv6 disabled entirely falls back to the IPv4 wildcard rather
/// than refusing to start — a server that will not boot is worse than one that
/// serves the only family available.
pub(crate) fn udp(addr: SocketAddr) -> io::Result<std::net::UdpSocket> {
    let wanted = resolve(addr);

    match configured(wanted, Type::DGRAM, Protocol::UDP) {
        Ok(socket) => Ok(socket.into()),
        // Only worth retrying when we substituted the address ourselves.
        Err(error) if wanted != addr => {
            tracing::warn!(%error, %addr, "IPv6 unavailable; binding IPv4 only");
            configured(addr, Type::DGRAM, Protocol::UDP).map(Into::into)
        }
        Err(error) => Err(error),
    }
}

/// Bind a TCP listener that accepts both address families when asked to.
///
/// # Errors
///
/// As [`udp`].
pub(crate) fn tcp(addr: SocketAddr) -> io::Result<std::net::TcpListener> {
    let wanted = resolve(addr);

    let listen = |addr: SocketAddr| -> io::Result<std::net::TcpListener> {
        let socket = configured(addr, Type::STREAM, Protocol::TCP)?;
        // The backlog `std` uses. Named rather than inherited because this
        // constructs the socket by hand and would otherwise get the OS default,
        // which on some platforms is far smaller.
        socket.listen(128)?;
        Ok(socket.into())
    };

    match listen(wanted) {
        Ok(listener) => Ok(listener),
        Err(error) if wanted != addr => {
            tracing::warn!(%error, %addr, "IPv6 unavailable; listening on IPv4 only");
            listen(addr)
        }
        Err(error) => Err(error),
    }
}

/// A bound socket with the options this server needs.
fn configured(addr: SocketAddr, kind: Type, protocol: Protocol) -> io::Result<Socket> {
    let domain = Domain::for_address(addr);
    let socket = Socket::new(domain, kind, Some(protocol))?;

    if domain == Domain::IPV6 && is_wildcard(addr) {
        // The whole point. Windows and OpenBSD default this on, so an IPv6
        // wildcard there would still refuse IPv4 without saying so.
        socket.set_only_v6(false)?;
    }

    // Otherwise a restart inside the TIME_WAIT window fails to bind, which for
    // a server is the most common restart there is.
    #[cfg(not(windows))]
    socket.set_reuse_address(true)?;

    socket.bind(&addr.into())?;
    // tokio requires this; a blocking socket handed to it stalls the runtime.
    socket.set_nonblocking(true)?;
    Ok(socket)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn both_wildcards_are_recognised() {
        assert!(is_wildcard(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 1))));
        assert!(is_wildcard(SocketAddr::from((Ipv6Addr::UNSPECIFIED, 1))));
    }

    #[test]
    fn a_chosen_address_is_not_a_wildcard() {
        // An operator naming an interface means that interface. Widening it
        // would expose a server on networks it was deliberately kept off.
        assert!(!is_wildcard(SocketAddr::from((
            Ipv4Addr::new(192, 0, 2, 7),
            1
        ))));
        assert!(!is_wildcard(SocketAddr::from((Ipv4Addr::LOCALHOST, 1))));
        assert!(!is_wildcard(SocketAddr::from((Ipv6Addr::LOCALHOST, 1))));
    }

    #[test]
    fn a_wildcard_resolves_to_the_dual_stack_address() {
        let resolved = resolve(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 64_738)));
        assert!(
            resolved.is_ipv6(),
            "0.0.0.0 stayed IPv4 and will not hear IPv6"
        );
        assert_eq!(resolved.port(), 64_738);
    }

    #[test]
    fn a_chosen_address_is_left_alone() {
        let chosen = SocketAddr::from((Ipv4Addr::new(192, 0, 2, 7), 64_738));
        assert_eq!(resolve(chosen), chosen);
    }

    #[test]
    fn a_wildcard_udp_socket_hears_both_families() {
        // The regression, stated as a test. Before this, a client resolving
        // `localhost` to `::1` had every audio frame dropped by the OS — no
        // error, no packet, and nothing in any log to explain the silence.
        let bound = udp(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))).expect("bind");
        let port = bound.local_addr().expect("local addr").port();
        bound.set_nonblocking(false).expect("blocking for the test");
        bound
            .set_read_timeout(Some(std::time::Duration::from_secs(2)))
            .expect("timeout");

        for (from, to) in [
            (
                SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
                SocketAddr::from((Ipv4Addr::LOCALHOST, port)),
            ),
            (
                SocketAddr::from((Ipv6Addr::LOCALHOST, 0)),
                SocketAddr::from((Ipv6Addr::LOCALHOST, port)),
            ),
        ] {
            let client = std::net::UdpSocket::bind(from).expect("client bind");
            let _ = client.send_to(b"probe", to).expect("send");

            let mut buffer = [0; 16];
            let (len, _) = bound
                .recv_from(&mut buffer)
                .unwrap_or_else(|e| panic!("nothing arrived from {to}: {e}"));
            assert_eq!(&buffer[..len], b"probe", "from {to}");
        }
    }

    #[test]
    fn a_wildcard_tcp_listener_accepts_both_families() {
        let listener = tcp(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))).expect("bind");
        let port = listener.local_addr().expect("local addr").port();

        for to in [
            SocketAddr::from((Ipv4Addr::LOCALHOST, port)),
            SocketAddr::from((Ipv6Addr::LOCALHOST, port)),
        ] {
            let client = std::net::TcpStream::connect(to)
                .unwrap_or_else(|e| panic!("could not connect to {to}: {e}"));
            drop(client);
        }
    }

    #[test]
    fn a_specific_address_still_binds() {
        let bound = udp(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).expect("bind");
        assert!(bound.local_addr().expect("local addr").is_ipv4());
    }

    #[test]
    fn a_taken_port_is_an_error_not_a_panic() {
        let first = udp(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).expect("bind");
        let taken = first.local_addr().expect("local addr");
        assert!(udp(taken).is_err());
    }
}
