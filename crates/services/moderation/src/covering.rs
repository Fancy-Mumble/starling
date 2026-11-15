//! Who a ban covers: one rule for a login being checked and for the people
//! already connected when a ban is written.
//!
//! murmur matches a ban by address, under its mask, or by certificate hash
//! (`Server.cpp:1587`, `:1724`). Its name is kept for display and never
//! matched, so a ban naming only a name turned nobody away. Here such a ban
//! matches that name, ignoring case; a ban that has an address or a
//! certificate still matches by those alone, so banning one guest called Bob
//! does not ban every Bob.

use starling_proto_fancy::moderation::{Ban, BanVerdict};
use starling_proto_fancy::sessionview::Session;
use starling_runtime::plane::disconnect;
use starling_runtime::roster::Roster;

use crate::ModerationService;

/// Somebody a ban may cover.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Person<'a> {
    /// The sixteen v6-mapped bytes a mask is counted over.
    pub address: &'a [u8],
    pub cert_hash: &'a [u8],
    pub name: &'a str,
}

impl Person<'_> {
    /// Whether `ban` covers this person.
    pub(crate) fn is_covered_by(&self, ban: &Ban) -> bool {
        let by_address = crate::covers(&sixteen_bytes(ban), self.address);
        let by_cert = !ban.cert_hash.is_empty() && ban.cert_hash == self.cert_hash;
        let name_only = ban.address.is_empty() && ban.cert_hash.is_empty();
        let by_name = name_only
            && !ban.name.is_empty()
            && ban.name.to_lowercase() == self.name.to_lowercase();
        by_address || by_cert || by_name
    }
}

/// `ban` with its address in the sixteen-byte form a login is compared in.
///
/// `operator-api` once stored an IPv4 ban as its four octets under a /32,
/// which compares against nothing; such a row is read as the mapped address
/// it meant, so a ban written before the fix starts to work after it.
pub(crate) fn sixteen_bytes(ban: &Ban) -> Ban {
    let Ok(octets) = <[u8; 4]>::try_from(ban.address.as_slice()) else {
        return ban.clone();
    };
    Ban {
        address: std::net::Ipv4Addr::from(octets)
            .to_ipv6_mapped()
            .octets()
            .to_vec(),
        prefix_len: 96 + ban.prefix_len.min(32),
        ..ban.clone()
    }
}

/// What a login is told about `ban`.
pub(crate) fn verdict(ban: &Ban) -> BanVerdict {
    BanVerdict {
        banned: true,
        reason: ban.reason.clone(),
        expires_at_ms: if ban.duration_s == 0 {
            0
        } else {
            ban.start_ms + u64::from(ban.duration_s) * 1000
        },
    }
}

/// The connected sessions any of `bans` covers, with every other device of
/// the same user: a user is banned, not one of their connections.
pub(crate) fn covered(sessions: &[Session], bans: &[Ban]) -> Vec<u64> {
    let roster = Roster::of(sessions.to_vec());
    let mut users = Vec::new();
    for session in sessions {
        let address = crate::address_bytes(&session.address);
        let person = Person {
            address: &address,
            cert_hash: &session.cert_hash,
            name: &session.name,
        };
        if bans.iter().any(|ban| person.is_covered_by(ban)) {
            let user = roster.presented_as(session.session);
            if !users.contains(&user) {
                users.push(user);
            }
        }
    }
    let devices: Vec<u32> = users
        .into_iter()
        .flat_map(|user| roster.devices_of(user))
        .collect();
    sessions
        .iter()
        .filter(|session| devices.contains(&session.session))
        .map(|session| session.conn)
        .collect()
}

impl ModerationService {
    /// Disconnect everybody connected whom one of `bans` covers.
    ///
    /// For a ban written while its subject is here: a kick-ban already
    /// disconnects the one it names, and a ban written by address,
    /// certificate or in a list has to reach whoever it covers in the same
    /// way, or it only takes effect at their next login.
    pub(crate) async fn turn_away(&self, scope: u32, bans: &[Ban]) {
        if bans.is_empty() {
            return;
        }
        for conn in covered(&self.listed(scope).await, bans) {
            self.fanout.push(disconnect(conn, "banned"));
        }
    }

    /// Everyone connected in `scope`, from `session-view`; nobody when it
    /// cannot be reached.
    pub(crate) async fn listed(&self, scope: u32) -> Vec<Session> {
        use starling_proto_fancy::sessionview::SubscribeRequest;
        use starling_proto_fancy::sessionview::session_view_client::SessionViewClient;

        let Ok(transport) = self.resolver.channel("session-view") else {
            return Vec::new();
        };
        SessionViewClient::new(transport)
            .list(SubscribeRequest {
                scope: Some(starling_proto_fancy::common::Scope { instance: scope }),
                subscriber: "moderation".to_owned(),
            })
            .await
            .map(|listed| listed.into_inner().sessions)
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4(octets: [u8; 4]) -> Vec<u8> {
        std::net::Ipv4Addr::from(octets)
            .to_ipv6_mapped()
            .octets()
            .to_vec()
    }

    fn ban(address: Vec<u8>, prefix_len: u32, cert: &[u8], name: &str) -> Ban {
        Ban {
            address,
            prefix_len,
            cert_hash: cert.to_vec(),
            name: name.to_owned(),
            ..Ban::default()
        }
    }

    fn session(id: u32, presented_as: u32, address: &str, cert: &[u8], name: &str) -> Session {
        Session {
            session: id,
            conn: u64::from(id) * 10,
            presented_as,
            address: address.to_owned(),
            cert_hash: cert.to_vec(),
            name: name.to_owned(),
            ..Session::default()
        }
    }

    #[test]
    fn an_address_ban_covers_its_mask_as_the_wire_counts_it() {
        // One IPv4 address is /128 over the v6-mapped sixteen bytes.
        let one = ban(v4([10, 0, 0, 4]), 128, &[], "");
        let subnet = ban(v4([10, 0, 0, 0]), 120, &[], "");
        let here = v4([10, 0, 0, 4]);
        let there = v4([10, 0, 1, 4]);
        fn person(address: &[u8]) -> Person<'_> {
            Person {
                address,
                cert_hash: &[],
                name: "anyone",
            }
        }
        assert!(person(&here).is_covered_by(&one));
        assert!(person(&here).is_covered_by(&subnet));
        assert!(!person(&there).is_covered_by(&one));
        assert!(!person(&there).is_covered_by(&subnet));
    }

    #[test]
    fn an_ipv4_ban_stored_as_four_bytes_still_covers_its_address() {
        // How `operator-api` wrote them until it stored the mapped form.
        let legacy = ban(vec![10, 0, 0, 4], 32, &[], "");
        let subnet = ban(vec![10, 0, 0, 0], 24, &[], "");
        let person = Person {
            address: &v4([10, 0, 0, 4]),
            cert_hash: &[],
            name: "x",
        };
        assert!(person.is_covered_by(&legacy));
        assert!(person.is_covered_by(&subnet));
        let elsewhere = Person {
            address: &v4([10, 0, 1, 4]),
            ..person
        };
        assert!(!elsewhere.is_covered_by(&legacy));
        assert!(!elsewhere.is_covered_by(&subnet));
    }

    #[test]
    fn a_certificate_ban_follows_the_certificate_anywhere() {
        let cert = ban(Vec::new(), 0, &[7; 20], "");
        let person = Person {
            address: &v4([192, 168, 1, 1]),
            cert_hash: &[7; 20],
            name: "x",
        };
        assert!(person.is_covered_by(&cert));
        let other = Person {
            cert_hash: &[8; 20],
            ..person
        };
        assert!(!other.is_covered_by(&cert));
    }

    #[test]
    fn a_name_matches_only_a_ban_that_has_nothing_else() {
        let name_only = ban(Vec::new(), 0, &[], "Bob");
        let with_address = ban(v4([10, 0, 0, 4]), 128, &[], "Bob");
        let bob = Person {
            address: &v4([172, 16, 0, 9]),
            cert_hash: &[],
            name: "bob",
        };
        assert!(bob.is_covered_by(&name_only), "case is ignored");
        assert!(
            !bob.is_covered_by(&with_address),
            "a ban with an address does not ban every Bob"
        );
    }

    #[test]
    fn a_covered_user_is_turned_away_on_every_device() {
        // 4 and 5 are one user shown as 4; 5 is on the banned address, 4 is
        // not, and both go. 6 is somebody else.
        let sessions = vec![
            session(4, 4, "10.0.0.1:5000", &[], "ann"),
            session(5, 4, "10.0.0.9:5000", &[], "ann"),
            session(6, 6, "10.0.0.2:5000", &[], "cid"),
        ];
        let bans = [ban(v4([10, 0, 0, 9]), 128, &[], "")];
        let mut conns = covered(&sessions, &bans);
        conns.sort_unstable();
        assert_eq!(conns, vec![40, 50]);
    }

    #[test]
    fn a_timed_ban_says_when_it_ends_and_a_permanent_one_says_never() {
        let mut timed = ban(Vec::new(), 0, &[1], "");
        timed.start_ms = 1_000;
        timed.duration_s = 60;
        assert_eq!(verdict(&timed).expires_at_ms, 61_000);
        timed.duration_s = 0;
        assert_eq!(verdict(&timed).expires_at_ms, 0);
    }
}
