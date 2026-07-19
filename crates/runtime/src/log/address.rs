//! Whether an operator's log records addresses or pseudonyms for them.
//!
//! murmur's `obfuscate` (`Server.cpp:2545`). `obfuscate_ips` existed in
//! `server-config` and was read by nothing, so addresses were written out in
//! full whatever an operator had set (`docs/GAP-ANALYSIS.md` §5), and an
//! operator log is exactly the artefact that gets copied into a ticket, kept
//! for a month, and read by more people than the person who runs the server.
//!
//! # Why it is a pseudonym and not a redaction
//!
//! `<<hash>>:port` rather than `<<hidden>>`, because the question an operator
//! asks of an address is almost never "what is it"; it is "is this the same
//! one as that". Two records from one address still match; the address itself
//! is not recoverable from the record. Blanking the field would take the answer
//! away along with the address.
//!
//! The salt is **random per process**, as murmur's is: it makes the mapping
//! unstable across restarts, which is deliberate. A stable one is a rainbow
//! table away from being no obfuscation at all, since the input space is four
//! bytes wide.
//!
//! # Why it is applied here and not at the call sites
//!
//! There is one writer thread and every operator-facing record passes through
//! it. A rule applied at call sites is a rule that is missing from the call
//! site somebody adds next month, and the missing one looks exactly like the
//! others.

use std::sync::LazyLock;

use sha2::{Digest as _, Sha256};

use crate::log::event::{Field, FieldValue, LogEvent};

/// Field names whose values are addresses.
///
/// A list rather than a guess at the shape of the value: a heuristic that
/// looked for something IP-shaped would obfuscate a version string that happens
/// to have three dots in it, and would miss a hostname.
const ADDRESS_FIELDS: &[&str] = &["address", "peer", "remote", "ip"];

/// This process's salt.
///
/// Derived once from the system clock and the process id. Not a cryptographic
/// secret; it is a nonce that makes the mapping unpredictable and
/// process-local, which is the whole of what it is for.
static SALT: LazyLock<[u8; 16]> = LazyLock::new(|| {
    let mut hasher = Sha256::new();
    hasher.update(std::process::id().to_be_bytes());
    hasher.update(crate::ids::now_ms().to_be_bytes());
    let digest = hasher.finalize();
    let mut salt = [0_u8; 16];
    salt.copy_from_slice(&digest[..16]);
    salt
});

/// The pseudonym for `address`, keeping any port it carries.
///
/// The port survives because it distinguishes two connections from one host and
/// discloses nothing about who they are, which is murmur's reasoning, and why
/// its own form is `<<hash>>:port`.
#[must_use]
pub fn obfuscate(address: &str) -> String {
    let (host, port) = split_port(address);
    let mut hasher = Sha256::new();
    hasher.update(*SALT);
    hasher.update(host.as_bytes());
    let digest = hasher.finalize();
    // Ten hex characters: enough that two addresses on one server will not
    // collide, short enough to read in a log line.
    let short: String = digest
        .iter()
        .take(5)
        .map(|byte| format!("{byte:02x}"))
        .collect();
    match port {
        Some(port) => format!("<<{short}>>:{port}"),
        None => format!("<<{short}>>"),
    }
}

/// Split a host from its port, understanding the bracketed IPv6 form.
///
/// `[::1]:64738` splits; a bare `::1` does not, because every colon in it is
/// part of the address. Getting this wrong would hash a *different* string for
/// the same host depending on whether a port was attached, and the "is this the
/// same address" question the pseudonym exists to answer would stop working.
fn split_port(address: &str) -> (&str, Option<&str>) {
    if let Some(rest) = address.strip_prefix('[') {
        return match rest.split_once("]:") {
            Some((host, port)) => (host, Some(port)),
            None => (rest.trim_end_matches(']'), None),
        };
    }
    match address.rsplit_once(':') {
        // More than one colon and no brackets: a bare IPv6 address.
        Some(_) if address.matches(':').count() > 1 => (address, None),
        Some((host, port)) => (host, Some(port)),
        None => (address, None),
    }
}

/// Replace every address field in `event` with its pseudonym.
pub fn obfuscate_event(event: &mut LogEvent) {
    for field in &mut event.fields {
        if !ADDRESS_FIELDS.contains(&field.key.as_ref()) {
            continue;
        }
        if let FieldValue::Text(address) = &field.value {
            *field = Field {
                key: field.key.clone(),
                value: FieldValue::Text(obfuscate(address)),
            };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::log::event::Category;

    #[test]
    fn the_same_address_reads_the_same_twice() {
        // The property that makes a pseudonym useful at all: "is this the same
        // address as that one" still has an answer.
        assert_eq!(
            obfuscate("198.51.100.9:64738"),
            obfuscate("198.51.100.9:64738")
        );
    }

    #[test]
    fn different_addresses_read_differently() {
        assert_ne!(obfuscate("198.51.100.9:1"), obfuscate("198.51.100.10:1"));
    }

    #[test]
    fn the_address_is_not_recoverable_from_the_record() {
        // The point. An operator log ends up in tickets and in backups.
        let hidden = obfuscate("198.51.100.9:64738");
        assert!(!hidden.contains("198.51.100.9"));
        assert!(hidden.starts_with("<<"));
    }

    #[test]
    fn the_port_survives_because_it_discloses_nothing() {
        assert!(obfuscate("198.51.100.9:64738").ends_with(":64738"));
    }

    #[test]
    fn one_host_reads_the_same_from_two_ports() {
        // Two connections from one machine must still be recognisable as one
        // machine, which is the question an operator is actually asking.
        let one = obfuscate("198.51.100.9:1000");
        let two = obfuscate("198.51.100.9:2000");
        let strip = |text: String| text.split(':').next().unwrap_or_default().to_owned();
        assert_eq!(strip(one), strip(two));
    }

    #[test]
    fn a_bracketed_ipv6_address_splits_at_its_port_and_a_bare_one_does_not() {
        // Otherwise the same host hashes differently depending on whether a
        // port was attached, and the sameness test above stops working.
        assert_eq!(
            split_port("[2001:db8::1]:64738"),
            ("2001:db8::1", Some("64738"))
        );
        assert_eq!(split_port("2001:db8::1"), ("2001:db8::1", None));
        assert_eq!(
            split_port("198.51.100.9:64738"),
            ("198.51.100.9", Some("64738"))
        );
        assert_eq!(split_port("example.test"), ("example.test", None));
    }

    #[test]
    fn only_the_address_fields_are_touched() {
        // A record whose every field was hashed would be unreadable, and the
        // name of the user who connected is not the thing being protected here.
        let mut event = LogEvent::info(Category::Session, "user authenticated")
            .with("address", "198.51.100.9:64738")
            .with("name", "someone")
            .with("session", 7_u32);
        obfuscate_event(&mut event);

        let value = |key: &str| {
            event
                .fields
                .iter()
                .find(|field| field.key == key)
                .map(|field| field.value.to_string())
                .unwrap_or_default()
        };
        assert!(value("address").starts_with("<<"));
        assert_eq!(value("name"), "someone");
        assert_eq!(value("session"), "7");
    }
}
