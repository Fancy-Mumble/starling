//! A ban list written from a client's ban editor, and the list a client reads.
//!
//! murmur's editor sends the whole list back with `query` unset, and that is
//! how a ban is added, changed or lifted: the list replaces the stored one
//! (`vendor/server/src/murmur/Messages.cpp:989`, `msgBanList`).
//!
//! Every address travels as sixteen bytes, IPv4 as `::ffff:a.b.c.d`, and the
//! mask counts leading bits over all sixteen: one IPv4 address is 128, an IPv4
//! /24 is 120. A mask under 96 on a mapped address therefore covers every IPv4
//! address there is, and that is exactly what a client sends when it counts
//! the mask in IPv4 terms (the web client starts a new ban at 32). murmur
//! stores it and turns everybody away; here the list is refused instead.

use starling_proto::proto::tcp::ban_list::BanEntry;
use starling_proto_fancy::moderation::Ban;

use crate::ban_ids::BanIds;

/// The bits of `::ffff:0:0/96` in front of every mapped IPv4 address.
const MAPPED_PREFIX: [u8; 12] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff];
/// How many of a mapped address's bits are that prefix.
const MAPPED_BITS: u32 = 96;
/// The ban table's `name` column.
const NAME_CHARS: usize = 190;

/// The bans `entries` asks for, or why none of the list is taken.
///
/// An entry the list already holds, by certificate, address and mask, keeps
/// its id and the moment it began, so editing a ban's reason or duration does
/// not restart it; a new one begins now. Entries naming neither an address nor
/// a certificate are dropped and duplicates collapse, as murmur does.
///
/// # Errors
///
/// The reason the client is shown, for the first entry that cannot be
/// stored as written.
pub(crate) fn bans_from(
    entries: &[BanEntry],
    held: &[Ban],
    ids: &BanIds,
    now_ms: u64,
) -> Result<Vec<Ban>, String> {
    let mut bans: Vec<Ban> = Vec::with_capacity(entries.len());
    for entry in entries {
        let Some(mut ban) = ban_of(entry)? else {
            continue;
        };
        if bans.iter().any(|kept| same_ban(kept, &ban)) {
            continue;
        }
        match held.iter().find(|old| same_ban(old, &ban)) {
            Some(old) => {
                ban.id = old.id;
                ban.start_ms = old.start_ms;
            }
            None => {
                ban.id = ids.next(now_ms);
                ban.start_ms = now_ms;
            }
        }
        bans.push(ban);
    }
    Ok(bans)
}

/// The bans in `now` that `before` did not hold.
///
/// What a written list adds, which is what anything acting on a new ban
/// (closing the connections it covers) has to look at.
pub(crate) fn added(now: &[Ban], before: &[Ban]) -> Vec<Ban> {
    now.iter()
        .filter(|ban| !before.iter().any(|old| same_ban(old, ban)))
        .cloned()
        .collect()
}

/// One stored ban as a client's list shows it.
///
/// In the sixteen-byte form whatever the row holds: a row stored as four IPv4
/// octets under a /32 would otherwise reach a client as a mask of 32, which
/// the wire's counting reads as every IPv4 address.
pub(crate) fn entry_of(ban: &Ban) -> BanEntry {
    let ban = crate::covering::sixteen_bytes(ban);
    BanEntry {
        address: ban.address,
        mask: ban.prefix_len,
        name: Some(ban.name),
        hash: Some(hex(&ban.cert_hash)),
        reason: Some(ban.reason),
        // murmur sends `QDateTime::toString(Qt::ISODate)` in UTC.
        start: Some(iso_date(ban.start_ms)),
        duration: Some(ban.duration_s),
    }
}

/// One entry as a ban, `None` for an entry that names nobody.
fn ban_of(entry: &BanEntry) -> Result<Option<Ban>, String> {
    let address = entry.address.clone();
    if !address.is_empty() && address.len() != 16 {
        return Err("A ban's address travels as sixteen bytes.".to_owned());
    }
    if entry.mask > 128 {
        return Err(format!(
            "A mask of {} is longer than an address.",
            entry.mask
        ));
    }
    if !address.is_empty() && covers_everybody(&address, entry.mask) {
        return Err(format!(
            "A mask of {} covers every address, so this list was not saved. \
             An IPv4 address counts its bits after 96: one address is 128, a /24 is 120.",
            entry.mask
        ));
    }
    let Some(cert_hash) = unhex(entry.hash.as_deref().unwrap_or_default()) else {
        return Err("A ban's certificate hash is written in hex.".to_owned());
    };
    if address.is_empty() && cert_hash.is_empty() {
        return Ok(None);
    }
    Ok(Some(Ban {
        id: 0,
        prefix_len: if address.is_empty() { 0 } else { entry.mask },
        address,
        name: entry
            .name
            .as_deref()
            .unwrap_or_default()
            .chars()
            .take(NAME_CHARS)
            .collect(),
        cert_hash,
        reason: entry.reason.clone().unwrap_or_default(),
        start_ms: 0,
        duration_s: entry.duration.unwrap_or_default(),
    }))
}

/// Whether a mask on `address` reaches past what any one family can mean:
/// all of IPv6, or every IPv4 address at once.
fn covers_everybody(address: &[u8], mask: u32) -> bool {
    mask == 0 || (address.starts_with(&MAPPED_PREFIX) && mask < MAPPED_BITS)
}

/// The same ban, as murmur's de-duplication keys it (`Ban::toKey`).
fn same_ban(a: &Ban, b: &Ban) -> bool {
    a.cert_hash == b.cert_hash && a.address == b.address && a.prefix_len == b.prefix_len
}

/// Certificate hashes travel as hex on the wire, as they do in murmur.
pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// The bytes of a hex string, `None` when it is not one.
fn unhex(text: &str) -> Option<Vec<u8>> {
    let text = text.trim();
    if !text.len().is_multiple_of(2) {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(text.get(at..at + 2)?, 16).ok())
        .collect()
}

/// `ms` since the epoch as `yyyy-MM-ddTHH:mm:ssZ`.
fn iso_date(ms: u64) -> String {
    let at = std::time::UNIX_EPOCH + std::time::Duration::from_millis(ms);
    let full = starling_runtime::log::timestamp::rfc3339(at);
    // The microseconds murmur's clients do not expect; the rest is the same.
    format!("{}Z", full.get(..19).unwrap_or(&full))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mapped(v4: [u8; 4]) -> Vec<u8> {
        std::net::Ipv4Addr::from(v4)
            .to_ipv6_mapped()
            .octets()
            .to_vec()
    }

    fn entry(address: Vec<u8>, mask: u32) -> BanEntry {
        BanEntry {
            address,
            mask,
            name: Some("Nobody".to_owned()),
            hash: Some(String::new()),
            reason: Some("by hand".to_owned()),
            start: None,
            duration: Some(0),
        }
    }

    #[test]
    fn a_short_mask_on_an_ipv4_address_is_refused_rather_than_banning_everybody() {
        let refused = bans_from(
            &[entry(mapped([203, 0, 113, 7]), 32)],
            &[],
            &BanIds::default(),
            1,
        );
        assert!(refused.is_err_and(|why| why.contains("every address")));
        // The same address counted over the sixteen bytes is one host.
        let one = bans_from(
            &[entry(mapped([203, 0, 113, 7]), 128)],
            &[],
            &BanIds::default(),
            1,
        )
        .expect("one host is a ban");
        assert_eq!(one.len(), 1);
        assert_eq!(one[0].prefix_len, 128);
        // And a /24 in the wire's terms is still a /24.
        assert!(
            bans_from(
                &[entry(mapped([203, 0, 113, 0]), 120)],
                &[],
                &BanIds::default(),
                1
            )
            .is_ok()
        );
    }

    #[test]
    fn a_mask_of_nothing_is_refused_for_ipv6_too() {
        let v6: Vec<u8> = "2001:db8::1"
            .parse::<std::net::Ipv6Addr>()
            .unwrap()
            .octets()
            .to_vec();
        assert!(bans_from(&[entry(v6.clone(), 0)], &[], &BanIds::default(), 1).is_err());
        assert!(bans_from(&[entry(v6, 64)], &[], &BanIds::default(), 1).is_ok());
    }

    #[test]
    fn an_address_that_is_not_sixteen_bytes_is_refused() {
        assert!(
            bans_from(
                &[entry(vec![203, 0, 113, 7], 32)],
                &[],
                &BanIds::default(),
                1
            )
            .is_err()
        );
    }

    #[test]
    fn a_ban_already_held_keeps_its_start_and_a_new_one_begins_now() {
        let held = Ban {
            id: 5,
            address: mapped([198, 51, 100, 1]),
            prefix_len: 128,
            start_ms: 1_000,
            ..Ban::default()
        };
        let mut edited = entry(mapped([198, 51, 100, 1]), 128);
        edited.duration = Some(3_600);
        let bans = bans_from(
            &[edited, entry(mapped([203, 0, 113, 7]), 128)],
            std::slice::from_ref(&held),
            &BanIds::default(),
            9_000,
        )
        .expect("a valid list");
        assert_eq!(
            (bans[0].id, bans[0].start_ms, bans[0].duration_s),
            (5, 1_000, 3_600)
        );
        assert_eq!(bans[1].start_ms, 9_000);
        assert_ne!(bans[1].id, 5);
        assert_eq!(added(&bans, &[held]).len(), 1, "only the new one is added");
    }

    #[test]
    fn two_new_bans_in_one_list_get_two_ids() {
        // Ids are minted from the clock, and a list adds several in the same
        // millisecond; the table's key is the id.
        let bans = bans_from(
            &[
                entry(mapped([203, 0, 113, 7]), 128),
                entry(mapped([203, 0, 113, 8]), 128),
            ],
            &[],
            &BanIds::default(),
            9_000,
        )
        .expect("a valid list");
        assert_ne!(bans[0].id, bans[1].id);
    }

    #[test]
    fn duplicates_collapse_and_an_entry_naming_nobody_is_dropped() {
        let bans = bans_from(
            &[
                entry(mapped([203, 0, 113, 7]), 128),
                entry(mapped([203, 0, 113, 7]), 128),
                entry(Vec::new(), 0),
            ],
            &[],
            &BanIds::default(),
            1,
        )
        .expect("a valid list");
        assert_eq!(bans.len(), 1);
    }

    #[test]
    fn a_certificate_ban_round_trips_through_the_hex_the_wire_carries() {
        let mut by_cert = entry(Vec::new(), 0);
        by_cert.hash = Some("00ff10".to_owned());
        let bans = bans_from(&[by_cert], &[], &BanIds::default(), 1).expect("a valid list");
        assert_eq!(bans[0].cert_hash, vec![0x00, 0xff, 0x10]);
        assert_eq!(entry_of(&bans[0]).hash.as_deref(), Some("00ff10"));
        let mut odd = entry(Vec::new(), 0);
        odd.hash = Some("abc".to_owned());
        assert!(bans_from(&[odd], &[], &BanIds::default(), 1).is_err());
    }

    /// A row as `operator-api` once stored an IPv4 ban: four octets, /32.
    fn old_row() -> Ban {
        Ban {
            id: 5,
            address: vec![198, 51, 100, 1],
            prefix_len: 32,
            start_ms: 1_000,
            ..Ban::default()
        }
    }

    #[test]
    fn an_old_four_octet_row_reaches_a_client_as_one_address_not_all_of_them() {
        let read = entry_of(&old_row());
        assert_eq!(read.address, mapped([198, 51, 100, 1]));
        assert_eq!(read.mask, 128);
    }

    #[test]
    fn an_old_row_written_back_unchanged_stays_the_same_ban() {
        // The editor sends the whole list back as it read it. The row is
        // compared in the form it was shown in, so it keeps its id and start
        // and is not counted as lifted and added again.
        let held = vec![crate::covering::sixteen_bytes(&old_row())];
        let written = entry_of(&old_row());
        let bans = bans_from(&[written], &held, &BanIds::default(), 9_000).expect("valid");
        assert_eq!((bans[0].id, bans[0].start_ms), (5, 1_000));
        assert_eq!((bans[0].address.len(), bans[0].prefix_len), (16, 128));
        assert!(added(&bans, &held).is_empty());
        assert!(added(&held, &bans).is_empty());
    }

    #[test]
    fn a_ban_read_back_says_when_it_began() {
        let read = entry_of(&Ban {
            start_ms: 1_700_000_000_000,
            ..Ban::default()
        });
        assert_eq!(read.start.as_deref(), Some("2023-11-14T22:13:20Z"));
    }
}
