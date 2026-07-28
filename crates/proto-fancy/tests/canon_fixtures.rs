//! The epoch-honesty check: Starling reads what an epoch-1 client writes.
//!
//! `scripts/canon-fixtures.json` holds complete frames captured from the
//! *client's* encoder, and this asserts Starling decodes them into the meaning
//! the fixture names. The client has the mirror of this test, asserting it
//! still produces the same bytes.
//!
//! # Why a checked-in fixture rather than a shared helper
//!
//! Because the thing being tested is that two independent implementations agree,
//! and a helper both sides import would agree with itself while disagreeing with
//! the wire. That is not hypothetical: it is precisely D1
//! (`docs/PROTOCOL-REDESIGN.md` §0), where both ends were confident and wrong.
//!
//! The three structural checks in `scripts/` narrow what is left for this one.
//! They prove the `.proto` files are identical, that frozen tags have not moved
//! and that the outer types agree, none of which says the *codecs* agree.
//! Bytes do.
//!
//! # When this fails
//!
//! Either the canon changed and the fixture is stale, or one end drifted. Do
//! not regenerate the fixture to make it pass without establishing which: the
//! whole value here is that a drifting codec cannot quietly re-baseline itself.

use prost::Message as _;
use starling_proto_fancy::fancy::pchat::{PchatEnvelope, pchat_envelope};
use starling_proto_fancy::fancy::social::{SocialEnvelope, social_envelope};
use starling_proto_fancy::types::ServiceKind;

/// The outer types these fixtures travel under, from the table that owns them.
///
/// Read from `ServiceKind` rather than written out again: a second copy of the
/// number is the thing `check-proto-hygiene.py`'s outer-type check exists to
/// catch, and putting one in the test that guards routing would be funny.
const SOCIAL: u16 = ServiceKind::Social.outer_type();
const PCHAT: u16 = ServiceKind::Pchat.outer_type();

// A test target inherits the crate's dependencies and `unused_crate_dependencies`
// judges it on its own imports, so the three this test does not touch have to be
// named. The workspace convention, rather than an `#[allow]` that would also hide
// a genuinely unused dependency later.
use bitflags as _;
use tonic as _;
use tonic_prost as _;

/// Frame header: `type:u16 BE ‖ len:u32 BE`.
const HEADER: usize = 6;

/// One fixture, parsed out of the JSON without pulling in a JSON dependency.
///
/// The file is ours and its shape is fixed, so a scan for the three fields is
/// enough, and a test dependency that exists only to read a test's own input
/// is a dependency the server ships nothing for.
struct Fixture {
    name: String,
    outer: u16,
    frame: Vec<u8>,
}

fn fixtures() -> Vec<Fixture> {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../scripts/canon-fixtures.json"
    );
    let Ok(text) = std::fs::read_to_string(path) else {
        panic!("the fixture file is checked in, and this test is the reason: {path}")
    };
    let mut out = Vec::new();
    let mut name = String::new();
    let mut outer = 0_u16;
    for line in text.lines() {
        let line = line.trim();
        if let Some(value) = field(line, "\"name\":") {
            name = value.trim_matches('"').to_owned();
        } else if let Some(value) = field(line, "\"outer\":") {
            outer = value.trim_end_matches(',').parse().unwrap_or(0);
        } else if let Some(value) = field(line, "\"hex\":") {
            let hex = value.trim_matches('"');
            // Over bytes rather than `&hex[i..i + 2]`: slicing a `str` by index
            // is a panic if the fixture ever picks up a multi-byte character,
            // and the panic would name a UTF-8 boundary rather than the fixture.
            let mut frame = Vec::with_capacity(hex.len() / 2);
            for pair in hex.as_bytes().chunks_exact(2) {
                let (Some(hi), Some(lo)) = (pair.first(), pair.last()) else {
                    continue;
                };
                frame.push((nibble(*hi) << 4) | nibble(*lo));
            }
            out.push(Fixture {
                name: std::mem::take(&mut name),
                outer,
                frame,
            });
        }
    }
    assert!(!out.is_empty(), "the fixture file yielded nothing");
    out
}

/// One hex digit's value.
///
/// Panics rather than returning an error: a malformed fixture is a broken test
/// input, not a condition the test could carry on from, and the message has to
/// name the offending character or the failure reads as a decode bug.
fn nibble(digit: u8) -> u8 {
    match digit {
        b'0'..=b'9' => digit - b'0',
        b'a'..=b'f' => digit - b'a' + 10,
        b'A'..=b'F' => digit - b'A' + 10,
        other => panic!("the fixture hex holds a non-hex digit: {:?}", other as char),
    }
}

/// The value after `key` on a line, with the trailing comma removed.
fn field<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    line.strip_prefix(key)
        .map(|rest| rest.trim().trim_end_matches(','))
}

#[test]
fn starling_reads_every_frame_the_client_writes() {
    for fixture in fixtures() {
        let frame = &fixture.frame;
        assert!(frame.len() > HEADER, "{}: truncated fixture", fixture.name);

        // The framing first: a frame that arrives at the wrong outer type is
        // routed to a service that will not recognise it and skip it silently,
        // which is the failure the outer-type check in `check-proto-hygiene.py`
        // exists for, asserted here too, because this is where it would bite.
        let outer = u16::from_be_bytes([frame[0], frame[1]]);
        assert_eq!(outer, fixture.outer, "{}: wrong outer type", fixture.name);
        let len = u32::from_be_bytes([frame[2], frame[3], frame[4], frame[5]]) as usize;
        assert_eq!(
            len,
            frame.len() - HEADER,
            "{}: the declared length does not match the frame",
            fixture.name
        );

        // Decoded as the service the outer type routes it to, which is the
        // whole of what the gateway knows: an envelope decoded as the wrong
        // service is the D1 shape, and it very often *succeeds*.
        let carries_a_body = match outer {
            SOCIAL => SocialEnvelope::decode(&frame[HEADER..])
                .map(|envelope| envelope.body.is_some())
                .unwrap_or_else(|e| panic!("{}: Starling cannot decode it: {e}", fixture.name)),
            PCHAT => PchatEnvelope::decode(&frame[HEADER..])
                .map(|envelope| envelope.body.is_some())
                .unwrap_or_else(|e| panic!("{}: Starling cannot decode it: {e}", fixture.name)),
            other => panic!(
                "{}: outer type {other} has no service in this test; a fixture \
                 for a service nothing decodes proves nothing",
                fixture.name
            ),
        };
        assert!(
            carries_a_body,
            "{}: decoded to an empty envelope, the shapes have diverged and \
             protobuf did not notice, which is exactly D1",
            fixture.name
        );
    }
}

#[test]
fn the_typing_indicator_means_what_the_fixture_says() {
    // Decoding without erroring is not agreement: two incompatible schemas can
    // both "succeed" and disagree about every field, which is how D1 stayed
    // invisible. So the values are asserted, not just the parse.
    let fixture = fixtures()
        .into_iter()
        .find(|f| f.name.contains("typing"))
        .expect("the typing fixture");
    let envelope = SocialEnvelope::decode(&fixture.frame[HEADER..]).expect("decodes");
    let Some(social_envelope::Body::Typing(typing)) = envelope.body else {
        panic!("expected a typing indicator, got {:?}", envelope.body);
    };
    assert_eq!(typing.channel, 4);
    assert!(typing.typing);
}

#[test]
fn the_reaction_keeps_its_emoji_and_its_target() {
    let fixture = fixtures()
        .into_iter()
        .find(|f| f.name.contains("reaction"))
        .expect("the reaction fixture");
    let envelope = SocialEnvelope::decode(&fixture.frame[HEADER..]).expect("decodes");
    let Some(social_envelope::Body::Reaction(reaction)) = envelope.body else {
        panic!("expected a reaction, got {:?}", envelope.body);
    };
    assert_eq!(reaction.channel, 4);
    assert_eq!(reaction.message_id, "m-1");
    assert!(!reaction.remove);

    // The distinction `wire.Emoji` exists for: a shortcode resolves against the
    // server's custom set and a grapheme is rendered as-is, and a bare string
    // could not say which.
    let kind = reaction
        .emoji
        .and_then(|emoji| emoji.kind)
        .expect("the emoji survived");
    assert_eq!(
        kind,
        starling_proto_fancy::fancy::wire::emoji::Kind::Unicode("\u{1f44d}".to_owned())
    );
}

#[test]
fn the_poll_keeps_its_question_and_the_order_of_its_options() {
    // Order is not decoration: a client renders option 0 first and sends back
    // the *index* it was shown, so options that arrive reordered record votes
    // for the wrong answer, and nothing anywhere reports a problem.
    let fixture = fixtures()
        .into_iter()
        .find(|f| f.name.contains("poll"))
        .expect("the poll fixture");
    let envelope = SocialEnvelope::decode(&fixture.frame[HEADER..]).expect("decodes");
    let Some(social_envelope::Body::Poll(poll)) = envelope.body else {
        panic!("expected a poll, got {:?}", envelope.body);
    };
    assert_eq!(poll.poll_id, "p-1");
    assert_eq!(poll.channel, 4);
    assert_eq!(poll.question, "lunch?");
    assert_eq!(poll.options, vec!["yes".to_owned(), "no".to_owned()]);
    assert!(!poll.multiple);
}

#[test]
fn the_pchat_message_arrives_whole_and_unattributed() {
    // Two properties in one frame. The ciphertext is opaque and must survive
    // byte for byte, since the server cannot tell a corrupted one from a valid
    // one and the recipient's decryption is what finds out.
    //
    // And `sender_cert` must be **empty**: it is stamped by the server from the
    // TLS connection, so a value arriving from the wire would be a claim about
    // identity, and pchat's whole archive is keyed on it.
    let fixture = fixtures()
        .into_iter()
        .find(|f| f.name.contains("encrypted message"))
        .expect("the pchat fixture");
    let envelope = PchatEnvelope::decode(&fixture.frame[HEADER..]).expect("decodes");
    let Some(pchat_envelope::Body::Message(message)) = envelope.body else {
        panic!("expected a message, got {:?}", envelope.body);
    };
    assert_eq!(message.message_id, "m-7");
    assert_eq!(message.channel, 4);
    assert_eq!(message.ciphertext, vec![0xde, 0xad, 0xbe, 0xef]);
    assert_eq!(message.sent_at_ms, 1_700_000_000_000);
    assert_eq!(message.epoch, 2);
    assert_eq!(message.chain_index, 9);
    assert!(
        message.sender_cert.is_empty(),
        "a client-supplied sender_cert is a claim, not an identity"
    );
}

#[test]
fn the_fetch_asks_for_the_page_size_it_meant() {
    // The bug `Cursor::page_size` exists for: an unset limit is
    // proto3-indistinguishable from 0, and every caller used to clamp 0 up to
    // 1, so a client that never set the field paged one message at a time. A
    // fixture that carries a real limit is what keeps the field on the wire.
    let fixture = fixtures()
        .into_iter()
        .find(|f| f.name.contains("fetch"))
        .expect("the fetch fixture");
    let envelope = PchatEnvelope::decode(&fixture.frame[HEADER..]).expect("decodes");
    let Some(pchat_envelope::Body::Fetch(fetch)) = envelope.body else {
        panic!("expected a fetch, got {:?}", envelope.body);
    };
    assert_eq!(fetch.channel, 4);
    assert_eq!(fetch.page.map(|page| page.limit), Some(50));
}
