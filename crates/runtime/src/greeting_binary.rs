//! The greeting a Fancy client is sent, as bytes rather than as a string.
//!
//! # Why this exists
//!
//! Every other client is sent `ServerSync.welcome_text`, which is a string, and
//! a string can only carry a picture as a `data:` URI. That costs a third more
//! bytes than the picture does - base64 is four characters per three bytes -
//! and it has to fit inside [`MAX_BODY`], which is four kilobytes spent on every
//! single join. The practical effect is that a designed greeting can carry a
//! line icon and nothing else: a photograph is out of the question, and no
//! amount of interface hides that.
//!
//! A Fancy client is not held to any of it. It announced itself at the session
//! plane, so the server knows before it composes anything that this peer can
//! receive a message rather than a paragraph - and a message can carry the
//! markup and the pictures side by side, each as what it is.
//!
//! # What is *not* here
//!
//! Compression. The Fancy wire already zstd's a batch for any client that
//! announced `Hello.zstd`, so a payload compressed here would be compressed
//! twice - and the second pass on already-compressed image bytes costs CPU to
//! make them very slightly bigger. Markup compresses well and gets that for
//! free from the transport; JPEG and WebP are compressed already and are sent
//! as they are.
//!
//! # The digest
//!
//! A greeting changes when an operator edits it and not otherwise, while a peer
//! may join twenty times a day. So what identifies a payload is a hash of it,
//! exactly as [`crate::livery`] identifies a livery document, and a client that
//! recognises the hash already has the bytes.

use sha2::{Digest as _, Sha256};
use starling_proto_fancy::serverconfig::{Greeting, GreetingAsset, GreetingNode, greeting_node};

use crate::greeting::Facts;

/// Bytes of the SHA-256 that identify a payload.
///
/// The whole hash. Unlike the livery digest this never has to fit in a UDP
/// ping, and a full hash costs twenty-four bytes more on a message that may
/// carry a quarter of a megabyte.
pub const DIGEST_BYTES: usize = 32;

/// The most a Fancy greeting may weigh, markup and pictures together.
///
/// Paid on every join that misses the cache, which is what the number is about
/// rather than storage. A quarter of a megabyte is a full-width photograph and
/// a few icons with room to spare; it is also about a second on a poor
/// connection, spent while somebody is looking at a connecting dialog, and
/// there is no version of this worth making them wait longer for.
pub const MAX_PAYLOAD: usize = 262_144;

/// The most one picture may weigh.
///
/// Well under the whole, so that one photograph cannot consume the budget and
/// leave a design unable to carry the icons beside it.
pub const MAX_ASSET: usize = 196_608;

/// Pictures one design may carry.
pub const MAX_ASSETS: usize = 16;

/// The image types a client will render. Anything else is refused at save.
///
/// An allow-list rather than a sniff: the client renders by the declared type,
/// and a payload that declares one thing and carries another is a payload that
/// draws nothing on the reader's machine and gives the operator no idea why.
pub const MIMES: &[&str] = &[
    "image/webp",
    "image/jpeg",
    "image/png",
    "image/gif",
    "image/avif",
];

/// A greeting composed for one peer, as it goes on the wire.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Payload {
    /// The assembled markup, with `fm-a-<id>` markers where pictures go.
    pub markup: String,
    /// Only the pictures this peer's markup actually references.
    pub assets: Vec<GreetingAsset>,
}

impl Payload {
    /// What it weighs on the wire, which is what the cap is about.
    #[must_use]
    pub fn weight(&self) -> usize {
        self.markup.len()
            + self
                .assets
                .iter()
                .map(|asset| asset.data.len())
                .sum::<usize>()
    }

    /// What identifies this payload, so a client that has it need not be sent it.
    ///
    /// Over the markup and every asset's id and bytes, in the order they are
    /// sent. Ids are hashed as well as bytes because two payloads that differ
    /// only in which id a picture is filed under are two different documents to
    /// the markup that references them.
    #[must_use]
    pub fn digest(&self) -> [u8; DIGEST_BYTES] {
        let mut hasher = Sha256::new();
        hasher.update((self.markup.len() as u64).to_be_bytes());
        hasher.update(self.markup.as_bytes());
        for asset in &self.assets {
            hasher.update((asset.id.len() as u64).to_be_bytes());
            hasher.update(asset.id.as_bytes());
            hasher.update(asset.mime.as_bytes());
            hasher.update((asset.data.len() as u64).to_be_bytes());
            hasher.update(&asset.data);
        }
        hasher.finalize().into()
    }
}

/// The marker the markup uses where a picture goes.
///
/// A class and not an `<img src>`: the client swaps it for a real picture from
/// the payload, and the sanitiser it renders through would strip a `src` that
/// pointed at anything but a `data:` URI - which is the whole thing being
/// avoided here.
#[must_use]
pub fn asset_marker(id: &str) -> String {
    format!("fm-a-{id}")
}

/// Whether this markup references the asset filed under `id`.
#[must_use]
fn references(markup: &str, id: &str) -> bool {
    markup.contains(&asset_marker(id))
}

/// The payload `greet` composes to for a peer with these facts.
///
/// `None` where this peer gets the ordinary string instead: one that did not
/// announce a Fancy version, or a greeting with no `fancy` target compiled.
/// Falling through rather than approximating is deliberate - a design built for
/// bytes, flattened into a string, is neither of the two things it could have
/// been.
#[must_use]
pub fn compose(graph: &Greeting, greet: &GreetingNode, facts: &Facts) -> Option<Payload> {
    // Stock Mumble announces zero, which is a fact and not an absence.
    if facts.fancy_version.is_none_or(|version| version == 0) {
        return None;
    }
    let greeting_node::Body::Greet(body) = greet.body.as_ref()? else {
        return None;
    };
    let design = body.design.as_ref()?;
    // `fancy` is its own target rather than a flag on `rich`, because it is a
    // different document: the markup names pictures the string target has no
    // way to carry, so a reader of one is not reading a shorter version of the
    // other.
    let markup = crate::greeting::assemble_target(graph, greet, facts, FANCY_TARGET)?;
    let assets = design
        .assets
        .iter()
        .filter(|asset| references(&markup, &asset.id))
        .cloned()
        .collect();
    Some(Payload { markup, assets })
}

/// The target name a design compiles its Fancy document under.
pub const FANCY_TARGET: &str = "fancy";

/// Why a design's pictures were refused, in the words an operator acts on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refused {
    /// More pictures than a greeting is allowed to carry.
    TooMany(usize),
    /// One picture is over its own limit.
    Asset {
        /// Which picture.
        id: String,
        /// What it weighs.
        bytes: usize,
    },
    /// The pictures and markup together are over the payload limit.
    TooHeavy(usize),
    /// A type no client renders.
    Mime {
        /// Which picture.
        id: String,
        /// The type it declared.
        mime: String,
    },
    /// Two pictures filed under one id, so the markup cannot say which it means.
    Duplicate(String),
    /// A picture nothing draws, which is weight paid for nothing.
    Unused(String),
}

/// What is wrong with this design's pictures, if anything.
///
/// Checked when the design is *saved* rather than when somebody joins: an
/// operator can fix a refused picture, and a peer halfway through a handshake
/// cannot.
#[must_use]
pub fn refuse(assets: &[GreetingAsset], markup: &[&str]) -> Vec<Refused> {
    let mut problems = Vec::new();
    if assets.len() > MAX_ASSETS {
        problems.push(Refused::TooMany(assets.len()));
    }
    let mut seen: Vec<&str> = Vec::new();
    let mut total = 0usize;
    for asset in assets {
        if seen.contains(&asset.id.as_str()) {
            problems.push(Refused::Duplicate(asset.id.clone()));
        }
        seen.push(&asset.id);
        if !MIMES.contains(&asset.mime.as_str()) {
            problems.push(Refused::Mime {
                id: asset.id.clone(),
                mime: asset.mime.clone(),
            });
        }
        if asset.data.len() > MAX_ASSET {
            problems.push(Refused::Asset {
                id: asset.id.clone(),
                bytes: asset.data.len(),
            });
        }
        if !markup.iter().any(|body| references(body, &asset.id)) {
            problems.push(Refused::Unused(asset.id.clone()));
        }
        total += asset.data.len();
    }
    let heaviest = markup.iter().map(|body| body.len()).max().unwrap_or(0);
    if total + heaviest > MAX_PAYLOAD {
        problems.push(Refused::TooHeavy(total + heaviest));
    }
    problems
}

#[cfg(test)]
mod tests {
    use super::*;

    fn asset(id: &str, mime: &str, bytes: usize) -> GreetingAsset {
        GreetingAsset {
            id: id.to_owned(),
            mime: mime.to_owned(),
            data: vec![7u8; bytes],
        }
    }

    fn drawn(id: &str) -> String {
        format!("<span class=\"{}\"></span>", asset_marker(id))
    }

    #[test]
    fn a_payload_is_identified_by_what_is_in_it() {
        // The whole reason a digest travels: a greeting changes when an
        // operator edits it, and a peer joins twenty times a day. Two composes
        // of an unedited greeting have to agree, or the cache never hits.
        let one = Payload {
            markup: drawn("a"),
            assets: vec![asset("a", "image/webp", 32)],
        };
        let two = Payload {
            markup: drawn("a"),
            assets: vec![asset("a", "image/webp", 32)],
        };
        assert_eq!(one.digest(), two.digest());
    }

    #[test]
    fn a_different_picture_under_the_same_name_is_a_different_payload() {
        let one = Payload {
            markup: drawn("a"),
            assets: vec![asset("a", "image/webp", 32)],
        };
        let two = Payload {
            markup: drawn("a"),
            assets: vec![asset("a", "image/webp", 33)],
        };
        assert_ne!(one.digest(), two.digest());
    }

    #[test]
    fn the_same_picture_under_a_different_name_is_a_different_payload() {
        // The markup refers to pictures by id, so which id a picture is filed
        // under is part of the document and not an implementation detail.
        let one = Payload {
            markup: drawn("a"),
            assets: vec![asset("a", "image/webp", 32)],
        };
        let two = Payload {
            markup: drawn("a"),
            assets: vec![asset("b", "image/webp", 32)],
        };
        assert_ne!(one.digest(), two.digest());
    }

    #[test]
    fn markup_that_differs_only_in_length_is_a_different_payload() {
        // The length is hashed as well as the bytes, so two documents cannot
        // collide by running into each other at a field boundary.
        let one = Payload {
            markup: "ab".to_owned(),
            assets: Vec::new(),
        };
        let two = Payload {
            markup: "a".to_owned(),
            assets: vec![asset("b", "image/webp", 0)],
        };
        assert_ne!(one.digest(), two.digest());
    }

    #[test]
    fn weight_counts_the_pictures_and_not_a_base64_of_them() {
        // The entire point. The same greeting as a string would weigh a third
        // more for the pictures alone, before the 4096-character cap refused
        // it outright.
        let payload = Payload {
            markup: "x".repeat(100),
            assets: vec![asset("a", "image/webp", 50_000)],
        };
        assert_eq!(payload.weight(), 50_100);
    }

    #[test]
    fn refuses_a_picture_nothing_draws() {
        // Weight paid for on every join, for something no reader ever sees.
        let problems = refuse(
            &[asset("a", "image/webp", 10)],
            &["<p>no pictures here</p>"],
        );
        assert_eq!(problems, vec![Refused::Unused("a".to_owned())]);
    }

    #[test]
    fn refuses_a_type_no_client_renders() {
        let problems = refuse(&[asset("a", "image/tiff", 10)], &[&drawn("a")]);
        assert_eq!(
            problems,
            vec![Refused::Mime {
                id: "a".to_owned(),
                mime: "image/tiff".to_owned()
            }]
        );
    }

    #[test]
    fn refuses_two_pictures_under_one_name() {
        // The markup could not say which it meant.
        let problems = refuse(
            &[asset("a", "image/webp", 10), asset("a", "image/webp", 20)],
            &[&drawn("a")],
        );
        assert!(problems.contains(&Refused::Duplicate("a".to_owned())));
    }

    #[test]
    fn refuses_one_picture_that_would_eat_the_whole_budget() {
        let problems = refuse(&[asset("a", "image/webp", MAX_ASSET + 1)], &[&drawn("a")]);
        assert!(problems.iter().any(|p| matches!(p, Refused::Asset { .. })));
    }

    #[test]
    fn refuses_pictures_that_only_together_are_too_heavy() {
        // Each is legal and the payload is not, which is the case a per-picture
        // limit alone would let through.
        let markup = format!("{}{}", drawn("a"), drawn("b"));
        let problems = refuse(
            &[
                asset("a", "image/webp", 150_000),
                asset("b", "image/webp", 150_000),
            ],
            &[&markup],
        );
        assert!(problems.iter().any(|p| matches!(p, Refused::TooHeavy(_))));
    }

    #[test]
    fn accepts_a_design_that_fits() {
        let markup = format!("{}{}", drawn("a"), drawn("b"));
        let problems = refuse(
            &[
                asset("a", "image/webp", 20_000),
                asset("b", "image/jpeg", 8_000),
            ],
            &[&markup],
        );
        assert_eq!(problems, Vec::new());
    }

    #[test]
    fn a_stock_client_is_not_offered_bytes() {
        // Zero is stock Mumble rather than an absence, and a peer that cannot
        // receive a message gets the string every other client gets.
        let facts = Facts {
            fancy_version: Some(0),
            ..Facts::default()
        };
        assert!(compose(&Greeting::default(), &GreetingNode::default(), &facts).is_none());
    }

    #[test]
    fn a_client_that_announced_nothing_is_not_offered_bytes() {
        let facts = Facts {
            fancy_version: None,
            ..Facts::default()
        };
        assert!(compose(&Greeting::default(), &GreetingNode::default(), &facts).is_none());
    }
}
