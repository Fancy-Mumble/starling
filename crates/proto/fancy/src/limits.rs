//! How large an inter-service reply is allowed to be.
//!
//! tonic caps what a **client** will decode at 4 MiB and leaves what a server
//! sends unbounded, so the ceiling that matters is set by the reader and is
//! invisible to the writer. Worse, the refusal arrives as a status on the call
//! rather than as an error the caller went looking for: a unary reply over the
//! limit fails the request, and a stream's first message over it ends the
//! stream, which a subscriber cannot tell from a server that hung up. A
//! subscription that never once succeeded then looks exactly like one that
//! finished normally, and re-attaching produces the same oversized message
//! again, forever.
//!
//! One reply in this crate can exceed 4 MiB, and does so in the field.

/// The **default** decode limit a client reading metadata's `Tree` is given.
///
/// The value in force is `[runtime] max_tree_message`, which defaults to this
/// and is what an operator raises; readers take it from
/// `starling_runtime::channel::Resolver::max_tree_message`. The number lives
/// here rather than beside that key because it is a fact about this contract:
/// which reply can grow, and why.
///
/// `Tree` is the only reply here that is neither paged nor deduplicated by
/// hash: it carries every channel with its `description` inline, and a
/// description is operator-supplied HTML. Murmur has always allowed images in
/// one, stored base64 in the markup, and a server imported from murmur can
/// therefore arrive with several MiB of channel artwork spread over a few dozen
/// channels - 5.75 MiB across 47 channels on the deployment that found this,
/// with a single channel at 695 KB. Everything else is bounded by design:
/// accounts carry `texture_hash`/`comment_hash` and fetch the blob separately
/// (`docs/STORAGE.md` L4), and the account list is paged.
///
/// A fresh server never comes close, which is why this was shipped for as long
/// as it was. The failure is not gradual either - one channel's worth of
/// artwork past the line takes out the whole tree, and with it the channel
/// flood every client is sent at login.
///
/// 64 MiB, not "unlimited": the sender already holds the whole tree in memory
/// and every reader is a service on the same mesh, so this is not a defence
/// against a hostile peer, it is the point at which a tree has stopped being a
/// tree and something has gone wrong upstream of here. It leaves an order of
/// magnitude over the largest real server anyone has imported.
pub const MAX_TREE_MESSAGE: usize = 64 * 1024 * 1024;
