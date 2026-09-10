//! Which part of the store a key belongs to, and what reaching it costs.
//!
//! Every object lives under a namespace, and the namespace is the key's first
//! component. `docs/STORAGE-UNIFICATION.md` D2.
//!
//! The channel namespace has no prefix letter, because it had no prefix before
//! this existed: keys are minted `{channel}/{id}/{name}` and there are servers
//! full of them. A number is not a letter, so the old shape stays exactly
//! itself and every stored key keeps working, which is the whole reason the
//! new namespaces are lettered rather than the old one being moved.
//!
//! A namespace's key prefix always ends in the separator: without it `u/4` is
//! a prefix of `u/42`, and an authorisation for one account would reach
//! another's objects.
//!
//! ```text
//!   3/0189/sunset.png            a file shared in channel 3
//!   u/42/library.json            account 42's own
//!   srv/emotes/blobfish.png      the server's, reachable by anyone
//!   p/fancy-live-doc/notes.md    the live-doc plugin's
//! ```

/// What a key names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Namespace {
    /// A file shared in a channel. The pre-existing shape, unchanged.
    Channel(u32),
    /// One account's own objects.
    Account(u64),
    /// The server's own, under a named section (`srv/emotes/…`).
    ///
    /// `srv` and not `s`: the data plane serves public share links from
    /// `/s/{key}`, so an object key starting `s/` is routed to the share
    /// handler and never reaches the object one.
    Server(String),
    /// A plugin's own, under its registered name.
    Plugin(String),
}

/// Which namespace `key` belongs to.
///
/// A key that names nothing recognisable is `Channel(0)`, which is what an
/// unparseable key answered before namespaces existed: the asker still has to
/// hold permission on the root, so the fallback refuses rather than admits.
pub(crate) fn namespace_of(key: &str) -> Namespace {
    let mut parts = key.split('/');
    let (Some(first), Some(second)) = (parts.next(), parts.next()) else {
        return Namespace::Channel(0);
    };
    match first {
        "u" => second
            .parse()
            .map_or(Namespace::Channel(0), Namespace::Account),
        "srv" => Namespace::Server(second.to_owned()),
        "p" => Namespace::Plugin(second.to_owned()),
        _ => first
            .parse()
            .map_or(Namespace::Channel(0), Namespace::Channel),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_channel_key_keeps_the_shape_it_always_had() {
        assert_eq!(namespace_of("3/0189/sunset.png"), Namespace::Channel(3));
        assert_eq!(namespace_of("0/0189/a.png"), Namespace::Channel(0));
    }

    #[test]
    fn the_lettered_namespaces_are_read_off_the_first_component() {
        assert_eq!(namespace_of("u/42/library.json"), Namespace::Account(42));
        assert_eq!(
            namespace_of("srv/emotes/blobfish.png"),
            Namespace::Server("emotes".to_owned())
        );
        assert_eq!(
            namespace_of("p/fancy-live-doc/notes.md"),
            Namespace::Plugin("fancy-live-doc".to_owned())
        );
    }

    #[test]
    fn a_key_that_names_nothing_falls_back_to_the_root_channel() {
        // Which is a channel the asker must still hold permission on, so the
        // fallback refuses rather than admits.
        assert_eq!(namespace_of(""), Namespace::Channel(0));
        assert_eq!(namespace_of("nonsense"), Namespace::Channel(0));
        assert_eq!(namespace_of("u/notanumber/x"), Namespace::Channel(0));
    }
}
