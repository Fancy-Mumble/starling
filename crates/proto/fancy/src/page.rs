//! Reading and writing the shared pagination primitives.
//!
//! pchat, text and audit each page a UUIDv7-ordered store, and each hand-rolled
//! the same three fields before `wire.Cursor` existed. The rules they were
//! duplicating live here instead, including the one they all got wrong.

use crate::fancy::wire::{Cursor, PageInfo};

/// How many entries to return for a requested `limit`.
///
/// **An unset limit means `default`, never one entry.** Stated once here because
/// every plane had its own copy of the mistake: the client wire, the gRPC mesh
/// and the REST admin surface each wrote `limit.clamp(1, max)`, and proto3,
/// like `serde(default)`, cannot distinguish an unset `u32` from a zero. So a
/// caller that simply never set the field asked for 0, was clamped *up* to 1,
/// and paged one entry at a time. Nothing errors; it just looks slow, and on
/// `GET /v1/log` it looked like an audit log with one row in it.
///
/// Takes a bare `u32` rather than a [`Cursor`] so the mesh contracts, which
/// carry a flat `limit`, share the rule instead of reimplementing it.
#[must_use]
pub fn page_size(limit: u32, default: u32, max: u32) -> u32 {
    if limit == 0 {
        default.min(max)
    } else {
        limit.clamp(1, max)
    }
}

impl Cursor {
    /// How many entries to return: what the client asked for, bounded by the
    /// server's cap. See [`page_size`] for the rule.
    #[must_use]
    pub fn page_size(&self, default: u32, max: u32) -> u32 {
        page_size(self.limit, default, max)
    }
}

/// Which way a caller is walking the store.
///
/// A page is a contiguous range either side of a cursor, and which side decides
/// both the SQL and which half of [`PageInfo`] the reader continues from. Kept
/// as a type rather than a `bool` because "true means forward" is exactly the
/// kind of parameter that gets passed the wrong way round once.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// Older than the cursor, newest first. What every caller did before there
    /// was a choice, and what a client too old to ask for anything else gets.
    Backward,
    /// Newer than the cursor, oldest first.
    Forward,
}

impl Cursor {
    /// Which way this cursor walks, or `None` if it names both ends.
    ///
    /// Both cursors set is refused rather than guessed at: it is a request for
    /// a bounded range, which no store here implements, and picking one end
    /// silently would serve a page the caller did not ask for.
    #[must_use]
    pub fn direction(&self) -> Option<Direction> {
        match (self.before_id.is_empty(), self.after_id.is_empty()) {
            (false, false) => None,
            (true, false) => Some(Direction::Forward),
            _ => Some(Direction::Backward),
        }
    }
}

impl PageInfo {
    /// The tail of a page with nothing behind it.
    #[must_use]
    pub fn complete() -> Self {
        Self {
            more: false,
            next_before_id: String::new(),
            next_after_id: String::new(),
        }
    }

    /// The tail of a page that has more behind it, resuming at `next_before_id`.
    ///
    /// The caller passes the id of the last entry it is returning: pages run
    /// newest-first, so "before the oldest one you just got" is where the next
    /// page starts.
    #[must_use]
    pub fn more_before(next_before_id: impl Into<String>) -> Self {
        Self {
            more: true,
            next_before_id: next_before_id.into(),
            next_after_id: String::new(),
        }
    }

    /// The tail of a forward page that has more ahead of it.
    ///
    /// The mirror of [`Self::more_before`]: a forward walk returns oldest
    /// first, so "after the newest one you just got" is the next page.
    #[must_use]
    pub fn more_after(next_after_id: impl Into<String>) -> Self {
        Self {
            more: true,
            next_before_id: String::new(),
            next_after_id: next_after_id.into(),
        }
    }

    /// The tail for a page of `entries` that was cut off at `limit`.
    ///
    /// The convention every caller shares: fetch `limit + 1` rows, and if the
    /// extra one arrived there is another page. `last_id` is read only in that
    /// case, so a caller that has nothing more to give never computes it.
    #[must_use]
    pub fn after(returned: usize, limit: u32, last_id: impl FnOnce() -> String) -> Self {
        Self::walking(Direction::Backward, returned, limit, last_id)
    }

    /// [`Self::after`], for a caller that knows which way it walked.
    ///
    /// A page that was not cut off is [`Self::complete`] in both directions,
    /// and for a forward walk that is the signal that matters: it means the
    /// reader has reached the newest entry and can follow the live tail rather
    /// than ask again.
    #[must_use]
    pub fn walking(
        direction: Direction,
        returned: usize,
        limit: u32,
        last_id: impl FnOnce() -> String,
    ) -> Self {
        if returned <= limit as usize {
            return Self::complete();
        }
        match direction {
            Direction::Backward => Self::more_before(last_id()),
            Direction::Forward => Self::more_after(last_id()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_unset_limit_is_the_default_and_not_a_single_entry() {
        // The bug this type was introduced to stop repeating: proto3 cannot
        // tell "unset" from 0, and clamping 0 up to 1 paged one at a time.
        let asked_for_nothing = Cursor::default();
        assert_eq!(asked_for_nothing.page_size(50, 200), 50);
    }

    #[test]
    fn the_rule_is_the_same_one_off_the_client_wire() {
        // The mesh and REST planes carry a flat `limit` rather than a `Cursor`,
        // and each had its own `clamp(1, max)`, which is how `GET /v1/log`
        // with no limit came back holding a single audit entry. Same function,
        // so the planes cannot drift apart again.
        assert_eq!(page_size(0, 50, 500), 50, "unset must not mean one");
        assert_eq!(Cursor::default().page_size(50, 500), page_size(0, 50, 500));

        // And an explicit 1 still means 1: the fix must not take away the
        // ability to ask for a single entry on purpose.
        assert_eq!(page_size(1, 50, 500), 1);
    }

    #[test]
    fn the_cap_is_the_servers_and_not_the_clients() {
        let greedy = Cursor {
            limit: 10_000,
            ..Cursor::default()
        };
        assert_eq!(greedy.page_size(50, 200), 200);

        // ...and it bounds the default too, so a caller cannot widen its own
        // cap by passing a default above it.
        assert_eq!(Cursor::default().page_size(500, 200), 200);
    }

    #[test]
    fn a_limit_within_the_cap_is_honoured() {
        let asked = Cursor {
            limit: 25,
            ..Cursor::default()
        };
        assert_eq!(asked.page_size(50, 200), 25);
    }

    #[test]
    fn a_cursor_naming_neither_end_walks_backward() {
        // What every caller did before there was a choice, and what a client
        // too old to set `after_id` must keep getting.
        assert_eq!(Cursor::default().direction(), Some(Direction::Backward));
    }

    #[test]
    fn each_cursor_walks_its_own_way() {
        let back = Cursor {
            before_id: "id-9".to_owned(),
            ..Cursor::default()
        };
        assert_eq!(back.direction(), Some(Direction::Backward));

        let forward = Cursor {
            after_id: "id-1".to_owned(),
            ..Cursor::default()
        };
        assert_eq!(forward.direction(), Some(Direction::Forward));
    }

    #[test]
    fn naming_both_ends_is_refused_rather_than_guessed_at() {
        // A bounded range is not something any store here implements, and
        // silently honouring one end would serve a page nobody asked for.
        let both = Cursor {
            before_id: "id-9".to_owned(),
            after_id: "id-1".to_owned(),
            ..Cursor::default()
        };
        assert_eq!(both.direction(), None);
    }

    #[test]
    fn a_forward_page_continues_from_the_other_end() {
        let cut_off = PageInfo::walking(Direction::Forward, 51, 50, || "id-50".to_owned());
        assert!(cut_off.more);
        assert_eq!(cut_off.next_after_id, "id-50");
        // Not the backward field: a reader that continued from `next_before_id`
        // here would walk away from the rows it has not seen.
        assert!(cut_off.next_before_id.is_empty());
    }

    #[test]
    fn a_forward_page_that_caught_up_says_so_by_saying_nothing() {
        // The signal that lets a reader stop asking and follow the live tail.
        let caught_up = PageInfo::walking(Direction::Forward, 12, 50, || {
            panic!("not computed when complete")
        });
        assert!(!caught_up.more);
        assert!(caught_up.next_after_id.is_empty());
    }

    #[test]
    fn the_extra_row_is_what_says_there_is_another_page() {
        // limit + 1 rows came back, so one was held over.
        let cut_off = PageInfo::after(51, 50, || "id-50".to_owned());
        assert!(cut_off.more);
        assert_eq!(cut_off.next_before_id, "id-50");

        // Exactly limit rows: the store had no more to give.
        let exact = PageInfo::after(50, 50, || panic!("not computed when complete"));
        assert!(!exact.more);
        assert!(exact.next_before_id.is_empty());
    }
}
