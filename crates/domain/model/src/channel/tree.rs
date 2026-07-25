//! In-memory [`ChannelStore`] implementation.

use std::collections::{HashMap, VecDeque};

use crate::channel::{Channel, ChannelStore};
use crate::ids::{ChannelId, ROOT_CHANNEL};

/// The channel tree, held entirely in memory.
///
/// The Phase 0 implementation of [`ChannelStore`]; Phase 2 adds a SQL-backed
/// sibling. All [`ChannelStore`] invariants are enforced here rather than by
/// callers.
#[derive(Debug)]
pub struct ChannelTree {
    channels: HashMap<ChannelId, Channel>,
    next_id: u32,
}

impl ChannelTree {
    /// Create a tree containing only the root channel, named `root_name`.
    #[must_use]
    pub fn new(root_name: impl Into<String>) -> Self {
        let mut channels = HashMap::new();
        let _ = channels.insert(
            ROOT_CHANNEL,
            Channel::new(ROOT_CHANNEL, None, root_name.into()),
        );
        Self {
            channels,
            next_id: 1,
        }
    }

    /// Mutable access to a channel, for property edits that cannot re-parent it.
    ///
    /// Re-parenting must go through [`ChannelStore::insert`] /
    /// [`ChannelStore::remove`]; a `parent` changed through this borrow would
    /// desynchronise the `children` index (invariant 3).
    pub fn get_mut(&mut self, id: ChannelId) -> Option<&mut Channel> {
        self.channels.get_mut(&id)
    }
}

impl ChannelStore for ChannelTree {
    fn get(&self, id: ChannelId) -> Option<&Channel> {
        self.channels.get(&id)
    }

    fn len(&self) -> usize {
        self.channels.len()
    }

    fn breadth_first(&self) -> Vec<&Channel> {
        let mut out = Vec::with_capacity(self.channels.len());
        let mut queue = VecDeque::from([ROOT_CHANNEL]);
        while let Some(id) = queue.pop_front() {
            if let Some(channel) = self.channels.get(&id) {
                out.push(channel);
                queue.extend(channel.children.iter().copied());
            }
        }
        out
    }

    fn insert(&mut self, parent: ChannelId, name: &str) -> Option<ChannelId> {
        if !self.channels.contains_key(&parent) {
            return None;
        }
        let id = ChannelId(self.next_id);
        self.next_id += 1;

        let _ = self
            .channels
            .insert(id, Channel::new(id, Some(parent), name));
        if let Some(p) = self.channels.get_mut(&parent) {
            p.children.push(id);
        }
        Some(id)
    }

    fn remove(&mut self, id: ChannelId) -> Vec<ChannelId> {
        if id == ROOT_CHANNEL || !self.channels.contains_key(&id) {
            return Vec::new();
        }

        // Detach from the parent first so the subtree walk cannot revisit it.
        if let Some(parent) = self.channels.get(&id).and_then(|c| c.parent) {
            if let Some(p) = self.channels.get_mut(&parent) {
                p.children.retain(|&c| c != id);
            }
        }

        let mut removed = Vec::new();
        let mut stack = vec![id];
        while let Some(current) = stack.pop() {
            if let Some(channel) = self.channels.remove(&current) {
                stack.extend(channel.children.iter().copied());
                removed.push(current);
            }
        }
        removed
    }

    fn contains(&self, id: ChannelId) -> bool {
        self.channels.contains_key(&id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The [`ChannelStore`] contract, asserted against any implementation.
    ///
    /// Phase 2's SQL-backed store runs this same function.
    fn assert_store_contract(store: &mut dyn ChannelStore) {
        // 1. The root exists and cannot be removed.
        assert!(store.contains(ROOT_CHANNEL));
        assert!(store.remove(ROOT_CHANNEL).is_empty());
        assert!(store.contains(ROOT_CHANNEL));
        assert!(!store.is_empty());

        // 2 + 3. parent/children stay mutually consistent.
        let a = store.insert(ROOT_CHANNEL, "A").expect("root exists");
        let b = store.insert(a, "B").expect("a exists");
        assert_eq!(store.get(b).expect("b").parent, Some(a));
        assert!(store.get(a).expect("a").children.contains(&b));

        // 5. Parents always precede children.
        let order: Vec<_> = store.breadth_first().iter().map(|c| c.id).collect();
        for channel in store.breadth_first() {
            if let Some(parent) = channel.parent {
                assert!(
                    order.iter().position(|&id| id == parent)
                        < order.iter().position(|&id| id == channel.id),
                    "{:?} preceded its parent",
                    channel.id
                );
            }
        }

        // 4. Ids are never reused.
        let _ = store.remove(a);
        let fresh = store.insert(ROOT_CHANNEL, "C").expect("root exists");
        assert_ne!(fresh, a);
        assert_ne!(fresh, b);
    }

    #[test]
    fn the_in_memory_tree_satisfies_the_store_contract() {
        assert_store_contract(&mut ChannelTree::new("Root"));
    }

    #[test]
    fn a_new_tree_has_exactly_the_root() {
        let tree = ChannelTree::new("Root");
        assert_eq!(tree.len(), 1);
        let root = tree.get(ROOT_CHANNEL).expect("root must exist");
        assert_eq!(root.name, "Root");
        assert_eq!(root.parent, None);
    }

    #[test]
    fn insert_under_a_missing_parent_is_refused() {
        let mut tree = ChannelTree::new("Root");
        assert_eq!(tree.insert(ChannelId(999), "Orphan"), None);
        assert_eq!(tree.len(), 1, "no channel should have been created");
    }

    #[test]
    fn breadth_first_yields_parents_before_children() {
        let mut tree = ChannelTree::new("Root");
        let a = tree.insert(ROOT_CHANNEL, "A").expect("root exists");
        let b = tree.insert(a, "B").expect("a exists");
        let c = tree.insert(b, "C").expect("b exists");

        let order: Vec<_> = tree.breadth_first().iter().map(|ch| ch.id).collect();
        assert_eq!(order, vec![ROOT_CHANNEL, a, b, c]);
    }

    #[test]
    fn remove_takes_the_whole_subtree_and_nothing_else() {
        let mut tree = ChannelTree::new("Root");
        let a = tree.insert(ROOT_CHANNEL, "A").expect("root exists");
        let b = tree.insert(a, "B").expect("a exists");
        let c = tree.insert(b, "C").expect("b exists");
        let sibling = tree.insert(ROOT_CHANNEL, "Sibling").expect("root exists");

        let mut removed = tree.remove(a);
        removed.sort();
        let mut expected = vec![a, b, c];
        expected.sort();
        assert_eq!(removed, expected);

        assert!(!tree.contains(a) && !tree.contains(c));
        assert!(tree.contains(sibling), "unrelated subtree must survive");
        assert_eq!(
            tree.get(ROOT_CHANNEL).expect("root").children,
            vec![sibling],
            "removed child must be unlinked from its parent"
        );
    }

    #[test]
    fn removing_a_missing_channel_is_a_no_op() {
        let mut tree = ChannelTree::new("Root");
        assert!(tree.remove(ChannelId(42)).is_empty());
        assert_eq!(tree.len(), 1);
    }

    #[test]
    fn get_mut_allows_property_edits() {
        let mut tree = ChannelTree::new("Root");
        let lobby = tree.insert(ROOT_CHANNEL, "Lobby").expect("root exists");
        tree.get_mut(lobby).expect("lobby").max_users = 5;
        assert_eq!(tree.get(lobby).expect("lobby").max_users, 5);
    }
}
