//! In-memory [`UserRegistry`] implementation.

use std::collections::{HashMap, HashSet};

use crate::ids::{ChannelId, SessionId};
use crate::user::{User, UserRegistry};

/// Connected users plus a channel → members index, held in memory.
///
/// The index lives here rather than in callers because every voice packet and
/// every channel broadcast reads it. Letting handlers update it by hand is how
/// murmur ended up with occupancy bugs that only reproduce under concurrent
/// moves.
#[derive(Debug, Default)]
pub struct Users {
    by_session: HashMap<SessionId, User>,
    by_channel: HashMap<ChannelId, HashSet<SessionId>>,
}

impl Users {
    /// An empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Drop `session` from `channel`'s index, forgetting the channel if empty.
    ///
    /// Invariant 4 of [`UserRegistry`] lives here, in one place, so removal and
    /// relocation cannot disagree about it.
    fn unindex(&mut self, channel: ChannelId, session: SessionId) {
        if let Some(members) = self.by_channel.get_mut(&channel) {
            let _ = members.remove(&session);
            if members.is_empty() {
                let _ = self.by_channel.remove(&channel);
            }
        }
    }
}

impl UserRegistry for Users {
    fn insert(&mut self, user: User) {
        let _ = self
            .by_channel
            .entry(user.channel)
            .or_default()
            .insert(user.session);
        let _ = self.by_session.insert(user.session, user);
    }

    fn remove(&mut self, session: SessionId) -> Option<User> {
        let user = self.by_session.remove(&session)?;
        self.unindex(user.channel, session);
        Some(user)
    }

    fn get(&self, session: SessionId) -> Option<&User> {
        self.by_session.get(&session)
    }

    fn get_mut(&mut self, session: SessionId) -> Option<&mut User> {
        self.by_session.get_mut(&session)
    }

    fn move_to(&mut self, session: SessionId, target: ChannelId) -> Option<ChannelId> {
        let user = self.by_session.get_mut(&session)?;
        let previous = user.channel;
        if previous == target {
            return Some(previous);
        }
        user.channel = target;

        self.unindex(previous, session);
        let _ = self.by_channel.entry(target).or_default().insert(session);
        Some(previous)
    }

    fn in_channel(&self, channel: ChannelId) -> Vec<SessionId> {
        self.by_channel
            .get(&channel)
            .map(|m| m.iter().copied().collect())
            .unwrap_or_default()
    }

    fn sessions(&self) -> Vec<SessionId> {
        self.by_session.keys().copied().collect()
    }

    fn all(&self) -> Vec<&User> {
        self.by_session.values().collect()
    }

    fn len(&self) -> usize {
        self.by_session.len()
    }

    fn find_by_name(&self, name: &str) -> Option<&User> {
        self.by_session.values().find(|u| u.name == name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ids::ROOT_CHANNEL;

    fn user(session: u32, channel: ChannelId) -> User {
        User::new(SessionId(session), format!("user{session}"), channel)
    }

    /// The [`UserRegistry`] contract, asserted against any implementation.
    fn assert_registry_contract(reg: &mut dyn UserRegistry) {
        let lobby = ChannelId(1);
        assert!(reg.is_empty());

        // 1. insert indexes into the channel.
        reg.insert(user(1, ROOT_CHANNEL));
        assert_eq!(reg.in_channel(ROOT_CHANNEL), vec![SessionId(1)]);

        // 3. move_to relocates the user and the index together.
        assert_eq!(reg.move_to(SessionId(1), lobby), Some(ROOT_CHANNEL));
        assert_eq!(reg.get(SessionId(1)).expect("user").channel, lobby);
        assert_eq!(reg.in_channel(lobby), vec![SessionId(1)]);

        // 4. the emptied channel is gone from the index.
        assert!(reg.in_channel(ROOT_CHANNEL).is_empty());

        // 2. remove clears membership entirely.
        assert!(reg.remove(SessionId(1)).is_some());
        assert!(reg.in_channel(lobby).is_empty());
        assert!(reg.is_empty());
    }

    #[test]
    fn the_in_memory_registry_satisfies_the_contract() {
        assert_registry_contract(&mut Users::new());
    }

    #[test]
    fn removing_an_unknown_session_is_a_no_op() {
        let mut users = Users::new();
        assert!(users.remove(SessionId(99)).is_none());
    }

    #[test]
    fn moving_to_the_same_channel_leaves_the_index_intact() {
        let mut users = Users::new();
        users.insert(user(1, ROOT_CHANNEL));
        assert_eq!(
            users.move_to(SessionId(1), ROOT_CHANNEL),
            Some(ROOT_CHANNEL)
        );
        assert_eq!(users.in_channel(ROOT_CHANNEL), vec![SessionId(1)]);
    }

    #[test]
    fn moving_an_unknown_session_reports_it_rather_than_creating_state() {
        let mut users = Users::new();
        assert_eq!(users.move_to(SessionId(1), ChannelId(5)), None);
        assert!(users.in_channel(ChannelId(5)).is_empty());
    }

    #[test]
    fn emptied_channels_drop_out_of_the_index() {
        let lobby = ChannelId(1);
        let mut users = Users::new();
        users.insert(user(1, lobby));
        let _ = users.move_to(SessionId(1), ROOT_CHANNEL);
        assert!(
            !users.by_channel.contains_key(&lobby),
            "an empty channel must not be retained"
        );
    }

    #[test]
    fn find_by_name_is_case_sensitive() {
        let mut users = Users::new();
        users.insert(User::new(SessionId(1), "Alice", ROOT_CHANNEL));
        assert!(users.find_by_name("Alice").is_some());
        assert!(users.find_by_name("alice").is_none());
    }

    #[test]
    fn several_users_can_share_a_channel() {
        let mut users = Users::new();
        users.insert(user(1, ROOT_CHANNEL));
        users.insert(user(2, ROOT_CHANNEL));
        let mut members = users.in_channel(ROOT_CHANNEL);
        members.sort();
        assert_eq!(members, vec![SessionId(1), SessionId(2)]);
    }
}
