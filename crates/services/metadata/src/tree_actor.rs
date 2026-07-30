//! One tree per virtual server, and every mutation that touches it.
//!
//! Sharded by virtual server because that is the unit of a Mumble deployment;
//! within one, mutation is serialised, which is what makes the order channels
//! change in a total order rather than a race between callers.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use starling_proto_fancy::metadata::{Channel, ChannelResult, EnterResult, Membership, Tree};
use starling_runtime::ids::now_ms;
use starling_runtime::storage::Store;

/// Flags packed into `Channel::flags`, in the order `docs/STORAGE.md` lists.
pub const FLAG_HIDDEN: u32 = 1;
/// The channel disappears when its last member leaves.
pub const FLAG_TEMPORARY: u32 = 2;
/// ACL inheritance is off for this channel.
pub const FLAG_DETACHED: u32 = 4;
/// A grouping node nobody can enter.
pub const FLAG_STRUCTURAL: u32 = 8;

/// Every virtual server's tree.
#[derive(Debug, Clone, Default)]
pub struct Trees {
    inner: Arc<Mutex<HashMap<u32, TreeState>>>,
}

#[derive(Debug, Default)]
struct TreeState {
    version: u64,
    next_id: u32,
    channels: HashMap<u32, Channel>,
    members: HashMap<u32, Membership>,
    /// When a channel last saw somebody arrive or leave.
    ///
    /// Only sliding expiry (`EXPIRY_SLIDING`) reads it, and only in memory: an
    /// idle window is about *recent* use, so a deadline restored from disk
    /// after a restart would be measuring a period when nobody could have been
    /// in the channel at all. A channel with no entry here falls back to its
    /// creation time, which is what "no activity yet" means.
    last_active_ms: HashMap<u32, u64>,
}

impl Trees {
    /// One tree per virtual server, each with a root channel named `root_name`.
    #[must_use]
    pub fn new(scopes: &[u32], root_name: &str) -> Self {
        let mut inner = HashMap::new();
        for scope in scopes {
            let mut state = TreeState {
                version: 1,
                next_id: 1,
                ..TreeState::default()
            };
            let _ = state.channels.insert(
                0,
                Channel {
                    id: 0,
                    parent: None,
                    name: root_name.to_owned(),
                    created_at_ms: now_ms(),
                    ..Channel::default()
                },
            );
            let _ = inner.insert(*scope, state);
        }
        Self {
            inner: Arc::new(Mutex::new(inner)),
        }
    }

    /// Load persisted channels over the boot tree.
    ///
    /// Four queries at boot, independent of channel count, because there are no
    /// property rows to walk (`docs/STORAGE.md` D2).
    pub async fn load(&self, store: &Store) {
        use sqlx::Row as _;
        let Ok(rows) = sqlx::query(
            "SELECT server_id, id, parent_id, name, description, position, max_users, flags, \
                    expiry_mode, expiry_duration_s, created_at_ms FROM channel",
        )
        .fetch_all(store.pool())
        .await
        else {
            return;
        };
        let Ok(mut inner) = self.inner.lock() else {
            return;
        };
        for row in rows {
            let scope: i64 = row.try_get("server_id").unwrap_or(1);
            let state = inner.entry(scope as u32).or_default();
            let id: i64 = row.try_get("id").unwrap_or_default();
            let parent: Option<i64> = row.try_get("parent_id").ok().flatten();
            let channel = Channel {
                id: id as u32,
                parent: parent.map(|p| p as u32),
                name: row.try_get("name").unwrap_or_default(),
                description: row.try_get("description").unwrap_or_default(),
                position: row.try_get::<i64, _>("position").unwrap_or_default() as i32,
                max_users: row.try_get::<i64, _>("max_users").unwrap_or_default() as u32,
                flags: row.try_get::<i64, _>("flags").unwrap_or_default() as u32,
                expiry_mode: row.try_get::<i64, _>("expiry_mode").unwrap_or_default() as u32,
                expiry_duration_s: row
                    .try_get::<i64, _>("expiry_duration_s")
                    .unwrap_or_default() as u32,
                created_at_ms: row.try_get::<i64, _>("created_at_ms").unwrap_or_default() as u64,
                ..Channel::default()
            };
            state.next_id = state.next_id.max(channel.id + 1);
            let _ = state.channels.insert(channel.id, channel);
        }
    }

    /// The whole tree, plus who is in it.
    #[must_use]
    pub fn snapshot(&self, scope: u32) -> Tree {
        self.with(scope, |state| Tree {
            version: state.version,
            channels: state.channels.values().cloned().collect(),
            members: state.members.values().cloned().collect(),
        })
        .unwrap_or_default()
    }

    /// Create a channel.
    ///
    /// A name that is taken under the same parent is refused rather than
    /// silently renamed: murmur refuses too, and two channels with one name in
    /// one place is a UI nobody can use.
    pub fn create(&self, scope: u32, channel: Option<Channel>, temporary: bool) -> ChannelResult {
        let Some(mut channel) = channel else {
            return refused("no channel was described");
        };
        self.mutate(scope, |state| {
            if channel.name.trim().is_empty() {
                return refused("a channel must have a name");
            }
            let parent = channel.parent.unwrap_or(0);
            if !state.channels.contains_key(&parent) {
                return refused("no such parent channel");
            }
            let taken = state
                .channels
                .values()
                .any(|other| other.parent.unwrap_or(0) == parent && other.name == channel.name);
            if taken {
                return refused("a channel with that name already exists here");
            }

            channel.id = state.next_id;
            state.next_id += 1;
            channel.created_at_ms = now_ms();
            if temporary {
                channel.flags |= FLAG_TEMPORARY;
            }
            let _ = state.channels.insert(channel.id, channel.clone());
            state.version += 1;
            ChannelResult {
                applied: true,
                refused: String::new(),
                channel: Some(channel),
                version: state.version,
            }
        })
    }

    /// Update named fields of a channel.
    pub fn update(
        &self,
        scope: u32,
        id: u32,
        values: Option<Channel>,
        fields: &[String],
    ) -> ChannelResult {
        let Some(values) = values else {
            return refused("no values were given");
        };
        self.mutate(scope, |state| {
            let Some(channel) = state.channels.get_mut(&id) else {
                return refused("no such channel");
            };
            for field in fields {
                match field.as_str() {
                    "name" => channel.name = values.name.clone(),
                    "description" => channel.description = values.description.clone(),
                    "position" => channel.position = values.position,
                    "max_users" => channel.max_users = values.max_users,
                    "flags" => channel.flags = values.flags,
                    "parent" => channel.parent = values.parent,
                    "expiry_mode" => channel.expiry_mode = values.expiry_mode,
                    "expiry_duration_s" => channel.expiry_duration_s = values.expiry_duration_s,
                    other => tracing::warn!(field = other, "ignoring an unknown channel field"),
                }
            }
            let updated = channel.clone();
            state.version += 1;
            ChannelResult {
                applied: true,
                refused: String::new(),
                channel: Some(updated),
                version: state.version,
            }
        })
    }

    /// Remove a channel, and everything under it.
    ///
    /// The root is refused: a server with no root has nowhere to put anyone.
    pub fn remove(&self, scope: u32, id: u32) -> ChannelResult {
        self.mutate(scope, |state| {
            if id == 0 {
                return refused("the root channel cannot be removed");
            }
            if !state.channels.contains_key(&id) {
                return refused("no such channel");
            }
            let doomed = descendants(state, id);
            for victim in &doomed {
                let _ = state.channels.remove(victim);
            }
            // An iterator chain rather than a `for`: nothing here observes the
            // order, and saying so in the shape keeps `iter_over_hash_type`
            // pointed at the loops where order would leak out.
            state
                .members
                .values_mut()
                .filter(|membership| doomed.contains(&membership.channel))
                .for_each(|membership| membership.channel = 0);
            state.version += 1;
            ChannelResult {
                applied: true,
                refused: String::new(),
                channel: None,
                version: state.version,
            }
        })
    }

    /// Link and unlink channels.
    pub fn link(&self, scope: u32, id: u32, link: &[u32], unlink: &[u32]) -> ChannelResult {
        self.mutate(scope, |state| {
            let known: Vec<u32> = state.channels.keys().copied().collect();
            let Some(channel) = state.channels.get_mut(&id) else {
                return refused("no such channel");
            };
            for target in link {
                if known.contains(target) && !channel.links.contains(target) {
                    channel.links.push(*target);
                }
            }
            channel.links.retain(|target| !unlink.contains(target));
            let updated = channel.clone();
            state.version += 1;
            ChannelResult {
                applied: true,
                refused: String::new(),
                channel: Some(updated),
                version: state.version,
            }
        })
    }

    /// Move a session into a channel.
    ///
    /// A structural channel is refused, and a temporary channel emptied by the
    /// move is collected — both are reported rather than done silently, because
    /// a client that renders a channel the server has deleted is a client
    /// showing a world that does not exist.
    pub fn enter(&self, scope: u32, session: u32, channel: u32) -> EnterResult {
        self.mutate(scope, |state| {
            let Some(target) = state.channels.get(&channel) else {
                return EnterResult {
                    applied: false,
                    refused: "no such channel".to_owned(),
                    ..EnterResult::default()
                };
            };
            if target.flags & FLAG_STRUCTURAL != 0 {
                return EnterResult {
                    applied: false,
                    refused: "that channel is structural and cannot be entered".to_owned(),
                    ..EnterResult::default()
                };
            }
            let occupants = state
                .members
                .values()
                .filter(|member| member.channel == channel)
                .count();
            if target.max_users > 0 && occupants >= target.max_users as usize {
                return EnterResult {
                    applied: false,
                    refused: "that channel is full".to_owned(),
                    ..EnterResult::default()
                };
            }

            let previous = state.members.get(&session).map(|member| member.channel);
            let _ = state.members.insert(
                session,
                Membership {
                    session,
                    channel,
                    listening: Vec::new(),
                },
            );
            state.version += 1;
            // Both ends of the move count as activity: arriving keeps the
            // destination alive, and leaving is the moment a sliding window
            // starts running on the channel just vacated.
            let _ = state.last_active_ms.insert(channel, now_ms());
            if let Some(old) = previous {
                let _ = state.last_active_ms.insert(old, now_ms());
            }
            let collected = previous.and_then(|old| collect_temporary(state, old));
            EnterResult {
                applied: true,
                refused: String::new(),
                channel,
                previous,
                collected,
            }
        })
    }

    /// Drop a session's membership.
    pub fn leave(&self, scope: u32, session: u32) {
        let _ = self.mutate(scope, |state| {
            if let Some(member) = state.members.remove(&session) {
                let _ = state.last_active_ms.insert(member.channel, now_ms());
                let _ = collect_temporary(state, member.channel);
            }
            state.version += 1;
            ChannelResult::default()
        });
    }

    /// Add or remove channel listeners for a session.
    pub fn listen(&self, scope: u32, session: u32, listen: &[u32], unlisten: &[u32]) {
        let _ = self.mutate(scope, |state| {
            let known: Vec<u32> = state.channels.keys().copied().collect();
            let member = state.members.entry(session).or_insert(Membership {
                session,
                channel: 0,
                listening: Vec::new(),
            });
            for channel in listen {
                if known.contains(channel) && !member.listening.contains(channel) {
                    member.listening.push(*channel);
                }
            }
            member
                .listening
                .retain(|channel| !unlisten.contains(channel));
            state.version += 1;
            ChannelResult::default()
        });
    }

    fn with<T>(&self, scope: u32, read: impl FnOnce(&TreeState) -> T) -> Option<T> {
        self.inner
            .lock()
            .ok()
            .and_then(|inner| inner.get(&scope).map(read))
    }

    fn mutate<T: Default>(&self, scope: u32, write: impl FnOnce(&mut TreeState) -> T) -> T {
        match self.inner.lock() {
            Ok(mut inner) => write(inner.entry(scope).or_default()),
            Err(_) => T::default(),
        }
    }
}

/// A channel and everything beneath it.
fn descendants(state: &TreeState, root: u32) -> Vec<u32> {
    let mut found = vec![root];
    let mut index = 0;
    while index < found.len() {
        let parent = found[index];
        index += 1;
        let mut children: Vec<u32> = state
            .channels
            .values()
            .filter(|channel| channel.parent == Some(parent))
            .map(|channel| channel.id)
            .collect();
        // Sorted because the scan above walks a `HashMap`, whose order is
        // randomised per process. Every caller today treats the result as a set,
        // so the order is not observable — but this is the list of channels a
        // removal destroys, and the day one of them reports it to clients the
        // ordering would differ between two servers running the same code.
        children.sort_unstable();
        for id in children {
            if !found.contains(&id) {
                found.push(id);
            }
        }
    }
    found
}

/// Delete `channel` if it is temporary and now empty, returning its id.
/// `expiry_mode`: the channel lives until a fixed deadline from creation.
pub const EXPIRY_ABSOLUTE: u32 = 1;
/// `expiry_mode`: the channel lives until it has been idle for the duration.
pub const EXPIRY_SLIDING: u32 = 2;

/// One occupant of a channel that is being reaped, and where they end up.
#[derive(Debug, Clone, Copy)]
pub struct Relocated {
    /// The occupant that was moved.
    pub session: u32,
    /// The channel they were moved into — the reaped channel's parent.
    pub to: u32,
}

/// What a reap pass did, so the caller can tell clients.
#[derive(Debug, Default)]
pub struct Reaped {
    /// Channels removed by this pass.
    pub channels: Vec<u32>,
    /// Occupants relocated out of them.
    pub moved: Vec<Relocated>,
}

impl Trees {
    /// Remove channels whose expiry has come, relocating anyone inside.
    ///
    /// Two modes, both from the client's `ChannelState`:
    ///
    /// * **absolute** — a deadline measured from creation. The channel goes at
    ///   the deadline whether or not it is in use, which is what a scheduled
    ///   room is for.
    /// * **sliding** — an *idle* window. Every arrival and departure pushes the
    ///   deadline out, so a room in use survives and only a quiet one is
    ///   reaped.
    ///
    /// Occupants are **moved to the parent, not disconnected**. Removing the
    /// channel underneath a client without relocating them leaves it rendering
    /// a room the server has forgotten, and the user cannot leave a channel
    /// that no longer exists.
    ///
    /// The root is never reaped, whatever it is flagged with: it is the parent
    /// of last resort, and losing it would leave every remaining channel
    /// orphaned.
    pub fn reap_expired(&self, scope: u32, now: u64) -> Reaped {
        let mut reaped = Reaped::default();
        let _ = self.mutate(scope, |state| {
            let due: Vec<u32> = state
                .channels
                .values()
                .filter(|channel| channel.id != 0)
                .filter(|channel| {
                    let seconds = u64::from(channel.expiry_duration_s);
                    if seconds == 0 {
                        return false;
                    }
                    let window = seconds.saturating_mul(1_000);
                    match channel.expiry_mode {
                        EXPIRY_ABSOLUTE => now >= channel.created_at_ms.saturating_add(window),
                        EXPIRY_SLIDING => {
                            let since = state
                                .last_active_ms
                                .get(&channel.id)
                                .copied()
                                .unwrap_or(channel.created_at_ms);
                            now >= since.saturating_add(window)
                        }
                        _ => false,
                    }
                })
                .map(|channel| channel.id)
                .collect();

            for id in due {
                reaped.moved.extend(evict(state, id));
                reaped.channels.push(id);
            }
            if !reaped.channels.is_empty() {
                state.version += 1;
            }
            ChannelResult::default()
        });
        reaped
    }
}

/// Remove one channel, relocating whatever was hanging off it.
///
/// Occupants go to the parent rather than being disconnected, and so do child
/// channels: a child left pointing at a removed parent is orphaned, and a
/// client building a tree from parent ids never renders it again.
fn evict(state: &mut TreeState, id: u32) -> Vec<Relocated> {
    let parent = state
        .channels
        .get(&id)
        .and_then(|channel| channel.parent)
        .unwrap_or(0);

    let moved: Vec<Relocated> = state
        .members
        .values_mut()
        .filter(|member| member.channel == id)
        .map(|member| {
            member.channel = parent;
            Relocated {
                session: member.session,
                to: parent,
            }
        })
        .collect();

    state
        .channels
        .values_mut()
        .filter(|child| child.parent == Some(id))
        .for_each(|child| child.parent = Some(parent));

    let _ = state.channels.remove(&id);
    let _ = state.last_active_ms.remove(&id);
    moved
}

fn collect_temporary(state: &mut TreeState, channel: u32) -> Option<u32> {
    if channel == 0 {
        return None;
    }
    let temporary = state
        .channels
        .get(&channel)
        .is_some_and(|c| c.flags & FLAG_TEMPORARY != 0);
    if !temporary {
        return None;
    }
    let empty = !state
        .members
        .values()
        .any(|member| member.channel == channel);
    if !empty {
        return None;
    }
    let _ = state.channels.remove(&channel);
    Some(channel)
}

fn refused(reason: &str) -> ChannelResult {
    ChannelResult {
        applied: false,
        refused: reason.to_owned(),
        channel: None,
        version: 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn trees() -> Trees {
        Trees::new(&[1], "Starling")
    }

    fn named(name: &str, parent: u32) -> Option<Channel> {
        Some(Channel {
            name: name.to_owned(),
            parent: Some(parent),
            ..Channel::default()
        })
    }

    #[test]
    fn two_channels_cannot_share_a_name_under_one_parent() {
        // murmur refuses this, and a tree with two identically named siblings
        // is a UI nobody can navigate.
        let trees = trees();
        assert!(trees.create(1, named("General", 0), false).applied);
        let second = trees.create(1, named("General", 0), false);
        assert!(!second.applied);
        assert!(second.refused.contains("already exists"));
    }

    #[test]
    fn the_root_channel_cannot_be_removed() {
        assert!(!trees().remove(1, 0).applied);
    }

    #[test]
    fn removing_a_channel_takes_its_descendants_and_rehomes_their_members() {
        // Leaving a member pointing at a channel that no longer exists is the
        // silent desync this avoids.
        let trees = trees();
        let parent = trees.create(1, named("Parent", 0), false);
        let parent_id = parent.channel.map(|c| c.id).unwrap_or_default();
        let child = trees.create(1, named("Child", parent_id), false);
        let child_id = child.channel.map(|c| c.id).unwrap_or_default();
        let _ = trees.enter(1, 42, child_id);

        assert!(trees.remove(1, parent_id).applied);
        let snapshot = trees.snapshot(1);
        assert!(!snapshot.channels.iter().any(|c| c.id == child_id));
        assert_eq!(
            snapshot
                .members
                .iter()
                .find(|m| m.session == 42)
                .map(|m| m.channel),
            Some(0)
        );
    }

    #[test]
    fn a_structural_channel_cannot_be_entered() {
        let trees = trees();
        let created = trees.create(
            1,
            Some(Channel {
                name: "Category".to_owned(),
                parent: Some(0),
                flags: FLAG_STRUCTURAL,
                ..Channel::default()
            }),
            false,
        );
        let id = created.channel.map(|c| c.id).unwrap_or_default();
        let result = trees.enter(1, 1, id);
        assert!(!result.applied);
        assert!(result.refused.contains("structural"));
    }

    #[test]
    fn a_temporary_channel_is_collected_when_its_last_member_leaves() {
        let trees = trees();
        let created = trees.create(1, named("Scratch", 0), true);
        let id = created.channel.map(|c| c.id).unwrap_or_default();
        let _ = trees.enter(1, 1, id);
        let moved = trees.enter(1, 1, 0);
        assert_eq!(moved.collected, Some(id));
        assert!(!trees.snapshot(1).channels.iter().any(|c| c.id == id));
    }

    #[test]
    fn a_full_channel_refuses_rather_than_overfilling() {
        let trees = trees();
        let created = trees.create(
            1,
            Some(Channel {
                name: "Duo".to_owned(),
                parent: Some(0),
                max_users: 1,
                ..Channel::default()
            }),
            false,
        );
        let id = created.channel.map(|c| c.id).unwrap_or_default();
        assert!(trees.enter(1, 1, id).applied);
        assert!(!trees.enter(1, 2, id).applied);
    }
}
