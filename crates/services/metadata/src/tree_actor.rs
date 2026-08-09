//! One tree per server instance, and every mutation that touches it.
//!
//! Sharded by server instance because that is the unit of a Mumble deployment;
//! within one, mutation is serialised, which is what makes the order channels
//! change in a total order rather than a race between callers.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

use starling_proto_fancy::metadata::{Channel, ChannelResult, EnterResult, Membership, Tree};
use starling_proto_fancy::serverconfig::Snapshot;
use starling_runtime::ids::now_ms;
use starling_runtime::storage::Store;

use crate::channel::is_full_for;

pub use starling_proto_fancy::channel::{
    FLAG_DETACHED, FLAG_HIDDEN, FLAG_STRUCTURAL, FLAG_TEMPORARY, is_detached,
};

/// `flags` with detachment forced to what the channel already was.
///
/// [`FLAG_DETACHED`] is fixed at creation, so a `flags` write carries the old
/// value rather than the new one. Carried rather than refused: an edit that
/// sets `hidden` on a meeting room has to apply, and refusing the whole write
/// for a bit it never meant to touch would stop it.
#[must_use]
pub const fn with_detachment(flags: u32, detached: bool) -> u32 {
    if detached {
        flags | FLAG_DETACHED
    } else {
        flags & !FLAG_DETACHED
    }
}

/// The operator's ceilings on the tree.
///
/// Passed in rather than read here: the tree is a data structure with a lock
/// held across every mutation, and a gRPC round trip to `server-config` inside
/// that lock would serialise every channel edit on the network. The caller
/// holds a live snapshot ([`starling_runtime::Settings`]) and hands over the
/// four numbers.
///
/// Every one of these is **zero means unlimited**, which is murmur's
/// convention throughout and the reading that fails safe: a service that has
/// not yet heard from `server-config` refuses nothing rather than refusing
/// everything.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TreeLimits {
    /// How deep a channel may sit below the root (`channel_nesting_limit`).
    pub nesting: u32,
    /// How many channels a server instance may hold (`channel_count_limit`).
    pub count: u32,
    /// How many listeners one channel may carry (`listeners_per_channel`).
    pub listeners_per_channel: u32,
    /// How many channels one session may listen to (`listeners_per_user`).
    pub listeners_per_user: u32,
    /// How many people one channel may hold (`users_per_channel`).
    ///
    /// The fallback for a channel that states no `max_users` of its own, never a
    /// second ceiling on top of one that does. See [`is_full_for`].
    pub users_per_channel: u32,
}

/// What a creation asks for beyond the channel record itself.
///
/// A struct rather than three more positional arguments, because two of them
/// are booleans: a call reading `create(scope, channel, true, false, limits)`
/// is one nobody can check and eventually one somebody writes the wrong way
/// round.
///
/// [`Default`] is the ordinary client creation: permanent, refuse a name that
/// is taken, and no ceilings ([`TreeLimits`] is zero-means-unlimited).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Creation {
    /// The channel vanishes when its last member leaves.
    pub temporary: bool,
    /// Return the channel that already holds this name instead of refusing it.
    ///
    /// What makes provisioning a room idempotent: a meeting room is created by
    /// whichever of "the start time arrived" and "somebody asked to join"
    /// happens first, and both may run twice.
    pub reuse_existing: bool,
    /// The ceilings in force for the caller.
    pub limits: TreeLimits,
}

impl TreeLimits {
    /// No limit at all, for the paths that are the operator's own.
    ///
    /// gRPC and `operator-api` are administrative surfaces: an operator
    /// building a tree through them is the person who set the limits, and
    /// refusing them their own ceiling turns a deliberate action into a
    /// mystery. murmur draws the line in the same place, `canNest` and the
    /// count check live in `msgChannelState`, which is the *client* path.
    pub const UNLIMITED: Self = Self {
        nesting: 0,
        count: 0,
        listeners_per_channel: 0,
        listeners_per_user: 0,
        users_per_channel: 0,
    };
}

impl From<&Snapshot> for TreeLimits {
    fn from(snapshot: &Snapshot) -> Self {
        Self {
            nesting: snapshot.channel_nesting_limit,
            count: snapshot.channel_count_limit,
            listeners_per_channel: snapshot.listeners_per_channel,
            listeners_per_user: snapshot.listeners_per_user,
            users_per_channel: snapshot.users_per_channel,
        }
    }
}

/// Why a listener was not registered, so the client can be told which limit it
/// met rather than watching the request do nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListenRefusal {
    /// `listeners_per_channel` is reached for that channel.
    ChannelFull,
    /// `listeners_per_user` is reached for that session.
    UserFull,
}

/// Listeners a channel removal cancelled, for one session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unlistened {
    /// Whose listeners were cancelled.
    pub session: u32,
    /// The channels they are no longer listening to, because there is no longer
    /// anything to listen to.
    pub channels: Vec<u32>,
}

/// What [`Trees::remove`] did.
///
/// Carries the cancelled listeners alongside the result because they are found
/// under the same lock: asking a second time would race with the next removal,
/// and the channels to ask about have by then stopped existing.
#[derive(Debug, Clone, Default)]
pub struct Removal {
    /// The outcome, as every other tree mutation reports it.
    pub result: ChannelResult,
    /// Listeners cancelled by the removal, one entry per affected session.
    pub unlistened: Vec<Unlistened>,
    /// Occupants the removal displaced, and where they landed.
    ///
    /// Carried for the same reason `unlistened` is, and it was the half that
    /// was missing: the tree moved them to the root and nothing told them, so a
    /// client whose channel was deleted under it went on rendering itself
    /// inside a room the server had forgotten, with no way to leave a channel
    /// that no longer exists. murmur sends a `UserState` per displaced user
    /// (`vendor/server/src/murmur/Server.cpp:2180`).
    pub moved: Vec<Relocated>,
}

impl Removal {
    fn refused(why: &str) -> Self {
        Self {
            result: refused(why),
            unlistened: Vec::new(),
            moved: Vec::new(),
        }
    }
}

/// What [`Trees::listen`] did.
#[derive(Debug, Default, Clone)]
pub struct Listened {
    /// Channels this session now listens to that it did not before.
    pub added: Vec<u32>,
    /// Channels it stopped listening to.
    pub removed: Vec<u32>,
    /// Requests refused, and by which limit.
    pub refused: Vec<(u32, ListenRefusal)>,
    /// Gains that changed, keyed by channel.
    pub volume: HashMap<u32, f32>,
}

impl Listened {
    /// Whether anything about this session's listeners actually changed.
    ///
    /// A `UserState` that asks to listen to a channel already listened to is a
    /// no-op, and broadcasting it would tell every client in the server that
    /// something happened when nothing did.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.added.is_empty() && self.removed.is_empty() && self.volume.is_empty()
    }
}

/// Every server instance's tree.
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
    /// One tree per server instance, each with a root channel named `root_name`.
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

    /// Which of `channels` are temporary, and so must not be written to disk.
    ///
    /// A temporary channel is gone when its last member leaves, so a listener
    /// row pointing at one would outlive the thing it names and be restored
    /// against an id that has since been handed to a different room. murmur
    /// applies the same guard at every write (`Server.cpp:3224`).
    ///
    /// Unknown ids count as temporary: refusing to persist something the tree
    /// cannot vouch for is the direction that fails safe.
    #[must_use]
    pub fn transient(&self, scope: u32, channels: &[u32]) -> HashSet<u32> {
        self.with(scope, |state| {
            channels
                .iter()
                .filter(|channel| {
                    state
                        .channels
                        .get(channel)
                        .is_none_or(|c| c.flags & FLAG_TEMPORARY != 0)
                })
                .copied()
                .collect()
        })
        .unwrap_or_default()
    }

    /// Whether `channel` is a channel this server instance still has.
    ///
    /// For the callers holding an id that came from storage rather than from
    /// the tree: a remembered channel may have been deleted while its owner was
    /// away, and an id that names nothing is worse than no id at all.
    #[must_use]
    pub fn exists(&self, scope: u32, channel: u32) -> bool {
        self.with(scope, |state| state.channels.contains_key(&channel))
            .unwrap_or(false)
    }

    /// Put a returning user's stored listeners back on `session`.
    ///
    /// Applied without the ceilings: they bound what a user may *ask for*, and
    /// a set that was already granted must not become un-restorable because an
    /// operator has since lowered a limit. murmur restores unconditionally too
    /// (`DBWrapper.cpp:1151`).
    pub fn restore(&self, scope: u32, session: u32, stored: &[(u32, f32)]) -> Listened {
        self.mutate(scope, |state| {
            let mut outcome = Listened::default();
            let known: Vec<u32> = state.channels.keys().copied().collect();
            let member = state.members.entry(session).or_insert(Membership {
                session,
                channel: 0,
                listening: Vec::new(),
                listening_volume: HashMap::new(),
            });
            for (channel, gain) in stored {
                // Dropping a stale row here is cheaper than a sweep nobody
                // would remember to run.
                let channel_is_gone = !known.contains(channel);
                let already_listening = member.listening.contains(channel);
                if channel_is_gone || already_listening {
                    continue;
                }
                member.listening.push(*channel);
                outcome.added.push(*channel);
                if !is_unity(*gain) {
                    let _ = member.listening_volume.insert(*channel, *gain);
                    let _ = outcome.volume.insert(*channel, *gain);
                }
            }
            state.version += 1;
            outcome
        })
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

    /// Create a channel, as `how` asks for it.
    ///
    /// A name that is taken in the same place is refused rather than silently
    /// renamed: murmur refuses too, and two channels with one name in one place
    /// is a UI nobody can use. `Creation::reuse_existing` turns that refusal
    /// into the existing channel, which is what makes provisioning idempotent.
    ///
    /// The two ceilings are murmur's, in murmur's order, nesting is checked
    /// against the parent before the count, so a client that is both too deep
    /// and on a full server is told the more specific of the two.
    ///
    /// A **detached** channel ([`FLAG_DETACHED`]) is created parentless, as
    /// `createChannelForPlugin` does (`vendor/server/src/murmur/Server.cpp:3544`,
    /// which severs it from the root again straight after creating it there).
    /// Whatever the caller put in `parent` is dropped rather than honoured: a
    /// detached channel that kept one would be an ordinary channel wearing the
    /// flag, and every rule below that reads the tree would then disagree with
    /// every rule that reads the flag. It has no siblings to be unique among,
    /// so its name is checked against the other detached channels, and no depth
    /// to measure, so the nesting limit does not apply to it.
    pub fn create(&self, scope: u32, channel: Option<Channel>, how: Creation) -> ChannelResult {
        let Some(mut channel) = channel else {
            return refused("no channel was described");
        };
        self.mutate(scope, |state| {
            if channel.name.trim().is_empty() {
                return refused("a channel must have a name");
            }
            let detached = is_detached(&channel);
            let parent = channel.parent.unwrap_or(0);
            if !detached && !state.channels.contains_key(&parent) {
                return refused("no such parent channel");
            }
            // Detached channels are matched against each other and tree
            // channels against their siblings, and neither set sees the other:
            // a parentless channel reads as `parent == 0` here, so without the
            // split a meeting room would collide with a room at the root.
            let existing = state
                .channels
                .values()
                .find(|other| {
                    other.name == channel.name
                        && if detached {
                            is_detached(other)
                        } else {
                            !is_detached(other) && other.parent.unwrap_or(0) == parent
                        }
                })
                .cloned();
            if let Some(existing) = existing {
                if !how.reuse_existing {
                    return refused("a channel with that name already exists here");
                }
                // Applied, but not `created`: the caller must be able to tell
                // that it found somebody else's room rather than minting one,
                // because the invitee ACL is written only on a real creation.
                return ChannelResult {
                    applied: true,
                    refused: String::new(),
                    channel: Some(existing),
                    version: state.version,
                    created: false,
                };
            }
            // murmur's `canNest` (`Server.cpp:2801`), with a subtree depth of
            // zero because a channel being created has nothing under it yet.
            if !detached && !can_nest(state, parent, 0, how.limits.nesting) {
                return refused(NESTING_REFUSED);
            }
            if how.limits.count != 0 && state.channels.len() >= how.limits.count as usize {
                return refused(COUNT_REFUSED);
            }

            channel.id = state.next_id;
            state.next_id += 1;
            channel.created_at_ms = now_ms();
            if detached {
                channel.parent = None;
            }
            if how.temporary {
                channel.flags |= FLAG_TEMPORARY;
            }
            let _ = state.channels.insert(channel.id, channel.clone());
            state.version += 1;
            ChannelResult {
                applied: true,
                refused: String::new(),
                channel: Some(channel),
                version: state.version,
                created: true,
            }
        })
    }

    /// Update named fields of a channel, within `limits`.
    pub fn update(
        &self,
        scope: u32,
        id: u32,
        values: Option<Channel>,
        fields: &[String],
        limits: TreeLimits,
    ) -> ChannelResult {
        let Some(values) = values else {
            return refused("no values were given");
        };
        self.mutate(scope, |state| {
            let Some(before) = state.channels.get(&id) else {
                return refused("no such channel");
            };
            // A detached channel has no place in the tree to be moved to or
            // from, so a `parent` write on one is refused outright rather than
            // measured against the nesting limit below. Accepting it would give
            // a parentless channel a parent while it kept the flag saying it
            // has none, which is the state every walk here reads two ways.
            let was_detached = is_detached(before);
            if was_detached && fields.iter().any(|field| field == "parent") {
                return refused("a detached channel cannot be moved into the tree");
            }
            // Re-parenting is the other way a tree gets too deep, and the one
            // that moves a whole subtree at once: murmur measures the new
            // parent's level plus the *height* of what is being moved
            // (`Server.cpp:2801`), so dragging a three-deep branch under a
            // channel that is already eight down is refused as a unit rather
            // than one channel at a time.
            if fields.iter().any(|field| field == "parent")
                && let Some(new_parent) = values.parent
            {
                if new_parent == id || descendants(state, id).contains(&new_parent) {
                    // Not a limit but the same shape of mistake: a channel
                    // parented into its own subtree is unreachable from the
                    // root, so every client stops rendering it and the walk
                    // that would delete it never finds it either.
                    return refused("a channel cannot be moved inside itself");
                }
                if !state.channels.contains_key(&new_parent) {
                    return refused("no such parent channel");
                }
                if !can_nest(state, new_parent, height_of(state, id), limits.nesting) {
                    return refused(NESTING_REFUSED);
                }
            }
            let Some(channel) = state.channels.get_mut(&id) else {
                return refused("no such channel");
            };
            for field in fields {
                match field.as_str() {
                    "name" => channel.name = values.name.clone(),
                    "description" => channel.description = values.description.clone(),
                    "position" => channel.position = values.position,
                    "max_users" => channel.max_users = values.max_users,
                    // Detachment is carried over rather than taken from the
                    // write: it is fixed at creation (see [`FLAG_DETACHED`]),
                    // and preserving it here means an edit that sets `hidden`
                    // on a meeting room still applies instead of being refused
                    // for touching a bit it never meant to change.
                    "flags" => channel.flags = with_detachment(values.flags, was_detached),
                    "parent" => channel.parent = values.parent,
                    "expiry_mode" => channel.expiry_mode = values.expiry_mode,
                    "expiry_duration_s" => channel.expiry_duration_s = values.expiry_duration_s,
                    "pchat_protocol" => channel.pchat_protocol = values.pchat_protocol,
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
                created: false,
            }
        })
    }

    /// Remove a channel, and everything under it.
    ///
    /// The root is refused: a server with no root has nowhere to put anyone.
    ///
    /// A **detached** channel is removable like any other, and its occupants go
    /// to the root. That is the one case worth naming, because it is where the
    /// C++ server crashed: `Server::removeChannel` took the parent as the
    /// destination for displaced users and then dereferenced it, so deleting a
    /// meeting room or a friend DM - the two parentless kinds - took the server
    /// down (`vendor/server/src/murmur/Server.cpp:2161`). Here the destination
    /// is the root by construction rather than by fallback, so there is no
    /// parent to be missing.
    pub fn remove(&self, scope: u32, id: u32) -> Removal {
        self.mutate(scope, |state| {
            if id == 0 {
                return Removal::refused("the root channel cannot be removed");
            }
            if !state.channels.contains_key(&id) {
                return Removal::refused("no such channel");
            }
            let doomed = descendants(state, id);
            for victim in &doomed {
                let _ = state.channels.remove(victim);
            }
            forget_links_to(state, &doomed);

            let mut unlistened = Vec::new();
            let mut moved = Vec::new();
            // An iterator chain rather than a `for`: the sessions are walked in
            // whatever order the map holds them, and the result is sorted below
            // so the shape says the order is not observed.
            state.members.values_mut().for_each(|membership| {
                if doomed.contains(&membership.channel) {
                    // The root, not the removed channel's parent: the parent is
                    // being removed too when the whole subtree goes, and a
                    // detached channel has none at all.
                    membership.channel = 0;
                    moved.push(Relocated {
                        session: membership.session,
                        to: 0,
                    });
                }
                // A listener on a channel that no longer exists would be a
                // subscription to nothing that the owning client still shows in
                // its tree, with no way to cancel it, murmur deletes them and
                // tells the client (`Server.cpp:2194`). The gains are kept: they
                // are keyed by channel id, and the ids are gone with it.
                let dropped: Vec<u32> = membership
                    .listening
                    .iter()
                    .filter(|channel| doomed.contains(channel))
                    .copied()
                    .collect();
                if dropped.is_empty() {
                    return;
                }
                membership.listening.retain(|c| !doomed.contains(c));
                for channel in &dropped {
                    let _ = membership.listening_volume.remove(channel);
                }
                unlistened.push(Unlistened {
                    session: membership.session,
                    channels: dropped,
                });
            });
            // Sorted so the broadcast order does not depend on a hash seed: the
            // messages are independent, but a test that reads them is not.
            unlistened.sort_by_key(|entry| entry.session);
            moved.sort_by_key(|entry: &Relocated| entry.session);

            state.version += 1;
            Removal {
                result: ChannelResult {
                    applied: true,
                    refused: String::new(),
                    channel: None,
                    version: state.version,
                    created: false,
                },
                unlistened,
                moved,
            }
        })
    }

    /// Link and unlink channels.
    ///
    /// **Symmetric**, as murmur's `Channel::link` is (`Channel.cpp:189`): it
    /// writes the edge into both channels. Audio crossing a link is a property
    /// of the pair, not of whichever channel the operator happened to edit, and
    /// a one-sided edge is a link that works in one direction, which is not a
    /// thing Mumble has.
    ///
    /// A channel cannot be linked to itself: it would be an edge that says
    /// "also send this audio here", where here is already here.
    pub fn link(&self, scope: u32, id: u32, link: &[u32], unlink: &[u32]) -> ChannelResult {
        self.mutate(scope, |state| {
            if !state.channels.contains_key(&id) {
                return refused("no such channel");
            }
            // Every named channel is resolved before anything is written.
            // murmur returns without applying any of them if one is unknown
            // (`Messages.cpp:2061`), so a request naming a channel that has
            // been removed does not half-apply.
            for target in link.iter().chain(unlink.iter()) {
                if !state.channels.contains_key(target) {
                    return refused("no such channel to link");
                }
            }
            if link.contains(&id) {
                return refused("a channel cannot be linked to itself");
            }

            for target in link {
                add_link(state, id, *target);
                add_link(state, *target, id);
            }
            for target in unlink {
                remove_link(state, id, *target);
                remove_link(state, *target, id);
            }

            let updated = state.channels.get(&id).cloned();
            state.version += 1;
            ChannelResult {
                applied: true,
                refused: String::new(),
                channel: updated,
                version: state.version,
                created: false,
            }
        })
    }

    /// Move a session into a channel.
    ///
    /// A structural channel is refused, and a temporary channel emptied by the
    /// move is collected, both are reported rather than done silently, because
    /// a client that renders a channel the server has deleted is a client
    /// showing a world that does not exist.
    ///
    /// `bypass_full` is the caller's `Write` answer, and only fullness listens
    /// to it: a structural channel holds nobody at all, so no permission makes
    /// one enterable.
    pub fn enter(
        &self,
        scope: u32,
        session: u32,
        channel: u32,
        limits: TreeLimits,
        bypass_full: bool,
    ) -> EnterResult {
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
            // The rule the entity models, called rather than re-stated: see
            // `channel::is_full_for`, and `GAP-ANALYSIS.md` C4 for what having
            // two copies of it cost.
            if is_full_for(
                target.max_users,
                limits.users_per_channel,
                occupants,
                bypass_full,
            ) {
                return EnterResult {
                    applied: false,
                    refused: FULL_REFUSED.to_owned(),
                    ..EnterResult::default()
                };
            }

            let previous = state.members.get(&session).map(|member| member.channel);
            // Entered in place rather than replaced, so that a move keeps the
            // listeners and gains the session already had. Overwriting the
            // membership wholesale would make walking into another room silently
            // cancel every channel that user was listening to, murmur touches
            // only the channel (`Server.cpp:1291`), and the two are unrelated
            // facts about a session.
            let member = state.members.entry(session).or_insert(Membership {
                session,
                channel,
                listening: Vec::new(),
                listening_volume: HashMap::new(),
            });
            member.channel = channel;
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

    /// Add or remove channel listeners for a session, within `limits`.
    ///
    /// Both ceilings are murmur's (`Messages.cpp:1179`), and both are checked
    /// **per channel in the request** rather than for the request as a whole:
    /// a client asking to listen to five channels with room for three gets
    /// three, and is told about the two that were refused. Refusing the whole
    /// request would make a client that asks for everything it can see get
    /// nothing at all.
    ///
    /// Un-listening is never refused. A limit exists to stop listeners
    /// accumulating, and a limit that could trap somebody in a subscription
    /// they are trying to leave would be the wrong shape of rule.
    ///
    /// `volume` is applied last and is not subject to either ceiling. murmur
    /// stores an adjustment for a listener that does not exist
    /// (`Server.cpp:3238` consults the database when the manager has never
    /// heard of it), so a client may set a gain before it starts listening and
    /// keeps it after it stops.
    pub fn listen(
        &self,
        scope: u32,
        session: u32,
        listen: &[u32],
        unlisten: &[u32],
        volume: &HashMap<u32, f32>,
        limits: TreeLimits,
    ) -> Listened {
        self.mutate(scope, |state| {
            let mut outcome = Listened::default();
            let known: Vec<u32> = state.channels.keys().copied().collect();
            // Counted before the borrow below, because both are reads of the
            // same map the membership is inserted into.
            let mut per_channel = listener_counts(state);

            let member = state.members.entry(session).or_insert(Membership {
                session,
                channel: 0,
                listening: Vec::new(),
                listening_volume: HashMap::new(),
            });

            // Removals first, as murmur has them: a client that swaps one
            // listener for another in a single message would otherwise be
            // refused on a ceiling it is in the act of making room under.
            for channel in unlisten {
                if !member.listening.contains(channel) {
                    continue;
                }
                member.listening.retain(|held| held != channel);
                outcome.removed.push(*channel);
                let count = per_channel.entry(*channel).or_default();
                *count = count.saturating_sub(1);
            }

            for channel in listen {
                if !known.contains(channel) || member.listening.contains(channel) {
                    continue;
                }
                let in_channel = per_channel.get(channel).copied().unwrap_or_default();
                if limits.listeners_per_channel != 0
                    && in_channel >= limits.listeners_per_channel as usize
                {
                    outcome.refused.push((*channel, ListenRefusal::ChannelFull));
                    continue;
                }
                if limits.listeners_per_user != 0
                    && member.listening.len() >= limits.listeners_per_user as usize
                {
                    outcome.refused.push((*channel, ListenRefusal::UserFull));
                    continue;
                }
                member.listening.push(*channel);
                *per_channel.entry(*channel).or_default() += 1;
                outcome.added.push(*channel);
            }

            // An iterator chain rather than a `for`: the map is unordered and
            // each entry is independent, so nothing here can observe a sequence.
            volume.iter().for_each(|(channel, gain)| {
                if !known.contains(channel) {
                    return;
                }
                // Unity is the absence of an adjustment, not an adjustment of
                // one: storing it would keep a row alive for every channel a
                // user ever nudged back to normal, and hand the routing snapshot
                // an entry that changes nothing.
                let changed = if is_unity(*gain) {
                    member.listening_volume.remove(channel).is_some()
                } else {
                    member.listening_volume.insert(*channel, *gain) != Some(*gain)
                };
                if changed {
                    let _ = outcome.volume.insert(*channel, *gain);
                }
            });

            state.version += 1;
            outcome
        })
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

/// What a client is told when the tree may not get deeper.
pub(crate) const NESTING_REFUSED: &str = "the channel nesting limit has been reached";
/// What a client is told when the server holds as many channels as it may.
pub(crate) const COUNT_REFUSED: &str = "the channel count limit has been reached";
/// What a client is told when a channel is at its own occupant limit.
pub(crate) const FULL_REFUSED: &str = "that channel is full";

/// Whether a gain is "no adjustment at all".
///
/// Compared with a tolerance rather than `== 1.0` because the number arrives as
/// a float from a client that computed it from a decibel slider, and a value
/// that lands a millionth away from unity is a user who dragged the slider back
/// to the middle, not a request for an imperceptible attenuation worth storing
/// a row for.
fn is_unity(gain: f32) -> bool {
    (gain - 1.0).abs() < f32::EPSILON
}

/// How many listeners each channel currently carries.
///
/// Built in one pass rather than counted per candidate: a request naming five
/// channels would otherwise walk every membership five times, and the count has
/// to be taken before the caller's own membership is borrowed mutably anyway.
fn listener_counts(state: &TreeState) -> HashMap<u32, usize> {
    let mut counts: HashMap<u32, usize> = HashMap::new();
    // The order is not observable (this is a tally) which is what makes
    // walking a `HashMap` acceptable here.
    for channel in state.members.values().flat_map(|member| &member.listening) {
        *counts.entry(*channel).or_default() += 1;
    }
    counts
}

/// How far below the root `channel` sits. The root is zero.
fn level_of(state: &TreeState, channel: u32) -> u32 {
    let mut level = 0;
    let mut current = channel;
    // Bounded by the number of channels, so a parent cycle written by a buggy
    // caller costs one wasted walk rather than hanging the actor with the tree
    // lock held.
    while level as usize <= state.channels.len() {
        match state.channels.get(&current).and_then(|c| c.parent) {
            Some(parent) => {
                level += 1;
                current = parent;
            }
            None => break,
        }
    }
    level
}

/// How tall the subtree rooted at `channel` is. A leaf is zero.
fn height_of(state: &TreeState, channel: u32) -> u32 {
    let deepest = descendants(state, channel)
        .into_iter()
        .map(|id| level_of(state, id))
        .max()
        .unwrap_or_default();
    deepest.saturating_sub(level_of(state, channel))
}

/// murmur's `canNest` (`Server.cpp:2801`): whether a subtree `height` tall may
/// be hung under `parent` without passing `limit`.
///
/// Zero is unlimited, so a server whose settings have not arrived yet nests
/// freely rather than refusing every channel.
fn can_nest(state: &TreeState, parent: u32, height: u32, limit: u32) -> bool {
    limit == 0 || level_of(state, parent).saturating_add(height) < limit
}

/// Record that `from` is linked to `to`, if it is not already.
fn add_link(state: &mut TreeState, from: u32, to: u32) {
    if let Some(channel) = state.channels.get_mut(&from)
        && !channel.links.contains(&to)
    {
        channel.links.push(to);
    }
}

/// Drop the edge from `from` to `to`.
fn remove_link(state: &mut TreeState, from: u32, to: u32) {
    if let Some(channel) = state.channels.get_mut(&from) {
        channel.links.retain(|linked| *linked != to);
    }
}

/// Drop every edge pointing at a channel that has gone.
///
/// Called wherever a channel is destroyed. A link is a pair, so removing one
/// end without the other leaves the survivor advertising an edge to a channel
/// no client can render, and `ChannelState.links` is a *complete* statement of
/// the set, so the stale id would be re-sent on every announcement.
fn forget_links_to(state: &mut TreeState, gone: &[u32]) {
    // An iterator chain rather than a `for`, as `remove` uses above: nothing
    // here observes the order, and saying so in the shape keeps
    // `iter_over_hash_type` pointed at the loops where order would leak out.
    state
        .channels
        .values_mut()
        .for_each(|channel| channel.links.retain(|linked| !gone.contains(linked)));
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
        // so the order is not observable, but this is the list of channels a
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
    /// The channel they were moved into, the reaped channel's parent.
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
    /// * **absolute**, a deadline measured from creation. The channel goes at
    ///   the deadline whether or not it is in use, which is what a scheduled
    ///   room is for.
    /// * **sliding**, an *idle* window. Every arrival and departure pushes the
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
///
/// A parentless channel - the root, or a detached room whose expiry has come -
/// sends them to the root instead. The C++ server had no such fallback and
/// dereferenced the null parent (`Server.cpp:2161`).
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
    forget_links_to(state, &[id]);
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
    forget_links_to(state, &[channel]);
    Some(channel)
}

fn refused(reason: &str) -> ChannelResult {
    ChannelResult {
        applied: false,
        refused: reason.to_owned(),
        channel: None,
        version: 0,
        created: false,
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

    /// Create under `parent` with no ceilings, returning the new id.
    fn create(trees: &Trees, name: &str, parent: u32) -> u32 {
        trees
            .create(1, named(name, parent), Creation::default())
            .channel
            .map(|channel| channel.id)
            .unwrap_or_default()
    }

    /// The link set of one channel, sorted, for comparing both ends of a pair.
    fn links_of(trees: &Trees, id: u32) -> Vec<u32> {
        let mut links = trees
            .snapshot(1)
            .channels
            .into_iter()
            .find(|channel| channel.id == id)
            .map(|channel| channel.links)
            .unwrap_or_default();
        links.sort_unstable();
        links
    }

    #[test]
    fn two_channels_cannot_share_a_name_under_one_parent() {
        // murmur refuses this, and a tree with two identically named siblings
        // is a UI nobody can navigate.
        let trees = trees();
        assert!(
            trees
                .create(1, named("General", 0), Creation::default())
                .applied
        );
        let second = trees.create(1, named("General", 0), Creation::default());
        assert!(!second.applied);
        assert!(second.refused.contains("already exists"));
    }

    #[test]
    fn the_root_channel_cannot_be_removed() {
        assert!(!trees().remove(1, 0).result.applied);
    }

    #[test]
    fn removing_a_channel_takes_its_descendants_and_rehomes_their_members() {
        // Leaving a member pointing at a channel that no longer exists is the
        // silent desync this avoids.
        let trees = trees();
        let parent_id = create(&trees, "Parent", 0);
        let child_id = create(&trees, "Child", parent_id);
        let _ = trees.enter(1, 42, child_id, TreeLimits::UNLIMITED, false);

        assert!(trees.remove(1, parent_id).result.applied);
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
            Creation::default(),
        );
        let id = created.channel.map(|c| c.id).unwrap_or_default();
        let result = trees.enter(1, 1, id, TreeLimits::UNLIMITED, false);
        assert!(!result.applied);
        assert!(result.refused.contains("structural"));
    }

    #[test]
    fn a_temporary_channel_is_collected_when_its_last_member_leaves() {
        let trees = trees();
        let created = trees.create(
            1,
            named("Scratch", 0),
            Creation {
                temporary: true,
                ..Creation::default()
            },
        );
        let id = created.channel.map(|c| c.id).unwrap_or_default();
        let _ = trees.enter(1, 1, id, TreeLimits::UNLIMITED, false);
        let moved = trees.enter(1, 1, 0, TreeLimits::UNLIMITED, false);
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
            Creation::default(),
        );
        let id = created.channel.map(|c| c.id).unwrap_or_default();
        assert!(trees.enter(1, 1, id, TreeLimits::UNLIMITED, false).applied);
        assert!(!trees.enter(1, 2, id, TreeLimits::UNLIMITED, false).applied);
    }

    /// The ceilings, with nesting and count set and the listener caps off.
    fn depth_limit(nesting: u32, count: u32) -> TreeLimits {
        TreeLimits {
            nesting,
            count,
            ..TreeLimits::UNLIMITED
        }
    }

    /// An ordinary creation under `limits`.
    fn within(limits: TreeLimits) -> Creation {
        Creation {
            limits,
            ..Creation::default()
        }
    }

    /// A meeting room as the calendar provisions one: out of the tree, hidden,
    /// end-to-end encrypted and on an absolute deadline.
    fn room(name: &str) -> Option<Channel> {
        Some(Channel {
            name: name.to_owned(),
            // Deliberately set, and deliberately ignored: the caller has no
            // meaningful parent to name and murmur's own host callback passes
            // the root here too.
            parent: Some(0),
            flags: FLAG_DETACHED | FLAG_HIDDEN,
            pchat_protocol: 4,
            expiry_mode: EXPIRY_ABSOLUTE,
            expiry_duration_s: 60,
            ..Channel::default()
        })
    }

    /// The tree's record for `id`.
    fn record(trees: &Trees, id: u32) -> Channel {
        trees
            .snapshot(1)
            .channels
            .into_iter()
            .find(|channel| channel.id == id)
            .expect("the channel is in the tree")
    }

    #[test]
    fn a_detached_channel_is_created_parentless_rather_than_under_the_root() {
        // The whole of what "out of tree" means on the wire: a client builds
        // its tree from parent ids, so a meeting room that kept `parent: 0`
        // would render in everyone's channel list.
        let trees = trees();
        let created = trees.create(1, room("Standup [abc]"), Creation::default());
        assert!(created.applied && created.created);
        let id = created.channel.map(|c| c.id).unwrap_or_default();

        let room = record(&trees, id);
        assert_eq!(room.parent, None, "the parent the caller named is dropped");
        assert!(is_detached(&room));
        assert_ne!(id, 0, "and it is still not the root");
    }

    #[test]
    fn a_detached_channel_shares_a_name_with_a_channel_in_the_tree() {
        // They are not in the same place, so they are not siblings. A meeting
        // called "Standup" must not be refused because a room at the root
        // happens to be called that, in either order.
        let trees = trees();
        assert!(
            trees
                .create(1, named("Standup", 0), Creation::default())
                .applied
        );
        assert!(
            trees
                .create(1, room("Standup"), Creation::default())
                .applied
        );
        assert_eq!(trees.snapshot(1).channels.len(), 3);
    }

    #[test]
    fn two_detached_channels_cannot_share_a_name() {
        // The only uniqueness rule a parentless channel can have, and what
        // makes `reuse_existing` able to find the room it is looking for.
        let trees = trees();
        assert!(
            trees
                .create(1, room("Standup"), Creation::default())
                .applied
        );
        let second = trees.create(1, room("Standup"), Creation::default());
        assert!(!second.applied);
        assert!(second.refused.contains("already exists"));
    }

    #[test]
    fn provisioning_the_same_room_twice_returns_the_first_one() {
        // Idempotency, which is what lets the two triggers for a meeting room -
        // its start time arriving and somebody asking to join - both run
        // without minting a second room or failing.
        let trees = trees();
        let how = Creation {
            reuse_existing: true,
            ..Creation::default()
        };
        let first = trees.create(1, room("Standup"), how);
        let second = trees.create(1, room("Standup"), how);

        assert!(first.created, "the first call made it");
        assert!(second.applied, "the second call succeeds");
        assert!(!second.created, "but it did not create anything");
        assert_eq!(
            first.channel.map(|c| c.id),
            second.channel.map(|c| c.id),
            "both callers hold the same room"
        );
        assert_eq!(trees.snapshot(1).channels.len(), 2, "root plus one room");
    }

    #[test]
    fn a_detached_channel_cannot_be_moved_into_the_tree() {
        // It would then have a parent while carrying the flag that says it has
        // none, and every walk here reads one or the other.
        let trees = trees();
        let id = trees
            .create(1, room("Standup"), Creation::default())
            .channel
            .map(|c| c.id)
            .unwrap_or_default();

        let moved = trees.update(
            1,
            id,
            Some(Channel {
                parent: Some(0),
                ..Channel::default()
            }),
            &["parent".to_owned()],
            TreeLimits::UNLIMITED,
        );
        assert!(!moved.applied);
        assert_eq!(record(&trees, id).parent, None);
    }

    #[test]
    fn an_edit_cannot_detach_a_channel_or_reattach_one() {
        // DETACHED is create-only, and the guard is here rather than in the
        // wire decoder so that it holds for gRPC and clients alike. The rest of
        // the flags in the same write still apply, or setting `hidden` on a
        // meeting room would be refused for touching a bit it never named.
        let trees = trees();
        let ordinary = create(&trees, "Lobby", 0);
        let detach = trees.update(
            1,
            ordinary,
            Some(Channel {
                flags: FLAG_DETACHED | FLAG_HIDDEN,
                ..Channel::default()
            }),
            &["flags".to_owned()],
            TreeLimits::UNLIMITED,
        );
        assert!(detach.applied, "the hidden half of the write still lands");
        let after = record(&trees, ordinary);
        assert!(!is_detached(&after), "but it is still in the tree");
        assert_eq!(after.flags & FLAG_HIDDEN, FLAG_HIDDEN);

        let room_id = trees
            .create(1, room("Standup"), Creation::default())
            .channel
            .map(|c| c.id)
            .unwrap_or_default();
        let reattach = trees.update(
            1,
            room_id,
            Some(Channel {
                flags: 0,
                ..Channel::default()
            }),
            &["flags".to_owned()],
            TreeLimits::UNLIMITED,
        );
        assert!(reattach.applied);
        let after = record(&trees, room_id);
        assert!(
            is_detached(&after),
            "a room cannot be dragged into the tree"
        );
        assert_eq!(
            after.flags & FLAG_HIDDEN,
            0,
            "the rest of the write applied"
        );
    }

    #[test]
    fn deleting_a_detached_channel_sends_its_occupants_to_the_root() {
        // The C++ server's crash: `removeChannel` took the parent as the
        // destination for displaced users and dereferenced it, so deleting a
        // meeting room or a friend DM took the server down
        // (`Server.cpp:2161`). There is no parent here to be missing.
        let trees = trees();
        let id = trees
            .create(1, room("Standup"), Creation::default())
            .channel
            .map(|c| c.id)
            .unwrap_or_default();
        assert!(trees.enter(1, 42, id, TreeLimits::UNLIMITED, false).applied);

        let removal = trees.remove(1, id);
        assert!(removal.result.applied);
        let snapshot = trees.snapshot(1);
        assert!(!snapshot.channels.iter().any(|c| c.id == id));
        assert_eq!(
            snapshot
                .members
                .iter()
                .find(|m| m.session == 42)
                .map(|m| m.channel),
            Some(0),
            "a displaced occupant lands at the root, not nowhere"
        );
    }

    #[test]
    fn an_expired_detached_room_relocates_to_the_root_as_well() {
        // The same absent parent, by the path that runs unattended: a meeting
        // room reaches its deadline while somebody is still sitting in it.
        let trees = trees();
        let id = trees
            .create(1, room("Standup"), Creation::default())
            .channel
            .map(|c| c.id)
            .unwrap_or_default();
        assert!(trees.enter(1, 7, id, TreeLimits::UNLIMITED, false).applied);

        let reaped = trees.reap_expired(1, now_ms() + 61 * 1_000);
        assert_eq!(reaped.channels, vec![id]);
        assert_eq!(reaped.moved.len(), 1);
        assert_eq!(reaped.moved[0].to, 0);
    }

    #[test]
    fn a_removal_reports_who_it_displaced_and_not_only_who_it_unsubscribed() {
        // The tree moved them and nothing told them, so a client whose channel
        // was deleted under it went on rendering itself inside a room the
        // server had forgotten - and there is no way to leave a channel that
        // does not exist. The caller can only send the `UserState` murmur sends
        // (`Server.cpp:2180`) if the removal hands back the list.
        let trees = trees();
        let parent_id = create(&trees, "Parent", 0);
        let child_id = create(&trees, "Child", parent_id);
        let _ = trees.enter(1, 42, child_id, TreeLimits::UNLIMITED, false);
        let _ = trees.enter(1, 7, parent_id, TreeLimits::UNLIMITED, false);

        let removal = trees.remove(1, parent_id);
        let moved: Vec<(u32, u32)> = removal
            .moved
            .iter()
            .map(|entry| (entry.session, entry.to))
            .collect();
        assert_eq!(
            moved,
            vec![(7, 0), (42, 0)],
            "both occupants, from the channel and from its descendant, sorted"
        );
    }

    #[test]
    fn a_detached_channel_is_not_a_child_of_the_root() {
        // `parent: None` is true of the root too, so a walk that read it as
        // "belongs to the root" would delete every meeting room on the server
        // the first time an operator removed a channel near the top.
        let trees = trees();
        let lobby = create(&trees, "Lobby", 0);
        let room_id = trees
            .create(1, room("Standup"), Creation::default())
            .channel
            .map(|c| c.id)
            .unwrap_or_default();

        assert!(trees.remove(1, lobby).result.applied);
        assert!(
            trees.snapshot(1).channels.iter().any(|c| c.id == room_id),
            "removing a channel in the tree left the out-of-tree room alone"
        );
    }

    #[test]
    fn the_nesting_limit_refuses_the_channel_one_past_it() {
        // C2. A limit of 2 admits root → A → B and refuses a third level,
        // which is murmur's `canNest`: the deepest channel sits *at* the limit.
        let trees = trees();
        let limits = depth_limit(2, 0);
        let first = trees.create(1, named("A", 0), within(limits));
        let first_id = first.channel.map(|c| c.id).unwrap_or_default();
        assert!(first.applied);

        let second = trees.create(1, named("B", first_id), within(limits));
        let second_id = second.channel.map(|c| c.id).unwrap_or_default();
        assert!(second.applied, "a channel at the limit is allowed");

        let third = trees.create(1, named("C", second_id), within(limits));
        assert!(
            !third.applied,
            "the tree must not get deeper than the limit"
        );
        assert_eq!(third.refused, NESTING_REFUSED);
    }

    #[test]
    fn raising_the_nesting_limit_admits_what_it_had_refused() {
        // The §5 property, stated as a test: the *value* has to change the
        // outcome, not merely round-trip through the API. Same tree, same
        // request, two different settings.
        let trees = trees();
        let a = create(&trees, "A", 0);
        let b = trees
            .create(1, named("B", a), within(depth_limit(1, 0)))
            .applied;
        assert!(!b, "a limit of 1 refuses a second level");
        assert!(
            trees
                .create(1, named("B", a), within(depth_limit(2, 0)))
                .applied,
            "raising the limit admits the identical request"
        );
    }

    #[test]
    fn a_nesting_limit_of_zero_is_unlimited_rather_than_flat() {
        // The reading that would otherwise refuse every channel on a server
        // whose settings have not arrived yet.
        let trees = trees();
        let mut parent = 0;
        for step in 0..12 {
            let result = trees.create(
                1,
                named(&format!("deep{step}"), parent),
                within(depth_limit(0, 0)),
            );
            assert!(result.applied, "step {step} was refused");
            parent = result.channel.map(|c| c.id).unwrap_or_default();
        }
    }

    #[test]
    fn moving_a_subtree_is_measured_by_its_whole_height() {
        // A three-deep branch dragged under a channel near the ceiling passes
        // the limit as a unit, and murmur refuses it as a unit rather than
        // letting the drag succeed and the tree end up too deep.
        let trees = trees();
        let limits = depth_limit(3, 0);
        let top = create(&trees, "Top", 0);
        let middle = create(&trees, "Middle", top);
        let branch = create(&trees, "Branch", 0);
        let _leaf = create(&trees, "Leaf", branch);

        let moved = trees.update(
            1,
            branch,
            Some(Channel {
                parent: Some(middle),
                ..Channel::default()
            }),
            &["parent".to_owned()],
            limits,
        );
        assert!(
            !moved.applied,
            "the branch is two tall and would sit at 2+2"
        );
        assert_eq!(moved.refused, NESTING_REFUSED);
    }

    #[test]
    fn a_channel_cannot_be_moved_inside_its_own_subtree() {
        // Not a limit, the same shape of loss: the channel would be
        // unreachable from the root and no client would ever render it again.
        let trees = trees();
        let parent = create(&trees, "Parent", 0);
        let child = create(&trees, "Child", parent);
        let moved = trees.update(
            1,
            parent,
            Some(Channel {
                parent: Some(child),
                ..Channel::default()
            }),
            &["parent".to_owned()],
            TreeLimits::UNLIMITED,
        );
        assert!(!moved.applied);
        assert!(moved.refused.contains("inside itself"));
    }

    #[test]
    fn the_channel_count_limit_refuses_the_one_past_it() {
        // C3. The root counts, as it does in murmur, `qhChannels` holds it.
        let trees = trees();
        let limits = depth_limit(0, 3);
        assert!(trees.create(1, named("A", 0), within(limits)).applied);
        assert!(trees.create(1, named("B", 0), within(limits)).applied);
        let over = trees.create(1, named("C", 0), within(limits));
        assert!(!over.applied, "the fourth channel is one past the limit");
        assert_eq!(over.refused, COUNT_REFUSED);
    }

    #[test]
    fn lowering_the_count_limit_stops_new_channels_without_removing_any() {
        // What an operator actually does with it, and the direction that has
        // to keep working: the tree they already have stays.
        let trees = trees();
        let _ = create(&trees, "A", 0);
        let _ = create(&trees, "B", 0);
        assert!(
            !trees
                .create(1, named("C", 0), within(depth_limit(0, 2)))
                .applied
        );
        assert_eq!(trees.snapshot(1).channels.len(), 3, "nothing was removed");
        assert!(
            trees
                .create(1, named("C", 0), within(depth_limit(0, 9)))
                .applied
        );
    }

    #[test]
    fn a_link_is_written_into_both_channels() {
        // C1. murmur's `Channel::link` writes both ends, and audio crossing a
        // link is a property of the pair rather than of whichever channel the
        // operator happened to have open.
        let trees = trees();
        let lobby = create(&trees, "Lobby", 0);
        let annex = create(&trees, "Annex", 0);

        assert!(trees.link(1, lobby, &[annex], &[]).applied);
        assert_eq!(links_of(&trees, lobby), vec![annex]);
        assert_eq!(links_of(&trees, annex), vec![lobby], "the far end too");

        assert!(trees.link(1, lobby, &[], &[annex]).applied);
        assert!(links_of(&trees, lobby).is_empty());
        assert!(links_of(&trees, annex).is_empty());
    }

    #[test]
    fn linking_the_same_pair_twice_does_not_duplicate_the_edge() {
        let trees = trees();
        let lobby = create(&trees, "Lobby", 0);
        let annex = create(&trees, "Annex", 0);
        let _ = trees.link(1, lobby, &[annex], &[]);
        let _ = trees.link(1, annex, &[lobby], &[]);
        assert_eq!(links_of(&trees, lobby), vec![annex]);
        assert_eq!(links_of(&trees, annex), vec![lobby]);
    }

    #[test]
    fn a_link_naming_a_channel_that_does_not_exist_applies_nothing() {
        // murmur returns without applying any of them, so a request naming a
        // channel that has just been removed does not half-apply.
        let trees = trees();
        let lobby = create(&trees, "Lobby", 0);
        let annex = create(&trees, "Annex", 0);
        let result = trees.link(1, lobby, &[annex, 4_242], &[]);
        assert!(!result.applied);
        assert!(links_of(&trees, lobby).is_empty(), "nothing was written");
    }

    #[test]
    fn a_channel_cannot_be_linked_to_itself() {
        let trees = trees();
        let lobby = create(&trees, "Lobby", 0);
        assert!(!trees.link(1, lobby, &[lobby], &[]).applied);
    }

    #[test]
    fn removing_a_channel_takes_the_links_pointing_at_it() {
        // `ChannelState.links` is a complete statement of the set, so a stale
        // id would be re-sent on every announcement and every client would
        // render an edge to a room that is gone.
        let trees = trees();
        let lobby = create(&trees, "Lobby", 0);
        let annex = create(&trees, "Annex", 0);
        let _ = trees.link(1, lobby, &[annex], &[]);
        assert!(trees.remove(1, annex).result.applied);
        assert!(links_of(&trees, lobby).is_empty());
    }

    #[test]
    fn a_collected_temporary_channel_takes_its_links_with_it() {
        // The same dangling edge, by the path nobody triggers on purpose.
        let trees = trees();
        let lobby = create(&trees, "Lobby", 0);
        let scratch = trees
            .create(
                1,
                named("Scratch", 0),
                Creation {
                    temporary: true,
                    ..Creation::default()
                },
            )
            .channel
            .map(|channel| channel.id)
            .unwrap_or_default();
        let _ = trees.link(1, lobby, &[scratch], &[]);
        let _ = trees.enter(1, 7, scratch, TreeLimits::UNLIMITED, false);
        assert_eq!(
            trees.enter(1, 7, 0, TreeLimits::UNLIMITED, false).collected,
            Some(scratch)
        );
        assert!(links_of(&trees, lobby).is_empty());
    }

    /// The ceilings, with only the listener caps set.
    fn listener_limit(per_channel: u32, per_user: u32) -> TreeLimits {
        TreeLimits {
            listeners_per_channel: per_channel,
            listeners_per_user: per_user,
            ..TreeLimits::UNLIMITED
        }
    }

    /// `Trees::listen` on the default scope with no volume changes, which is
    /// what all but the volume tests below are about.
    fn listen(
        trees: &Trees,
        session: u32,
        add: &[u32],
        drop: &[u32],
        limits: TreeLimits,
    ) -> Listened {
        trees.listen(1, session, add, drop, &HashMap::new(), limits)
    }

    /// The channels `session` is listening to, in the order they were added.
    fn listening(trees: &Trees, session: u32) -> Vec<u32> {
        trees
            .snapshot(1)
            .members
            .into_iter()
            .find(|member| member.session == session)
            .map(|member| member.listening)
            .unwrap_or_default()
    }

    /// The gain `session` set on `channel`, if any.
    fn gain(trees: &Trees, session: u32, channel: u32) -> Option<f32> {
        trees
            .snapshot(1)
            .members
            .into_iter()
            .find(|member| member.session == session)
            .and_then(|member| member.listening_volume.get(&channel).copied())
    }

    #[test]
    fn listeners_per_channel_refuses_the_listener_past_the_cap() {
        let trees = trees();
        let lobby = create(&trees, "Lobby", 0);
        let limits = listener_limit(1, 0);

        assert_eq!(listen(&trees, 1, &[lobby], &[], limits).added, vec![lobby]);
        let second = listen(&trees, 2, &[lobby], &[], limits);
        assert!(second.added.is_empty());
        assert_eq!(second.refused, vec![(lobby, ListenRefusal::ChannelFull)]);
    }

    #[test]
    fn raising_listeners_per_channel_admits_the_same_request() {
        // §5 again: the setting has to be the thing that decides.
        let trees = trees();
        let lobby = create(&trees, "Lobby", 0);
        let _ = listen(&trees, 1, &[lobby], &[], listener_limit(1, 0));
        assert!(
            listen(&trees, 2, &[lobby], &[], listener_limit(1, 0))
                .added
                .is_empty()
        );
        assert_eq!(
            listen(&trees, 2, &[lobby], &[], listener_limit(2, 0)).added,
            vec![lobby]
        );
    }

    #[test]
    fn listeners_per_user_caps_one_session_across_channels() {
        let trees = trees();
        let one = create(&trees, "One", 0);
        let two = create(&trees, "Two", 0);
        let limits = listener_limit(0, 1);

        let outcome = listen(&trees, 5, &[one, two], &[], limits);
        assert_eq!(
            outcome.added,
            vec![one],
            "the first fits, the second does not"
        );
        assert_eq!(outcome.refused, vec![(two, ListenRefusal::UserFull)]);
    }

    #[test]
    fn a_listener_can_always_be_dropped_even_at_the_cap() {
        // A limit that could trap somebody in a subscription they are trying to
        // leave would be the wrong shape of rule.
        let trees = trees();
        let one = create(&trees, "One", 0);
        let two = create(&trees, "Two", 0);
        let limits = listener_limit(0, 1);
        let _ = listen(&trees, 5, &[one], &[], limits);

        // Swapping one for another in a single request works, because the
        // removal is applied first.
        let swap = listen(&trees, 5, &[two], &[one], limits);
        assert_eq!(swap.removed, vec![one]);
        assert_eq!(swap.added, vec![two]);
        assert!(swap.refused.is_empty());
    }

    #[test]
    fn moving_channel_keeps_the_listeners_you_had() {
        // Walking into another room is not a request to cancel every channel
        // you were listening to. murmur touches only the channel.
        let trees = trees();
        let lobby = create(&trees, "Lobby", 0);
        let annex = create(&trees, "Annex", 0);
        let _ = trees.enter(1, 5, lobby, TreeLimits::UNLIMITED, false);
        let _ = trees.listen(
            1,
            5,
            &[annex],
            &[],
            &volume(annex, 0.4),
            TreeLimits::UNLIMITED,
        );

        assert!(
            trees
                .enter(1, 5, annex, TreeLimits::UNLIMITED, false)
                .applied
        );
        assert_eq!(listening(&trees, 5), vec![annex]);
        assert_eq!(gain(&trees, 5, annex), Some(0.4));
    }

    /// One channel's gain, as `listen` takes them.
    fn volume(channel: u32, gain: f32) -> HashMap<u32, f32> {
        HashMap::from([(channel, gain)])
    }

    #[test]
    fn a_gain_can_be_set_before_the_listener_exists() {
        // murmur consults the database for a listener the manager has never
        // heard of (`Server.cpp:3242`), so the adjustment does not depend on
        // which order the client sends the two things in.
        let trees = trees();
        let lobby = create(&trees, "Lobby", 0);
        let set = trees.listen(1, 5, &[], &[], &volume(lobby, 0.5), TreeLimits::UNLIMITED);
        assert_eq!(set.volume.get(&lobby), Some(&0.5));
        assert!(set.added.is_empty());

        let _ = listen(&trees, 5, &[lobby], &[], TreeLimits::UNLIMITED);
        assert_eq!(gain(&trees, 5, lobby), Some(0.5));
    }

    #[test]
    fn a_gain_survives_the_listener_being_dropped_and_re_added() {
        // Turning a room off and on again must not silently reset a slider the
        // user set deliberately.
        let trees = trees();
        let lobby = create(&trees, "Lobby", 0);
        let _ = trees.listen(
            1,
            5,
            &[lobby],
            &[],
            &volume(lobby, 0.3),
            TreeLimits::UNLIMITED,
        );
        let _ = listen(&trees, 5, &[], &[lobby], TreeLimits::UNLIMITED);
        assert!(listening(&trees, 5).is_empty());

        let _ = listen(&trees, 5, &[lobby], &[], TreeLimits::UNLIMITED);
        assert_eq!(gain(&trees, 5, lobby), Some(0.3));
    }

    #[test]
    fn setting_a_gain_back_to_unity_forgets_it() {
        // Unity is the absence of an adjustment, not an adjustment of one:
        // keeping the row would hand the routing snapshot an entry that changes
        // nothing, forever.
        let trees = trees();
        let lobby = create(&trees, "Lobby", 0);
        let _ = trees.listen(
            1,
            5,
            &[lobby],
            &[],
            &volume(lobby, 0.3),
            TreeLimits::UNLIMITED,
        );
        let reset = trees.listen(1, 5, &[], &[], &volume(lobby, 1.0), TreeLimits::UNLIMITED);
        assert_eq!(reset.volume.get(&lobby), Some(&1.0), "the client is told");
        assert_eq!(gain(&trees, 5, lobby), None, "but nothing is kept");
    }

    #[test]
    fn re_setting_the_same_gain_reports_no_change() {
        // Otherwise every repeat of a `UserState` a client re-sends would
        // broadcast a volume change to the whole server.
        let trees = trees();
        let lobby = create(&trees, "Lobby", 0);
        let limits = TreeLimits::UNLIMITED;
        let _ = trees.listen(1, 5, &[lobby], &[], &volume(lobby, 0.3), limits);
        let again = trees.listen(1, 5, &[lobby], &[], &volume(lobby, 0.3), limits);
        assert!(again.is_empty(), "nothing changed, so nothing to announce");
    }

    #[test]
    fn a_gain_for_a_channel_that_does_not_exist_is_ignored() {
        let trees = trees();
        let outcome = trees.listen(1, 5, &[], &[], &volume(404, 0.5), TreeLimits::UNLIMITED);
        assert!(outcome.volume.is_empty());
    }

    #[test]
    fn removing_a_channel_cancels_the_listeners_on_it() {
        // A listener on a channel that no longer exists is a subscription to
        // nothing that the client still shows, with no way to cancel it.
        let trees = trees();
        let lobby = create(&trees, "Lobby", 0);
        let annex = create(&trees, "Annex", 0);
        let _ = trees.listen(
            1,
            5,
            &[lobby, annex],
            &[],
            &volume(annex, 0.5),
            TreeLimits::UNLIMITED,
        );

        let removal = trees.remove(1, annex);
        assert!(removal.result.applied);
        assert_eq!(
            removal.unlistened,
            vec![Unlistened {
                session: 5,
                channels: vec![annex],
            }],
            "the client has to be told, or it renders a listener it cannot cancel"
        );
        assert_eq!(listening(&trees, 5), vec![lobby], "the other one survives");
        assert_eq!(gain(&trees, 5, annex), None, "and the gain goes with it");
    }

    #[test]
    fn removing_a_channel_cancels_listeners_on_its_descendants_too() {
        // The removal takes the subtree, so it takes the subtree's listeners.
        let trees = trees();
        let parent = create(&trees, "Parent", 0);
        let child = create(&trees, "Child", parent);
        let _ = listen(&trees, 5, &[child], &[], TreeLimits::UNLIMITED);

        let removal = trees.remove(1, parent);
        assert_eq!(
            removal.unlistened,
            vec![Unlistened {
                session: 5,
                channels: vec![child],
            }]
        );
        assert!(listening(&trees, 5).is_empty());
    }

    #[test]
    fn removing_a_channel_nobody_listened_to_announces_nothing() {
        let trees = trees();
        let annex = create(&trees, "Annex", 0);
        assert!(trees.remove(1, annex).unlistened.is_empty());
    }

    #[test]
    fn a_listener_cap_of_zero_is_unlimited() {
        let trees = trees();
        let lobby = create(&trees, "Lobby", 0);
        for session in 1..20 {
            assert_eq!(
                listen(&trees, session, &[lobby], &[], TreeLimits::UNLIMITED).added,
                vec![lobby]
            );
        }
    }
}
