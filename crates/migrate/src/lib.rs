//! `starling-migrate`: murmur compatibility.
//!
//! Two halves of one move, and both follow the same rule: **what used to mean
//! something must not quietly mean less here**, so anything that cannot be
//! carried across is reported rather than dropped.
//!
//! * [`Ini`] reads a `mumble-server.ini` and [`Ini::migrate`] renders the
//!   deployment layer of it as `starling.toml` (`docs/ARCHITECTURE.md` §4).
//!   Everything murmur's `.ini` configures *live* -- `users`, `bandwidth`,
//!   `welcometext`, ... -- is operational config owned by the `server-config`
//!   service and lands under `[instances.settings]`.
//! * [`Murmur`] reads a murmur **database**, either schema, and hands back what
//!   is in it as [`Server`]: the channel tree, the accounts, the ACL entries and
//!   groups, the bans, the listeners and the `config` table. Turning that into
//!   Starling's own tables is `starling migrate-db`'s job, because each of those
//!   lands in a different service's database and every service owns its own
//!   schema (`docs/STORAGE.md` §1).
//!
//! The `config` table and the `.ini` share their key names, which is not a
//! coincidence: murmur's table overrides the file key for key. So the database
//! reader hands its `config` map to [`Ini::from_pairs`] and the same code maps
//! both, rather than a second table of key names existing to fall behind the
//! first.
//!
//! This is a migration aid with an expiry date, not a permanent second config
//! format (`docs/PORTING-PLAN.md` §4).

mod db;
mod ini;

pub use db::{
    Acl, Ban, Channel, Group, GroupMember, Layout, Link, Listener, Murmur, Password, ReadError,
    Report, Server, User,
};
pub use ini::{Ini, MigrateError};
