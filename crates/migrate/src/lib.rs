//! `starling-migrate` — murmur compatibility.
//!
//! [`Ini`] reads a `mumble-server.ini`, quirks included, and [`Ini::migrate`]
//! renders the subset that still has a home in
//! [`starling_runtime::config::Config`] — the deployment layer
//! (`docs/ARCHITECTURE.md` §4). Everything murmur's `.ini` configures live
//! (`users`, `bandwidth`, `welcometext`, ...) is now **operational** config
//! owned by the `server-config` service, which has no migration target yet
//! because it has no schema yet; those keys are reported rather than silently
//! dropped, and mapping them is future work once that service exists.
//!
//! Not yet wired to a CLI: the entrypoint's argument parsing is a separate,
//! not-yet-built piece (`crates/starling`), so nothing outside this crate
//! calls [`Ini::migrate`] yet. This is a migration aid with an expiry date,
//! not a permanent second config format (`PORTING-PLAN.md` §4).

mod ini;

pub use ini::Ini;
