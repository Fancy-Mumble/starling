//! How a feature announces itself.
//!
//! The composition root does not name features. It asks [`registered`] what is
//! linked into this build, so adding one costs a dependency edge and **no code**.
//!
//! # Why not a list in the binary
//!
//! Because the list is the coupling. A binary that writes
//! `.register(Box::new(PermissionQueryHandler))` has to import the feature, know
//! its type, and know how to construct it — three facts about a component it
//! should only be hosting. Every new feature then edits the same file, which is
//! exactly the merge-conflict funnel a microkernel exists to avoid.
//!
//! # How
//!
//! [`inventory`] collects submissions into a link-section slice at compile time.
//! A feature crate writes [`register_feature!`](crate::register_feature) once at module scope; the
//! constructor runs before `main`, and the binary sees it without referencing it.
//!
//! The one thing this cannot remove is the **dependency edge** — a crate nobody
//! depends on is not linked, so `Cargo.toml` must still name it. That is a
//! property of static linking, not of this design. Runtime loading (the WASM host
//! in Phase 3) is what removes the last line.

use crate::handler::Handler;

/// A unit of server behaviour that is not part of the stock protocol baseline.
///
/// Implementations are constructed by the host, so they must not need arguments:
/// everything a feature reads arrives through [`Authority`](crate::Authority) at
/// handle time, not at construction.
pub trait Feature: std::fmt::Debug + Send + Sync {
    /// Stable identifier, for logs and for an operator disabling it.
    fn name(&self) -> &'static str;

    /// The message handlers this feature contributes.
    ///
    /// A feature may contribute several — persistent chat owns 24 wire types —
    /// or none, if it only subscribes to events.
    fn handlers(&self) -> Vec<Box<dyn Handler>>;
}

/// One feature's entry in the link-time registry.
///
/// Built by [`register_feature!`](crate::register_feature); there is no reason to write one by hand.
#[derive(Debug)]
pub struct Registration {
    /// The feature's name, for diagnostics before it is constructed.
    pub name: &'static str,
    /// Constructs the feature. A `fn` pointer rather than a value, so nothing
    /// runs before `main`.
    pub make: fn() -> Box<dyn Feature>,
}

inventory::collect!(Registration);

/// Every feature linked into this build.
///
/// Order is the linker's and must not be relied on: a feature that needs to run
/// before another has a dependency, not a position.
#[must_use]
pub fn registered() -> Vec<Box<dyn Feature>> {
    inventory::iter::<Registration>
        .into_iter()
        .map(|entry| (entry.make)())
        .collect()
}

/// Names of every linked feature, without constructing them.
#[must_use]
pub fn registered_names() -> Vec<&'static str> {
    inventory::iter::<Registration>
        .into_iter()
        .map(|entry| entry.name)
        .collect()
}

/// Announce a [`Feature`] to the host.
///
/// Write once at module scope in a feature crate:
///
/// ```ignore
/// starling_api::register_feature!(MyFeature);
/// ```
///
/// The type must implement [`Feature`] and [`Default`].
#[macro_export]
macro_rules! register_feature {
    ($ty:ty) => {
        $crate::inventory::submit! {
            $crate::feature::Registration {
                name: ::core::stringify!($ty),
                make: || ::std::boxed::Box::new(<$ty as ::core::default::Default>::default()),
            }
        }
    };
}

/// Link one or more plugin crates so their registrations survive.
///
/// A plugin announces itself with
/// [`register_feature!`](crate::register_feature), but **rustc will not link an
/// rlib it never resolves a symbol from** — so without a reference somewhere in
/// the binary, the registration is silently dropped and the plugin is simply
/// absent from a clean build.
///
/// This is crate resolution, not a linker optimisation. Measured on rustc 1.95:
/// `-C link-dead-code` does not help, because the object code never reaches the
/// linker. `rustc --extern force:name=path` does exactly what is wanted but needs
/// `-Z unstable-options`, and Cargo cannot pass it — the path carries a
/// per-build metadata hash.
///
/// So one reference per plugin is the stable floor. This macro is that reference,
/// in one place:
///
/// ```ignore
/// // crates/edges/starling/src/plugins.rs
/// starling_api::register_plugin! {
///     starling_feature_permission_query,
///     starling_feature_query_users,
/// }
/// ```
///
/// Each name must also be a dependency of the binary; a crate nobody depends on
/// is not built at all.
#[macro_export]
macro_rules! register_plugin {
    ($($plugin:ident),+ $(,)?) => {
        $(
            #[doc = ::core::concat!("Linked plugin: `", ::core::stringify!($plugin), "`.")]
            #[allow(clippy::single_component_path_imports, unused_imports)]
            use $plugin as _;
        )+
    };
}
