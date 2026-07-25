//! Message routing (Registry + Command).
//!
//! Adding a message type is a [`Dispatcher::register`] call, never a new arm in
//! a growing `match`. That matters concretely: Phases 3–5 add roughly seventy
//! Fancy extension handlers, and a seventy-arm match in one file would be the
//! worst code in the workspace.

mod dispatcher;

pub use dispatcher::Dispatcher;
