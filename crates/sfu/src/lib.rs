//! The WebRTC SFU: one broadcaster in, N viewers out.
//!
//! Ported from `vendor/server/3rdparty/webrtc-sfu`, which the C++ fork loads at
//! runtime and drives through a C FFI. **The FFI did not come with it**, and
//! neither did the 325-line `WebRtcSfuManager` around it: symbol resolution
//! through `QLibrary`, a `QTimer` polling for events, and Qt signals to carry
//! them back are all things a Rust caller does not need. `screenshare` calls
//! this directly and reads `poll_event` from a task.
//!
//! This crate provides a server-side SFU that receives a single WebRTC
//! stream from a broadcaster and re-broadcasts it to N viewers.  Each
//! viewer gets its own WebRTC connection to the server.
//!
//! # Architecture
//!
//! - Uses [`str0m`] in Sans-IO mode: the crate manages its own UDP
//!   sockets via a [`tokio`] runtime running on a background thread.
//! - Uses ICE-lite on the server side (no candidate gathering).
//!
//! # Signal flow
//!
//! ```text
//! Broadcaster                 Server SFU              Viewer
//!    |-- START (broadcast) -->| relay to ch |<------ |
//!    |-- SDP_OFFER --------->| create recv |         |
//!    |<-- SDP_ANSWER --------| peer        |         |
//!    |-- ICE_CANDIDATE ----->|             |         |
//!    |===== media (UDP) ====>|             |         |
//!    |                       |<-- SDP_OFFER ---------|
//!    |                       | create send |         |
//!    |                       |-- SDP_ANSWER -------->|
//!    |                       |===== media (UDP) ===>|
//! ```

mod session;

pub use session::{BroadcastSession, SfuConfig, SfuEvent, SfuHandle, StartError};
