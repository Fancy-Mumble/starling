//! `starling-config` — the server's resolved settings.
//!
//! Plain values. It knows nothing about files, formats, the command line, or
//! features, which is why it can sit under all of them.
//!
//! # Two tiers, and the line between them is the protocol
//!
//! [`Limits`] holds what the server **already tells every client** in
//! `ServerSync` and `ServerConfig` (`handlers/handshake/sync.rs`): the message
//! size caps, the bandwidth budget, the welcome text, whether HTML and recording
//! are allowed. A feature reading those learns nothing a connected client does
//! not already know, so they are safe to hand across the feature contract.
//!
//! [`ServerConfig`] holds those *plus* what a client is never told: the bind
//! address, the port, the public name, and the server password. Only the state
//! service sees it.
//!
//! That split exists because the feature contract used to hand out the whole
//! struct — including `server_password` — to every feature, and no feature read
//! configuration at all. Drawing the line where the protocol already draws it
//! keeps the useful 7 fields available and the secret out of reach.
//!
//! # Why not in `starling-api`
//!
//! It was, briefly. That made `starling-cli` — the command-line surface — depend
//! on the *feature contract* for one struct, which is a dependency between two
//! crates that have nothing to say to each other. Configuration is a domain
//! concept both of them consume.

/// Settings a connected client is told anyway.
///
/// Safe to expose to a feature: every field here is sent to clients during the
/// handshake, so there is nothing to leak.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Limits {
    /// Maximum concurrent users (`users`). Also sizes the session-id pool.
    pub max_users: u32,
    /// Total bandwidth budget in bits/sec (`bandwidth`), sent in `ServerSync`.
    pub max_bandwidth: u32,
    /// Message shown to clients on connect (`welcometext`).
    pub welcome_text: String,
    /// Whether chat messages may contain HTML (`allowhtml`).
    pub allow_html: bool,
    /// Maximum chat message length in bytes (`textmessagelength`).
    pub max_text_message_length: u32,
    /// Maximum image message length in bytes (`imagemessagelength`).
    pub max_image_message_length: u32,
    /// Whether clients may announce that they are recording.
    pub allow_recording: bool,
}

impl Default for Limits {
    /// murmur's defaults, from `Meta.cpp`.
    fn default() -> Self {
        Self {
            max_users: 100,
            max_bandwidth: 72_000,
            welcome_text: String::new(),
            allow_html: true,
            max_text_message_length: 5000,
            max_image_message_length: 131_072,
            allow_recording: true,
        }
    }
}

/// Server settings the MVP honours.
///
/// Keys murmur accepts but Starling does not act on yet are parsed and warned
/// about by the binary rather than silently dropped, so a config that "worked"
/// never quietly means something different here.
#[derive(Debug, Clone)]
pub struct ServerConfig {
    /// Address to bind the control/voice listener to (`host`).
    pub host: String,
    /// TCP (and, from Phase 1, UDP) port (`port`).
    pub port: u16,
    /// Public server name (`registerName`), which is also the root channel's name.
    ///
    /// Note the camelCase key: it is case-sensitive on Linux, and the e2e
    /// fixture relies on that spelling.
    pub register_name: String,
    /// Password required to connect (`serverpassword`); empty means none.
    ///
    /// Deliberately **not** in [`Limits`]: a feature has no business reading it.
    /// The contract exposes `password_accepted` instead, so a caller can ask
    /// whether a candidate is right without being told what right is.
    pub server_password: String,
    /// Everything a client is told during the handshake.
    pub limits: Limits,
}

impl ServerConfig {
    /// Whether a password is required to connect.
    #[must_use]
    pub fn requires_password(&self) -> bool {
        !self.server_password.is_empty()
    }

    /// Whether `candidate` matches the configured server password.
    ///
    /// Always `true` when no password is configured, matching murmur
    /// (`Messages.cpp:381`: the check is skipped when `qsPassword` is empty).
    #[must_use]
    pub fn password_matches(&self, candidate: &str) -> bool {
        !self.requires_password() || self.server_password == candidate
    }
}

/// murmur's defaults (`Meta.cpp`).
///
/// Hand-written rather than derived: `String::default()` and `0` are not
/// meaningful for a bind address and a port, and a derived `Default` would hand
/// out a configuration that binds nowhere.
impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            host: "0.0.0.0".into(),
            port: 64738,
            register_name: "Root".into(),
            server_password: String::new(),
            limits: Limits::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_empty_password_accepts_anything() {
        let config = ServerConfig::default();
        assert!(!config.requires_password());
        assert!(config.password_matches(""));
        assert!(config.password_matches("whatever"));
    }

    #[test]
    fn a_configured_password_must_match_exactly() {
        let config = ServerConfig {
            server_password: "hunter2".into(),
            ..ServerConfig::default()
        };
        assert!(config.requires_password());
        assert!(config.password_matches("hunter2"));
        assert!(!config.password_matches("Hunter2"));
        assert!(!config.password_matches(""));
    }

    #[test]
    fn the_password_is_not_reachable_from_limits() {
        // A compile-time guarantee, asserted here so the intent is recorded: the
        // feature contract hands out `Limits`, and there is no field on it that
        // could carry a secret.
        let limits = Limits::default();
        assert_eq!(limits, ServerConfig::default().limits);
    }
}
