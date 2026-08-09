//! The settings an operator can also write in the file, per server instance.
//!
//! # Why these are here at all, when they belong to `server-config`
//!
//! They still do. `server-config` owns them at run time, an operator changes
//! them live, and a change takes effect without a restart
//! (`docs/CONFIGURATION.md`). What was missing is a way to say what they should
//! be *before* anyone has run anything: the name of a server was in the file
//! while the number of people allowed into it was reachable only through the
//! admin API, so the first question anybody setting up a server asks -- "how do
//! I let twenty friends in and put a password on it?" -- had no answer that
//! looked like configuration.
//!
//! So every key here is **a starting value, not an override**. Each field is an
//! `Option`: absent means "no opinion, use murmur's default", and a value means
//! "this, unless an operator has since changed it at run time". `server-config`
//! records which settings an operator actually set and lets those win, so
//! editing the file changes anything nobody has touched and never silently
//! reverts a decision somebody made in the admin UI.

use serde::{Deserialize, Serialize};
use starling_proto_fancy::serverconfig::Snapshot;

/// Starting values for one server instance's operational settings.
///
/// Every field is optional so that "not mentioned" is a distinct state from
/// every value the field could hold -- `max_users = 0` is a real setting
/// (nobody may connect) and must not be what an empty block means.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct ServerSettings {
    /// Shown to each user once, on connect.
    pub welcome_text: Option<String>,
    /// Required to connect. Empty means the server is open.
    ///
    /// A server with one set is never listed publicly, which is murmur's rule
    /// rather than ours.
    pub password: Option<String>,
    /// Connections beyond this are refused as full.
    pub max_users: Option<u32>,
    /// Bits per second per speaking user.
    pub max_bandwidth: Option<u32>,
    /// Whether clients may record, and announce that they are.
    pub allow_recording: Option<bool>,
    /// Tell everyone when a user changes a per-channel listening volume.
    pub broadcast_listener_volume_adjustments: Option<bool>,
    /// Characters per message, after markup is stripped. Zero is unlimited.
    pub text_message_length: Option<u32>,
    /// Bytes, for a message that is an image rather than text.
    pub image_message_length: Option<u32>,
    /// Whether messages may carry markup.
    pub allow_html: Option<bool>,
    /// How deep the channel tree may go.
    pub channel_nesting_limit: Option<u32>,
    /// How many channels may exist at all.
    pub channel_count_limit: Option<u32>,
    /// Listeners one channel may hold. Zero is unlimited.
    pub listeners_per_channel: Option<u32>,
    /// Channels one user may listen to at once. Zero is unlimited.
    pub listeners_per_user: Option<u32>,
    /// Refuse connections from users with no certificate.
    pub cert_required: Option<bool>,
    /// Days of chat history kept.
    pub log_days: Option<u32>,
    /// Sustained messages per second before a client is throttled.
    pub message_limit: Option<u32>,
    /// How many may arrive at once before that rate applies.
    pub message_burst: Option<u32>,
    /// The same pair, for plugin messages.
    pub plugin_message_limit: Option<u32>,
    /// How many plugin messages may arrive at once.
    pub plugin_message_burst: Option<u32>,
    /// Write addresses to the log with the host part masked.
    pub obfuscate_ips: Option<bool>,
    /// Answer unauthenticated pings from server browsers.
    ///
    /// Also gates public-list registration: a listing the list cannot measure
    /// is a dead entry.
    pub allow_ping: Option<bool>,
    /// How the server appears in the public list. Empty means do not register.
    pub registry_name: Option<String>,
    /// Proves to the public list that a later update is this same server.
    pub registry_password: Option<String>,
    /// The page a listing links to. Registration refuses to run without one.
    pub registry_url: Option<String>,
    /// The DNS name the public list should reach this server at.
    pub registry_hostname: Option<String>,
    /// ISO country code, shown beside the listing.
    pub registry_location: Option<String>,
    /// Occupants any one channel may hold. Zero is unlimited.
    pub users_per_channel: Option<u32>,
    /// Where a user lands when nothing better is known. Zero is the root.
    pub default_channel: Option<u32>,
    /// Whether a registered user is put back where they were.
    pub remember_channel: Option<bool>,
    /// How long that memory lasts, in seconds. Zero is forever.
    pub remember_channel_duration: Option<u32>,
    /// What a channel name may look like. Empty means no restriction.
    pub channel_name_regex: Option<String>,
    /// What a user name may look like. Empty means no restriction.
    pub user_name_regex: Option<String>,
}

impl ServerSettings {
    /// Whether the operator wrote anything at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self == &Self::default()
    }

    /// Write every value that was named into `snapshot`, and say which.
    ///
    /// The returned names are the file's claim on those settings; a caller that
    /// also has settings from somewhere else uses them to decide what wins.
    pub fn overlay(&self, snapshot: &mut Snapshot) -> Vec<String> {
        let mut named = Vec::new();
        // A macro rather than twenty-six hand-written `if let`s: the failure it
        // rules out is a line that reads one field and writes another, which
        // compiles and is invisible in review.
        macro_rules! set {
            ($($field:ident),* $(,)?) => {
                $(
                    if let Some(value) = self.$field.clone() {
                        snapshot.$field = value;
                        named.push(stringify!($field).to_owned());
                    }
                )*
            };
        }
        set!(
            welcome_text,
            password,
            max_users,
            max_bandwidth,
            allow_recording,
            broadcast_listener_volume_adjustments,
            text_message_length,
            image_message_length,
            allow_html,
            channel_nesting_limit,
            channel_count_limit,
            listeners_per_channel,
            listeners_per_user,
            cert_required,
            log_days,
            message_limit,
            message_burst,
            plugin_message_limit,
            plugin_message_burst,
            obfuscate_ips,
            allow_ping,
            registry_name,
            registry_password,
            registry_url,
            registry_hostname,
            registry_location,
            users_per_channel,
            default_channel,
            remember_channel,
            remember_channel_duration,
            channel_name_regex,
            user_name_regex,
        );
        named
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::settings::defaults;

    #[test]
    fn an_empty_block_changes_nothing() {
        // "Not mentioned" must not read as "set to zero": `max_users = 0` is a
        // server nobody may connect to.
        let mut snapshot = defaults(1);
        let named = ServerSettings::default().overlay(&mut snapshot);
        assert!(named.is_empty());
        assert_eq!(snapshot.max_users, defaults(1).max_users);
    }

    #[test]
    fn a_named_setting_is_written_and_reported() {
        let mut snapshot = defaults(1);
        let settings = ServerSettings {
            max_users: Some(20),
            welcome_text: Some("hello".to_owned()),
            ..ServerSettings::default()
        };
        let named = settings.overlay(&mut snapshot);

        assert_eq!(snapshot.max_users, 20);
        assert_eq!(snapshot.welcome_text, "hello");
        assert!(named.contains(&"max_users".to_owned()));
        assert!(named.contains(&"welcome_text".to_owned()));
        assert_eq!(named.len(), 2, "only what was written is claimed");
    }

    #[test]
    fn zero_is_a_setting_and_not_an_absence() {
        // The one that would be silently wrong with plain (non-`Option`)
        // fields: an operator closing a server to everyone.
        let mut snapshot = defaults(1);
        let named = ServerSettings {
            max_users: Some(0),
            ..ServerSettings::default()
        }
        .overlay(&mut snapshot);
        assert_eq!(snapshot.max_users, 0);
        assert_eq!(named, vec!["max_users".to_owned()]);
    }

    #[test]
    fn every_key_the_file_offers_is_one_the_service_knows() {
        // The two lists are written separately -- this struct, and
        // `server-config`'s field-wise merge -- so a key spelled differently
        // here is a setting an operator can write in the file and never see
        // take effect.
        let all = ServerSettings {
            welcome_text: Some(String::new()),
            password: Some(String::new()),
            max_users: Some(1),
            max_bandwidth: Some(1),
            allow_recording: Some(true),
            broadcast_listener_volume_adjustments: Some(true),
            text_message_length: Some(1),
            image_message_length: Some(1),
            allow_html: Some(true),
            channel_nesting_limit: Some(1),
            channel_count_limit: Some(1),
            listeners_per_channel: Some(1),
            listeners_per_user: Some(1),
            cert_required: Some(true),
            log_days: Some(1),
            message_limit: Some(1),
            message_burst: Some(1),
            plugin_message_limit: Some(1),
            plugin_message_burst: Some(1),
            obfuscate_ips: Some(true),
            allow_ping: Some(true),
            registry_name: Some(String::new()),
            registry_password: Some(String::new()),
            registry_url: Some(String::new()),
            registry_hostname: Some(String::new()),
            registry_location: Some(String::new()),
            users_per_channel: Some(1),
            default_channel: Some(1),
            remember_channel: Some(true),
            remember_channel_duration: Some(1),
            channel_name_regex: Some(String::new()),
            user_name_regex: Some(String::new()),
        };
        let mut snapshot = defaults(1);
        let named = all.overlay(&mut snapshot);

        // Every field of the struct, or the macro above skipped one.
        let fields = toml::Table::try_from(&all).expect("the block serialises");
        assert_eq!(
            named.len(),
            fields.len(),
            "the file offers {} keys but only {} reach a snapshot",
            fields.len(),
            named.len()
        );
    }
}
