//! The field-level merge, and what is never read back.
//!
//! The **defaults** are not here. They moved to
//! [`starling_runtime::settings::defaults`] when the settings in `§5` of
//! `docs/GAP-ANALYSIS.md` were made to take effect: every service that enforces
//! a setting needs the same answer when this service cannot be reached, and a
//! second copy of a default table is one copy that eventually disagrees, the
//! symptom being a limit that depends on which service restarted last. This
//! module re-exports it so the name still reads as this service's own.

use starling_proto_fancy::fancy::domain::{Setting, setting::Kind};
use starling_proto_fancy::serverconfig::Snapshot;

pub use starling_runtime::settings::defaults;

/// Copy only `fields` from `values` into `current`.
///
/// A whole-snapshot write would make two operators editing different settings
/// silently overwrite each other, which is a data-loss bug that looks like a
/// race and reproduces once a month.
pub fn apply_fields(current: &mut Snapshot, values: &Snapshot, fields: &[String]) {
    for field in fields {
        match field.as_str() {
            "welcome_text" => current.welcome_text = values.welcome_text.clone(),
            "password" => current.password = values.password.clone(),
            "max_users" => current.max_users = values.max_users,
            "max_bandwidth" => current.max_bandwidth = values.max_bandwidth,
            "text_message_length" => current.text_message_length = values.text_message_length,
            "image_message_length" => current.image_message_length = values.image_message_length,
            "allow_html" => current.allow_html = values.allow_html,
            "allow_recording" => current.allow_recording = values.allow_recording,
            "broadcast_listener_volume_adjustments" => {
                current.broadcast_listener_volume_adjustments =
                    values.broadcast_listener_volume_adjustments;
            }
            "channel_nesting_limit" => current.channel_nesting_limit = values.channel_nesting_limit,
            "channel_count_limit" => current.channel_count_limit = values.channel_count_limit,
            "listeners_per_channel" => current.listeners_per_channel = values.listeners_per_channel,
            "listeners_per_user" => current.listeners_per_user = values.listeners_per_user,
            "cert_required" => current.cert_required = values.cert_required,
            "log_days" => current.log_days = values.log_days,
            "message_limit" => current.message_limit = values.message_limit,
            "message_burst" => current.message_burst = values.message_burst,
            "plugin_message_limit" => current.plugin_message_limit = values.plugin_message_limit,
            "plugin_message_burst" => current.plugin_message_burst = values.plugin_message_burst,
            "registry_name" => current.registry_name = values.registry_name.clone(),
            "obfuscate_ips" => current.obfuscate_ips = values.obfuscate_ips,
            "allow_ping" => current.allow_ping = values.allow_ping,
            "registry_password" => current.registry_password = values.registry_password.clone(),
            "registry_url" => current.registry_url = values.registry_url.clone(),
            "registry_hostname" => current.registry_hostname = values.registry_hostname.clone(),
            "registry_location" => current.registry_location = values.registry_location.clone(),
            other => {
                // Unknown keys land in `extra` rather than being dropped: a
                // service that adds an operator-facing knob should not need a
                // proto release for it to be settable.
                if let Some(value) = values.extra.get(other) {
                    let _ = current.extra.insert(other.to_owned(), value.clone());
                } else {
                    tracing::warn!(field = other, "ignoring an unknown configuration field");
                }
            }
        }
    }
}

/// The readable settings, with the schema a client renders them from.
///
/// Schema and value live in one table on purpose. They used to be two, a map
/// of values and a separate list of withheld names, and two lists keyed by the
/// same strings drift: a secret added to one and not the other is a password
/// printed on a settings screen.
///
/// Secrets are named but never valued. Saying nothing at all would leave a
/// client unable to tell "no password set" from "password withheld", and the
/// two mean very different things to whoever is looking at the screen.
#[must_use]
pub fn redact(snapshot: &Snapshot) -> Vec<Setting> {
    let mut settings: Vec<Setting> = SCHEMA
        .iter()
        .map(|row| Setting {
            key: row.key.to_owned(),
            kind: row.kind as i32,
            group: row.group.to_owned(),
            label: row.label.to_owned(),
            // The one place secrecy is enforced, rather than at each call site.
            value: if row.secret {
                String::new()
            } else {
                (row.read)(snapshot)
            },
            options: Vec::new(),
            secret: row.secret,
            help: row.help.to_owned(),
        })
        .collect();

    // Keys a service added without a proto change (`Snapshot.extra`). They have
    // no schema, so they are offered as plain strings under their own heading
    // rather than dropped, an operator can still read and set them, and the
    // absence of a label is visible instead of silent.
    settings.extend(snapshot.extra.iter().map(|(key, value)| Setting {
        key: key.clone(),
        kind: Kind::String as i32,
        group: "Other".to_owned(),
        label: key.clone(),
        value: value.clone(),
        options: Vec::new(),
        secret: false,
        help: String::new(),
    }));
    settings
}

/// One row of the settings schema: what a field is, and how to read it.
struct Row {
    key: &'static str,
    kind: Kind,
    group: &'static str,
    label: &'static str,
    help: &'static str,
    /// Never sent outward with a value, and only ever received.
    secret: bool,
    /// How to project it out of a snapshot. A function rather than a second
    /// table, so a row cannot describe one setting and read another.
    read: fn(&Snapshot) -> String,
}

/// Every operator-editable setting, in the order a form should show them.
const SCHEMA: &[Row] = &[
    Row {
        key: "welcome_text",
        kind: Kind::Text,
        group: "General",
        label: "Welcome text",
        help: "Shown to each user once, on connect.",
        secret: false,
        read: |s| s.welcome_text.clone(),
    },
    Row {
        key: "password",
        kind: Kind::String,
        group: "General",
        label: "Server password",
        help: "Required to connect. Empty means the server is open.",
        secret: true,
        read: |_| String::new(),
    },
    Row {
        key: "max_users",
        kind: Kind::Int,
        group: "General",
        label: "Maximum users",
        help: "Connections beyond this are rejected as full.",
        secret: false,
        read: |s| s.max_users.to_string(),
    },
    Row {
        key: "max_bandwidth",
        kind: Kind::Int,
        group: "Audio",
        label: "Maximum bandwidth",
        help: "Bits per second per speaking user.",
        secret: false,
        read: |s| s.max_bandwidth.to_string(),
    },
    Row {
        key: "allow_recording",
        kind: Kind::Bool,
        group: "Audio",
        label: "Allow recording",
        help: "Whether clients may record, and announce that they are.",
        secret: false,
        read: |s| s.allow_recording.to_string(),
    },
    Row {
        key: "broadcast_listener_volume_adjustments",
        kind: Kind::Bool,
        group: "Audio",
        label: "Broadcast listener volumes",
        help: "Tell everyone when a user changes a per-channel volume.",
        secret: false,
        read: |s| s.broadcast_listener_volume_adjustments.to_string(),
    },
    Row {
        key: "text_message_length",
        kind: Kind::Int,
        group: "Messages",
        label: "Maximum message length",
        help: "Characters, measured after markup is stripped.",
        secret: false,
        read: |s| s.text_message_length.to_string(),
    },
    Row {
        key: "image_message_length",
        kind: Kind::Int,
        group: "Messages",
        label: "Maximum image length",
        help: "Bytes, for a message that is an image rather than text.",
        secret: false,
        read: |s| s.image_message_length.to_string(),
    },
    Row {
        key: "allow_html",
        kind: Kind::Bool,
        group: "Messages",
        label: "Allow HTML",
        help: "Whether messages may carry markup.",
        secret: false,
        read: |s| s.allow_html.to_string(),
    },
    Row {
        key: "channel_nesting_limit",
        kind: Kind::Int,
        group: "Channels",
        label: "Channel nesting limit",
        help: "How deep the channel tree may go.",
        secret: false,
        read: |s| s.channel_nesting_limit.to_string(),
    },
    Row {
        key: "message_limit",
        kind: Kind::Int,
        group: "Rate limits",
        label: "Messages per second",
        help: "Sustained rate before a client is throttled.",
        secret: false,
        read: |s| s.message_limit.to_string(),
    },
    Row {
        key: "message_burst",
        kind: Kind::Int,
        group: "Rate limits",
        label: "Message burst",
        help: "How many may arrive at once before the rate applies.",
        secret: false,
        read: |s| s.message_burst.to_string(),
    },
    Row {
        key: "cert_required",
        kind: Kind::Bool,
        group: "Access",
        label: "Require a certificate",
        help: "Refuse connections from users without one.",
        secret: false,
        read: |s| s.cert_required.to_string(),
    },
    Row {
        key: "allow_ping",
        kind: Kind::Bool,
        group: "Public listing",
        label: "Answer server-browser pings",
        help: "Also gates public-list registration: a listing nobody can measure is a dead entry.",
        secret: false,
        read: |s| s.allow_ping.to_string(),
    },
    Row {
        key: "registry_name",
        kind: Kind::String,
        group: "Public listing",
        label: "Listed name",
        help: "How the server appears in the public list.",
        secret: false,
        read: |s| s.registry_name.clone(),
    },
    Row {
        key: "registry_url",
        kind: Kind::String,
        group: "Public listing",
        label: "Website",
        help: "The page a listing links to. Registration refuses to run without one.",
        secret: false,
        read: |s| s.registry_url.clone(),
    },
    Row {
        key: "registry_hostname",
        kind: Kind::String,
        group: "Public listing",
        label: "Hostname",
        help: "The address the public list should reach this server at.",
        secret: false,
        read: |s| s.registry_hostname.clone(),
    },
    Row {
        key: "registry_location",
        kind: Kind::String,
        group: "Public listing",
        label: "Location",
        help: "ISO country code, shown beside the listing.",
        secret: false,
        read: |s| s.registry_location.clone(),
    },
    Row {
        key: "registry_password",
        kind: Kind::String,
        group: "Public listing",
        label: "Listing secret",
        help: "Proves to the public list that a later update is this same server.",
        secret: true,
        read: |_| String::new(),
    },
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_unknown_field_is_kept_in_extra_rather_than_dropped() {
        // A service adding an operator-facing knob should not need a proto
        // release before an operator can set it.
        let mut current = defaults(1);
        let mut values = defaults(1);
        let _ = values
            .extra
            .insert("whiteboard_max_strokes".to_owned(), "500".to_owned());
        apply_fields(
            &mut current,
            &values,
            &["whiteboard_max_strokes".to_owned()],
        );
        assert_eq!(
            current
                .extra
                .get("whiteboard_max_strokes")
                .map(String::as_str),
            Some("500")
        );
    }

    #[test]
    fn a_server_nobody_configured_is_pingable_but_unlisted() {
        // Two different defaults, and both are murmur's. Ping on, because a
        // server absent from every browser looks broken. Registration off,
        // because announcing a server to a public list is the operator's
        // decision and cannot be undone by them changing their mind.
        let snapshot = defaults(1);
        assert!(snapshot.allow_ping);
        assert!(snapshot.registry_name.is_empty());
        assert!(snapshot.registry_password.is_empty());
        assert!(snapshot.registry_url.is_empty());
    }

    #[test]
    fn the_registry_password_is_named_but_never_shown() {
        // A client must be able to tell "not set" from "withheld"; the two mean
        // very different things to whoever is looking at the screen.
        let mut snapshot = defaults(1);
        snapshot.registry_password = "hunter2".to_owned();
        let settings = redact(&snapshot);
        let listed = settings
            .iter()
            .find(|s| s.key == "registry_password")
            .expect("named even though it is withheld");
        assert!(listed.secret);
        assert!(
            !settings.iter().any(|s| s.value.contains("hunter2")),
            "the registry password must not appear in a readable field"
        );
    }

    #[test]
    fn every_setting_carries_enough_schema_to_render_itself() {
        // The point of the change: a client builds the form from this and
        // nothing else, so a row without a label or a group is a field that
        // shows up blank or in the wrong section, and one whose kind defaults
        // to STRING renders a checkbox as a text box.
        for setting in redact(&defaults(1)) {
            assert!(!setting.key.is_empty());
            assert!(!setting.label.is_empty(), "{} has no label", setting.key);
            assert!(!setting.group.is_empty(), "{} has no group", setting.key);
            assert!(!setting.help.is_empty(), "{} has no help", setting.key);
        }
    }

    #[test]
    fn a_setting_with_no_schema_is_offered_rather_than_dropped() {
        // `Snapshot.extra` exists so a service can add an operator-facing knob
        // without a proto release. Dropping those from the form would make the
        // mechanism useless the moment anyone used it.
        let mut snapshot = defaults(1);
        let _ = snapshot
            .extra
            .insert("some_new_knob".to_owned(), "7".to_owned());
        let settings = redact(&snapshot);
        let extra = settings
            .iter()
            .find(|s| s.key == "some_new_knob")
            .expect("an unschema'd key is still offered");
        assert_eq!(extra.value, "7");
        assert!(
            !extra.secret,
            "an unknown key must not be treated as secret"
        );
    }

    #[test]
    fn the_defaults_are_murmurs_and_not_a_fresh_designs() {
        // An operator migrating from murmur must not silently get different
        // limits than the ones their clients were tuned against.
        let snapshot = defaults(1);
        assert_eq!(snapshot.max_bandwidth, 72_000);
        assert_eq!(snapshot.text_message_length, 5_000);
        assert_eq!(snapshot.log_days, 31);
    }
}
