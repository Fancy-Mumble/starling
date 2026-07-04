//! The field-level merge, and what is never read back.
//!
//! The **defaults** are not here. They moved to
//! [`starling_runtime::settings::defaults`] when the settings in `§5` of
//! `docs/GAP-ANALYSIS.md` were made to take effect: every service that enforces
//! a setting needs the same answer when this service cannot be reached, and a
//! second copy of a default table is one copy that eventually disagrees — the
//! symptom being a limit that depends on which service restarted last. This
//! module re-exports it so the name still reads as this service's own.

use std::collections::HashMap;

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

/// The readable settings, and the names of the ones withheld.
///
/// Secrets are named but not shown. Saying nothing at all would leave a client
/// unable to tell "no password set" from "password withheld", and the two mean
/// very different things to whoever is looking at the screen.
#[must_use]
pub fn redact(snapshot: &Snapshot) -> (HashMap<String, String>, Vec<String>) {
    let mut values = HashMap::from([
        ("welcome_text".to_owned(), snapshot.welcome_text.clone()),
        ("max_users".to_owned(), snapshot.max_users.to_string()),
        (
            "max_bandwidth".to_owned(),
            snapshot.max_bandwidth.to_string(),
        ),
        (
            "text_message_length".to_owned(),
            snapshot.text_message_length.to_string(),
        ),
        (
            "image_message_length".to_owned(),
            snapshot.image_message_length.to_string(),
        ),
        ("allow_html".to_owned(), snapshot.allow_html.to_string()),
        (
            "allow_recording".to_owned(),
            snapshot.allow_recording.to_string(),
        ),
        (
            "broadcast_listener_volume_adjustments".to_owned(),
            snapshot.broadcast_listener_volume_adjustments.to_string(),
        ),
        (
            "channel_nesting_limit".to_owned(),
            snapshot.channel_nesting_limit.to_string(),
        ),
        (
            "message_limit".to_owned(),
            snapshot.message_limit.to_string(),
        ),
        (
            "message_burst".to_owned(),
            snapshot.message_burst.to_string(),
        ),
        (
            "cert_required".to_owned(),
            snapshot.cert_required.to_string(),
        ),
        ("allow_ping".to_owned(), snapshot.allow_ping.to_string()),
        ("registry_name".to_owned(), snapshot.registry_name.clone()),
        ("registry_url".to_owned(), snapshot.registry_url.clone()),
        (
            "registry_hostname".to_owned(),
            snapshot.registry_hostname.clone(),
        ),
        (
            "registry_location".to_owned(),
            snapshot.registry_location.clone(),
        ),
    ]);
    values.extend(
        snapshot
            .extra
            .iter()
            .map(|(key, value)| (key.clone(), value.clone())),
    );
    // Named but not shown. The registry password proves to the public list that
    // a later update is the same server as the first, so it is exactly as much
    // a secret as the server password is.
    (
        values,
        vec!["password".to_owned(), "registry_password".to_owned()],
    )
}

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
        let (values, withheld) = redact(&snapshot);
        assert!(withheld.contains(&"registry_password".to_owned()));
        assert!(
            !values.values().any(|value| value.contains("hunter2")),
            "the registry password must not appear in a readable field"
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
