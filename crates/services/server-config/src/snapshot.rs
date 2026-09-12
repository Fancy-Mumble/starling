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
            "profile_history" => current.profile_history = values.profile_history,
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
            "users_per_channel" => current.users_per_channel = values.users_per_channel,
            "default_channel" => current.default_channel = values.default_channel,
            "remember_channel" => current.remember_channel = values.remember_channel,
            "remember_channel_duration" => {
                current.remember_channel_duration = values.remember_channel_duration;
            }
            "channel_name_regex" => {
                current.channel_name_regex = values.channel_name_regex.clone();
            }
            "user_name_regex" => current.user_name_regex = values.user_name_regex.clone(),
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
    /// How to put a typed-in value back, answering false when the text does
    /// not fit the field. Beside `read` for the same reason `read` is beside
    /// `kind`: a row that read one setting and wrote another would be a form
    /// whose fields swap under an operator, and nothing about it would look
    /// wrong.
    write: fn(&mut Snapshot, &str) -> bool,
}

/// Parse a whole number, or refuse it.
///
/// Refusing rather than saturating: "12 users" is a mistake, and the two
/// plausible coercions of it -- 12 and 0 -- are a limit the operator did not
/// ask for either way.
fn set_u32(target: &mut u32, value: &str) -> bool {
    match value.trim().parse::<u32>() {
        Ok(parsed) => {
            *target = parsed;
            true
        }
        Err(_) => false,
    }
}

/// Parse a flag the way every client that renders one sends it.
///
/// `1`/`0` as well as the words, because a checkbox has been serialised both
/// ways for as long as there have been forms, and a setting that silently
/// ignores one of them is a switch that does nothing.
fn set_bool(target: &mut bool, value: &str) -> bool {
    match value.trim() {
        "true" | "1" => {
            *target = true;
            true
        }
        "false" | "0" => {
            *target = false;
            true
        }
        _ => false,
    }
}

/// Write an admin's typed-in values into `current`, and name what they changed.
///
/// The wire carries every value as text because a form does: a client renders
/// what [`redact`] describes and hands back what was typed. The schema is the
/// only thing that knows `max_users` is a number, so the coercion belongs here
/// rather than in the service -- one table, one answer, and a knob added to
/// `SCHEMA` becomes settable from a client with no second edit.
///
/// The returned list is what the service records as the operator's, so a value
/// that could not be read must not be on it: a field claimed but never written
/// stops following the deployment file while showing whatever it happened to
/// hold.
///
/// A key with no schema row goes to `extra`, the same place [`apply_fields`]
/// puts it, so a service can add an operator-facing knob without a proto change
/// and have it settable from the admin screen the same day.
#[must_use]
pub fn apply_wire(
    current: &mut Snapshot,
    values: &std::collections::HashMap<String, String>,
) -> Vec<String> {
    // Sorted, because the field list is persisted and logged, and a set that
    // reorders itself every call makes two identical writes look different.
    let ordered: std::collections::BTreeMap<&String, &String> = values.iter().collect();
    let mut written = Vec::new();
    for (key, value) in ordered {
        match SCHEMA.iter().find(|row| row.key == key.as_str()) {
            Some(row) => {
                if (row.write)(current, value) {
                    written.push(key.clone());
                } else {
                    // Reported rather than ignored: an operator who typed
                    // "many" into a limit is owed the reason their change did
                    // not take, and the only place that can say so is here.
                    tracing::info!(
                        field = key.as_str(),
                        "ignoring a settings write whose value does not fit the field"
                    );
                }
            }
            None => {
                let _ = current.extra.insert(key.clone(), value.clone());
                written.push(key.clone());
            }
        }
    }
    written
}

/// Every operator-editable setting, in the order a form should show them.
const SCHEMA: &[Row] = &[
    Row {
        key: "welcome_text",
        kind: Kind::Html,
        group: "General",
        label: "Welcome text",
        help: "Shown to each user once, on connect. Formatting is kept; a client renders it through its own allow-list.",
        secret: false,
        read: |s| s.welcome_text.clone(),
        write: |s, v| {
            s.welcome_text = v.to_owned();
            true
        },
    },
    Row {
        key: "password",
        kind: Kind::String,
        group: "General",
        label: "Server password",
        help: "Required to connect. Empty means the server is open.",
        secret: true,
        read: |_| String::new(),
        write: |s, v| {
            s.password = v.to_owned();
            true
        },
    },
    Row {
        key: "max_users",
        kind: Kind::Int,
        group: "General",
        label: "Maximum users",
        help: "Connections beyond this are rejected as full.",
        secret: false,
        read: |s| s.max_users.to_string(),
        write: |s, v| set_u32(&mut s.max_users, v),
    },
    Row {
        key: "max_bandwidth",
        kind: Kind::Int,
        group: "Audio",
        label: "Maximum bandwidth",
        help: "Bits per second per speaking user.",
        secret: false,
        read: |s| s.max_bandwidth.to_string(),
        write: |s, v| set_u32(&mut s.max_bandwidth, v),
    },
    Row {
        key: "allow_recording",
        kind: Kind::Bool,
        group: "Audio",
        label: "Allow recording",
        help: "Whether clients may record, and announce that they are.",
        secret: false,
        read: |s| s.allow_recording.to_string(),
        write: |s, v| set_bool(&mut s.allow_recording, v),
    },
    Row {
        key: "broadcast_listener_volume_adjustments",
        kind: Kind::Bool,
        group: "Audio",
        label: "Broadcast listener volumes",
        help: "Tell everyone when a user changes a per-channel volume.",
        secret: false,
        read: |s| s.broadcast_listener_volume_adjustments.to_string(),
        write: |s, v| set_bool(&mut s.broadcast_listener_volume_adjustments, v),
    },
    Row {
        key: "text_message_length",
        kind: Kind::Int,
        group: "Messages",
        label: "Maximum message length",
        help: "Characters, measured after markup is stripped.",
        secret: false,
        read: |s| s.text_message_length.to_string(),
        write: |s, v| set_u32(&mut s.text_message_length, v),
    },
    Row {
        key: "image_message_length",
        kind: Kind::Int,
        group: "Messages",
        label: "Maximum image length",
        help: "Bytes, for a message that is an image rather than text.",
        secret: false,
        read: |s| s.image_message_length.to_string(),
        write: |s, v| set_u32(&mut s.image_message_length, v),
    },
    Row {
        key: "allow_html",
        kind: Kind::Bool,
        group: "Messages",
        label: "Allow HTML",
        help: "Whether messages may carry markup.",
        secret: false,
        read: |s| s.allow_html.to_string(),
        write: |s, v| set_bool(&mut s.allow_html, v),
    },
    Row {
        key: "channel_nesting_limit",
        kind: Kind::Int,
        group: "Channels",
        label: "Channel nesting limit",
        help: "How deep the channel tree may go.",
        secret: false,
        read: |s| s.channel_nesting_limit.to_string(),
        write: |s, v| set_u32(&mut s.channel_nesting_limit, v),
    },
    Row {
        key: "users_per_channel",
        kind: Kind::Int,
        group: "Channels",
        label: "Users per channel",
        help: "Occupants any one channel may hold. Zero is unlimited, and a channel with its own limit uses that instead.",
        secret: false,
        read: |s| s.users_per_channel.to_string(),
        write: |s, v| set_u32(&mut s.users_per_channel, v),
    },
    Row {
        key: "channel_name_regex",
        kind: Kind::String,
        group: "Channels",
        label: "Channel name pattern",
        help: "A channel name must match this whole. Empty means no restriction.",
        secret: false,
        read: |s| s.channel_name_regex.clone(),
        write: |s, v| {
            s.channel_name_regex = v.to_owned();
            true
        },
    },
    Row {
        key: "default_channel",
        kind: Kind::Int,
        group: "Channels",
        label: "Default channel",
        help: "Where a user lands when nothing better is known. Zero is the root.",
        secret: false,
        read: |s| s.default_channel.to_string(),
        write: |s, v| set_u32(&mut s.default_channel, v),
    },
    Row {
        key: "remember_channel",
        kind: Kind::Bool,
        group: "Channels",
        label: "Remember last channel",
        help: "Put a registered user back in the channel they left.",
        secret: false,
        read: |s| s.remember_channel.to_string(),
        write: |s, v| set_bool(&mut s.remember_channel, v),
    },
    Row {
        key: "remember_channel_duration",
        kind: Kind::Int,
        group: "Channels",
        label: "Remember for",
        help: "Seconds since they disconnected before that memory expires. Zero is forever.",
        secret: false,
        read: |s| s.remember_channel_duration.to_string(),
        write: |s, v| set_u32(&mut s.remember_channel_duration, v),
    },
    Row {
        key: "profile_history",
        kind: Kind::Int,
        group: "Audit",
        label: "Profile history",
        help: "Past avatars and comments kept per user, for moderators. Zero keeps none.",
        secret: false,
        read: |s| s.profile_history.to_string(),
        write: |s, v| set_u32(&mut s.profile_history, v),
    },
    Row {
        key: "message_limit",
        kind: Kind::Int,
        group: "Rate limits",
        label: "Messages per second",
        help: "Sustained rate before a client is throttled.",
        secret: false,
        read: |s| s.message_limit.to_string(),
        write: |s, v| set_u32(&mut s.message_limit, v),
    },
    Row {
        key: "message_burst",
        kind: Kind::Int,
        group: "Rate limits",
        label: "Message burst",
        help: "How many may arrive at once before the rate applies.",
        secret: false,
        read: |s| s.message_burst.to_string(),
        write: |s, v| set_u32(&mut s.message_burst, v),
    },
    Row {
        key: "cert_required",
        kind: Kind::Bool,
        group: "Access",
        label: "Require a certificate",
        help: "Refuse connections from users without one.",
        secret: false,
        read: |s| s.cert_required.to_string(),
        write: |s, v| set_bool(&mut s.cert_required, v),
    },
    Row {
        key: "user_name_regex",
        kind: Kind::String,
        group: "Access",
        label: "User name pattern",
        help: "A user name must match this whole, at login and at registration. Empty means no restriction.",
        secret: false,
        read: |s| s.user_name_regex.clone(),
        write: |s, v| {
            s.user_name_regex = v.to_owned();
            true
        },
    },
    Row {
        key: "allow_ping",
        kind: Kind::Bool,
        group: "Public listing",
        label: "Answer server-browser pings",
        help: "Also gates public-list registration: a listing nobody can measure is a dead entry.",
        secret: false,
        read: |s| s.allow_ping.to_string(),
        write: |s, v| set_bool(&mut s.allow_ping, v),
    },
    Row {
        key: "registry_name",
        kind: Kind::String,
        group: "Public listing",
        label: "Listed name",
        help: "How the server appears in the public list.",
        secret: false,
        read: |s| s.registry_name.clone(),
        write: |s, v| {
            s.registry_name = v.to_owned();
            true
        },
    },
    Row {
        key: "registry_url",
        kind: Kind::String,
        group: "Public listing",
        label: "Website",
        help: "The page a listing links to. Registration refuses to run without one.",
        secret: false,
        read: |s| s.registry_url.clone(),
        write: |s, v| {
            s.registry_url = v.to_owned();
            true
        },
    },
    Row {
        key: "registry_hostname",
        kind: Kind::String,
        group: "Public listing",
        label: "Hostname",
        help: "The address the public list should reach this server at.",
        secret: false,
        read: |s| s.registry_hostname.clone(),
        write: |s, v| {
            s.registry_hostname = v.to_owned();
            true
        },
    },
    Row {
        key: "registry_location",
        kind: Kind::String,
        group: "Public listing",
        label: "Location",
        help: "ISO country code, shown beside the listing.",
        secret: false,
        read: |s| s.registry_location.clone(),
        write: |s, v| {
            s.registry_location = v.to_owned();
            true
        },
    },
    Row {
        key: "registry_password",
        kind: Kind::String,
        group: "Public listing",
        label: "Listing secret",
        help: "Proves to the public list that a later update is this same server.",
        secret: true,
        read: |_| String::new(),
        write: |s, v| {
            s.registry_password = v.to_owned();
            true
        },
    },
];

#[cfg(test)]
mod tests {
    use super::*;

    /// The map a client sends, from pairs.
    fn wire(pairs: &[(&str, &str)]) -> std::collections::HashMap<String, String> {
        pairs
            .iter()
            .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
            .collect()
    }

    #[test]
    fn a_typed_in_value_reaches_the_field_its_schema_row_describes() {
        // The whole read/write pairing: a form renders what `redact` said and
        // hands the text back, so every kind has to survive the round trip in
        // the type the snapshot holds it as.
        let mut current = defaults(1);
        let written = apply_wire(
            &mut current,
            &wire(&[
                ("welcome_text", "hello"),
                ("max_users", "42"),
                ("allow_html", "false"),
                ("cert_required", "1"),
            ]),
        );

        assert_eq!(current.welcome_text, "hello");
        assert_eq!(current.max_users, 42);
        assert!(!current.allow_html);
        assert!(current.cert_required);
        assert_eq!(
            written,
            vec![
                "allow_html".to_owned(),
                "cert_required".to_owned(),
                "max_users".to_owned(),
                "welcome_text".to_owned(),
            ],
            "the claimed fields are sorted, so two identical writes look identical"
        );
    }

    #[test]
    fn the_welcome_text_is_advertised_as_markup_rather_than_guessed_at() {
        // Every client that renders it puts it through an HTML allow-list, so
        // whoever writes it is writing markup whether or not they were offered
        // a toolbar. Stated here so a client does not have to infer it from the
        // key - which is what one of them did, with a regex over the label.
        let welcome = redact(&defaults(1))
            .into_iter()
            .find(|setting| setting.key == "welcome_text")
            .expect("the welcome text is an editable setting");
        assert_eq!(welcome.kind(), Kind::Html);
    }

    #[test]
    fn a_value_that_does_not_fit_the_field_is_refused_rather_than_coerced() {
        // Both plausible readings of "many" - the parse prefix and zero - are a
        // limit the operator did not ask for, and claiming the field would stop
        // it following the deployment file while holding one of them.
        let mut current = defaults(1);
        let before = current.max_users;
        let written = apply_wire(&mut current, &wire(&[("max_users", "many")]));

        assert_eq!(current.max_users, before, "nothing was written");
        assert!(written.is_empty(), "and nothing was claimed");
    }

    #[test]
    fn a_secret_can_be_written_even_though_it_is_never_read_back() {
        // `redact` withholds it, which is what makes an empty box mean
        // "unchanged" at the far end. A secret that could not be *set* from the
        // same screen would be a field that exists only to look editable.
        let mut current = defaults(1);
        let written = apply_wire(&mut current, &wire(&[("password", "hunter2")]));

        assert_eq!(current.password, "hunter2");
        assert_eq!(written, vec!["password".to_owned()]);
        assert!(
            !redact(&current).iter().any(|s| s.value == "hunter2"),
            "and it still never comes back out"
        );
    }

    #[test]
    fn a_key_with_no_schema_row_is_settable_through_extra() {
        // The other half of `a_setting_with_no_schema_is_offered_rather_than
        // _dropped`: offering a field that cannot be saved is worse than not
        // offering it.
        let mut current = defaults(1);
        let written = apply_wire(&mut current, &wire(&[("whiteboard_max_strokes", "500")]));

        assert_eq!(
            current
                .extra
                .get("whiteboard_max_strokes")
                .map(String::as_str),
            Some("500")
        );
        assert_eq!(written, vec!["whiteboard_max_strokes".to_owned()]);
    }

    #[test]
    fn every_readable_setting_can_also_be_written() {
        // A row whose `write` did not match its `read` would be a field that
        // renders, accepts a value, and silently reverts on the next query.
        for setting in redact(&defaults(1)) {
            let mut current = defaults(1);
            let sample = match setting.kind() {
                Kind::Int => "7",
                Kind::Bool => "true",
                _ => "x",
            };
            assert_eq!(
                apply_wire(&mut current, &wire(&[(&setting.key, sample)])),
                vec![setting.key.clone()],
                "{} is offered by the schema but not settable",
                setting.key
            );
        }
    }

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
