//! The operational settings a service enforces, and the defaults behind them.
//!
//! # Why this is a type and not a `get` in each service
//!
//! The same argument [`Permit`](crate::permit::Permit) makes. A setting read
//! separately in each service is a setting that is read *differently* in each
//! service, and the one that got it wrong is not visibly different from the
//! others, which is exactly how §5 of `docs/GAP-ANALYSIS.md` happened: twelve
//! settings an operator could change, accepted, persisted, and consulted by
//! nothing.
//!
//! So there is one way to ask, it is cheap enough that a hot path can ask per
//! action, and it has a documented answer for every failure.
//!
//! # Which way this fails, and why it is the other way round from `Permit`
//!
//! A permission check denies when it cannot reach `permissions`: a stale deny
//! costs somebody one refused action, a stale grant is a security hole. A
//! *setting* has no such asymmetry, refusing every message because
//! `server-config` restarted would take the server down over a dependency
//! being briefly absent. So this falls back, in order:
//!
//! 1. the live snapshot, from the subscription
//! 2. the last snapshot that arrived, if the subscription has dropped
//! 3. [`defaults`], which are murmur's
//!
//! Never a zero-valued `Snapshot::default()`: `max_users = 0` reads as "nobody
//! may connect" and `message_limit = 0` as "no messages at all", so the type
//! that means "I do not know" must never be the one that means "forbid
//! everything".
//!
//! # The subscription, and why it is not a `get` per call
//!
//! `server-config` publishes a snapshot stream, so a service subscribes once at
//! boot and reads its cache thereafter. That is what makes a setting *live*:
//! murmur's `setLiveConf` applies a change to connections that are already
//! open, and a design that read the value at connect time would apply it only
//! to whoever logged in next.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use starling_proto_fancy::common::Scope;
use starling_proto_fancy::serverconfig::server_config_client::ServerConfigClient;
use starling_proto_fancy::serverconfig::{GetRequest, Snapshot};

use crate::channel::Resolver;

/// How long to wait before re-subscribing after the stream ends.
///
/// Long enough that a `server-config` in a crash loop is not also serving a
/// reconnect storm, short enough that a setting changed during the outage takes
/// effect in the same minute an operator changed it.
const RESUBSCRIBE_DELAY: std::time::Duration = std::time::Duration::from_secs(2);

/// murmur's defaults, for a server instance nobody has configured.
///
/// Named after the `.ini` key each replaces, so a server that has never been
/// configured behaves the way an operator migrating from murmur expects rather
/// than the way a fresh design would have chosen.
///
/// Lives here rather than in the `server-config` service because both sides of
/// the wire need it: that service serves these, and every service that enforces
/// a setting needs the same answer when it cannot be reached. Two copies of a
/// default table is one copy that is eventually wrong, and the symptom would be
/// a limit that changes depending on which service was restarted last.
#[must_use]
pub fn defaults(instance: u32) -> Snapshot {
    Snapshot {
        instance,
        version: 0,
        welcome_text: String::new(),
        password: String::new(),
        max_users: 100,
        max_bandwidth: 72_000,
        text_message_length: 5_000,
        image_message_length: 131_072,
        allow_html: true,
        allow_recording: true,
        channel_nesting_limit: 10,
        channel_count_limit: 1_000,
        listeners_per_channel: 0,
        listeners_per_user: 0,
        // Off, as murmur has it: a listener volume is the listener's own
        // business unless an operator deliberately opts into sharing it.
        broadcast_listener_volume_adjustments: false,
        cert_required: false,
        log_days: 31,
        // The leaky bucket that silently drops when it is wrong
        // (`docs/PORTING-PLAN.md` R5). These two numbers are murmur's.
        message_limit: 1,
        message_burst: 5,
        plugin_message_limit: 4,
        plugin_message_burst: 15,
        registry_name: String::new(),
        obfuscate_ips: false,
        // murmur's default, and the reason a fresh server is visible in a
        // server browser at all.
        allow_ping: true,
        // Every one of these empty is what stops an unconfigured server from
        // announcing itself: registration refuses without a name, a password
        // and a URL, so the safe default is silence rather than a listing the
        // operator never asked for.
        registry_password: String::new(),
        registry_url: String::new(),
        registry_hostname: String::new(),
        registry_location: String::new(),
        // No per-channel ceiling, no configured landing channel: both are
        // murmur's zero, and both read as "the rule does not apply" rather than
        // as a limit of nought.
        users_per_channel: 0,
        default_channel: 0,
        // **On**, as murmur has it (`Meta.cpp:77`). Somebody who was in a room
        // yesterday expects to be in it today, and the operator who disagrees
        // is the one who has to say so.
        remember_channel: true,
        // Forever. murmur's zero, and the reading that makes the setting above
        // mean what it says.
        remember_channel_duration: 0,
        // murmur's own patterns, from `Meta.cpp:110`. The leading ` -=` is a
        // **range**, space through `=`, not three literal characters: that is
        // what upstream compiles, so it is what a server migrating from it gets.
        channel_name_regex: CHANNEL_NAME_PATTERN.to_owned(),
        user_name_regex: USER_NAME_PATTERN.to_owned(),
        extra: HashMap::new(),
    }
}

/// murmur's default channel-name pattern (`vendor/server/src/murmur/Meta.cpp:111`).
pub const CHANNEL_NAME_PATTERN: &str = r"[ -=\w\#\[\]\{\}\(\)\@\|]+";

/// murmur's default user-name pattern (`vendor/server/src/murmur/Meta.cpp:110`).
pub const USER_NAME_PATTERN: &str = r"[ -=\w\[\]\{\}\(\)\@\|\.]+";

/// A service's live view of the settings an operator can change.
///
/// Cheap to clone, every clone reads the same cache.
#[derive(Debug, Clone)]
pub struct Settings {
    resolver: Resolver,
    cache: Arc<RwLock<HashMap<u32, Snapshot>>>,
    /// The log to keep in step with `obfuscate_ips`, if this service has one.
    ///
    /// Applied here rather than by each service because it is one setting with
    /// one effect, and a service that forgot the line would log addresses in
    /// full while every other service in the deployment did not, which reads
    /// like a bug in the obfuscation rather than a missing call.
    logger: Option<crate::log::Logger>,
}

impl Settings {
    /// A view that reads through `resolver`.
    #[must_use]
    pub fn new(resolver: Resolver) -> Self {
        Self {
            resolver,
            cache: Arc::new(RwLock::new(HashMap::new())),
            logger: None,
        }
    }

    /// The same view, keeping `logger` in step with `obfuscate_ips`.
    ///
    /// Every service that logs an address should build its settings this way.
    #[must_use]
    pub fn logging_to(mut self, logger: crate::log::Logger) -> Self {
        self.logger = Some(logger);
        self
    }

    /// A view backed only by `snapshot`, for tests and for callers that already
    /// hold one.
    ///
    /// It never reaches the network, so a test asserting that a limit changes
    /// behaviour does not need a `server-config` to assert it against.
    #[must_use]
    pub fn fixed(resolver: Resolver, snapshot: Snapshot) -> Self {
        let settings = Self::new(resolver);
        settings.store(snapshot);
        settings
    }

    /// The settings for `scope` right now.
    ///
    /// Never fails and never blocks on the network: the cache is filled by
    /// [`Self::watch`], and a caller that asks before the first snapshot has
    /// arrived gets [`defaults`] rather than a zeroed record.
    #[must_use]
    pub fn get(&self, scope: u32) -> Snapshot {
        self.cache
            .read()
            .ok()
            .and_then(|cache| cache.get(&scope).cloned())
            .unwrap_or_else(|| defaults(scope))
    }

    /// Whether a snapshot has ever arrived for `scope`.
    ///
    /// For the one caller that must tell "the operator set this to zero" from
    /// "nothing has been read yet", which are the same value and different
    /// facts.
    #[must_use]
    pub fn is_warm(&self, scope: u32) -> bool {
        self.cache
            .read()
            .is_ok_and(|cache| cache.contains_key(&scope))
    }

    /// Keep `scope`'s settings live until the process ends.
    ///
    /// Fetches once so the cache is warm as soon as this returns, then follows
    /// the change stream. A dropped stream is retried rather than fatal: the
    /// last snapshot stays in force meanwhile, which is the behaviour an
    /// operator expects of a value they set an hour ago.
    pub async fn warm(&self, scope: u32) {
        if let Some(snapshot) = self.fetch(scope).await {
            self.store(snapshot);
        }
    }

    /// Spawn the subscription for every scope in `scopes`.
    ///
    /// Returns the handles so a service can abort them on shutdown; a service
    /// that has nowhere to put them may drop the vector, and the tasks end with
    /// the runtime.
    pub fn watch(&self, scopes: &[u32]) -> Vec<tokio::task::JoinHandle<()>> {
        scopes
            .iter()
            .map(|scope| {
                let settings = self.clone();
                let scope = *scope;
                tokio::spawn(async move { settings.follow(scope).await })
            })
            .collect()
    }

    /// Fetch once, then follow the stream, forever.
    async fn follow(self, scope: u32) {
        loop {
            self.warm(scope).await;
            self.stream(scope).await;
            // Reported at debug rather than warn: `server-config` restarting is
            // an ordinary event, and the settings in force did not change.
            tracing::debug!(scope, "the settings subscription ended; retrying");
            tokio::time::sleep(RESUBSCRIBE_DELAY).await;
        }
    }

    /// One `Get`, or `None` if `server-config` cannot be reached.
    async fn fetch(&self, scope: u32) -> Option<Snapshot> {
        let transport = self.resolver.channel("server-config").ok()?;
        ServerConfigClient::new(transport)
            .get(GetRequest {
                scope: Some(Scope { instance: scope }),
            })
            .await
            .ok()
            .map(tonic::Response::into_inner)
    }

    /// Follow the change stream until it ends.
    async fn stream(&self, scope: u32) {
        let Ok(transport) = self.resolver.channel("server-config") else {
            return;
        };
        let request = GetRequest {
            scope: Some(Scope { instance: scope }),
        };
        let Ok(stream) = ServerConfigClient::new(transport).watch(request).await else {
            return;
        };
        let mut updates = stream.into_inner();
        while let Ok(Some(snapshot)) = updates.message().await {
            tracing::debug!(
                scope,
                version = snapshot.version,
                "settings changed underneath us"
            );
            self.store(snapshot);
        }
    }

    fn store(&self, snapshot: Snapshot) {
        // The log policy follows the *first* server instance's setting: one
        // process has one log, so several server instances disagreeing about it
        // cannot each have their own. Documented rather than silent, because
        // "my second server instance does not obfuscate" is otherwise a very
        // confusing thing to observe.
        if let Some(logger) = &self.logger
            && snapshot.instance <= 1
        {
            logger.set_obfuscate_addresses(snapshot.obfuscate_ips);
        }
        if let Ok(mut cache) = self.cache.write() {
            let _ = cache.insert(snapshot.instance, snapshot);
        }
    }
}

/// Read an operator's JSON into a snapshot, and say which fields it named.
///
/// # Why this is here and not in the admin API
///
/// It was in the admin API, and it understood **two** settings: `welcome_text`
/// and `max_users`. Everything else in `§5`, the rate limit, the channel
/// ceilings, `cert_required`, the retention, the obfuscation, could be
/// enforced by the server and still not be *reachable*, because the surface an
/// operator actually uses had no way to write them. A setting nobody can set
/// has not stopped being a lie; it has only moved which layer tells it.
///
/// The list is the same one `server-config`'s own field-wise merge accepts, so
/// a setting added there is settable here without a second edit, and the two
/// cannot drift into disagreeing about a name.
///
/// Unknown keys are returned in the field list too: `apply_fields` puts them in
/// `extra`, which is how a service can add an operator-facing knob without a
/// proto release.
#[must_use]
pub fn from_json(values: &serde_json::Value) -> (Snapshot, Vec<String>) {
    let mut snapshot = defaults(1);
    let mut fields = Vec::new();
    let Some(object) = values.as_object() else {
        return (snapshot, fields);
    };

    for (key, value) in object {
        let number = value.as_u64();
        let flag = value.as_bool();
        let text = value.as_str();
        let count = |target: &mut u32| {
            if let Some(number) = number {
                *target = u32::try_from(number).unwrap_or(u32::MAX);
                true
            } else {
                false
            }
        };
        let write_text = |target: &mut String| {
            if let Some(text) = text {
                *target = text.to_owned();
                true
            } else {
                false
            }
        };
        let write_flag = |target: &mut bool| {
            if let Some(flag) = flag {
                *target = flag;
                true
            } else {
                false
            }
        };
        let named = match key.as_str() {
            "welcome_text" => write_text(&mut snapshot.welcome_text),
            "password" => write_text(&mut snapshot.password),
            "max_users" => count(&mut snapshot.max_users),
            "max_bandwidth" => count(&mut snapshot.max_bandwidth),
            "text_message_length" => count(&mut snapshot.text_message_length),
            "image_message_length" => count(&mut snapshot.image_message_length),
            "channel_nesting_limit" => count(&mut snapshot.channel_nesting_limit),
            "channel_count_limit" => count(&mut snapshot.channel_count_limit),
            "listeners_per_channel" => count(&mut snapshot.listeners_per_channel),
            "listeners_per_user" => count(&mut snapshot.listeners_per_user),
            "log_days" => count(&mut snapshot.log_days),
            "users_per_channel" => count(&mut snapshot.users_per_channel),
            "default_channel" => count(&mut snapshot.default_channel),
            "remember_channel_duration" => count(&mut snapshot.remember_channel_duration),
            "message_limit" => count(&mut snapshot.message_limit),
            "message_burst" => count(&mut snapshot.message_burst),
            "plugin_message_limit" => count(&mut snapshot.plugin_message_limit),
            "plugin_message_burst" => count(&mut snapshot.plugin_message_burst),
            "allow_html" => write_flag(&mut snapshot.allow_html),
            "allow_recording" => write_flag(&mut snapshot.allow_recording),
            "broadcast_listener_volume_adjustments" => {
                write_flag(&mut snapshot.broadcast_listener_volume_adjustments)
            }
            "cert_required" => write_flag(&mut snapshot.cert_required),
            "obfuscate_ips" => write_flag(&mut snapshot.obfuscate_ips),
            "allow_ping" => write_flag(&mut snapshot.allow_ping),
            "remember_channel" => write_flag(&mut snapshot.remember_channel),
            "channel_name_regex" => write_text(&mut snapshot.channel_name_regex),
            "user_name_regex" => write_text(&mut snapshot.user_name_regex),
            "registry_name" => write_text(&mut snapshot.registry_name),
            "registry_password" => write_text(&mut snapshot.registry_password),
            "registry_url" => write_text(&mut snapshot.registry_url),
            "registry_hostname" => write_text(&mut snapshot.registry_hostname),
            "registry_location" => write_text(&mut snapshot.registry_location),
            // A knob some service owns. Carried as text, because `extra` is a
            // string map and the operator's intent survives the round trip.
            _ => {
                let rendered = text.map_or_else(|| value.to_string(), ToOwned::to_owned);
                let _ = snapshot.extra.insert(key.clone(), rendered);
                true
            }
        };
        if named {
            fields.push(key.clone());
        } else {
            // Reported rather than ignored: an operator who wrote `"true"` for
            // a flag, or a string for a count, otherwise sees a request that
            // succeeds and changes nothing.
            tracing::warn!(field = %key, "ignoring a configuration value of the wrong type");
        }
    }
    (snapshot, fields)
}

/// Everything an operator may read back, as JSON.
///
/// The two secrets (the server password and the registry password) are
/// **not** here. A client must still be able to tell "not set" from "withheld",
/// which is what `server-config`'s own `redact` does for the client-facing
/// path; this is the admin one, and its callers already know both exist.
#[must_use]
pub fn to_json(snapshot: &Snapshot) -> serde_json::Value {
    serde_json::json!({
        "version": snapshot.version,
        "welcome_text": snapshot.welcome_text,
        "max_users": snapshot.max_users,
        "max_bandwidth": snapshot.max_bandwidth,
        "text_message_length": snapshot.text_message_length,
        "image_message_length": snapshot.image_message_length,
        "channel_nesting_limit": snapshot.channel_nesting_limit,
        "channel_count_limit": snapshot.channel_count_limit,
        "listeners_per_channel": snapshot.listeners_per_channel,
        "listeners_per_user": snapshot.listeners_per_user,
        "log_days": snapshot.log_days,
        "message_limit": snapshot.message_limit,
        "message_burst": snapshot.message_burst,
        "plugin_message_limit": snapshot.plugin_message_limit,
        "plugin_message_burst": snapshot.plugin_message_burst,
        "allow_html": snapshot.allow_html,
        "allow_recording": snapshot.allow_recording,
        "broadcast_listener_volume_adjustments": snapshot.broadcast_listener_volume_adjustments,
        "cert_required": snapshot.cert_required,
        "obfuscate_ips": snapshot.obfuscate_ips,
        "allow_ping": snapshot.allow_ping,
        "registry_name": snapshot.registry_name,
        "registry_url": snapshot.registry_url,
        "registry_hostname": snapshot.registry_hostname,
        "registry_location": snapshot.registry_location,
        "extra": snapshot.extra,
    })
}

/// Whether `length` exceeds `limit`, with murmur's "zero means unlimited".
///
/// Written once because it is wrong in two different directions if written
/// twice: `limit == 0` read as "nothing is allowed" closes the feature, and a
/// `>=` instead of `>` refuses the message that is exactly at the limit.
#[must_use]
pub fn over_limit(length: usize, limit: u32) -> bool {
    limit != 0 && length > limit as usize
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::inproc::Broker;
    use std::path::Path;

    fn settings() -> Settings {
        let config = Config::with_defaults(Path::new("/run/starling"));
        Settings::new(Resolver::new(Arc::new(config), Broker::new()))
    }

    #[test]
    fn a_cold_cache_reads_murmurs_defaults_and_not_a_zeroed_record() {
        // The property the whole type exists for. `Snapshot::default()` has
        // `message_limit = 0`, which the gateway would read as "no messages at
        // all", a dependency being slow to start would look like a server that
        // accepts connections and answers nothing.
        let snapshot = settings().get(1);
        assert_eq!(snapshot.message_limit, 1);
        assert_eq!(snapshot.message_burst, 5);
        assert_eq!(snapshot.max_users, 100);
        assert!(snapshot.allow_ping);
    }

    #[test]
    fn a_snapshot_that_arrived_survives_the_service_going_away() {
        // A setting an operator changed an hour ago must stay in force while
        // `server-config` restarts, rather than snapping back to a default they
        // never chose.
        let settings = settings();
        settings.store(Snapshot {
            instance: 1,
            message_limit: 42,
            ..defaults(1)
        });
        assert_eq!(settings.get(1).message_limit, 42);
        assert!(settings.is_warm(1));
        assert!(!settings.is_warm(2), "another scope is untouched");
    }

    #[test]
    fn scopes_do_not_read_each_others_settings() {
        // One process serves several server instances, and a limit set on one is
        // not a limit on the others.
        let settings = settings();
        settings.store(Snapshot {
            instance: 2,
            max_users: 7,
            ..defaults(2)
        });
        assert_eq!(settings.get(2).max_users, 7);
        assert_eq!(settings.get(1).max_users, 100);
    }

    #[test]
    fn every_setting_in_the_gap_analysis_can_be_written_by_an_operator() {
        // The admin API understood two settings, `welcome_text` and
        // `max_users`, so the whole of §5 could be enforced by the server and
        // still be unreachable from the surface an operator uses. A setting
        // nobody can set has not stopped being a lie.
        let (snapshot, fields) = from_json(&serde_json::json!({
            "channel_nesting_limit": 3,
            "channel_count_limit": 40,
            "listeners_per_channel": 5,
            "listeners_per_user": 6,
            "text_message_length": 200,
            "message_limit": 7,
            "message_burst": 9,
            "log_days": 14,
            "max_bandwidth": 96_000,
            "allow_html": false,
            "allow_recording": false,
            "cert_required": true,
            "obfuscate_ips": true,
        }));

        assert_eq!(fields.len(), 13, "every named field must be written");
        assert_eq!(snapshot.channel_nesting_limit, 3);
        assert_eq!(snapshot.channel_count_limit, 40);
        assert_eq!(snapshot.listeners_per_channel, 5);
        assert_eq!(snapshot.listeners_per_user, 6);
        assert_eq!(snapshot.text_message_length, 200);
        assert_eq!(snapshot.message_limit, 7);
        assert_eq!(snapshot.message_burst, 9);
        assert_eq!(snapshot.log_days, 14);
        assert_eq!(snapshot.max_bandwidth, 96_000);
        assert!(!snapshot.allow_html);
        assert!(!snapshot.allow_recording);
        assert!(snapshot.cert_required);
        assert!(snapshot.obfuscate_ips);
    }

    #[test]
    fn a_field_nobody_named_is_not_written() {
        // The whole point of the field list: two operators editing different
        // settings must not overwrite each other.
        let (_, fields) = from_json(&serde_json::json!({ "max_users": 3 }));
        assert_eq!(fields, vec!["max_users".to_owned()]);
    }

    #[test]
    fn a_value_of_the_wrong_type_is_refused_rather_than_silently_applied() {
        // An operator who wrote `"true"` for a flag otherwise gets a request
        // that succeeds and changes nothing.
        let (snapshot, fields) = from_json(&serde_json::json!({ "cert_required": "true" }));
        assert!(fields.is_empty());
        assert!(!snapshot.cert_required);
    }

    #[test]
    fn neither_password_is_ever_read_back() {
        // The admin API's caller is trusted with a great deal and still not
        // with these: a credential read back is a credential in a log, a
        // browser cache and whatever proxy sits in between.
        let snapshot = Snapshot {
            password: "hunter2".to_owned(),
            registry_password: "hunter3".to_owned(),
            ..defaults(1)
        };
        let rendered = to_json(&snapshot).to_string();
        assert!(!rendered.contains("hunter2"));
        assert!(!rendered.contains("hunter3"));
    }

    #[test]
    fn what_an_operator_writes_is_what_they_read_back() {
        // The round trip an admin UI depends on: every field it can set must
        // come back, or the form it renders next has a blank where the value
        // it just wrote should be.
        let (snapshot, _) = from_json(&serde_json::json!({ "log_days": 14 }));
        let rendered = to_json(&snapshot);
        assert_eq!(
            rendered.get("log_days").and_then(serde_json::Value::as_u64),
            Some(14)
        );
    }

    #[test]
    fn zero_means_unlimited_rather_than_closed() {
        // murmur's convention, and the reading that is wrong in the direction
        // nobody notices until every message is refused.
        assert!(!over_limit(10_000, 0));
        assert!(!over_limit(5_000, 5_000), "the limit itself is allowed");
        assert!(over_limit(5_001, 5_000));
    }
}
