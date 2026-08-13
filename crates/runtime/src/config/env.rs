//! Environment overrides, so a Kubernetes `ConfigMap` works without templating
//! and `docker compose` works without a mount.
//!
//! One rule: `[services.text] endpoint` becomes
//! `STARLING_SERVICES_TEXT_ENDPOINT` -- uppercase, dots and dashes to
//! underscores, `STARLING_` prefix.
//!
//! The mapping runs config-to-variable, not the reverse: `link_preview` and
//! `link.preview` would yield the same variable, so the tree is walked and each
//! leaf's name computed, which a reverse split could not disambiguate.

use crate::config::{Config, ConfigError};

/// The environment variable that overrides `path`.
#[must_use]
pub fn env_key(path: &[&str]) -> String {
    let mut key = String::from("STARLING");
    for segment in path {
        key.push('_');
        key.push_str(&segment.replace(['-', '.'], "_").to_uppercase());
    }
    key
}

/// Apply every override present in `vars` to `config`.
///
/// # Errors
///
/// [`ConfigError::Environment`] when a value does not fit its key; a
/// non-numeric port is a startup failure, not a silent default.
pub fn apply_environment(
    config: &mut Config,
    vars: &[(String, String)],
) -> Result<(), ConfigError> {
    fn find<'a>(vars: &'a [(String, String)], key: &str) -> Option<&'a str> {
        vars.iter()
            .find(|(name, _)| name == key)
            .map(|(_, value)| value.as_str())
    }
    let lookup = |key: &str| find(vars, key);

    if let Some(value) = lookup(&env_key(&["runtime", "all_in_one"])) {
        config.runtime.all_in_one = parse(value, "runtime.all_in_one")?;
    }
    if let Some(value) = lookup(&env_key(&["runtime", "data_dir"])) {
        config.runtime.data_dir = value.into();
    }
    // Overridable from the environment like the rest, and for a sharper reason
    // than most: the server that needs it raised is one already running, whose
    // channel tree has just outgrown the default, and an operator reaching for
    // a variable is not editing a `ConfigMap` under a server that is down.
    if let Some(value) = lookup(&env_key(&["runtime", "max_tree_message"])) {
        config.runtime.max_tree_message = parse(value, "runtime.max_tree_message")?;
    }
    if let Some(value) = lookup(&env_key(&["gateway", "listen_tcp"])) {
        config.gateway.listen_tcp = value.to_owned();
    }
    if let Some(value) = lookup(&env_key(&["gateway", "control_queue"])) {
        config.gateway.control_queue = parse(value, "gateway.control_queue")?;
    }
    if let Some(value) = lookup(&env_key(&["telemetry", "metrics"])) {
        config.telemetry.metrics = Some(value.to_owned());
    }
    if let Some(value) = lookup(&env_key(&["telemetry", "otlp_endpoint"])) {
        config.telemetry.otlp_endpoint = Some(value.to_owned());
    }

    apply_service_overrides(config, &lookup)?;
    Ok(())
}

/// The per-service keys Kubernetes actually fills in: endpoints from DNS,
/// binds from the pod spec, and whether a service runs at all.
fn apply_service_overrides<'a>(
    config: &mut Config,
    lookup: &dyn Fn(&str) -> Option<&'a str>,
) -> Result<(), ConfigError> {
    let names: Vec<String> = config.services.keys().cloned().collect();
    for name in names {
        let Some(service) = config.services.get_mut(&name) else {
            continue;
        };
        if let Some(value) = lookup(&env_key(&["services", &name, "endpoint"])) {
            service.endpoint = Some(value.to_owned());
        }
        if let Some(value) = lookup(&env_key(&["services", &name, "bind"])) {
            service.bind = Some(value.to_owned());
        }
        if let Some(value) = lookup(&env_key(&["services", &name, "enabled"])) {
            service.enabled = parse(value, &format!("services.{name}.enabled"))?;
        }
        if let Some(value) = lookup(&env_key(&["services", &name, "storage", "url"])) {
            let storage = service.storage.get_or_insert_with(Default::default);
            storage.url = value.to_owned();
        }
    }
    Ok(())
}

fn parse<T: std::str::FromStr>(value: &str, key: &str) -> Result<T, ConfigError> {
    value.parse().map_err(|_| ConfigError::Environment {
        key: env_key(&[key]),
        reason: format!("{value:?} is not a valid value for {key}"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn a_dashed_service_name_produces_one_unambiguous_variable() {
        // link-preview and link.preview would collide if the variable were
        // split rather than computed.
        assert_eq!(
            env_key(&["services", "link-preview", "endpoint"]),
            "STARLING_SERVICES_LINK_PREVIEW_ENDPOINT"
        );
    }

    #[test]
    fn an_endpoint_from_the_environment_replaces_the_file() {
        let mut config = Config::with_defaults(Path::new("/run/starling"));
        apply_environment(
            &mut config,
            &[(
                "STARLING_SERVICES_TEXT_ENDPOINT".to_owned(),
                "http://text:50051".to_owned(),
            )],
        )
        .expect("a well-formed override applies");
        assert_eq!(
            config.services.get("text").and_then(|s| s.endpoint.clone()),
            Some("http://text:50051".to_owned())
        );
    }

    #[test]
    fn a_malformed_override_fails_startup_rather_than_falling_back() {
        // Falling back would run with a queue size the operator did not choose.
        let mut config = Config::with_defaults(Path::new("/run/starling"));
        let err = apply_environment(
            &mut config,
            &[(
                "STARLING_GATEWAY_CONTROL_QUEUE".to_owned(),
                "lots".to_owned(),
            )],
        )
        .expect_err("a non-numeric queue size must fail");
        assert!(matches!(err, ConfigError::Environment { .. }));
    }

    #[test]
    fn the_tree_limit_can_be_raised_without_editing_a_file() {
        // The server that needs it raised is one already running, whose channel
        // tree has just outgrown the default; a variable is what a `ConfigMap`
        // or a compose file has to hand.
        let mut config = Config::with_defaults(Path::new("/run/starling"));
        apply_environment(
            &mut config,
            &[(
                "STARLING_RUNTIME_MAX_TREE_MESSAGE".to_owned(),
                "128MiB".to_owned(),
            )],
        )
        .expect("a well-formed size applies");
        assert_eq!(config.runtime.max_tree_message.get(), 128 * 1024 * 1024);
    }
}
