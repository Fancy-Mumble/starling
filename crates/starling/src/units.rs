//! The table of what this binary can be.
//!
//! One entry per service, and the only place the concrete service types are
//! named. Everything below this file depends on the `Serve` trait and nothing
//! else, which is what makes the composition swappable without a service
//! knowing it has been composed.

use starling_runtime::serve::{ServiceContext, ServiceError};

// Used by the test below, which is the only thing in this binary that needs the
// protocol's own view of which services exist.
use starling_proto_fancy as _;

/// Start one service by name.
///
/// Returns `None` when nothing answers to that name, so the caller can print
/// the list rather than guess.
pub(crate) fn spawn(
    name: &str,
    ctx: ServiceContext,
) -> Option<tokio::task::JoinHandle<Result<(), ServiceError>>> {
    use starling_runtime::serve::spawn;
    Some(match name {
        "session-lifecycle" => spawn::<starling_session_lifecycle::SessionLifecycleService>(ctx),
        "session-view" => spawn::<starling_session_view::SessionViewService>(ctx),
        "permissions" => spawn::<starling_permissions::PermissionsService>(ctx),
        "metadata" => spawn::<starling_metadata::MetadataService>(ctx),
        "userdata" => spawn::<starling_userdata::UserdataService>(ctx),
        "server-config" => spawn::<starling_server_config::ServerConfigService>(ctx),
        "voice" => spawn::<starling_voice::VoiceService>(ctx),
        "text" => spawn::<starling_text::TextService>(ctx),
        "pchat" => spawn::<starling_pchat::PchatService>(ctx),
        "moderation" => spawn::<starling_moderation::ModerationService>(ctx),
        "screenshare" => spawn::<starling_screenshare::ScreenshareService>(ctx),
        "files" => spawn::<starling_files::FilesService>(ctx),
        "plugins" => spawn::<starling_plugins::PluginsService>(ctx),
        "push" => spawn::<starling_push::PushService>(ctx),
        "audit" => spawn::<starling_audit::AuditService>(ctx),
        "onboarding" => spawn::<starling_onboarding::OnboardingService>(ctx),
        "social" => spawn::<starling_social::SocialService>(ctx),
        "link-preview" => spawn::<starling_link_preview::LinkPreviewService>(ctx),
        "context-actions" => spawn::<starling_context_actions::ContextActionsService>(ctx),
        "directory" => spawn::<starling_directory::DirectoryService>(ctx),
        "operator-api" => spawn::<starling_operator_api::OperatorApi>(ctx),
        "health" => spawn::<starling_health::HealthService>(ctx),
        "gateway" => spawn::<starling_gateway::GatewayService>(ctx),
        _ => return None,
    })
}

/// Every service this binary can be, in tier order.
#[must_use]
pub(crate) fn names() -> &'static [&'static str] {
    &[
        "session-lifecycle",
        "session-view",
        "permissions",
        "metadata",
        "userdata",
        "server-config",
        "voice",
        "text",
        "pchat",
        "moderation",
        "screenshare",
        "files",
        "plugins",
        "push",
        "audit",
        "onboarding",
        "social",
        "link-preview",
        "context-actions",
        // No wire type and no gRPC surface: nothing calls it, it calls out.
        "directory",
        // No wire type either, but it does serve gRPC: it collects every
        // other service's readiness and `operator-api` reads the aggregate.
        // Listed last of the collectors so its first sweep finds the rest
        // already spawning rather than reporting a server that is not up yet.
        "health",
        "operator-api",
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use starling_proto_fancy::ServiceKind;

    #[test]
    fn every_service_with_an_outer_type_can_be_started() {
        // A service the protocol allocates a type to but the binary cannot run
        // is a routing table entry that never answers.
        for kind in ServiceKind::all() {
            assert!(
                names().contains(&kind.name()),
                "{} cannot be started by name",
                kind.name()
            );
        }
    }

    /// Every configuration file this repository ships, by the name an operator
    /// knows it as.
    ///
    /// The examples are here as well as the two deployment files: each is meant
    /// to be `include`d as it stands, so one that does not load is one an
    /// operator finds out about by their server failing to start.
    fn shipped_configs() -> Vec<(String, std::path::PathBuf)> {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let mut configs = vec![
            (
                "starling.example.toml".to_owned(),
                root.join("starling.example.toml"),
            ),
            (
                "deploy/starling.toml".to_owned(),
                root.join("deploy/starling.toml"),
            ),
        ];
        for directory in ["examples", "examples/advanced"] {
            let mut fragments: Vec<_> = std::fs::read_dir(root.join(directory))
                .unwrap_or_else(|error| panic!("{directory} must exist: {error}"))
                .filter_map(|entry| entry.ok().map(|entry| entry.path()))
                .filter(|path| path.extension().is_some_and(|ext| ext == "toml"))
                .map(|path| {
                    let name = path
                        .file_name()
                        .unwrap_or_default()
                        .to_string_lossy()
                        .into_owned();
                    (format!("{directory}/{name}"), path)
                })
                .collect();
            fragments.sort();
            configs.append(&mut fragments);
        }
        configs
    }

    #[test]
    fn every_shipped_config_loads_and_leaves_every_service_configured() {
        // A file is an overlay on `Config::with_defaults` rather than a
        // replacement for it, which is what makes a six-line configuration a
        // working server. Before that, a service a file forgot was a service
        // the operator silently switched off by passing a file at all: it
        // happened to `health`, and `/v1/health` -- the one route a dashboard
        // opens on -- answered 502 with nothing to say why.
        //
        // Through the real loader, not `toml::from_str`: this asserts what an
        // operator gets from `--config`, and a test with its own parser would
        // pass while the thing it stands for fails.
        for (label, path) in shipped_configs() {
            let config = starling_runtime::config::Config::load(&path)
                .unwrap_or_else(|error| panic!("`{label}` loads: {error}"));

            for name in names() {
                // The one service whose absence is the point: `operator-api` is
                // the highest-privilege surface there is, `Config::with_defaults`
                // deliberately creates no entry for it, and `compose::enabled`
                // reads that absence as "off". Requiring a block here would be
                // requiring every file to mention the admin plane.
                if *name == "operator-api" {
                    continue;
                }
                assert!(
                    config.services.contains_key(*name),
                    "`{name}` can be started but is absent from the configuration \
                     `{label}` produces, so a server started with it runs `{name}` \
                     unconfigured"
                );
            }
        }
    }

    #[test]
    fn including_an_advanced_example_does_not_move_the_port_off_the_server_instance() {
        // Found by booting the example: `rate-limits.toml` restated
        // `listen_tcp = "0.0.0.0:64738"`, which is the default and therefore
        // looked like documentation. It is not -- a file that states a key wins,
        // so including it pinned the gateway to 64738 and `port = 64999` in the
        // server instance silently did nothing. The server came up healthy on
        // the wrong port, which is the worst way to be wrong about a port.
        let dir = std::env::temp_dir().join("starling-advanced-include");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("a scratch directory");

        for (label, path) in shipped_configs() {
            if !label.starts_with("examples/") {
                continue;
            }
            let file = dir.join("starling.toml");
            std::fs::write(
                &file,
                format!(
                    "include = [{:?}]\n\n[[instances]]\nid = 1\nname = \"t\"\nport = 64999\n",
                    path.display().to_string()
                ),
            )
            .expect("a scratch file");

            let config = starling_runtime::config::Config::load(&file)
                .unwrap_or_else(|error| panic!("including `{label}` loads: {error}"));
            assert!(
                config.gateway.listen_tcp.ends_with(":64999"),
                "including `{label}` moved the gateway to {}, away from the port the \
                 server instance asked for",
                config.gateway.listen_tcp
            );
        }
    }

    #[test]
    fn the_reference_sheet_names_every_key_the_defaults_carry() {
        // A reference nobody checks is a reference that is wrong within two
        // releases, and the failure is quiet: the key exists, the file does not
        // mention it, and an operator concludes it does not exist.
        //
        // This walks the *serialised defaults*, so it covers every key that has
        // a value. It cannot see an `Option` that is `None` -- `bind`,
        // `storage`, the TLS paths, `webtransport` -- because those serialise
        // away; those are documented by hand and this test does not know about
        // them.
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let reference = std::fs::read_to_string(root.join("examples/reference.toml"))
            .expect("examples/reference.toml must be readable");

        let defaults = toml::Table::try_from(starling_runtime::config::Config::with_defaults(
            std::path::Path::new("starling-data/run"),
        ))
        .expect("the defaults serialise");

        fn leaves(table: &toml::Table, into: &mut std::collections::BTreeSet<String>) {
            for (key, value) in table {
                let _ = into.insert(key.clone());
                match value {
                    toml::Value::Table(nested) => leaves(nested, into),
                    // `[[instances]]`: the entries are tables too, and
                    // their keys are exactly the ones worth checking.
                    toml::Value::Array(items) => items
                        .iter()
                        .filter_map(toml::Value::as_table)
                        .for_each(|nested| leaves(nested, into)),
                    _ => {}
                }
            }
        }

        let mut keys = std::collections::BTreeSet::new();
        leaves(&defaults, &mut keys);

        let missing: Vec<_> = keys
            .iter()
            // Service and bucket *names* are keys in this walk too, and the
            // reference documents the shape once rather than every service.
            .filter(|key| !reference.contains(key.as_str()))
            .collect();
        assert!(
            missing.is_empty(),
            "examples/reference.toml never mentions {missing:?}"
        );
    }

    #[test]
    fn an_advanced_example_changes_only_what_it_is_about() {
        // They are a menu, and including one to raise a rate limit must not
        // also move an endpoint or switch a service off. The check that makes
        // that concrete: every service is still enabled, and still where the
        // defaults put it, except in the file whose subject is services.
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let defaults = starling_runtime::config::Config::with_defaults(std::path::Path::new(
            "starling-data/run",
        ));

        for label in [
            "advanced/logging.toml",
            "advanced/rate-limits.toml",
            "advanced/admin-api.toml",
            // The reference sheet states defaults and nothing else, so it is
            // held to the same rule: reading it must not move anything.
            "reference.toml",
        ] {
            let config = starling_runtime::config::Config::load(&root.join("examples").join(label))
                .unwrap_or_else(|error| panic!("`{label}` loads: {error}"));

            for (name, expected) in &defaults.services {
                let actual = config.services.get(name).expect("every service survives");
                assert_eq!(
                    actual.endpoint, expected.endpoint,
                    "`{label}` moved {name}, which is not what it is about"
                );
                assert_eq!(
                    actual.enabled, expected.enabled,
                    "`{label}` changed whether {name} runs"
                );
            }
        }
    }
}
