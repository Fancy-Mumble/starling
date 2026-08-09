//! `starling check-config`: answer "would this boot?" without booting.
//!
//! [`Config::load`] already refuses a file that is not TOML, carries a key
//! Starling does not know, has an `include` it cannot follow, or routes one wire
//! type to two services. Everything it accepts can still fail at startup,
//! because the rest of the answer is about the machine rather than the file: a
//! socket path longer than the kernel's limit, two services on one port, a
//! certificate that is not there. Those surface today as a service that starts
//! and then stops, in a log, one line among twenty-one -- and by then the
//! operator is debugging a running server rather than reading a file.
//!
//! So this loads the configuration exactly as a boot would, environment
//! overrides included, and then asks the boot-time questions with nothing bound
//! and nothing started.
//!
//! ```text
//! starling check-config                  the file this host would boot from
//! starling check-config --config c.toml  a specific one
//! starling check-config --strict         warnings fail too, for CI
//! ```

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::Path;

use starling_runtime::Config;
use starling_runtime::config::ServiceConfig;

use crate::compose;

/// How much a finding matters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Severity {
    /// The server would fail to start, or a service would die on its first
    /// call. Boot is not worth attempting.
    Error,
    /// Startable, and probably not what was meant. Two instances on one port
    /// boot fine and confuse everyone afterwards.
    Warning,
}

/// One thing worth saying about a configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Finding {
    /// Whether this stops a boot.
    pub(crate) severity: Severity,
    /// The setting at fault, in the spelling the file uses, so the reader can
    /// search for it: `services.voice.udp_listen`, not "the voice port".
    pub(crate) key: String,
    /// What is wrong, and where possible what to do instead.
    pub(crate) detail: String,
}

impl Finding {
    /// A finding that stops a boot.
    fn error(key: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            severity: Severity::Error,
            key: key.into(),
            detail: detail.into(),
        }
    }

    /// A finding that does not.
    fn warning(key: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            severity: Severity::Warning,
            key: key.into(),
            detail: detail.into(),
        }
    }
}

/// The longest path a Unix domain socket may have.
///
/// `sockaddr_un.sun_path` is a fixed array and the kernel needs room for the
/// terminating NUL, so the usable length is one less than it. 108 on Linux and
/// 104 on the BSDs, macOS included; the smaller number is not portable upward,
/// so each is stated rather than one being assumed to cover the other.
///
/// This is the check that pays for the command on its own. The path is
/// *generated* -- `data_dir` joined with `run/<service>.sock` -- so a
/// `data_dir` a few directories deep is enough to break it, the file that
/// caused it looks entirely reasonable, and what the operator sees is twenty
/// services reporting `path must be shorter than SUN_LEN` at once.
#[cfg(target_os = "linux")]
const SUN_PATH_MAX: usize = 107;
/// See the Linux arm.
#[cfg(not(target_os = "linux"))]
const SUN_PATH_MAX: usize = 103;

/// Run the checks and report, returning `Err` when the configuration is not
/// usable.
///
/// # Errors
///
/// The load error when the file cannot be read or does not parse, and a summary
/// when the checks found something. Under `--strict` a warning is enough.
pub(crate) fn check_config(arguments: &[String]) -> Result<(), String> {
    let strict = arguments.iter().any(|argument| argument == "--strict");

    // Deliberately the same path `--all-in-one` takes, rather than a private
    // one that reads the file directly: a check that resolved `--config`, the
    // platform directory or the environment even slightly differently would be
    // answering about a configuration this host would never boot.
    let config = compose::load(arguments).map_err(|error| error.to_string())?;

    let findings = inspect(&config);
    crate::out(&report(&config, &findings, strict))?;

    let errors = findings
        .iter()
        .filter(|finding| finding.severity == Severity::Error)
        .count();
    let warnings = findings.len() - errors;
    if errors > 0 {
        return Err(plural(errors, "problem", "problems") + " would stop this server from starting");
    }
    if strict && warnings > 0 {
        return Err(plural(warnings, "warning", "warnings") + " (--strict)");
    }
    Ok(())
}

/// `count` with the right noun, so no message says "1 problems".
fn plural(count: usize, one: &str, many: &str) -> String {
    format!("{count} {}", if count == 1 { one } else { many })
}

/// Every check, over an already-loaded configuration.
///
/// Split from [`check_config`] so the rules are testable against a `Config`
/// built in memory, with no file, no environment and no argument parsing.
pub(crate) fn inspect(config: &Config) -> Vec<Finding> {
    let mut findings = Vec::new();
    endpoints(config, &mut findings);
    socket_paths(config, &mut findings);
    addresses(config, &mut findings);
    instances(config, &mut findings);
    certificates(config, &mut findings);
    findings
}

/// The address every enabled service serves on, by service name.
///
/// `bind` when it is set and `endpoint` otherwise, which is the same rule the
/// runtime applies: one address per service unless the dialled name is not
/// bindable.
fn served(config: &Config) -> impl Iterator<Item = (&str, &str)> {
    config
        .services
        .iter()
        .filter(|(_, service)| service.enabled)
        .filter_map(|(name, service)| bound(service).map(|address| (name.as_str(), address)))
}

/// The address `service` binds, if it binds one.
fn bound(service: &ServiceConfig) -> Option<&str> {
    service
        .bind
        .as_deref()
        .or(service.endpoint.as_deref())
        .map(str::trim)
}

/// Refuse an endpoint string no transport claims.
///
/// A bare `host:port` is the likely typo, and the runtime refuses it on purpose
/// rather than assuming TCP; caught here it is a line in a file, caught at boot
/// it is one service that never registers while the rest come up.
fn endpoints(config: &Config, findings: &mut Vec<Finding>) {
    for (name, address) in served(config) {
        if starling_runtime::transport::parse(address).is_err() {
            findings.push(Finding::error(
                format!("services.{name}.endpoint"),
                format!(
                    "{address:?} names no transport Starling knows; \
                     use `unix:/path.sock`, `http://host:port` or `inproc:{name}`"
                ),
            ));
        }
    }
}

/// Refuse a Unix socket path the kernel cannot hold.
///
/// Only the paths this deployment would actually bind: an `inproc:` or `http://`
/// endpoint has no such limit, and neither does a named pipe.
fn socket_paths(config: &Config, findings: &mut Vec<Finding>) {
    if !cfg!(unix) {
        return;
    }
    for (name, address) in served(config) {
        let Some(path) = address.strip_prefix("unix:") else {
            continue;
        };
        if path.len() > SUN_PATH_MAX {
            findings.push(Finding::error(
                format!("services.{name}.endpoint"),
                format!(
                    "the socket path is {} bytes and the kernel allows {SUN_PATH_MAX}; \
                     shorten `runtime.data_dir`, which is what generates it",
                    path.len()
                ),
            ));
        }
    }
}

/// Refuse two listeners on one address.
///
/// Whichever binds second loses, and which one that is depends on start order,
/// so the same file can come up differently twice. Compared per protocol, since
/// TCP and UDP are separate namespaces and voice sharing the gateway's number is
/// not merely allowed but the murmur convention.
fn addresses(config: &Config, findings: &mut Vec<Finding>) {
    let mut tcp: Vec<(String, String)> = vec![(
        "gateway.listen_tcp".to_owned(),
        config.gateway.listen_tcp.trim().to_owned(),
    )];
    let mut udp: Vec<(String, String)> = Vec::new();

    for (name, service) in config.services.iter().filter(|(_, s)| s.enabled) {
        if let Some(address) = bound(service)
            && let Some(host_port) = address.strip_prefix("http://")
        {
            tcp.push((format!("services.{name}.endpoint"), host_port.to_owned()));
        }
        if let Some(listen) = service.listen.as_deref() {
            tcp.push((format!("services.{name}.listen"), listen.trim().to_owned()));
        }
        if let Some(udp_listen) = service.udp_listen.as_deref() {
            udp.push((
                format!("services.{name}.udp_listen"),
                udp_listen.trim().to_owned(),
            ));
        }
    }
    if let Some(metrics) = config.telemetry.metrics.as_deref() {
        tcp.push(("telemetry.metrics".to_owned(), metrics.trim().to_owned()));
    }

    collide(&tcp, "TCP", findings);
    collide(&udp, "UDP", findings);
}

/// Report every pair in `listeners` that would contend for one socket.
///
/// A wildcard host covers every address on its port, so `0.0.0.0:64738` and
/// `127.0.0.1:64738` collide even though the strings differ; two *specific*
/// hosts on one port are two interfaces and are fine.
fn collide(listeners: &[(String, String)], protocol: &str, findings: &mut Vec<Finding>) {
    for (index, (key, address)) in listeners.iter().enumerate() {
        let Some((host, port)) = split_host_port(address) else {
            continue;
        };
        for (other_key, other) in &listeners[index + 1..] {
            let Some((other_host, other_port)) = split_host_port(other) else {
                continue;
            };
            if port != other_port {
                continue;
            }
            if host == other_host || wildcard(host) || wildcard(other_host) {
                findings.push(Finding::error(
                    key.clone(),
                    format!(
                        "binds {protocol} port {port}, and so does `{other_key}` ({other}); \
                         whichever starts second fails"
                    ),
                ));
            }
        }
    }
}

/// `address` as host and port, splitting at the **last** colon so an IPv6
/// literal keeps its own.
fn split_host_port(address: &str) -> Option<(&str, &str)> {
    let (host, port) = address.rsplit_once(':')?;
    (!port.is_empty() && port.chars().all(|c| c.is_ascii_digit())).then_some((host, port))
}

/// Whether `host` stands for every address on the machine.
fn wildcard(host: &str) -> bool {
    matches!(host, "0.0.0.0" | "::" | "[::]" | "*" | "")
}

/// Refuse an instance list that cannot mean what it says.
///
/// An id is the key every stored row and every actor carries, so two entries
/// sharing one is two servers writing each other's history -- and it is the
/// spelling murmur users reach for, since there `1` and `2` are separate
/// servers by definition.
fn instances(config: &Config, findings: &mut Vec<Finding>) {
    if config.instances.is_empty() {
        findings.push(Finding::error(
            "instances",
            "no server instance is configured; \
             a deployment needs at least one `[[instances]]`",
        ));
        return;
    }

    let mut ids: BTreeMap<u32, usize> = BTreeMap::new();
    let mut ports: BTreeMap<u16, usize> = BTreeMap::new();
    for instance in &config.instances {
        *ids.entry(instance.id).or_default() += 1;
        *ports.entry(instance.port).or_default() += 1;
    }
    for (id, count) in ids {
        if count > 1 {
            findings.push(Finding::error(
                "instances.id",
                format!("{count} instances share id {id}; every instance needs its own"),
            ));
        }
    }
    for (port, count) in ports {
        if count > 1 {
            findings.push(Finding::warning(
                "instances.port",
                format!(
                    "{count} instances report port {port}; \
                     clients told to connect there reach whichever answers"
                ),
            ));
        }
    }
}

/// Refuse a TLS identity that is half-stated or not there.
///
/// Both keys or neither: with neither, a self-signed certificate is generated on
/// first boot, which is a supported deployment. With one, the operator meant to
/// present their own and the server would fall back to generating one instead --
/// silently presenting an identity nobody chose.
fn certificates(config: &Config, findings: &mut Vec<Finding>) {
    let tls = &config.gateway.tls;
    match (tls.cert.as_deref(), tls.key.as_deref()) {
        (Some(cert), Some(key)) => {
            readable("gateway.tls.cert", cert, findings);
            readable("gateway.tls.key", key, findings);
        }
        (Some(_), None) => findings.push(Finding::error(
            "gateway.tls.key",
            "`gateway.tls.cert` is set without it; \
             set both to present your own identity, or neither to generate one",
        )),
        (None, Some(_)) => findings.push(Finding::error(
            "gateway.tls.cert",
            "`gateway.tls.key` is set without it; \
             set both to present your own identity, or neither to generate one",
        )),
        (None, None) => {}
    }

    for (name, service) in config.services.iter().filter(|(_, s)| s.enabled) {
        if let Some(webtransport) = &service.webtransport
            && webtransport.enabled
        {
            if let Some(cert) = webtransport.cert.as_deref() {
                readable(
                    &format!("services.{name}.webtransport.cert"),
                    cert,
                    findings,
                );
            }
            if let Some(key) = webtransport.key.as_deref() {
                readable(&format!("services.{name}.webtransport.key"), key, findings);
            }
        }
    }
}

/// Report a file the server must read and cannot.
///
/// Opening it is the whole check: existence, permissions and "it is a directory"
/// are one question at this layer, and asking it the way the server will is more
/// honest than three guesses about metadata.
fn readable(key: &str, path: &Path, findings: &mut Vec<Finding>) {
    if let Err(error) = std::fs::File::open(path) {
        findings.push(Finding::error(key, format!("{}: {error}", path.display())));
    }
}

/// What the operator reads.
///
/// The summary prints whether or not anything was found: a check that says
/// nothing on success leaves "did it even read my file?" unanswered, and the
/// instance and port lines are how a wrong `--config` shows itself.
fn report(config: &Config, findings: &[Finding], strict: bool) -> String {
    let mut text = String::new();
    let enabled = config
        .services
        .values()
        .filter(|service| service.enabled)
        .count();
    let disabled = config.services.len() - enabled;

    let _ = writeln!(text, "gateway    {}", config.gateway.listen_tcp);
    let _ = writeln!(text, "data_dir   {}", config.runtime.data_dir.display());
    let _ = writeln!(text, "services   {enabled} enabled, {disabled} disabled");
    for instance in &config.instances {
        let _ = writeln!(
            text,
            "instance   {} {:?} on port {}",
            instance.id, instance.name, instance.port
        );
    }

    if findings.is_empty() {
        text.push_str("\nok\n");
        return text;
    }

    text.push('\n');
    for finding in findings {
        let label = match finding.severity {
            Severity::Error => "error",
            Severity::Warning => "warning",
        };
        let _ = writeln!(text, "{label}  {}\n       {}", finding.key, finding.detail);
    }

    let errors = findings
        .iter()
        .filter(|finding| finding.severity == Severity::Error)
        .count();
    if errors == 0 && !strict {
        text.push_str("ok, with warnings\n");
    }
    text
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use starling_runtime::config::Instance;

    /// A configuration shaped like the shipped defaults, with real local
    /// endpoints, so the checks run against what an operator would have.
    fn config() -> Config {
        Config::with_defaults(Path::new("/run/starling"))
    }

    #[test]
    fn the_shipped_defaults_pass_their_own_check() {
        // The defaults are generated, so a rule that rejected them would reject
        // every first boot, and the first person to see it would be a new user
        // running the binary with no file at all.
        assert_eq!(inspect(&config()), Vec::new());
    }

    #[test]
    fn a_socket_path_longer_than_the_kernel_allows_is_refused() {
        // The failure this command exists for. The path is generated from
        // `data_dir`, so nothing in the file looks wrong.
        let deep = PathBuf::from("/").join("x".repeat(SUN_PATH_MAX));
        let config = Config::with_defaults(&deep.join("run"));
        let findings = inspect(&config);
        assert!(
            findings
                .iter()
                .any(|f| f.severity == Severity::Error && f.detail.contains("kernel allows")),
            "{findings:?}"
        );
    }

    #[test]
    fn a_socket_path_that_fits_exactly_is_allowed() {
        // Off-by-one here would reject working deployments, which is worse than
        // the check not existing: the operator cannot argue with it.
        let path = format!("unix:{}", "x".repeat(SUN_PATH_MAX));
        let mut config = config();
        let service = config.services.get_mut("text").expect("text ships enabled");
        service.endpoint = Some(path);
        service.bind = None;
        assert_eq!(inspect(&config), Vec::new());
    }

    #[test]
    fn two_services_on_one_tcp_port_are_refused_before_either_binds() {
        let mut config = config();
        let port = config.gateway.listen_tcp.clone();
        config
            .services
            .get_mut("text")
            .expect("text ships enabled")
            .listen = Some(port);
        let findings = inspect(&config);
        assert!(
            findings
                .iter()
                .any(|f| f.key == "gateway.listen_tcp" && f.detail.contains("services.text.listen")),
            "{findings:?}"
        );
    }

    #[test]
    fn a_wildcard_host_collides_with_a_specific_one_on_its_port() {
        // The pair that looks fine as two strings and is one socket.
        let mut config = config();
        config.gateway.listen_tcp = "0.0.0.0:64738".to_owned();
        config
            .services
            .get_mut("text")
            .expect("text ships enabled")
            .listen = Some("127.0.0.1:64738".to_owned());
        assert!(
            inspect(&config)
                .iter()
                .any(|f| f.severity == Severity::Error),
            "a wildcard must collide with a specific address"
        );
    }

    #[test]
    fn voice_may_share_the_gateways_number_because_udp_is_not_tcp() {
        // murmur binds TCP and UDP on one number and every client assumes it,
        // so a rule that compared across protocols would reject the default.
        let mut config = config();
        config.gateway.listen_tcp = "0.0.0.0:64738".to_owned();
        config
            .services
            .get_mut("voice")
            .expect("voice ships enabled")
            .udp_listen = Some("0.0.0.0:64738".to_owned());
        assert_eq!(inspect(&config), Vec::new());
    }

    #[test]
    fn two_instances_sharing_an_id_are_refused() {
        let mut config = config();
        config.instances = vec![
            Instance {
                id: 1,
                port: 64738,
                ..Instance::default()
            },
            Instance {
                id: 1,
                port: 64739,
                ..Instance::default()
            },
        ];
        let findings = inspect(&config);
        assert!(
            findings
                .iter()
                .any(|f| f.key == "instances.id" && f.severity == Severity::Error),
            "{findings:?}"
        );
    }

    #[test]
    fn two_instances_sharing_a_port_are_a_warning_rather_than_an_error() {
        // It starts. It is also nearly always a copy-paste, and the server that
        // answers is whichever the client reaches first.
        let mut config = config();
        config.instances = vec![
            Instance {
                id: 1,
                port: 64738,
                ..Instance::default()
            },
            Instance {
                id: 2,
                port: 64738,
                ..Instance::default()
            },
        ];
        let findings = inspect(&config);
        assert!(
            findings.iter().all(|f| f.severity == Severity::Warning),
            "{findings:?}"
        );
        assert!(findings.iter().any(|f| f.key == "instances.port"));
    }

    #[test]
    fn a_deployment_with_no_instances_is_refused() {
        let mut config = config();
        config.instances.clear();
        let findings = inspect(&config);
        assert!(
            findings.iter().any(|f| f.key == "instances"),
            "{findings:?}"
        );
    }

    #[test]
    fn half_a_tls_identity_is_refused_rather_than_quietly_self_signed() {
        // Falling back to a generated certificate here would present an identity
        // the operator did not choose, to clients that pin fingerprints.
        let mut config = config();
        config.gateway.tls.cert = Some(PathBuf::from("/etc/starling/cert.pem"));
        config.gateway.tls.key = None;
        let findings = inspect(&config);
        assert!(
            findings.iter().any(|f| f.key == "gateway.tls.key"),
            "{findings:?}"
        );
    }

    #[test]
    fn a_certificate_that_is_not_there_is_reported_against_its_own_key() {
        let mut config = config();
        config.gateway.tls.cert = Some(PathBuf::from("/nonexistent/cert.pem"));
        config.gateway.tls.key = Some(PathBuf::from("/nonexistent/key.pem"));
        let findings = inspect(&config);
        assert_eq!(findings.len(), 2, "{findings:?}");
        assert!(findings.iter().any(|f| f.key == "gateway.tls.cert"));
        assert!(findings.iter().any(|f| f.key == "gateway.tls.key"));
    }

    #[test]
    fn an_endpoint_no_transport_claims_is_refused() {
        // `host:port` with no scheme is the typo the runtime refuses on purpose.
        let mut config = config();
        let service = config.services.get_mut("text").expect("text ships enabled");
        service.endpoint = Some("127.0.0.1:50051".to_owned());
        service.bind = None;
        let findings = inspect(&config);
        assert!(
            findings
                .iter()
                .any(|f| f.key == "services.text.endpoint" && f.detail.contains("no transport")),
            "{findings:?}"
        );
    }

    #[test]
    fn a_disabled_service_is_not_checked() {
        // Switching a service off is a supported deployment, and its endpoint
        // stops being a claim about anything once it is off.
        let mut config = config();
        let service = config.services.get_mut("text").expect("text ships enabled");
        service.enabled = false;
        service.endpoint = Some("nonsense".to_owned());
        service.bind = None;
        assert_eq!(inspect(&config), Vec::new());
    }

    #[test]
    fn the_report_names_the_instances_so_a_wrong_config_shows_itself() {
        // The failure mode this heads off is checking one file and booting
        // another; the port is what makes that visible.
        let config = config();
        let text = report(&config, &[], false);
        assert!(text.contains("64738"), "{text}");
        assert!(text.contains("ok"), "{text}");
    }

    #[test]
    fn the_report_says_ok_with_warnings_when_nothing_would_stop_a_boot() {
        let findings = vec![Finding::warning("instances.port", "two of them")];
        let text = report(&config(), &findings, false);
        assert!(text.contains("ok, with warnings"), "{text}");
        assert!(!text.contains("error"), "{text}");
    }

    #[test]
    fn strict_does_not_call_a_warning_ok() {
        // Under --strict the exit code is non-zero, so a summary line reading
        // "ok" would contradict it.
        let findings = vec![Finding::warning("instances.port", "two of them")];
        let text = report(&config(), &findings, true);
        assert!(!text.contains("ok"), "{text}");
    }

    #[test]
    fn one_problem_is_not_reported_as_one_problems() {
        assert_eq!(plural(1, "problem", "problems"), "1 problem");
        assert_eq!(plural(2, "problem", "problems"), "2 problems");
    }

    #[test]
    fn an_ipv6_endpoint_keeps_its_own_colons() {
        // Splitting at the first colon would read `[::1]` as host `[` and make
        // every IPv6 listener collide with every other.
        assert_eq!(split_host_port("[::1]:64738"), Some(("[::1]", "64738")));
        assert_eq!(split_host_port("unix:/run/x.sock"), None);
    }
}
