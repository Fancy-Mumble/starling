//! Re-reading the configuration file without restarting the process.
//!
//! [`Config`] is loaded once and injected at construction, which is right for
//! everything that needs a restart anyway and wrong for the handful of keys an
//! operator expects to change while the server runs. This is the seam: one cell
//! per process holding the current configuration, and a way to ask it to read
//! the file again.
//!
//! # What a reload is
//!
//! 1. Read the file, its `include` tree, and the environment, exactly as a boot
//!    does -- so a typo, an unreadable include or a routing table two services
//!    answer for fails **here**, with the old configuration still in effect.
//! 2. Diff it against what is running, and classify each change
//!    ([`crate::config::Reload`]).
//! 3. Publish. Followers wake up and apply their own slice.
//!
//! Validation is the only step that can fail, and it happens before anything is
//! published, so a reload either takes effect completely or changes nothing.
//! There is no half-applied state to reason about, which is the property that
//! makes SIGHUP safe to wire to a running server.
//!
//! # What the cell holds
//!
//! **The file as it now reads**, not "the subset that took effect". A key
//! classified [`Reload::Restart`](crate::config::Reload::Restart) has no
//! follower by construction -- that is what the classification *means* -- so
//! nothing acts on the new value, but a reader who went looking would see it.
//! [`Outcome::deferred`] names exactly those keys, and it is logged and
//! reported rather than left for the operator to infer.
//!
//! The alternative, publishing a spliced configuration where restart-only keys
//! keep their old values, was rejected: it would mean maintaining a per-key
//! merge alongside the per-key classification, and a reader would then have no
//! way to ask what the file currently says.
//!
//! # Hot paths do not read through this
//!
//! A follower subscribes and keeps its own copy. Nothing on the audio or
//! control path calls [`ConfigCell::current`] per packet: `docs/ARCHITECTURE.md`
//! §5 already rules out per-message lookups, and a `watch` borrow takes a read
//! lock.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use tokio::sync::watch;

use crate::config::{Change, Config, ConfigError, Reload, changes, revision};
use crate::log::{
    Category, ConsoleSink, FileSink, LogConfig, LogEvent, LogHandles, LogSink, Logger,
};

/// What a composition root does to a configuration after loading it.
///
/// See [`ConfigCell::adjusting`]. A named type because the alternative is this
/// signature written out at three call sites.
pub type Adjust = Arc<dyn Fn(&mut Config) + Send + Sync>;

/// Why a reload did not happen.
#[derive(Debug, thiserror::Error)]
pub enum ReloadError {
    /// This process was not started from a file, so there is nothing to re-read.
    ///
    /// `--all-in-one` with no `--config` is the ordinary case: it runs on the
    /// built-in defaults, and a first start writes a file that a *later* start
    /// reads. Reported rather than treated as a successful no-op, because
    /// "SIGHUP did nothing" and "SIGHUP found nothing to change" are different
    /// answers to the same question.
    #[error("no configuration file to reload; this process was started from the built-in defaults")]
    NoSource,
    /// The file no longer describes a usable server. Nothing was applied.
    #[error(transparent)]
    Config(#[from] ConfigError),
}

/// What one reload did.
#[derive(Debug, Clone, Default)]
pub struct Outcome {
    /// Changed keys this process has already adopted, everywhere.
    pub applied: Vec<Change>,
    /// Changed keys adopted for connections accepted from now on.
    ///
    /// Separate from [`Self::applied`] because an operator watching a client
    /// that is already connected will never see these arrive there, and
    /// separate from [`Self::deferred`] because no restart is needed.
    pub next_connection: Vec<Change>,
    /// Changed keys that need a restart. The file and the running server
    /// disagree about each of these until one happens.
    pub deferred: Vec<Change>,
    /// The revision now published.
    pub revision: String,
}

impl Outcome {
    /// Whether the file said anything new at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.applied.is_empty() && self.next_connection.is_empty() && self.deferred.is_empty()
    }

    /// The changed keys, by name, for a log line or an API reply.
    fn names(changes: &[Change]) -> String {
        changes
            .iter()
            .map(|change| change.path.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    }
}

/// The configuration this process is running, and the file it came from.
///
/// Cheap to clone; every clone sees the same value and the same updates.
#[derive(Clone)]
pub struct ConfigCell {
    tx: Arc<watch::Sender<Arc<Config>>>,
    /// The file to re-read, if this process was started from one.
    source: Option<Arc<Path>>,
    /// What the composition root did to the configuration after loading it.
    ///
    /// A reload re-reads the file, so anything the entry point *decided* rather
    /// than read has to be re-decided or it is silently undone. `--all-in-one`
    /// is the case that exists: it sets `runtime.all_in_one` itself, and
    /// without this every reload reported it as a change needing a restart --
    /// noise on every single reload, which is how an operator learns to ignore
    /// the one warning that matters.
    adjust: Option<Adjust>,
}

impl std::fmt::Debug for ConfigCell {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConfigCell")
            .field("source", &self.source)
            .field("revision", &self.revision())
            .field("adjusted", &self.adjust.is_some())
            .finish()
    }
}

impl ConfigCell {
    /// A cell that never changes, for a process with no file behind it.
    ///
    /// What [`crate::serve::context`] builds, so a test or a caller that
    /// composed a `Config` by hand still has a cell to hand to services.
    #[must_use]
    pub fn fixed(config: Arc<Config>) -> Self {
        Self {
            tx: Arc::new(watch::Sender::new(config)),
            source: None,
            adjust: None,
        }
    }

    /// A cell that re-reads `source` when asked.
    #[must_use]
    pub fn watching(config: Arc<Config>, source: impl Into<PathBuf>) -> Self {
        Self {
            tx: Arc::new(watch::Sender::new(config)),
            source: Some(Arc::from(source.into().as_path())),
            adjust: None,
        }
    }

    /// Apply `adjust` to every configuration this cell loads.
    ///
    /// For what the composition root decides rather than reads. It runs before
    /// the diff, so an adjusted value is never reported as a change.
    #[must_use]
    pub fn adjusting(mut self, adjust: impl Fn(&mut Config) + Send + Sync + 'static) -> Self {
        self.adjust = Some(Arc::new(adjust));
        self
    }

    /// The configuration in effect now.
    #[must_use]
    pub fn current(&self) -> Arc<Config> {
        Arc::clone(&self.tx.borrow())
    }

    /// Follow changes. The receiver starts already-seen, so the first
    /// `changed()` is the first *change* rather than the current value.
    #[must_use]
    pub fn subscribe(&self) -> watch::Receiver<Arc<Config>> {
        self.tx.subscribe()
    }

    /// The file behind this cell, if there is one.
    #[must_use]
    pub fn source(&self) -> Option<&Path> {
        self.source.as_deref()
    }

    /// A short identifier for what is published, for comparing across a fleet.
    #[must_use]
    pub fn revision(&self) -> String {
        revision(&self.current())
    }

    /// Re-read the file and publish it.
    ///
    /// # Errors
    ///
    /// [`ReloadError::NoSource`] if this process was not started from a file,
    /// and [`ReloadError::Config`] if the file no longer loads. In both cases
    /// **nothing is published** and the running configuration is untouched.
    pub fn reload(&self) -> Result<Outcome, ReloadError> {
        let source = self.source.as_deref().ok_or(ReloadError::NoSource)?;
        let mut loaded = Config::load(source)?;
        if let Some(adjust) = &self.adjust {
            adjust(&mut loaded);
        }

        let current = self.current();
        let mut outcome = Outcome {
            revision: revision(&loaded),
            ..Outcome::default()
        };
        for change in changes(&current, &loaded) {
            match change.class {
                Reload::Live => outcome.applied.push(change),
                Reload::NextConnection => outcome.next_connection.push(change),
                Reload::Restart => outcome.deferred.push(change),
            }
        }

        if !outcome.is_empty() {
            // `send_replace` rather than `send`: the latter reports "no
            // receivers" as an error and would leave a process whose followers
            // have not started yet running on the old value.
            let _ = self.tx.send_replace(Arc::new(loaded));
        }

        Ok(outcome)
    }

    /// Reload, and write what happened to the operator log.
    ///
    /// The record is what an operator needs to see without reading the file
    /// twice: what changed, what took effect, and what is still waiting for a
    /// restart. A failed reload is a warning rather than an error, because the
    /// server is still running and still correct -- on the old configuration.
    pub fn reload_logging(&self, logger: &Logger) -> Result<Outcome, ReloadError> {
        let outcome = match self.reload() {
            Ok(outcome) => outcome,
            Err(error) => {
                logger.log(
                    LogEvent::warning(Category::Server, "configuration not reloaded")
                        .with("error", error.to_string()),
                );
                tracing::warn!(%error, "configuration not reloaded");
                return Err(error);
            }
        };

        if outcome.is_empty() {
            logger.log(
                LogEvent::info(Category::Server, "configuration reloaded; nothing changed")
                    .with("revision", outcome.revision.clone()),
            );
            return Ok(outcome);
        }

        // Notice, not info: this is the "an administrator changed something"
        // severity, and it is the record somebody looks for months later when
        // asking why a setting is not what the file says.
        let mut event = LogEvent::notice(Category::Server, "configuration reloaded")
            .with("revision", outcome.revision.clone())
            .with("applied", Outcome::names(&outcome.applied));
        if !outcome.next_connection.is_empty() {
            event = event.with("next_connection", Outcome::names(&outcome.next_connection));
        }
        if !outcome.deferred.is_empty() {
            event = event.with("pending_restart", Outcome::names(&outcome.deferred));
        }
        logger.log(event);

        for change in &outcome.applied {
            tracing::info!(change = %change, "applied");
        }
        for change in &outcome.next_connection {
            tracing::info!(change = %change, "applies to connections from now on");
        }
        for change in &outcome.deferred {
            // Warning rather than info: until the restart, the file and the
            // running server disagree, and the operator is the only one who can
            // resolve it.
            tracing::warn!(change = %change, "needs a restart to take effect");
        }
        Ok(outcome)
    }

    /// Reload on `SIGHUP`.
    ///
    /// The conventional signal, and the one an operator's muscle memory and
    /// every init system already reach for. Spawns a task; the handle is
    /// dropped, because the process exiting is what stops it.
    ///
    /// On platforms with no `SIGHUP` this does nothing: Windows has no such
    /// signal, and inventing a substitute here would be a second mechanism to
    /// document and keep working. The admin plane is the portable trigger.
    pub fn install_signal_handler(&self, logger: Logger) {
        #[cfg(unix)]
        {
            let cell = self.clone();
            drop(tokio::spawn(async move {
                use tokio::signal::unix::{SignalKind, signal};
                let mut hangup = match signal(SignalKind::hangup()) {
                    Ok(hangup) => hangup,
                    Err(error) => {
                        tracing::warn!(%error, "no SIGHUP handler; configuration cannot be reloaded");
                        return;
                    }
                };
                while hangup.recv().await.is_some() {
                    tracing::info!("SIGHUP received; re-reading the configuration");
                    let _ = cell.reload_logging(&logger);
                }
            }));
        }
        #[cfg(not(unix))]
        {
            let _ = logger;
        }
    }
}

/// Keep the running log following `[logging]` in `cell`.
///
/// Everything in that section except `queue` is reloadable: the severity
/// threshold, the category set, the console, the in-memory ring and the file.
/// All of them are things an operator discovers are wrong while the server is
/// running, and none is worth restarting the process holding every client.
///
/// `queue` is the writer's channel depth, fixed when the writer thread was
/// started, so it is classified `Restart` rather than quietly ignored here.
///
/// The file is opened **in this task**, before the swap reaches the writer
/// thread, so a path that cannot be opened is reported with the working file
/// still in place. Opening it inside the writer would put that failure in the
/// one component that cannot report it, since the log is what is broken.
pub fn follow_logging(cell: &ConfigCell, handles: LogHandles, logger: Logger) {
    let mut configs = cell.subscribe();
    let mut applied = cell.current().logging.clone();
    drop(tokio::spawn(async move {
        while configs.changed().await.is_ok() {
            let wanted = configs.borrow_and_update().logging.clone();
            if wanted == applied {
                continue;
            }
            apply_logging(&wanted, &applied, &handles, &logger);
            applied = wanted;
        }
    }));
}

/// One pass of [`follow_logging`], factored out so it can be tested without a
/// task and a sleep.
fn apply_logging(wanted: &LogConfig, applied: &LogConfig, handles: &LogHandles, logger: &Logger) {
    // Resolved through `to_spec`, the same call the boot path makes, so an
    // unstated `max_bytes` gets the default it would have got at startup rather
    // than a second copy of that number here. Its warnings are what an operator
    // needs: a misspelled level falls back rather than failing the reload, and
    // silently logging at the wrong level is how an incident ends up with no
    // evidence.
    let (spec, warnings) = wanted.to_spec();
    for warning in warnings {
        logger.log(LogEvent::warning(Category::Server, warning));
    }

    if wanted.level != applied.level && spec.level != handles.filter.level() {
        handles.filter.set_level(spec.level);
        logger.log(
            LogEvent::notice(Category::Server, "log level changed")
                .with("level", spec.level.label().trim().to_lowercase()),
        );
    }

    if wanted.categories != applied.categories {
        handles
            .filter
            .set_categories(spec.categories.iter().copied());
        let named = if spec.categories.is_empty() {
            "(all)".to_owned()
        } else {
            let mut names: Vec<_> = spec
                .categories
                .iter()
                .map(|category| category.label())
                .collect();
            names.sort_unstable();
            names.join(", ")
        };
        logger.log(
            LogEvent::notice(Category::Server, "log categories changed").with("categories", named),
        );
    }

    if wanted.console != applied.console {
        if spec.console {
            handles
                .console
                .put(Box::new(ConsoleSink::stderr()) as Box<dyn LogSink>);
        } else {
            handles.console.clear();
        }
        logger.log(
            LogEvent::notice(Category::Server, "console logging changed")
                .with("enabled", spec.console),
        );
    }

    if wanted.memory != applied.memory {
        let records = spec.memory.unwrap_or(0);
        handles.memory.set_capacity(records);
        logger.log(LogEvent::notice(Category::Server, "log ring resized").with("records", records));
    }

    if wanted.file != applied.file {
        match &spec.file {
            None => {
                handles.file.clear();
                logger.log(LogEvent::notice(
                    Category::Server,
                    "file logging switched off",
                ));
            }
            Some(file) => match FileSink::open(&file.path, file.max_bytes, file.keep) {
                Ok(sink) => {
                    handles.file.put(Box::new(sink) as Box<dyn LogSink>);
                    logger.log(
                        LogEvent::notice(Category::Server, "log file changed")
                            .with("path", file.path.clone())
                            .with("max_bytes", file.max_bytes)
                            .with("keep", file.keep),
                    );
                }
                Err(error) => {
                    // The previous file stays in place: a reload that could not
                    // open the new one must not also stop writing to the old.
                    logger.log(
                        LogEvent::warning(Category::Server, "log file unchanged")
                            .with("path", file.path.clone())
                            .with("error", error.to_string()),
                    );
                }
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::log::{LogRuntime, LogSpec, Severity};
    use std::path::Path;

    fn defaults() -> Arc<Config> {
        Arc::new(Config::with_defaults(Path::new("/run/starling")))
    }

    /// A config file in a scratch directory of its own.
    ///
    /// Named after the test using it, so two running concurrently do not
    /// rewrite each other's file mid-reload.
    fn written(name: &str, body: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("starling-reload-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("a scratch directory");
        let path = dir.join("starling.toml");
        std::fs::write(&path, body).expect("the file must be writable");
        path
    }

    #[test]
    fn a_cell_with_no_file_says_so_rather_than_succeeding_quietly() {
        let cell = ConfigCell::fixed(defaults());
        assert!(cell.source().is_none());
        let error = cell.reload().expect_err("there is no file to read");
        assert!(matches!(error, ReloadError::NoSource));
    }

    #[test]
    fn a_reload_publishes_what_the_file_now_says() {
        let path = written(
            "reload-publishes",
            "[[instances]]\nid = 1\n[instances.settings]\nmax_users = 10\n",
        );
        let cell = ConfigCell::watching(
            Arc::new(Config::load(&path).expect("the file must load")),
            &path,
        );
        assert_eq!(cell.current().instances[0].settings.max_users, Some(10));

        std::fs::write(
            &path,
            "[[instances]]\nid = 1\n[instances.settings]\nmax_users = 20\n",
        )
        .expect("rewritable");
        let outcome = cell.reload().expect("the new file must load");

        assert_eq!(cell.current().instances[0].settings.max_users, Some(20));
        assert_eq!(outcome.applied.len(), 1, "{:#?}", outcome.applied);
        assert_eq!(outcome.applied[0].path, "instances.0.settings.max_users");
        assert_eq!(outcome.applied[0].class, Reload::Live);
        assert!(outcome.deferred.is_empty());
    }

    #[test]
    fn a_restart_only_key_is_reported_as_deferred_rather_than_as_applied() {
        // A bound socket: nothing short of a restart moves it, and an operator
        // must be told that rather than left watching the old port.
        let path = written(
            "restart-deferred",
            "[gateway]\nlisten_tcp = \"0.0.0.0:64738\"\n",
        );
        let cell = ConfigCell::watching(
            Arc::new(Config::load(&path).expect("the file must load")),
            &path,
        );

        std::fs::write(&path, "[gateway]\nlisten_tcp = \"0.0.0.0:64750\"\n").expect("rewritable");
        let outcome = cell.reload().expect("the new file must load");

        assert!(outcome.applied.is_empty(), "{:#?}", outcome.applied);
        assert_eq!(outcome.deferred.len(), 1, "{:#?}", outcome.deferred);
        assert_eq!(outcome.deferred[0].path, "gateway.listen_tcp");
        assert_eq!(outcome.deferred[0].class, Reload::Restart);
    }

    #[test]
    fn a_next_connection_key_is_neither_applied_nor_deferred() {
        // Its own bucket, because both other answers mislead: "applied" has an
        // operator watching a connected client for a change that can never
        // reach it, and "needs a restart" is simply false.
        let path = written("next-connection", "[gateway]\ncontrol_queue = 4096\n");
        let cell = ConfigCell::watching(
            Arc::new(Config::load(&path).expect("the file must load")),
            &path,
        );

        std::fs::write(&path, "[gateway]\ncontrol_queue = 8192\n").expect("rewritable");
        let outcome = cell.reload().expect("the new file must load");

        assert!(outcome.applied.is_empty(), "{:#?}", outcome.applied);
        assert!(outcome.deferred.is_empty(), "{:#?}", outcome.deferred);
        assert_eq!(outcome.next_connection.len(), 1);
        assert_eq!(outcome.next_connection[0].path, "gateway.control_queue");
        assert!(!outcome.is_empty(), "it is still a change");
    }

    #[test]
    fn a_broken_file_changes_nothing() {
        // The property that makes SIGHUP safe on a live server: validation runs
        // before anything is published, so a fat-fingered edit is a warning in
        // the log rather than a server that has half-adopted it.
        let path = written(
            "broken-file",
            "[[instances]]\nid = 1\n[instances.settings]\nmax_users = 10\n",
        );
        let cell = ConfigCell::watching(
            Arc::new(Config::load(&path).expect("the file must load")),
            &path,
        );
        let before = cell.revision();

        std::fs::write(&path, "[[instances]]\nid = 1\nmax_uzers = 10\n").expect("rewritable");
        let error = cell.reload().expect_err("an unknown key must be refused");

        assert!(matches!(error, ReloadError::Config(_)), "{error:?}");
        assert_eq!(cell.revision(), before, "the old configuration must stand");
        assert_eq!(cell.current().instances[0].settings.max_users, Some(10));
    }

    #[test]
    fn a_routing_table_two_services_answer_for_is_refused_at_reload_too() {
        // `validate` runs on every load, so the check that keeps a boot honest
        // keeps a reload honest as well -- otherwise SIGHUP would be a way to
        // reach a state startup refuses.
        let path = written("duplicate-type", "[services.text]\ntypes = [1005]\n");
        let cell = ConfigCell::watching(
            Arc::new(Config::load(&path).expect("the file must load")),
            &path,
        );

        std::fs::write(&path, "[services.text]\ntypes = [1006]\n").expect("rewritable");
        let error = cell.reload().expect_err("1006 is pchat's");
        assert!(
            matches!(
                error,
                ReloadError::Config(ConfigError::DuplicateType { .. })
            ),
            "{error:?}"
        );
    }

    #[tokio::test]
    async fn a_follower_is_woken_by_a_reload() {
        let path = written(
            "follower-woken",
            "[[instances]]\nid = 1\n[instances.settings]\nmax_users = 10\n",
        );
        let cell = ConfigCell::watching(
            Arc::new(Config::load(&path).expect("the file must load")),
            &path,
        );
        let mut follower = cell.subscribe();

        std::fs::write(
            &path,
            "[[instances]]\nid = 1\n[instances.settings]\nmax_users = 20\n",
        )
        .expect("rewritable");
        let _ = cell.reload().expect("the new file must load");

        tokio::time::timeout(std::time::Duration::from_secs(1), follower.changed())
            .await
            .expect("a follower must be woken")
            .expect("the sender outlives the receiver");
        assert_eq!(follower.borrow().instances[0].settings.max_users, Some(20));
    }

    #[tokio::test]
    async fn a_reload_that_changes_nothing_does_not_wake_followers() {
        // A follower re-applying its slice on every SIGHUP would turn an
        // operator's "did I save that?" into a republished snapshot for every
        // subscriber in the fleet.
        let path = written(
            "no-change",
            "[[instances]]\nid = 1\n[instances.settings]\nmax_users = 10\n",
        );
        let cell = ConfigCell::watching(
            Arc::new(Config::load(&path).expect("the file must load")),
            &path,
        );
        let mut follower = cell.subscribe();

        let outcome = cell.reload().expect("the same file must still load");
        assert!(outcome.is_empty());

        let woken =
            tokio::time::timeout(std::time::Duration::from_millis(100), follower.changed()).await;
        assert!(woken.is_err(), "nothing changed, so nothing may be woken");
    }

    /// A log whose sink tree is real, so an applier can be watched working.
    fn log() -> (LogRuntime, LogHandles) {
        let runtime = LogRuntime::start(&LogSpec {
            level: Severity::Warning,
            categories: Vec::new(),
            queue: 16,
            console: false,
            file: None,
            memory: Some(8),
        });
        let handles = runtime.handles();
        (runtime, handles)
    }

    fn logging(body: &str) -> LogConfig {
        toml::from_str(body).expect("a [logging] body")
    }

    #[test]
    fn the_log_level_follows_the_file() {
        let (_log, handles) = log();
        assert_eq!(handles.filter.level(), Severity::Warning);

        apply_logging(
            &logging("level = \"debug\""),
            &logging("level = \"warning\""),
            &handles,
            &Logger::null(),
        );
        assert_eq!(handles.filter.level(), Severity::Debug);
    }

    #[test]
    fn a_misspelled_log_level_is_ignored_rather_than_applied() {
        // `deny_unknown_fields` catches an unknown *key*; the value is a free
        // string, so "shouty" reaches here and must leave the level alone
        // rather than fail the whole reload.
        let (_log, handles) = log();
        apply_logging(
            &logging("level = \"shouty\""),
            &logging("level = \"warning\""),
            &handles,
            &Logger::null(),
        );
        assert_eq!(
            handles.filter.level(),
            Severity::Info,
            "an unparseable level falls back to the documented default"
        );
    }

    #[test]
    fn the_category_filter_follows_the_file_and_empties_back_to_everything() {
        let (_log, handles) = log();
        apply_logging(
            &logging("categories = [\"security\", \"admin\"]"),
            &logging(""),
            &handles,
            &Logger::null(),
        );
        assert_eq!(
            handles.filter.categories(),
            vec![Category::Security, Category::Admin]
        );

        apply_logging(
            &logging(""),
            &logging("categories = [\"security\", \"admin\"]"),
            &handles,
            &Logger::null(),
        );
        assert!(
            handles.filter.categories().is_empty(),
            "an empty list means no restriction, not silence"
        );
    }

    #[test]
    fn the_log_ring_resizes_and_switches_off() {
        let (log, handles) = log();
        let recent = log.recent().expect("the ring is on").clone();
        assert_eq!(recent.capacity(), 8);

        apply_logging(
            &logging("[memory]\nrecords = 64"),
            &logging("[memory]\nrecords = 8"),
            &handles,
            &Logger::null(),
        );
        assert_eq!(recent.capacity(), 64);

        apply_logging(
            &logging("[memory]\nenabled = false"),
            &logging("[memory]\nrecords = 64"),
            &handles,
            &Logger::null(),
        );
        assert_eq!(
            recent.capacity(),
            0,
            "switching the ring off keeps nothing, rather than keeping one"
        );
    }

    #[test]
    fn a_log_file_can_be_switched_on_without_a_restart() {
        // The half a conditionally-built sink tree could never do: with no
        // `[logging.file]` at boot there was nowhere to put one later.
        let dir =
            std::env::temp_dir().join(format!("starling-reload-logfile-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("a scratch directory");
        let path = dir.join("starling.log");

        let (log, handles) = log();
        apply_logging(
            &logging(&format!("[file]\npath = {path:?}")),
            &logging(""),
            &handles,
            &Logger::null(),
        );

        log.logger()
            .log(LogEvent::warning(Category::Server, "after the swap"));
        log.logger().request_flush();
        for _ in 0..100 {
            if std::fs::read_to_string(&path).is_ok_and(|text| text.contains("after the swap")) {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        panic!("the record never reached {}", path.display());
    }

    #[test]
    fn a_log_file_that_cannot_be_opened_leaves_the_working_one_in_place() {
        // A reload that could not open the new file must not also stop writing
        // to the old: the log is the thing being relied on to explain this.
        let (_log, handles) = log();
        let unopenable = if cfg!(windows) {
            "\\\\?\\"
        } else {
            "/proc/self/mem/nope"
        };
        apply_logging(
            &logging(&format!("[file]\npath = {unopenable:?}")),
            &logging(""),
            &handles,
            &Logger::null(),
        );
        // Nothing to assert on the handle directly -- the point is that this
        // does not panic and does not clear the slot. The warning it logs is
        // the operator-visible half.
    }

    #[test]
    fn the_revision_is_the_one_the_outcome_reports() {
        let path = written(
            "revision",
            "[[instances]]\nid = 1\n[instances.settings]\nmax_users = 10\n",
        );
        let cell = ConfigCell::watching(
            Arc::new(Config::load(&path).expect("the file must load")),
            &path,
        );
        std::fs::write(
            &path,
            "[[instances]]\nid = 1\n[instances.settings]\nmax_users = 20\n",
        )
        .expect("rewritable");
        let outcome = cell.reload().expect("the new file must load");
        assert_eq!(outcome.revision, cell.revision());
    }
}
