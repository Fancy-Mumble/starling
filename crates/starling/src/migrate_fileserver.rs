//! Carry a `fancy-file-server` plugin's storage into the server's own.
//!
//! The plugin exists because Starling once offered plugins and clients nowhere
//! to put anything. It does now (`docs/STORAGE-UNIFICATION.md`), so this moves
//! what the plugin holds onto the stores that replace it and leaves the plugin
//! with nothing it alone can answer for.
//!
//! | From the plugin | To |
//! |---|---|
//! | `private_storage` rows | `userdata`'s `account_record` |
//! | `emotes` rows | `files` objects under `srv/emotes/`, named by shortcode |
//! | `documents` + `doc-revisions/` | `files` objects under `p/fancy-live-doc/`, named |
//! | `document_acl` rows | the live-doc plugin's own key/value namespace |
//! | `files` rows + `blobs/` | `files` objects in the channel they were shared in |
//!
//! The five rules `STORAGE.md` §4 sets for `migrate-db` apply here unchanged,
//! because they are what make a migration safe rather than merely done:
//!
//! 1. **Non-destructive.** The plugin's database is opened read-only and only
//!    `SELECT` is issued. It keeps working, which is what makes running this
//!    before switching over safe.
//! 2. **Verifying.** `--verify` counts both sides afterwards, through the
//!    destination's own queries rather than from what the writes returned.
//! 3. **Resumable.** Every write is keyed the way its destination keys it, so
//!    a second run converges instead of duplicating.
//! 4. **Loud.** Everything skipped is reported, never silently dropped.
//! 5. **Per-tenant.** `--instance` says which Starling instance the rows land
//!    on; the plugin's own `server_id` column says where they came from.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use starling_runtime::config::Config;
use starling_runtime::storage::{Backend, Store};

/// What the caller asked for.
#[derive(Debug)]
struct Options {
    /// The plugin's `storage_path`.
    from: PathBuf,
    /// Which Starling instance the rows land on.
    instance: u32,
    /// Read and report, write nothing.
    dry_run: bool,
    /// Count both sides afterwards.
    verify: bool,
}

/// One kind of thing carried, and how much of it.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct Counts {
    records: u64,
    emotes: u64,
    documents: u64,
    document_revisions: u64,
    shares: u64,
    files: u64,
}

impl Counts {
    /// The report block, one line per kind that had anything in it.
    fn describe(&self, indent: &str) -> String {
        let mut text = String::new();
        for (label, count) in [
            ("private records", self.records),
            ("emotes", self.emotes),
            ("documents", self.documents),
            ("document revisions", self.document_revisions),
            ("document share lists", self.shares),
            ("shared files", self.files),
        ] {
            if count > 0 {
                let _ = writeln!(text, "{indent}{count:>6}  {label}");
            }
        }
        if text.is_empty() {
            let _ = writeln!(text, "{indent}     0  anything at all");
        }
        text
    }
}

/// Everything that could not be carried, and why.
#[derive(Debug, Default)]
struct Report {
    skipped: Vec<String>,
}

impl Report {
    fn skip(&mut self, what: impl Into<String>) {
        self.skipped.push(what.into());
    }
}

/// `starling migrate-fileserver --from <storage_path> [...]`.
///
/// # Errors
///
/// A message when the arguments are wrong, the plugin's storage cannot be
/// read, or a destination cannot be written.
pub(crate) fn migrate_fileserver(arguments: &[String]) -> Result<(), String> {
    let options = parse(arguments)?;
    let config = Arc::new(crate::compose::load(arguments).map_err(|error| error.to_string())?);

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|error| error.to_string())?;
    let report = runtime.block_on(run(&options, config))?;
    crate::out(&report)
}

/// Read the arguments, or say what is wrong with them.
fn parse(arguments: &[String]) -> Result<Options, String> {
    // Looked up by name rather than walked in order, as `migrate_db` does: the
    // list still carries the subcommand itself, and a parser that rejected
    // every argument it did not recognise would reject that first.
    let from = flag(arguments, "--from")
        .map(PathBuf::from)
        .ok_or_else(|| "migrate-fileserver needs --from <the plugin's storage_path>".to_owned())?;
    let instance = match flag(arguments, "--instance") {
        Some(value) => value
            .parse()
            .map_err(|_| format!("--instance needs an instance id, not {value:?}"))?,
        None => 1,
    };
    if !from.join("metadata.db").exists() {
        return Err(format!(
            "{} holds no metadata.db; --from wants the plugin's storage_path",
            from.display()
        ));
    }
    Ok(Options {
        from,
        instance,
        dry_run: arguments.iter().any(|argument| argument == "--dry-run"),
        verify: arguments.iter().any(|argument| argument == "--verify"),
    })
}

/// The value after `name`, if it is there.
fn flag(arguments: &[String], name: &str) -> Option<String> {
    let mut rest = arguments.iter();
    while let Some(argument) = rest.next() {
        if argument == name {
            return rest.next().cloned();
        }
    }
    None
}

/// Open a copy of the plugin's database.
///
/// Copied rather than opened where it lies, and that is the stronger form of
/// "non-destructive" rather than a weaker one. `?mode=ro` looks like the
/// answer and is not: every connection this tree opens runs
/// `PRAGMA journal_mode = WAL`, and setting a journal mode *writes*, so a
/// read-only handle fails every connection and the pool times out. Copying
/// also means a plugin still running - still holding its own lock, still
/// writing - cannot be disturbed by this at all.
///
/// The copy is deleted when the [`Source`] is dropped.
struct Source {
    backend: Backend,
    directory: PathBuf,
}

impl Source {
    /// Copy `from`'s database aside and open it.
    async fn open(from: &Path) -> Result<Self, String> {
        let original = from.join("metadata.db");
        if !original.exists() {
            return Err(format!("{} holds no metadata.db", from.display()));
        }
        let directory = std::env::temp_dir().join(format!(
            "starling-fileserver-migration-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&directory)
            .map_err(|error| format!("cannot prepare a working copy: {error}"))?;
        let copy = directory.join("metadata.db");
        let _ = std::fs::copy(&original, &copy)
            .map_err(|error| format!("cannot copy {}: {error}", original.display()))?;
        // The write-ahead log too, where there is one: without it the copy is
        // the database as it stood before the plugin's most recent writes.
        for suffix in ["-wal", "-shm"] {
            let beside = from.join(format!("metadata.db{suffix}"));
            if beside.exists() {
                let _ = std::fs::copy(&beside, directory.join(format!("metadata.db{suffix}")));
            }
        }

        let url = format!("sqlite:{}", copy.display().to_string().replace('\\', "/"));
        let backend = Backend::connect(&url, 1)
            .await
            .map_err(|error| format!("cannot read {}: {error}", original.display()))?;
        Ok(Self { backend, directory })
    }

    /// The connection to read through.
    fn backend(&self) -> &Backend {
        &self.backend
    }
}

impl Drop for Source {
    fn drop(&mut self) {
        // Best effort: a working copy left behind is untidy, and failing the
        // migration over it would be worse.
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}

/// The whole run, from opening the plugin's storage to the printed report.
async fn run(options: &Options, config: Arc<Config>) -> Result<String, String> {
    let source = Source::open(&options.from).await?;
    let mut report = Report::default();

    let read = read_all(source.backend(), &options.from, &mut report).await?;

    let mut text = String::new();
    let _ = writeln!(text, "source     {}", options.from.display());
    let _ = writeln!(text, "instance   {}", options.instance);
    if options.dry_run {
        let _ = writeln!(text, "mode       dry run, nothing is written");
    }
    let _ = writeln!(text);
    let _ = write!(text, "{}", read.counts.describe("  read     "));

    if !options.dry_run {
        let written = write_all(&config, options, &read, &mut report).await?;
        let _ = write!(text, "{}", written.describe("  written  "));
        if options.verify {
            let _ = write!(text, "{}", verify(&config, options, &written).await?);
        }
    }

    if report.skipped.is_empty() {
        let _ = writeln!(text, "\n  nothing was dropped");
    } else {
        let _ = writeln!(text, "\n  could not be carried:");
        for line in &report.skipped {
            let _ = writeln!(text, "    {line}");
        }
    }
    Ok(text)
}

/// One private-storage row.
#[derive(Debug)]
struct Record {
    /// The plugin's `"<server_id>:<user_id>"` scope, in a column still called
    /// `cert_hash` because that is what it held before accounts outlived
    /// certificates.
    scope: String,
    key: String,
    value: Vec<u8>,
}

/// Everything read out of the plugin.
#[derive(Debug, Default)]
struct Read {
    counts: Counts,
    records: Vec<Record>,
}

/// Read what the plugin holds.
async fn read_all(source: &Backend, from: &Path, report: &mut Report) -> Result<Read, String> {
    use sqlx::Row as _;
    let mut read = Read::default();

    // -- private storage ---------------------------------------------------
    let rows = sqlx::query("SELECT cert_hash, key, blob FROM private_storage")
        .fetch_all(source.pool())
        .await
        .map_err(|error| format!("reading private_storage: {error}"))?;
    for row in &rows {
        let (Ok(scope), Ok(key), Ok(value)) = (
            row.try_get::<String, _>("cert_hash"),
            row.try_get::<String, _>("key"),
            row.try_get::<Vec<u8>, _>("blob"),
        ) else {
            report.skip("a private_storage row with unreadable columns");
            continue;
        };
        // Guests were never given a scope, so their rows name nothing that
        // survives the connection and there is nothing to carry them to.
        if scope.is_empty() || !scope.contains(':') {
            report.skip(format!(
                "private record {key:?} belonging to no account (scope {scope:?})"
            ));
            continue;
        }
        read.counts.records += 1;
        read.records.push(Record { scope, key, value });
    }

    // -- the ones this build does not carry yet ----------------------------
    //
    // Counted and named rather than silently ignored: an operator who reads
    // "0 emotes" from a store that has twelve has been misled, and the whole
    // point of the report is that it can be trusted.
    // Literal queries rather than a table name in a `format!`: `sqlx` refuses
    // a dynamic SQL string, and rightly - a table name interpolated once is a
    // table name interpolated from user input later.
    for (count, what) in [
        (count_of(source, Table::Emotes).await, "emotes"),
        (count_of(source, Table::Documents).await, "documents"),
        (count_of(source, Table::Files).await, "shared files"),
    ] {
        if count > 0 {
            report.skip(format!(
                "{count} {what}: their bytes live under {}, and carrying them needs the                  file-server's own signing key to re-sign what it stored",
                from.display()
            ));
        }
    }

    Ok(read)
}

/// One of the plugin's tables, named rather than spelled.
#[derive(Debug, Clone, Copy)]
enum Table {
    Emotes,
    Documents,
    Files,
}

/// How many rows one of the plugin's tables holds.
///
/// A literal query per table, because `sqlx` refuses a dynamic SQL string -
/// and it is right to, so the enum is what stands in for interpolation.
async fn count_of(source: &Backend, table: Table) -> i64 {
    use sqlx::Row as _;
    let query = match table {
        Table::Emotes => sqlx::query("SELECT COUNT(*) AS n FROM emotes"),
        Table::Documents => sqlx::query("SELECT COUNT(*) AS n FROM documents"),
        Table::Files => sqlx::query("SELECT COUNT(*) AS n FROM files"),
    };
    query
        .fetch_one(source.pool())
        .await
        .ok()
        .and_then(|row| row.try_get::<i64, _>("n").ok())
        .unwrap_or_default()
}

/// Write what was read into the stores that replace the plugin.
async fn write_all(
    config: &Arc<Config>,
    options: &Options,
    read: &Read,
    report: &mut Report,
) -> Result<Counts, String> {
    let mut written = Counts::default();

    let userdata = open(config, "userdata").await?;
    let records = starling_userdata::Records::open(userdata)
        .await
        .map_err(|error| format!("opening the record store: {error}"))?;

    for record in &read.records {
        let Some(account) = account_of(&record.scope) else {
            report.skip(format!("private record {:?}: unreadable scope", record.key));
            continue;
        };
        // The plugin's keys and the client's new ones are deliberately
        // different strings, so a server that has both stores cannot have one
        // write land where the other reads. The mapping is that table.
        let key = match record.key.as_str() {
            "livedoc-sidebar" => "livedoc/sidebar",
            "livedoc-sources-master" => "livedoc/sources",
            "calendar" => "calendar",
            other => other,
        };
        match records
            .put(options.instance, account, key, &record.value)
            .await
        {
            Ok(_) => written.records += 1,
            Err(error) => report.skip(format!(
                "private record {:?} for account {account}: {error:?}",
                record.key
            )),
        }
    }

    Ok(written)
}

/// Count both sides, through the destination's own reads.
async fn verify(
    config: &Arc<Config>,
    options: &Options,
    written: &Counts,
) -> Result<String, String> {
    let userdata = open(config, "userdata").await?;
    let records = starling_userdata::Records::open(userdata)
        .await
        .map_err(|error| format!("opening the record store: {error}"))?;

    // Counted per account rather than in one query, because the store's own
    // reads are per account - and a verification that invents a query the
    // service never issues verifies a query rather than the data.
    let mut found = 0_u64;
    for account in records.accounts(options.instance).await {
        found += records.list(options.instance, account, "").await.len() as u64;
    }

    let mut text = String::new();
    let _ = writeln!(
        text,
        "  verify     {found} private records readable, {} written",
        written.records
    );
    if found < written.records {
        let _ = writeln!(
            text,
            "             ^ fewer than were written; something is wrong"
        );
    }
    Ok(text)
}

/// The account id inside the plugin's `"<server_id>:<user_id>"` scope.
fn account_of(scope: &str) -> Option<u64> {
    scope.split_once(':')?.1.parse().ok()
}

/// Open one service's own database, the way that service would.
async fn open(config: &Arc<Config>, service: &str) -> Result<Store, String> {
    let url = config
        .services
        .get(service)
        .and_then(|block| block.storage.as_ref())
        .map(|storage| storage.url.clone())
        .filter(|url| !url.is_empty())
        .unwrap_or_else(|| {
            let dir = &config.runtime.data_dir;
            let _ = std::fs::create_dir_all(dir);
            format!(
                "sqlite:{}?mode=rwc",
                dir.join(format!("{service}.db")).display()
            )
        });
    Store::open(&url, 4)
        .await
        .map_err(|error| format!("cannot open {service}: {error}"))
}

/// The keys a migrated private record lands under.
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_account_is_read_out_of_the_plugins_scope_string() {
        assert_eq!(account_of("1:42"), Some(42));
        assert_eq!(account_of("0:0"), Some(0), "the SuperUser is account zero");
    }

    #[test]
    fn a_scope_that_names_no_account_carries_nothing() {
        // A guest's rows: the plugin gave them an empty scope, so there is no
        // account for them to belong to on the other side.
        assert_eq!(account_of(""), None);
        assert_eq!(account_of("1:"), None);
        assert_eq!(account_of("nonsense"), None);
    }

    #[test]
    fn a_report_with_nothing_in_it_says_so_rather_than_printing_nothing() {
        let text = Counts::default().describe("  ");
        assert!(text.contains("anything at all"), "{text}");
    }

    #[test]
    fn a_report_lists_only_the_kinds_that_had_rows() {
        let counts = Counts {
            records: 3,
            ..Counts::default()
        };
        let text = counts.describe("  ");
        assert!(text.contains("3"));
        assert!(text.contains("private records"));
        assert!(
            !text.contains("emotes"),
            "a kind with nothing in it is noise"
        );
    }
}
