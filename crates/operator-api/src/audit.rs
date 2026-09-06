//! Fail-closed audit for the admin plane.
//!
//! Every operator action is recorded, and **a request is refused if it cannot
//! be recorded** unless the operator sets `fail_closed = false`. `audit` is an
//! optional service and the highest-privilege plane must not depend on one, so
//! `operator-api` writes this record itself (`docs/ARCHITECTURE.md` §3).
//!
//! This type writes and reports; the policy is applied one layer up, in
//! [`crate::OperatorApi::record`].

use std::sync::{Arc, Mutex};

use starling_runtime::config::OperatorAudit;
use starling_runtime::ids::{Uuid7, now_ms};
use starling_runtime::log::FileSink;

/// One recorded action.
#[derive(Debug, Clone)]
pub struct AuditRecord {
    /// Who did it.
    pub subject: String,
    /// What they did: the HTTP method and path.
    pub action: String,
    /// The outcome, once known.
    pub outcome: String,
}

/// The rotating file behind it.
///
/// Rotation is [`FileSink`]'s, the same one the runtime log uses, rather than a
/// second implementation here: this file used to be the one thing in the tree
/// that grew without bound.
#[derive(Debug)]
pub struct AuditLog {
    config: OperatorAudit,
    file: Arc<Mutex<Option<FileSink>>>,
}

impl AuditLog {
    /// A log over `config`.
    #[must_use]
    pub fn new(config: OperatorAudit) -> Self {
        Self {
            config,
            file: Arc::new(Mutex::new(None)),
        }
    }

    /// Record one action.
    ///
    /// # Errors
    ///
    /// The I/O error, which the caller turns into a refusal when
    /// `fail_closed` is set. With it unset the caller may proceed; that is an
    /// operator's decision to take, and it is not the default.
    pub async fn record(&self, record: &AuditRecord) -> std::io::Result<()> {
        let line = format!(
            "{{\"id\":\"{}\",\"at_ms\":{},\"subject\":{:?},\"action\":{:?},\"outcome\":{:?}}}",
            Uuid7::now(),
            now_ms(),
            record.subject,
            record.action,
            record.outcome
        );

        // Off the reactor. This is a synchronous `create_dir_all`, `open`,
        // `write` and `flush` under a `std::sync::Mutex`, called from async
        // handlers: on a slow or full disk it blocked a runtime worker, and the
        // worker it blocked was also carrying voice and control traffic for
        // everybody else.
        //
        // Still awaited, not fired and forgotten, because this log is
        // fail-closed by default: the caller refuses the request when the
        // record cannot be written, and a queue would take that answer away.
        let file = Arc::clone(&self.file);
        let config = self.config.clone();
        tokio::task::spawn_blocking(move || Self::append(&file, &config, &line))
            .await
            .map_err(|error| {
                std::io::Error::other(format!("the audit writer did not finish: {error}"))
            })?
    }

    /// Open on first use, then append one record and flush it.
    fn append(
        file: &Mutex<Option<FileSink>>,
        config: &OperatorAudit,
        line: &str,
    ) -> std::io::Result<()> {
        let mut held = file
            .lock()
            .map_err(|_| std::io::Error::other("the audit log is poisoned"))?;
        if held.is_none() {
            *held = Some(
                FileSink::open(&config.path, config.max_bytes, config.keep)
                    .map_err(|error| std::io::Error::other(error.to_string()))?,
            );
        }
        let Some(sink) = held.as_mut() else {
            return Err(std::io::Error::other("the audit log could not be opened"));
        };
        sink.write_line(line)
            .map_err(|error| std::io::Error::other(error.to_string()))?;
        // Flushed per record rather than per buffer: an operator action still
        // sitting in a page cache when the process dies was not recorded.
        starling_runtime::log::LogSink::flush(sink)
            .map_err(|error| std::io::Error::other(error.to_string()))
    }

    /// Whether a failure to record must refuse the request.
    #[must_use]
    pub const fn fail_closed(&self) -> bool {
        self.config.fail_closed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_log(name: &str) -> (AuditLog, std::path::PathBuf) {
        let path =
            std::env::temp_dir().join(format!("starling-audit-{name}-{}", std::process::id()));
        let _ = std::fs::remove_file(&path);
        (
            AuditLog::new(OperatorAudit {
                path: path.clone(),
                fail_closed: true,
                ..OperatorAudit::default()
            }),
            path,
        )
    }

    #[tokio::test]
    async fn a_record_reaches_the_disk_before_the_call_returns() {
        // An action still sitting in a page cache when the process dies was not
        // recorded, and fail-closed would be a lie.
        let (log, path) = temp_log("flush");
        log.record(&AuditRecord {
            subject: "token:ADMIN".to_owned(),
            action: "POST /accounts".to_owned(),
            outcome: "created".to_owned(),
        })
        .await
        .expect("record");

        let written = std::fs::read_to_string(&path).expect("the file exists");
        assert!(written.contains("POST /accounts"));
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn a_log_that_cannot_be_opened_reports_it_rather_than_succeeding_quietly() {
        let log = AuditLog::new(OperatorAudit {
            // A directory, not a file: opening it for append must fail.
            path: std::path::PathBuf::from("/"),
            fail_closed: true,
            ..OperatorAudit::default()
        });
        assert!(log.fail_closed());
        assert!(
            log.record(&AuditRecord {
                subject: "s".to_owned(),
                action: "a".to_owned(),
                outcome: "o".to_owned(),
            })
            .await
            .is_err()
        );
    }

    /// Defect 14: this file had no rotation, unlike the runtime's own log.
    #[tokio::test]
    async fn the_audit_log_rotates_instead_of_growing_forever() {
        let dir = std::env::temp_dir().join(format!("starling-audit-roll-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp dir");
        let path = dir.join("operator-audit.log");

        let log = AuditLog::new(OperatorAudit {
            path: path.clone(),
            fail_closed: true,
            // Small enough that a handful of records crosses it.
            max_bytes: 512,
            keep: 2,
        });

        for action in 0..64 {
            log.record(&AuditRecord {
                subject: "token:ADMIN".to_owned(),
                action: format!("POST /accounts/{action}"),
                outcome: "created".to_owned(),
            })
            .await
            .expect("record");
        }

        let live = std::fs::metadata(&path).expect("the live file").len();
        assert!(
            live <= 512 + 256,
            "the live file grew past its limit: {live} bytes"
        );
        let rolled = std::path::PathBuf::from(format!("{}.1", path.display()));
        assert!(rolled.exists(), "a generation must have been rolled");
        assert!(
            !std::path::PathBuf::from(format!("{}.3", path.display())).exists(),
            "keep = 2 must not leave a third generation"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }
}
