//! Fail-closed audit for the admin plane.
//!
//! Every operator action is recorded, and **a request is refused if it cannot
//! be recorded**. `audit` is an optional service and the highest-privilege
//! plane must not depend on one, so `operator-api` writes this record itself
//! (`docs/ARCHITECTURE.md` §3).

use std::io::Write as _;
use std::sync::Mutex;

use starling_runtime::config::OperatorAudit;
use starling_runtime::ids::{Uuid7, now_ms};

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

/// The append-only file behind it.
#[derive(Debug)]
pub struct AuditLog {
    config: OperatorAudit,
    file: Mutex<Option<std::fs::File>>,
}

impl AuditLog {
    /// A log over `config`.
    #[must_use]
    pub fn new(config: OperatorAudit) -> Self {
        Self {
            config,
            file: Mutex::new(None),
        }
    }

    /// Record one action.
    ///
    /// # Errors
    ///
    /// The I/O error, which the caller turns into a refusal when
    /// `fail_closed` is set. With it unset the caller may proceed — that is an
    /// operator's decision to take, and it is not the default.
    pub fn record(&self, record: &AuditRecord) -> std::io::Result<()> {
        let line = format!(
            "{{\"id\":\"{}\",\"at_ms\":{},\"subject\":{:?},\"action\":{:?},\"outcome\":{:?}}}\n",
            Uuid7::now(),
            now_ms(),
            record.subject,
            record.action,
            record.outcome
        );

        let mut held = self
            .file
            .lock()
            .map_err(|_| std::io::Error::other("the audit log is poisoned"))?;
        if held.is_none() {
            if let Some(parent) = self.config.path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            *held = Some(
                std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(&self.config.path)?,
            );
        }
        let Some(file) = held.as_mut() else {
            return Err(std::io::Error::other("the audit log could not be opened"));
        };
        file.write_all(line.as_bytes())?;
        // Flushed per record rather than per buffer: an operator action that is
        // still in a page cache when the process dies was not recorded.
        file.flush()
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
            }),
            path,
        )
    }

    #[test]
    fn a_record_reaches_the_disk_before_the_call_returns() {
        // An action still sitting in a page cache when the process dies was not
        // recorded, and fail-closed would be a lie.
        let (log, path) = temp_log("flush");
        log.record(&AuditRecord {
            subject: "token:ADMIN".to_owned(),
            action: "POST /accounts".to_owned(),
            outcome: "created".to_owned(),
        })
        .expect("record");

        let written = std::fs::read_to_string(&path).expect("the file exists");
        assert!(written.contains("POST /accounts"));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn a_log_that_cannot_be_opened_reports_it_rather_than_succeeding_quietly() {
        let log = AuditLog::new(OperatorAudit {
            // A directory, not a file: opening it for append must fail.
            path: std::path::PathBuf::from("/"),
            fail_closed: true,
        });
        assert!(log.fail_closed());
        assert!(
            log.record(&AuditRecord {
                subject: "s".to_owned(),
                action: "a".to_owned(),
                outcome: "o".to_owned(),
            })
            .is_err()
        );
    }
}
