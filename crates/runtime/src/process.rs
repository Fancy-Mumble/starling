//! This process's own resident memory, descriptors and threads.
//!
//! The three numbers a soak run and a memory alert are actually about, and none
//! of them is something the server counts for itself: they are properties of
//! the process, which only the kernel knows.
//!
//! Linux-only, and honest about it. `/proc/self` does not exist on macOS or
//! Windows, and inventing a figure there would be worse than reporting none: an
//! alert on a number that is always zero never fires, and nobody notices it
//! never fires.

/// What the kernel says this process is using.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ProcessStats {
    /// Resident set size, in bytes.
    pub resident_bytes: u64,
    /// Open file descriptors.
    pub open_fds: u64,
    /// The descriptor ceiling, or zero when it cannot be read.
    pub max_fds: u64,
    /// Threads in this process.
    pub threads: u64,
}

/// Read them, or `None` where this platform has no `/proc`.
#[cfg(target_os = "linux")]
#[must_use]
pub fn stats() -> Option<ProcessStats> {
    Some(ProcessStats {
        resident_bytes: resident_bytes()?,
        // A count of directory entries, which is a syscall per descriptor. Fine
        // at a scrape interval and not on any hot path.
        open_fds: std::fs::read_dir("/proc/self/fd").ok()?.count() as u64,
        max_fds: max_fds().unwrap_or(0),
        threads: threads().unwrap_or(0),
    })
}

/// Non-Linux: no `/proc`, so no numbers rather than invented ones.
#[cfg(not(target_os = "linux"))]
#[must_use]
pub fn stats() -> Option<ProcessStats> {
    None
}

/// Resident bytes, from `/proc/self/statm`.
///
/// The second field is resident pages. `statm` rather than `status` because it
/// is two lines of integers rather than forty lines of labelled text.
#[cfg(target_os = "linux")]
fn resident_bytes() -> Option<u64> {
    let statm = std::fs::read_to_string("/proc/self/statm").ok()?;
    let pages: u64 = statm.split_whitespace().nth(1)?.parse().ok()?;
    // 4 KiB on every architecture this runs on. Read from the kernel rather
    // than assumed would need libc; the assumption is stated here instead so a
    // reader on a 64 KiB-page machine knows what to check.
    Some(pages.saturating_mul(4096))
}

/// The soft descriptor limit, from `/proc/self/limits`.
#[cfg(target_os = "linux")]
fn max_fds() -> Option<u64> {
    let limits = std::fs::read_to_string("/proc/self/limits").ok()?;
    let line = limits
        .lines()
        .find(|line| line.starts_with("Max open files"))?;
    // "Max open files            65536                65536                files"
    line.split_whitespace().nth(3)?.parse().ok()
}

/// Threads, from `/proc/self/status`.
///
/// The number that catches a thread nobody joins: the SFU's runtime thread was
/// never joined, and a count that climbs with sessions is how that shows up.
#[cfg(target_os = "linux")]
fn threads() -> Option<u64> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    let line = status.lines().find(|line| line.starts_with("Threads:"))?;
    line.split_whitespace().nth(1)?.parse().ok()
}

/// The three as Prometheus text, using the conventional names.
///
/// `process_resident_memory_bytes`, `process_open_fds` and `process_max_fds`
/// are what every Prometheus client library exports, so a dashboard written
/// against any other service already knows them.
#[must_use]
pub fn render() -> String {
    let Some(stats) = stats() else {
        return String::new();
    };
    let mut out = String::new();
    for (name, kind, help, value) in [
        (
            "process_resident_memory_bytes",
            "gauge",
            "Resident memory, from /proc/self/statm.",
            stats.resident_bytes,
        ),
        (
            "process_open_fds",
            "gauge",
            "Open file descriptors.",
            stats.open_fds,
        ),
        (
            "process_max_fds",
            "gauge",
            "The soft descriptor limit.",
            stats.max_fds,
        ),
        (
            "process_threads",
            "gauge",
            "Threads in this process.",
            stats.threads,
        ),
    ] {
        if value == 0 && name == "process_max_fds" {
            // Unknown, not zero. A limit reported as zero makes every ratio
            // built on it a division by zero or an infinity.
            continue;
        }
        out.push_str(&format!(
            "# HELP {name} {help}\n# TYPE {name} {kind}\n{name} {value}\n"
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    #[test]
    fn this_process_reports_plausible_numbers() {
        let stats = stats().expect("Linux has /proc/self");
        assert!(
            stats.resident_bytes > 1024 * 1024,
            "a running test process uses more than a megabyte: {stats:?}"
        );
        assert!(stats.open_fds > 2, "stdin, stdout and stderr at least");
        assert!(stats.threads >= 1);
        assert!(
            stats.max_fds >= stats.open_fds,
            "the limit cannot be below the count"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn the_export_uses_the_conventional_metric_names() {
        // A dashboard written against any other Prometheus client already knows
        // these names; inventing our own would make it useless here.
        let rendered = render();
        assert!(rendered.contains("# TYPE process_resident_memory_bytes gauge"));
        assert!(rendered.contains("\nprocess_open_fds "));
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn a_platform_without_proc_reports_nothing_rather_than_zero() {
        // An alert on a metric that is always zero never fires, and nobody
        // notices that it never fires.
        assert_eq!(stats(), None);
        assert!(render().is_empty());
    }
}
