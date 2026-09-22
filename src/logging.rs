// SPDX-License-Identifier: Apache-2.0
use std::fs;
use std::io;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use tracing::level_filters::LevelFilter;
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::filter::Targets;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{fmt, EnvFilter, Layer};

use crate::paths::StateAccess;

/// Initializes logging INTO TWO FILES (the terminal is occupied by the TUI — can't go there):
/// the regular log (`log_file`, everything except target `bench`) and a separate
/// benchmarks log (`bench_file`, only target `bench` at info level).
///
/// `access` is how the mode reaches the state directory both files live in: a mode that writes
/// establishes it, a mode that only reports verifies it and changes nothing (see `open_logs`).
///
/// Returns both `WorkerGuard`s — they must be kept alive for the entire runtime
/// of the program (Drop flushes the remaining buffers).
pub fn init(log_file: &Path, bench_file: &Path, access: StateAccess) -> (WorkerGuard, WorkerGuard) {
    let (main_file, bench_file) = open_logs(log_file, bench_file, access);
    let (main_writer, main_guard) = make_writer(main_file);
    let (bench_writer, bench_guard) = make_writer(bench_file);

    // Regular log: filter from DEDCOM_LOG (info by default), but target `bench`
    // is excluded — it goes only to benchmarks.log.
    let env = EnvFilter::try_from_env("DEDCOM_LOG")
        .unwrap_or_else(|_| EnvFilter::new("info"))
        .add_directive("bench=off".parse().expect("directive bench=off is valid"));

    let main_layer = fmt::layer()
        .with_ansi(false)
        .with_writer(main_writer)
        .with_filter(env);

    // Benchmarks: only target `bench`, info level.
    let bench_layer = fmt::layer()
        .with_ansi(false)
        .with_writer(bench_writer)
        .with_filter(Targets::new().with_target("bench", LevelFilter::INFO));

    tracing_subscriber::registry()
        .with(main_layer)
        .with(bench_layer)
        .init();

    (main_guard, bench_guard)
}

/// Opens both log files, or neither. Separate from `init` because the subscriber `init` installs
/// is global to the process and can be installed once; this half can be called by a test.
fn open_logs(
    log_file: &Path,
    bench_file: &Path,
    access: StateAccess,
) -> (Option<fs::File>, Option<fs::File>) {
    // The state directory is checked first, the whole chain no-follow: otherwise OpenOptions
    // would follow a symlink ancestor BEFORE the fail-closed check of write mode. A mode that
    // writes establishes it (creates it, or takes an existing one only if it is ours or empty);
    // a mode that only reports verifies it and changes nothing. On a refusal the files are NOT
    // opened (sink): a log planted in somebody else's directory would also make it look like
    // ours to the mode's own check that follows. log_file and bench_file share one parent.
    let dir_usable = match log_file.parent() {
        Some(dir) => match access {
            StateAccess::Writing => crate::paths::establish_state_dir(dir).is_ok(),
            StateAccess::ReadOnly => crate::paths::verify_state_dir(dir).is_ok(),
        },
        None => false,
    };
    if !dir_usable {
        return (None, None);
    }
    (open_log(log_file), open_log(bench_file))
}

/// A log file for appending (`O_NOFOLLOW` — we do not follow a symlink on the log file itself);
/// `None` when it cannot be opened.
fn open_log(path: &Path) -> Option<fs::File> {
    fs::OpenOptions::new()
        .create(true)
        .append(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .ok()
}

/// Non-blocking writer to a file; on `None` (a state directory this mode may not log into, or a
/// file that would not open) — to «nowhere» (but not to the terminal, which is occupied by the
/// TUI).
fn make_writer(
    file: Option<fs::File>,
) -> (tracing_appender::non_blocking::NonBlocking, WorkerGuard) {
    match file {
        Some(file) => tracing_appender::non_blocking(file),
        None => tracing_appender::non_blocking(io::sink()),
    }
}

#[cfg(test)]
mod tests {
    use super::open_logs;
    use crate::paths::StateAccess;
    use crate::testfixtures::{mode_bits as mode_of, names_in};
    use std::ffi::OsString;
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};

    fn temp_base(tag: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let dir = std::env::temp_dir().join(format!(
            "dedcom_logging_{tag}_{}_{nanos}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// A directory holding `entries`, then set to `mode`.
    fn existing_dir(dir: &Path, mode: u32, entries: &[&str]) {
        std::fs::create_dir(dir).unwrap();
        for entry in entries {
            std::fs::write(dir.join(entry), b"earlier line\n").unwrap();
        }
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    fn logs_in(dir: &Path, access: StateAccess) -> (Option<std::fs::File>, Option<std::fs::File>) {
        open_logs(&dir.join("dedcom.log"), &dir.join("benchmarks.log"), access)
    }

    /// `--stats` over a state directory that is not there leaves it not there.
    #[test]
    fn a_reporting_mode_creates_no_directory_and_no_log() {
        let base = temp_base("ro_missing");
        let dir = base.join("state");
        let (log, bench) = logs_in(&dir, StateAccess::ReadOnly);
        assert!(log.is_none() && bench.is_none(), "the log goes nowhere");
        assert!(!dir.exists(), "the state directory is not created");
        std::fs::remove_dir_all(&base).ok();
    }

    /// `--state-dir /etc --stats`: `/etc` keeps its mode and gains no log.
    #[test]
    fn a_reporting_mode_leaves_a_foreign_directory_as_it_was() {
        let base = temp_base("ro_foreign");
        let dir = base.join("etc");
        existing_dir(&dir, 0o755, &["passwd"]);
        let (log, bench) = logs_in(&dir, StateAccess::ReadOnly);
        assert!(log.is_none() && bench.is_none(), "the log goes nowhere");
        assert_eq!(mode_of(&dir), 0o755);
        assert_eq!(names_in(&dir), [OsString::from("passwd")]);
        std::fs::remove_dir_all(&base).ok();
    }

    /// In its own directory a reporting mode logs as before — appending to the log that is there,
    /// creating the one that is missing — and leaves the directory's mode alone.
    #[test]
    fn a_reporting_mode_logs_into_its_own_directory_as_before() {
        let base = temp_base("ro_ours");
        let dir = base.join("state");
        existing_dir(&dir, 0o750, &["dedcom.db", "dedcom.log"]);
        let (log, bench) = logs_in(&dir, StateAccess::ReadOnly);
        let (mut log, bench) = (
            log.expect("the log is opened"),
            bench.expect("and the other"),
        );
        log.write_all(b"new line\n").unwrap();
        drop((log, bench));
        assert_eq!(
            std::fs::read(dir.join("dedcom.log")).unwrap(),
            b"earlier line\nnew line\n"
        );
        assert!(dir.join("benchmarks.log").is_file());
        assert_eq!(mode_of(&dir), 0o750, "the directory keeps its mode");
        std::fs::remove_dir_all(&base).ok();
    }

    /// The log is opened before the mode's own check of the directory, so it must not be what makes
    /// a foreign directory look like ours: a `dedcom.log` it planted would pass that check.
    #[test]
    fn a_writing_mode_plants_no_log_in_a_foreign_directory() {
        let base = temp_base("rw_foreign");
        let dir = base.join("etc");
        existing_dir(&dir, 0o755, &["passwd"]);
        let (log, bench) = logs_in(&dir, StateAccess::Writing);
        assert!(log.is_none() && bench.is_none(), "the log goes nowhere");
        assert_eq!(names_in(&dir), [OsString::from("passwd")]);
        assert_eq!(mode_of(&dir), 0o755);
        assert!(
            crate::paths::establish_state_dir(&dir).is_err(),
            "and the directory is still refused by the mode's own check"
        );
        std::fs::remove_dir_all(&base).ok();
    }

    /// A mode that writes still creates its missing directory at 0700 and both logs in it.
    #[test]
    fn a_writing_mode_creates_its_directory_and_both_logs() {
        let base = temp_base("rw_new");
        let dir = base.join("new").join("state");
        let (log, bench) = logs_in(&dir, StateAccess::Writing);
        assert!(log.is_some() && bench.is_some());
        assert_eq!(mode_of(&dir), 0o700);
        assert!(dir.join("dedcom.log").is_file() && dir.join("benchmarks.log").is_file());
        std::fs::remove_dir_all(&base).ok();
    }
}
