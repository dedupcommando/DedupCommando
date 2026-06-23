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

/// Initializes logging INTO TWO FILES (the terminal is occupied by the TUI — can't go there):
/// the regular log (`log_file`, everything except target `bench`) and a separate
/// benchmarks log (`bench_file`, only target `bench` at info level).
///
/// Returns both `WorkerGuard`s — they must be kept alive for the entire runtime
/// of the program (Drop flushes the remaining buffers).
pub fn init(log_file: &Path, bench_file: &Path) -> (WorkerGuard, WorkerGuard) {
    // Safely establish the state-dir (0700, no-follow check of the whole chain). On failure
    // (untrusted chain) — do NOT open the files (sink): otherwise OpenOptions would follow a
    // symlink ancestor BEFORE the fail-closed check of write mode. log_file and
    // bench_file share one parent (state-dir).
    let dir_secure = match log_file.parent() {
        Some(parent) => crate::paths::establish_state_dir(parent).is_ok(),
        None => false,
    };

    let (main_writer, main_guard) = make_writer(dir_secure.then_some(log_file));
    let (bench_writer, bench_guard) = make_writer(dir_secure.then_some(bench_file));

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

/// Non-blocking writer to a file (`O_NOFOLLOW` — we do not follow a symlink on the log
/// file itself); on `None` (untrusted state-dir) or open failure — to «nowhere» (but
/// not to the terminal, which is occupied by the TUI).
fn make_writer(file: Option<&Path>) -> (tracing_appender::non_blocking::NonBlocking, WorkerGuard) {
    let opened = file.and_then(|path| {
        fs::OpenOptions::new()
            .create(true)
            .append(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)
            .ok()
    });
    match opened {
        Some(file) => tracing_appender::non_blocking(file),
        None => tracing_appender::non_blocking(io::sink()),
    }
}
