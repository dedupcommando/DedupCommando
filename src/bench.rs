// SPDX-License-Identifier: Apache-2.0
//! Measures the duration of heavy operations. Writes one structured line
//! per operation to a separate log `benchmarks.log` via the `tracing` target
//! `bench`. Goal — to see performance degradation separately from the noise of
//! the regular log.
//!
//! Usage:
//! ```ignore
//! let mut span = bench::start("read_panel_dir").attach_dir(dir);
//! // … work …
//! span.set_entries(out.len() as u64);
//! // the line is written on Drop of span
//! ```

use std::path::{Path, PathBuf};
use std::time::Instant;

/// Measures one operation. The line is written on `Drop` — keep the span alive until work ends.
pub struct BenchSpan {
    op: &'static str,
    start: Instant,
    dir: Option<PathBuf>,
    entries: u64,
    ok: bool,
}

/// Starts measuring operation `op`.
pub fn start(op: &'static str) -> BenchSpan {
    BenchSpan {
        op,
        start: Instant::now(),
        dir: None,
        entries: 0,
        ok: true,
    }
}

impl BenchSpan {
    /// Attaches the path (directory/file) the operation relates to.
    pub fn attach_dir(mut self, dir: impl AsRef<Path>) -> Self {
        self.dir = Some(dir.as_ref().to_path_buf());
        self
    }

    /// How many entries/files were processed — for normalizing the time.
    pub fn set_entries(&mut self, entries: u64) {
        self.entries = entries;
    }

    /// Marks the operation as having ended with an error.
    pub fn fail(&mut self) {
        self.ok = false;
    }
}

/// The structured line a finished span reports, before it becomes a log event.
///
/// It exists so the tests can assert on what is reported without installing a `tracing`
/// subscriber: `tracing` caches callsite interest process-wide, and the `info!` below shares
/// its callsite with every other `BenchSpan` in the binary — including ones dropped on worker
/// threads of unrelated tests. A per-test subscriber therefore could not own what it captured.
#[derive(Debug, Clone, PartialEq, Eq)]
struct BenchRecord {
    op: &'static str,
    ms: u64,
    entries: u64,
    dir: String,
    ok: bool,
}

impl BenchSpan {
    /// What this span will report. Pure — no logging and no globals.
    fn record(&self) -> BenchRecord {
        BenchRecord {
            op: self.op,
            ms: self.start.elapsed().as_millis() as u64,
            entries: self.entries,
            // The path goes into benchmarks.log; raw ANSI/OSC would execute on
            // `cat benchmarks.log`. Escape control bytes (as in the regular log).
            dir: self
                .dir
                .as_ref()
                .map(|d| crate::textsan::terminal(&d.display().to_string()))
                .unwrap_or_default(),
            ok: self.ok,
        }
    }
}

impl Drop for BenchSpan {
    fn drop(&mut self) {
        emit(&self.record());
    }
}

/// The one place a bench record reaches `tracing`. Keeping the macro here and nowhere else
/// keeps the field mapping in a single auditable spot.
fn emit(record: &BenchRecord) {
    #[cfg(test)]
    tests::capture(record);
    tracing::info!(
        target: "bench",
        op = record.op,
        ms = record.ms,
        entries = record.entries,
        dir = %record.dir,
        ok = record.ok,
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    thread_local! {
        /// Records emitted on THIS thread while a `Capture` is alive. Thread-local and
        /// per-test on purpose: parallel tests share no subscriber, no buffer and no queue,
        /// and a `BenchSpan` dropped by some other test's worker thread cannot reach it.
        static CAPTURED: RefCell<Option<Vec<BenchRecord>>> = const { RefCell::new(None) };
    }

    /// Called by `emit` in test builds only; a no-op unless this thread is capturing.
    pub(super) fn capture(record: &BenchRecord) {
        CAPTURED.with(|slot| {
            if let Some(records) = slot.borrow_mut().as_mut() {
                records.push(record.clone());
            }
        });
    }

    /// Collects the bench records emitted on this thread for as long as it is alive, and
    /// stops collecting when it is dropped — including when the test panics.
    struct Capture;

    impl Capture {
        fn start() -> Self {
            CAPTURED.with(|slot| *slot.borrow_mut() = Some(Vec::new()));
            Self
        }

        fn records(&self) -> Vec<BenchRecord> {
            CAPTURED.with(|slot| slot.borrow().clone().unwrap_or_default())
        }
    }

    impl Drop for Capture {
        fn drop(&mut self) {
            CAPTURED.with(|slot| *slot.borrow_mut() = None);
        }
    }

    /// Asserts the record the span hands to `emit`, not the log line `tracing` formats from
    /// it — the field-to-log mapping lives in `emit` and is read there, not tested here.
    #[test]
    fn bench_span_captures_one_record_with_expected_fields() {
        let capture = Capture::start();
        {
            let mut span = start("read_panel_dir").attach_dir("/tank/data");
            span.set_entries(42);
        }

        let records = capture.records();
        assert_eq!(records.len(), 1, "exactly one record: {records:?}");
        assert_eq!(records[0].op, "read_panel_dir");
        assert_eq!(records[0].entries, 42);
        assert_eq!(records[0].dir, "/tank/data");
        assert!(records[0].ok);
    }

    #[test]
    fn bench_span_records_failure() {
        let capture = Capture::start();
        {
            let mut span = start("hash_file");
            span.fail();
        }

        let records = capture.records();
        assert_eq!(records.len(), 1, "exactly one record: {records:?}");
        assert_eq!(records[0].op, "hash_file");
        assert!(!records[0].ok);
    }

    #[test]
    fn bench_span_escapes_control_bytes_in_dir() {
        // Control bytes in the path must not reach benchmarks.log raw.
        let capture = Capture::start();
        drop(start("read_panel_dir").attach_dir("/tank/x\u{1b}[31m"));

        let records = capture.records();
        assert_eq!(records.len(), 1, "exactly one record: {records:?}");
        let dir = &records[0].dir;
        assert!(
            !dir.contains('\u{1b}'),
            "raw ESC must not reach the log: {dir:?}"
        );
        assert!(dir.contains("\\u{1b}"), "ESC must be escaped: {dir}");
    }

    /// A span dropped on a thread that is not capturing still emits its `tracing` event —
    /// that is the production path, and it is every other test's worker thread. What it must
    /// not do is leave a record behind for a capture that was never armed.
    #[test]
    fn a_span_without_capture_stores_no_test_record() {
        drop(start("read_panel_dir").attach_dir("/tank/data"));
        CAPTURED.with(|slot| assert!(slot.borrow().is_none()));
    }
}
