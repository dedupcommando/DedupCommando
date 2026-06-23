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

impl Drop for BenchSpan {
    fn drop(&mut self) {
        let ms = self.start.elapsed().as_millis() as u64;
        // The path goes into benchmarks.log; raw ANSI/OSC would execute on
        // `cat benchmarks.log`. Escape control bytes (as in the regular log).
        let dir = self
            .dir
            .as_ref()
            .map(|d| crate::textsan::terminal(&d.display().to_string()))
            .unwrap_or_default();
        tracing::info!(
            target: "bench",
            op = self.op,
            ms,
            entries = self.entries,
            dir = %dir,
            ok = self.ok,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::sync::{Arc, Mutex};

    #[derive(Clone)]
    struct BufWriter(Arc<Mutex<Vec<u8>>>);

    impl Write for BufWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn bench_span_emits_one_line_with_op() {
        let buf = Arc::new(Mutex::new(Vec::<u8>::new()));
        let writer = BufWriter(buf.clone());
        let subscriber = tracing_subscriber::fmt()
            .with_writer(move || writer.clone())
            .with_ansi(false)
            .finish();

        tracing::subscriber::with_default(subscriber, || {
            let mut span = start("read_panel_dir").attach_dir("/tank/data");
            span.set_entries(42);
            drop(span);
        });

        let out = String::from_utf8(buf.lock().unwrap().clone()).unwrap();
        assert_eq!(out.lines().count(), 1, "exactly one line: {out:?}");
        assert!(out.contains("read_panel_dir"), "{out}");
        assert!(out.contains("entries=42"), "{out}");
        assert!(out.contains("/tank/data"), "{out}");
        assert!(out.contains("ok=true"), "{out}");
    }

    #[test]
    fn bench_span_records_failure() {
        let buf = Arc::new(Mutex::new(Vec::<u8>::new()));
        let writer = BufWriter(buf.clone());
        let subscriber = tracing_subscriber::fmt()
            .with_writer(move || writer.clone())
            .with_ansi(false)
            .finish();

        tracing::subscriber::with_default(subscriber, || {
            let mut span = start("hash_file");
            span.fail();
            drop(span);
        });

        let out = String::from_utf8(buf.lock().unwrap().clone()).unwrap();
        assert!(out.contains("ok=false"), "{out}");
    }

    #[test]
    fn bench_span_escapes_control_bytes_in_dir() {
        // Control bytes in the path must not reach benchmarks.log raw.
        let buf = Arc::new(Mutex::new(Vec::<u8>::new()));
        let writer = BufWriter(buf.clone());
        let subscriber = tracing_subscriber::fmt()
            .with_writer(move || writer.clone())
            .with_ansi(false)
            .finish();

        tracing::subscriber::with_default(subscriber, || {
            let span = start("read_panel_dir").attach_dir("/tank/x\u{1b}[31m");
            drop(span);
        });

        let out = String::from_utf8(buf.lock().unwrap().clone()).unwrap();
        assert!(
            !out.contains('\u{1b}'),
            "raw ESC must not reach the log: {out:?}"
        );
        assert!(out.contains("\\u{1b}"), "ESC must be escaped: {out}");
    }
}
