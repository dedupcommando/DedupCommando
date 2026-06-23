// SPDX-License-Identifier: Apache-2.0
//! Single-instance lock: an advisory `flock` on a file in the state
//! directory grants the OPERATOR role (scanning, destructive operations, DB
//! writes). A second instance on the same state becomes a read-only observer.
//!
//! Why `libc::flock` directly rather than the `fs2`/`fd-lock` crate: the project
//! is Linux-only and already depends on `libc` (see the direct `lstat` in
//! `pipeline::walk`). An OS advisory lock is tied to the open file description and
//! is released when the fd is closed — including on a process crash. So there is
//! no such thing as a "stale" lock and a `--force-unlock` flag is unnecessary (it
//! makes sense only for a PID-file scheme, which additionally introduces an inode
//! race when unlinking the held file). The PID+time are written to the file only
//! for diagnostics in the second instance.

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};

const LOCK_FILE: &str = "dedcom.lock";

/// The lock holder's data (for a hint in the second instance).
#[derive(Debug, Clone)]
pub struct Holder {
    pub pid: i32,
    pub since: String,
}

/// RAII ownership of the lock: holds an fd with `flock(LOCK_EX)` until Drop. The
/// OS releases the lock when the fd is closed; in Drop we release it explicitly
/// for clarity.
pub struct InstanceLock {
    file: File,
}

impl Drop for InstanceLock {
    fn drop(&mut self) {
        unsafe {
            libc::flock(self.file.as_raw_fd(), libc::LOCK_UN);
        }
    }
}

/// The outcome of an attempt to acquire the lock.
pub enum Acquire {
    /// The lock is ours — we are the operator (the held guard is inside).
    Operator(InstanceLock),
    /// Held by another live process; inside is the holder's data, if readable.
    Busy(Option<Holder>),
}

/// The behavior policy when the lock is held (`<state_dir>/config.json`,
/// the `concurrency` field). Overridden by the `--read-only`/`--force` CLI flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ConcurrencyPolicy {
    /// Ask the user in the startup overlay (default).
    #[default]
    Ask,
    /// Silently enter read-only mode.
    ReadOnly,
    /// Do not start; print a message and exit.
    Block,
    /// Enter as operator without the lock (dangerous — two operators).
    Allow,
}

impl ConcurrencyPolicy {
    /// Parse the value of the `concurrency` field; unknown — `None`.
    pub fn from_str_opt(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "ask" => Some(Self::Ask),
            "readonly" | "read-only" => Some(Self::ReadOnly),
            "block" => Some(Self::Block),
            "allow" => Some(Self::Allow),
            _ => None,
        }
    }
}

/// The role decision at startup — the result of [`decide`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// Become the operator (with the lock if it is free, otherwise forcibly).
    Operator,
    /// Enter as a read-only observer.
    ReadOnly,
    /// Block the launch (the `block` policy when the lock is held).
    Blocked,
    /// Ask the user in the overlay (the `ask` policy when held).
    Ask,
}

/// The startup lock state passed into `App`.
pub struct Startup {
    /// The held lock (only when we are a real operator with a free lock).
    /// `None` — an observer, or a "forced" operator.
    pub lock: Option<InstanceLock>,
    /// The read-only role.
    pub read_only: bool,
    /// `Some` → show the startup choice overlay (the `ask` policy).
    pub prompt: Option<Holder>,
}

fn lock_path(state_dir: &Path) -> PathBuf {
    state_dir.join(LOCK_FILE)
}

/// Tries to acquire `flock(LOCK_EX|LOCK_NB)` without waiting. Success → writes
/// PID+time and returns [`Acquire::Operator`]. Held → [`Acquire::Busy`].
pub fn try_acquire(state_dir: &Path) -> std::io::Result<Acquire> {
    let path = lock_path(state_dir);
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&path)?;
    let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if rc == 0 {
        write_holder(&file);
        Ok(Acquire::Operator(InstanceLock { file }))
    } else {
        let err = std::io::Error::last_os_error();
        // On Linux EWOULDBLOCK == EAGAIN — a busy flock(LOCK_NB) yields this code.
        let busy = err.raw_os_error() == Some(libc::EWOULDBLOCK);
        if busy {
            Ok(Acquire::Busy(read_holder(&path)))
        } else {
            Err(err)
        }
    }
}

/// Writes the PID+time to the lock file (diagnostics). Errors are ignored — the
/// lock is already ours, the contents are merely informational.
fn write_holder(file: &File) {
    let pid = std::process::id();
    let now = chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
    let buf = format!("{pid}\n{now}\n");
    let mut f = file;
    let _ = f.set_len(0);
    let _ = f.seek(SeekFrom::Start(0));
    let _ = f.write_all(buf.as_bytes());
    let _ = f.flush();
}

/// Reads the PID+time from the lock file. `None` if the file is empty/unreadable.
fn read_holder(path: &Path) -> Option<Holder> {
    let mut s = String::new();
    File::open(path).ok()?.read_to_string(&mut s).ok()?;
    let mut lines = s.lines();
    let pid: i32 = lines.next()?.trim().parse().ok()?;
    let since = lines.next().unwrap_or("").trim().to_string();
    Some(Holder { pid, since })
}

/// Reads the `concurrency` policy from `<state_dir>/config.json`. File missing /
/// field absent / value unknown → [`ConcurrencyPolicy::Ask`].
pub fn load_policy(state_dir: &Path) -> ConcurrencyPolicy {
    #[derive(serde::Deserialize)]
    struct Cfg {
        concurrency: Option<String>,
    }
    let path = state_dir.join("config.json");
    let Ok(json) = std::fs::read_to_string(path) else {
        return ConcurrencyPolicy::default();
    };
    let Ok(cfg) = serde_json::from_str::<Cfg>(&json) else {
        return ConcurrencyPolicy::default();
    };
    cfg.concurrency
        .as_deref()
        .and_then(ConcurrencyPolicy::from_str_opt)
        .unwrap_or_default()
}

/// The pure role decision from the acquire outcome, the policy, and the CLI flags.
/// `--read-only` and `--force` are the highest-priority overrides.
pub fn decide(
    busy: bool,
    policy: ConcurrencyPolicy,
    cli_read_only: bool,
    cli_force: bool,
) -> Decision {
    if cli_read_only {
        return Decision::ReadOnly;
    }
    if !busy {
        return Decision::Operator;
    }
    if cli_force {
        return Decision::Operator; // forcibly, without the lock
    }
    match policy {
        ConcurrencyPolicy::Allow => Decision::Operator,
        ConcurrencyPolicy::ReadOnly => Decision::ReadOnly,
        ConcurrencyPolicy::Block => Decision::Blocked,
        ConcurrencyPolicy::Ask => Decision::Ask,
    }
}

/// The decision for headless modes that WRITE to the DB/FS (no UI — nowhere to
/// ask): like [`decide`], but `Ask` collapses to `Blocked`. The caller: `Operator`
/// → proceed (holding the guard, or without it under `--force`/`Allow`); otherwise
/// refuse.
pub fn decide_headless(
    busy: bool,
    policy: ConcurrencyPolicy,
    cli_read_only: bool,
    cli_force: bool,
) -> Decision {
    match decide(busy, policy, cli_read_only, cli_force) {
        Decision::Ask => Decision::Blocked,
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    static COUNTER: AtomicU32 = AtomicU32::new(0);

    fn temp_state_dir() -> PathBuf {
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("dedcom_lock_test_{}_{}", std::process::id(), n));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn second_acquire_is_busy_while_first_held() {
        let dir = temp_state_dir();
        let first = match try_acquire(&dir).unwrap() {
            Acquire::Operator(lock) => lock,
            Acquire::Busy(_) => panic!("the first launch must become the operator"),
        };
        match try_acquire(&dir).unwrap() {
            Acquire::Busy(holder) => {
                let holder = holder.expect("the holder's PID must read");
                assert_eq!(holder.pid as u32, std::process::id());
            }
            Acquire::Operator(_) => panic!("a held lock cannot be acquired a second time"),
        }
        drop(first);
        // After release one can become the operator again.
        assert!(matches!(try_acquire(&dir).unwrap(), Acquire::Operator(_)));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn free_lock_becomes_operator() {
        assert_eq!(
            decide(false, ConcurrencyPolicy::Ask, false, false),
            Decision::Operator
        );
    }

    #[test]
    fn read_only_flag_forces_readonly_even_when_free() {
        assert_eq!(
            decide(false, ConcurrencyPolicy::Ask, true, false),
            Decision::ReadOnly
        );
    }

    #[test]
    fn busy_default_policy_asks() {
        assert_eq!(
            decide(true, ConcurrencyPolicy::Ask, false, false),
            Decision::Ask
        );
    }

    #[test]
    fn busy_readonly_policy_is_readonly() {
        assert_eq!(
            decide(true, ConcurrencyPolicy::ReadOnly, false, false),
            Decision::ReadOnly
        );
    }

    #[test]
    fn busy_block_policy_blocks() {
        assert_eq!(
            decide(true, ConcurrencyPolicy::Block, false, false),
            Decision::Blocked
        );
    }

    #[test]
    fn busy_allow_policy_is_operator() {
        assert_eq!(
            decide(true, ConcurrencyPolicy::Allow, false, false),
            Decision::Operator
        );
    }

    #[test]
    fn busy_force_flag_overrides_to_operator() {
        assert_eq!(
            decide(true, ConcurrencyPolicy::Block, false, true),
            Decision::Operator
        );
    }

    #[test]
    fn policy_parsing() {
        assert_eq!(
            ConcurrencyPolicy::from_str_opt("readonly"),
            Some(ConcurrencyPolicy::ReadOnly)
        );
        assert_eq!(
            ConcurrencyPolicy::from_str_opt("ASK"),
            Some(ConcurrencyPolicy::Ask)
        );
        assert!(ConcurrencyPolicy::from_str_opt("nonsense").is_none());
    }

    #[test]
    fn headless_busy_ask_policy_blocks() {
        // No UI to ask with — `ask` with the lock held = block, not a silent
        // entry (otherwise headless would proceed without confirmation).
        assert_eq!(
            decide_headless(true, ConcurrencyPolicy::Ask, false, false),
            Decision::Blocked
        );
    }

    #[test]
    fn headless_passes_through_non_ask() {
        // Everything except Ask passes through as in `decide`: free → operator;
        // force when held → operator; read-only → readonly.
        assert_eq!(
            decide_headless(false, ConcurrencyPolicy::Ask, false, false),
            Decision::Operator
        );
        assert_eq!(
            decide_headless(true, ConcurrencyPolicy::Block, false, true),
            Decision::Operator
        );
        assert_eq!(
            decide_headless(true, ConcurrencyPolicy::ReadOnly, false, false),
            Decision::ReadOnly
        );
    }
}
