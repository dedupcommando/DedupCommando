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

/// What an acquire attempt established about the lock. `Busy` and `Unknown` must stay apart:
/// «somebody holds it» is a known state we have a policy for, while «flock could not be
/// evaluated» (ENOLCK on a network filesystem without lockd, EPERM, a read-only filesystem)
/// tells us nothing at all — including whether an operator is running.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockState {
    /// The lock is ours.
    Held,
    /// Another live process holds it.
    Busy,
    /// The lock could not be evaluated.
    Unknown,
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
    /// The role was asked for with `--read-only`. Otherwise an observer is one because another
    /// instance holds the lock — and there may be no other instance at all when it was asked for.
    pub read_only_asked: bool,
    /// `Some` → show the startup choice overlay (the `ask` policy).
    pub prompt: Option<Holder>,
}

pub(crate) fn lock_path(state_dir: &Path) -> PathBuf {
    state_dir.join(LOCK_FILE)
}

/// Whether this [`try_acquire`] error means the lock NAME holds something dedcom may not write to.
///
/// Three shapes, one answer, and each carries its own sentence in the error itself — a symbolic
/// link, a file with more than one name, a device or other non-regular node. The caller prints
/// that sentence rather than guessing which one it was: told "is a symbolic link" about a block
/// device, an operator goes looking for a link that is not there.
///
/// Recognised by `ErrorKind::InvalidInput` with no errno, which is the shape `try_acquire`
/// composes for exactly these and for nothing else. Everything else — EACCES, ENOSPC, an NFS
/// mount without lockd — stays a "the lock could not be evaluated" condition, whose standing
/// advice is to move the state directory or push past with `--force`. Neither applies here: this
/// is not the state directory dedcom made, and `--force` would proceed with no lock at all rather
/// than fix anything.
pub fn is_not_our_lock_file(err: &std::io::Error) -> bool {
    err.raw_os_error().is_none() && err.kind() == std::io::ErrorKind::InvalidInput
}

/// Tries to acquire `flock(LOCK_EX|LOCK_NB)` without waiting. Success → writes
/// PID+time and returns [`Acquire::Operator`]. Held → [`Acquire::Busy`].
///
/// The very next thing that happens to this file is `set_len(0)` and a write, so what is behind
/// the name has to be established before that, not assumed. `O_NOFOLLOW` rules out a symbolic
/// link. It rules out nothing else, and two other shapes carry the same truncation to somewhere
/// it was never meant to go:
///
/// - a HARD link, which looks exactly like a regular file at open time. A state directory copied
///   with `cp -al` or `rsync --link-dest` is full of them, and truncating one empties its partner;
/// - a DEVICE node. As root, `--state-dir` at a directory whose `dedcom.lock` is a block device
///   opens fine, `set_len(0)` fails silently on it, and the PID and timestamp land at offset 0 of
///   the device. This project has a post-mortem for exactly that outcome.
///
/// So the fd is `fstat`ed and has to be a regular file with exactly one link. Anything else is
/// refused by name, and the operator is told which file it is. The state directory is 0700 and
/// normally nobody else can put anything there — but `--state-dir` takes any pathname the
/// operator types, and being wrong about this costs someone their data.
pub fn try_acquire(state_dir: &Path) -> std::io::Result<Acquire> {
    use std::os::unix::fs::OpenOptionsExt;
    let path = lock_path(state_dir);
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&path)
        .map_err(|err| {
            // ELOOP from THIS open is the trailing component and nothing else — but only because
            // of a caller obligation, not because of anything here. `O_NOFOLLOW` constrains just
            // the last component (`open(2)`); a link anywhere in the `--state-dir` prefix would
            // raise ELOOP too. `establish_state_dir` runs first at both call sites and walks every
            // component from `/` with `openat(O_DIRECTORY|O_NOFOLLOW)`, refusing any link in the
            // chain, so by the time this runs `dedcom.lock` is the only component left.
            if err.raw_os_error() == Some(libc::ELOOP) {
                not_our_lock_file(&path, "is a symbolic link")
            } else {
                err
            }
        })?;
    require_plain_lock_file(&file, &path)?;
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

/// Refuses a lock fd that is not a regular file with exactly one name.
///
/// `InvalidInput` and no errno, so [`is_planted_symlink`] can recognise it alongside the ELOOP a
/// symbolic link produces: from the operator's side all three are the same answer — the file
/// under that name is not one this program may truncate.
fn require_plain_lock_file(file: &File, path: &Path) -> std::io::Result<()> {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: `file` owns a valid fd for the whole call, and `st` is a repr(C) aggregate of
    // integers for which an all-zero value is valid.
    if unsafe { libc::fstat(file.as_raw_fd(), &mut st) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    if (st.st_mode & libc::S_IFMT) != libc::S_IFREG {
        return Err(not_our_lock_file(path, "is not a regular file"));
    }
    if st.st_nlink != 1 {
        return Err(not_our_lock_file(
            path,
            &format!("has {} names, not one", st.st_nlink),
        ));
    }
    Ok(())
}

/// One shape for every "the name holds something else" refusal: `InvalidInput` with no errno, so
/// [`is_not_our_lock_file`] recognises it, carrying the sentence the operator needs to read.
fn not_our_lock_file(path: &Path, what: &str) -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        format!(
            "the lock file {} {what}",
            crate::textsan::terminal(&path.display().to_string())
        ),
    )
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
///
/// Re-opens by path rather than reading the fd above, because on the busy branch that fd belongs
/// to the failed `flock` attempt and is dropped before this runs. The path was proven not to be a
/// link moments earlier, and the payload is only a pid and a timestamp that the caller prints
/// through `textsan::terminal` — but the re-open is the one place in this module that still
/// resolves a name instead of holding a descriptor.
fn read_holder(path: &Path) -> Option<Holder> {
    let mut s = String::new();
    File::open(path).ok()?.read_to_string(&mut s).ok()?;
    let mut lines = s.lines();
    let pid: i32 = lines.next()?.trim().parse().ok()?;
    let since = lines.next().unwrap_or("").trim().to_string();
    Some(Holder { pid, since })
}

/// Reads the `concurrency` policy from `<state_dir>/config.json`, through the one reader of that
/// file. File missing or unreadable / field absent / value unknown → [`ConcurrencyPolicy::Ask`].
pub fn load_policy(state_dir: &Path) -> ConcurrencyPolicy {
    crate::maint::concurrency_policy(state_dir)
}

/// The pure role decision from the acquire outcome, the policy, and the CLI flags.
/// `--read-only` and `--force` are the highest-priority overrides.
pub fn decide(
    state: LockState,
    policy: ConcurrencyPolicy,
    cli_read_only: bool,
    cli_force: bool,
) -> Decision {
    // Observing is safe whatever the lock says — an observer gets a query_only connection.
    if cli_read_only {
        return Decision::ReadOnly;
    }
    match state {
        LockState::Held => Decision::Operator,
        // Fail closed. An unevaluable lock means we cannot tell whether an operator is
        // already running, and becoming a second one is precisely what the lock exists to
        // prevent — on a network filesystem without lockd every host would land here and all
        // of them would start writing. Only the explicit `--force` proceeds: the `allow`
        // policy deliberately does NOT, or a config file could quietly reinstate the very
        // fail-open this replaces.
        LockState::Unknown => {
            if cli_force {
                Decision::Operator
            } else {
                Decision::Blocked
            }
        }
        LockState::Busy => {
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
    }
}

/// The decision for headless modes that WRITE to the DB/FS (no UI — nowhere to
/// ask): like [`decide`], but `Ask` collapses to `Blocked`. The caller: `Operator`
/// → proceed (holding the guard, or without it under `--force`/`Allow`); otherwise
/// refuse.
pub fn decide_headless(
    state: LockState,
    policy: ConcurrencyPolicy,
    cli_read_only: bool,
    cli_force: bool,
) -> Decision {
    match decide(state, policy, cli_read_only, cli_force) {
        Decision::Ask => Decision::Blocked,
        other => other,
    }
}

/// Whether the observer role was asked for with `--read-only`, rather than taken because another
/// instance holds the lock. [`decide`] answers the flag before it looks at the lock, so an observer
/// without the flag is one by the `readonly` policy or while the `ask` overlay is waiting.
pub fn observer_asked(decision: &Decision, cli_read_only: bool) -> bool {
    matches!(decision, Decision::ReadOnly) && cli_read_only
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    /// Every way a window becomes an observer, and whether the flag asked for it: only then may a
    /// refused action say «started with --read-only».
    #[test]
    fn an_observer_is_asked_for_only_by_the_flag() {
        use ConcurrencyPolicy::{Ask, ReadOnly};
        for (state, policy, flag, asked) in [
            (LockState::Held, Ask, true, true),
            (LockState::Busy, Ask, true, true),
            (LockState::Unknown, Ask, true, true),
            (LockState::Busy, ReadOnly, false, false),
            (LockState::Busy, Ask, false, false),
            (LockState::Held, Ask, false, false),
        ] {
            let decision = decide(state, policy, flag, false);
            assert_eq!(
                observer_asked(&decision, flag),
                asked,
                "{state:?}, {policy:?}, --read-only {flag}: {decision:?}"
            );
        }
    }

    static COUNTER: AtomicU32 = AtomicU32::new(0);

    fn temp_state_dir() -> PathBuf {
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("dedcom_lock_test_{}_{}", std::process::id(), n));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// A symlink under the lock's name must not be followed: acquiring the lock truncates the
    /// file and writes the PID into it, so following the link would empty whatever it points at.
    /// Both the link and its target have to come back untouched.
    #[test]
    fn a_symlinked_lock_file_is_refused_and_its_target_survives() {
        let dir = temp_state_dir();
        let victim = dir.join("precious.txt");
        std::fs::write(&victim, b"keep me\n").unwrap();
        std::os::unix::fs::symlink(&victim, lock_path(&dir)).unwrap();

        match try_acquire(&dir) {
            Err(err) => {
                assert!(
                    is_not_our_lock_file(&err),
                    "the refusal must be recognisable as «not our file», not a generic failure: {err}"
                );
                assert!(
                    err.to_string().contains("is a symbolic link"),
                    "and must say which shape it was: {err}"
                );
            }
            Ok(_) => panic!("a symlinked lock file must not be acquired"),
        }

        assert_eq!(
            std::fs::read(&victim).unwrap(),
            b"keep me\n",
            "the link's target must not be truncated"
        );
        assert!(
            std::fs::symlink_metadata(lock_path(&dir))
                .unwrap()
                .file_type()
                .is_symlink(),
            "and the link itself must still be a link"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A hard link is indistinguishable from a regular file at open time, and truncating one
    /// empties its partner. `cp -al` and `rsync --link-dest` copies of a state directory are full
    /// of them, so this is not a hypothetical shape.
    #[test]
    fn a_hard_linked_lock_file_is_refused_by_its_link_count() {
        let dir = temp_state_dir();
        let victim = dir.join("precious.txt");
        std::fs::write(&victim, b"keep me\n").unwrap();
        std::fs::hard_link(&victim, lock_path(&dir)).unwrap();

        match try_acquire(&dir) {
            Err(err) => {
                assert!(is_not_our_lock_file(&err), "{err}");
                assert!(
                    err.to_string().contains("names, not one"),
                    "a hard link must be named as one, not called a symlink: {err}"
                );
            }
            Ok(_) => panic!("a hard-linked lock file must not be acquired"),
        }
        assert_eq!(
            std::fs::read(&victim).unwrap(),
            b"keep me\n",
            "the partner name must not be truncated"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The ordinary case must keep working, or "refuse everything" would pass the tests above.
    #[test]
    fn a_regular_lock_file_is_still_acquired() {
        let dir = temp_state_dir();
        let lock = match try_acquire(&dir).unwrap() {
            Acquire::Operator(lock) => lock,
            Acquire::Busy(_) => panic!("an unheld lock must grant the operator role"),
        };
        assert!(lock_path(&dir).is_file(), "the lock file is a regular file");
        let body = std::fs::read_to_string(lock_path(&dir)).unwrap();
        assert!(
            body.starts_with(&std::process::id().to_string()),
            "and carries this process's pid: {body:?}"
        );
        drop(lock);
        let _ = std::fs::remove_dir_all(&dir);
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
            decide(LockState::Held, ConcurrencyPolicy::Ask, false, false),
            Decision::Operator
        );
    }

    #[test]
    fn read_only_flag_forces_readonly_even_when_free() {
        assert_eq!(
            decide(LockState::Held, ConcurrencyPolicy::Ask, true, false),
            Decision::ReadOnly
        );
    }

    #[test]
    fn busy_default_policy_asks() {
        assert_eq!(
            decide(LockState::Busy, ConcurrencyPolicy::Ask, false, false),
            Decision::Ask
        );
    }

    #[test]
    fn busy_readonly_policy_is_readonly() {
        assert_eq!(
            decide(LockState::Busy, ConcurrencyPolicy::ReadOnly, false, false),
            Decision::ReadOnly
        );
    }

    #[test]
    fn busy_block_policy_blocks() {
        assert_eq!(
            decide(LockState::Busy, ConcurrencyPolicy::Block, false, false),
            Decision::Blocked
        );
    }

    #[test]
    fn busy_allow_policy_is_operator() {
        assert_eq!(
            decide(LockState::Busy, ConcurrencyPolicy::Allow, false, false),
            Decision::Operator
        );
    }

    #[test]
    fn busy_force_flag_overrides_to_operator() {
        assert_eq!(
            decide(LockState::Busy, ConcurrencyPolicy::Block, false, true),
            Decision::Operator
        );
    }

    #[test]
    fn unevaluable_lock_blocks_under_every_policy() {
        // The NFS-without-lockd case: we cannot tell whether an operator is running, so we do
        // not become one. Previously this path silently returned Operator.
        for policy in [
            ConcurrencyPolicy::Ask,
            ConcurrencyPolicy::ReadOnly,
            ConcurrencyPolicy::Block,
            ConcurrencyPolicy::Allow,
        ] {
            assert_eq!(
                decide(LockState::Unknown, policy, false, false),
                Decision::Blocked,
                "an unevaluable lock must fail closed under {policy:?}"
            );
        }
    }

    #[test]
    fn unevaluable_lock_yields_only_to_the_force_flag() {
        assert_eq!(
            decide(LockState::Unknown, ConcurrencyPolicy::Ask, false, true),
            Decision::Operator
        );
    }

    #[test]
    fn unevaluable_lock_still_allows_observing() {
        // An observer writes nothing, so it is safe even with no working lock.
        assert_eq!(
            decide(LockState::Unknown, ConcurrencyPolicy::Ask, true, false),
            Decision::ReadOnly
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
            decide_headless(LockState::Busy, ConcurrencyPolicy::Ask, false, false),
            Decision::Blocked
        );
    }

    #[test]
    fn headless_passes_through_non_ask() {
        // Everything except Ask passes through as in `decide`: free → operator;
        // force when held → operator; read-only → readonly.
        assert_eq!(
            decide_headless(LockState::Held, ConcurrencyPolicy::Ask, false, false),
            Decision::Operator
        );
        assert_eq!(
            decide_headless(LockState::Busy, ConcurrencyPolicy::Block, false, true),
            Decision::Operator
        );
        assert_eq!(
            decide_headless(LockState::Busy, ConcurrencyPolicy::ReadOnly, false, false),
            Decision::ReadOnly
        );
    }

    #[test]
    fn headless_unevaluable_lock_blocks_the_write() {
        // The destructive headless modes (--scan / --compact-db / --purge-quarantine) used to
        // proceed with no lock at all when flock could not be evaluated.
        assert_eq!(
            decide_headless(LockState::Unknown, ConcurrencyPolicy::Allow, false, false),
            Decision::Blocked
        );
        assert_eq!(
            decide_headless(LockState::Unknown, ConcurrencyPolicy::Ask, false, true),
            Decision::Operator
        );
    }
}
