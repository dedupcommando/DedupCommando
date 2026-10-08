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
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{PoisonError, RwLock, RwLockReadGuard, RwLockWriteGuard};

use crate::paths::PathIdentity;

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
    /// Its entry in [`LOCK_FILES`].
    entry: u64,
}

impl Drop for InstanceLock {
    fn drop(&mut self) {
        // The entry goes while the descriptor is still open: the number of a file is not kept
        // past the hold on the file, or in time it would refuse somebody else's. And it goes in
        // one step with the lock, the list held, so nothing is renamed between the two.
        let mut listed = lock_files_mut();
        listed.retain(|kept| kept.entry != self.entry);
        unsafe {
            libc::flock(self.file.as_raw_fd(), libc::LOCK_UN);
        }
    }
}

/// The lock files this process leaves at their names: one entry for each [`InstanceLock`] and
/// each [`LockName`] alive.
///
/// The lock is on an open FILE, and the next dedcom looks for that file by its NAME. A lock
/// file that is renamed stays locked and leaves the name free: the next dedcom makes a new file
/// there, locks that one, and runs as a second operator beside the first — the very thing the
/// lock is there to prevent. So the one rename this program makes of what an operator points at
/// (`actions::move_file::rename_noreplace`) asks this list before it renames — about a file, and
/// about a directory a lock file lies in ([`unless_part_of_lock`]).
///
/// A read-write lock, like the list of open databases (`paths::OpenDatabase`) and for the same
/// reason: the question and the rename are made with the list held to read, and a lock is taken
/// with it held to write — from before its file is opened until its entry stands
/// ([`try_acquire`]). So nothing is renamed between «the lock is taken» and «its file is
/// listed». The price is the same as there: a look or a rename that waits holds up whoever
/// takes or lets go of a lock meanwhile.
static LOCK_FILES: RwLock<Vec<Listed>> = RwLock::new(Vec::new());

/// Tells one entry of [`LOCK_FILES`] from another.
static NEXT_ENTRY: AtomicU64 = AtomicU64::new(0);

/// One lock file.
struct Listed {
    entry: u64,
    /// Where the lock file is looked for, absolute: a relative path has to go on naming the
    /// same place whatever the working directory is when it is next looked at.
    name: PathBuf,
    /// The file the lock is on, read from the descriptor that holds it — so the number cannot
    /// pass to another file while the entry stands. `None` for a name this process holds no
    /// lock at ([`LockName`]): whatever lies at the name answers for it.
    file: Option<PathIdentity>,
}

// A panic elsewhere while the list was held leaves it as true as it was, so a poisoned lock is
// taken all the same.
fn lock_files() -> RwLockReadGuard<'static, Vec<Listed>> {
    LOCK_FILES.read().unwrap_or_else(PoisonError::into_inner)
}

fn lock_files_mut() -> RwLockWriteGuard<'static, Vec<Listed>> {
    LOCK_FILES.write().unwrap_or_else(PoisonError::into_inner)
}

/// Enters the lock file at `name` in `listed`, which the caller holds to write, and returns the
/// number of the entry.
fn enter(listed: &mut Vec<Listed>, name: &Path, file: Option<PathIdentity>) -> u64 {
    let entry = NEXT_ENTRY.fetch_add(1, Ordering::Relaxed);
    listed.push(Listed {
        entry,
        name: std::path::absolute(name).unwrap_or_else(|_| name.to_path_buf()),
        file,
    });
    entry
}

/// Test-only: whether the list is held right now — by anybody, this thread included; it cannot
/// tell whose hold it is. What an act handed to [`unless_part_of_lock`] can ask from inside. A
/// test that asks takes `paths::alone_with_the_list` first, as for the list of open databases.
#[cfg(test)]
pub(crate) fn lock_files_are_held() -> bool {
    matches!(
        LOCK_FILES.try_write(),
        Err(std::sync::TryLockError::WouldBlock)
    )
}

/// The name of the lock file in a state directory, kept in [`LOCK_FILES`] for as long as this
/// value lives, whoever holds the lock. A window keeps one for the state directory it works in.
///
/// An operator let in past a live holder (`--force`, the `allow` policy, `F` in the start-up
/// overlay) holds no lock, but the lock file of its state directory is somebody's all the same:
/// renamed, it would let the NEXT dedcom in with a lock of its own and no question asked. There
/// is no descriptor to know a file by, so what is kept is the name: whatever non-directory lies
/// at it, and every directory on the way to it.
#[derive(Debug)]
pub struct LockName(u64);

impl LockName {
    pub fn in_dir(state_dir: &Path) -> Self {
        Self(enter(&mut lock_files_mut(), &lock_path(state_dir), None))
    }
}

impl Drop for LockName {
    fn drop(&mut self) {
        lock_files_mut().retain(|kept| kept.entry != self.0);
    }
}

/// Which part of a lock file's place a name holds — asked of a name that is about to be renamed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockPart {
    /// The file a lock of this process is on, a hard link to it, or a non-directory at the name
    /// of a listed lock file.
    File,
    /// A directory a listed lock file lies in, at whatever depth: the file would keep its name
    /// inside it, but the next dedcom looks for it by the path it is given, and finds none.
    Directory,
}

/// What the name `path` holds of the lock files in [`LOCK_FILES`], if anything — the question
/// for a name that is about to be renamed, asked without renaming. A name that cannot be looked
/// at is an error.
pub fn part_of_lock(path: &Path) -> std::io::Result<Option<LockPart>> {
    part_listed(&lock_files(), path)
}

/// Does `act` unless the name `path` holds part of a listed lock file's place, and says which
/// part stopped it — the look, the question and the act as one step, for the act that must not
/// happen to either part: a rename. No lock can be taken between the answer and the act (see
/// [`LOCK_FILES`]).
///
/// `act` runs with the list held: it must not take or let go of a lock, nor ask about a name.
pub fn unless_part_of_lock(path: &Path, act: impl FnOnce()) -> std::io::Result<Option<LockPart>> {
    let listed = lock_files();
    let part = part_listed(&listed, path)?;
    if part.is_none() {
        act();
    }
    Ok(part)
}

/// The question itself, after a look of its own that follows no link: a symbolic link answers
/// for itself. A directory is asked about as a directory, anything else as a file — by what the
/// look found, and by the name it was found under.
fn part_listed(listed: &[Listed], path: &Path) -> std::io::Result<Option<LockPart>> {
    use std::os::unix::fs::MetadataExt;
    let looked = std::fs::symlink_metadata(path)?;
    let thing = PathIdentity {
        device: looked.dev(),
        inode: looked.ino(),
    };
    Ok(if looked.is_dir() {
        lies_above(listed, thing).then_some(LockPart::Directory)
    } else {
        (holds(listed, thing) || names(listed, path)).then_some(LockPart::File)
    })
}

/// Whether `file` is a file a listed lock is on.
fn holds(listed: &[Listed], file: PathIdentity) -> bool {
    listed.iter().any(|kept| kept.file == Some(file))
}

/// Whether `path` is the name of a listed lock file: that name in that directory, by whatever
/// way the directory is reached.
///
/// Asked beside the file itself, because the name is what the next dedcom opens: whatever lies
/// at it — the file the lock is on, or one that took its place behind this process's back — is
/// what stands between that dedcom and a lock of its own. And for a [`LockName`] the name is
/// all there is.
///
/// The name is compared as its bytes, the spelling a panel hands on. Another spelling that a
/// dataset without case sensitivity would take for the same name is left to the file itself.
fn names(listed: &[Listed], path: &Path) -> bool {
    let (Some(name), Some(dir)) = (path.file_name(), path.parent()) else {
        return false;
    };
    // A directory is looked at through its `.`, so that a link at the end of the way to it is
    // followed, as the rename itself will follow it.
    let directory = |dir: &Path| crate::paths::identity_at(&dir.join(".")).ok();
    // This one once, and only if some lock file has this name.
    let mut ours = None;
    listed.iter().any(|kept| {
        kept.name.file_name() == Some(name)
            && kept.name.parent().is_some_and(|their_dir| {
                let ours = *ours.get_or_insert_with(|| directory(dir));
                ours.is_some() && ours == directory(their_dir)
            })
    })
}

/// Whether a listed lock file lies in the directory `dir`, at whatever depth.
///
/// Asked of the directories on the way to each lock file's name, each looked at now and by
/// `lstat`: nothing holds a directory open, so there is no number of one worth keeping. The way
/// to a state directory a mode that writes was started in has neither a link nor a `..` in it
/// (`paths::establish_state_dir`), so every name on it is a directory the lock file does lie in.
fn lies_above(listed: &[Listed], dir: PathIdentity) -> bool {
    listed.iter().any(|kept| {
        kept.name
            .ancestors()
            .skip(1)
            .any(|above| crate::paths::identity_at(above).is_ok_and(|theirs| theirs == dir))
    })
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
///
/// A lock that is taken is entered in [`LOCK_FILES`] before this returns, with the file it is
/// on as that same `fstat` found it. The list is held to write from before the file is opened:
/// a rename made by this process falls either before the open — and then the lock is taken on
/// whatever the name holds afterwards — or after the entry, which refuses it.
pub fn try_acquire(state_dir: &Path) -> std::io::Result<Acquire> {
    use std::os::unix::fs::OpenOptionsExt;
    let path = lock_path(state_dir);
    let mut listed = lock_files_mut();
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
            match err.raw_os_error() {
                Some(libc::ELOOP) => not_our_lock_file(&path, "is a symbolic link"),
                // A directory under the name is as much «not ours» as a link. Left raw, EISDIR
                // became an unevaluable lock and the advice about network filesystems.
                Some(libc::EISDIR) => not_our_lock_file(&path, "is a directory"),
                _ => err,
            }
        })?;
    let identity = require_plain_lock_file(&file, &path)?;
    let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if rc == 0 {
        #[cfg(test)]
        take_once_the_lock_is_taken();
        let entry = enter(&mut listed, &path, Some(identity));
        drop(listed);
        write_holder(&file);
        Ok(Acquire::Operator(InstanceLock { file, entry }))
    } else {
        let err = std::io::Error::last_os_error();
        drop(listed);
        // On Linux EWOULDBLOCK == EAGAIN — a busy flock(LOCK_NB) yields this code.
        let busy = err.raw_os_error() == Some(libc::EWOULDBLOCK);
        if busy {
            Ok(Acquire::Busy(read_holder(&path)))
        } else {
            Err(err)
        }
    }
}

// Test-only one-shot seam between the lock and its entry: the instant by which the list has to
// be held already. Thread-local, so it cannot fire in a parallel test; absent from every
// non-test build.
#[cfg(test)]
thread_local! {
    static ONCE_THE_LOCK_IS_TAKEN: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
fn take_once_the_lock_is_taken() {
    if let Some(seen) = ONCE_THE_LOCK_IS_TAKEN.with(|slot| slot.borrow_mut().take()) {
        seen();
    }
}

/// Refuses a lock fd that is not a regular file with exactly one name, and says which file the
/// fd is on.
///
/// `InvalidInput` and no errno, so [`is_planted_symlink`] can recognise it alongside the ELOOP a
/// symbolic link produces: from the operator's side all three are the same answer — the file
/// under that name is not one this program may truncate.
fn require_plain_lock_file(file: &File, path: &Path) -> std::io::Result<PathIdentity> {
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
    Ok(PathIdentity {
        device: st.st_dev as u64,
        inode: st.st_ino as u64,
    })
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

/// What an operator can do about a lock that could not be evaluated, from the error that stopped it.
///
/// Only ENOLCK (and EOPNOTSUPP) is a filesystem that cannot lock at all — the network filesystem
/// without lockd the old single sentence was written for. A read-only filesystem, a full one or
/// a permission problem got the same advice, and moving the state directory or `--force` fixes
/// none of them.
pub fn unknown_lock_advice(err: &std::io::Error) -> &'static str {
    match err.raw_os_error() {
        Some(libc::ENOLCK | libc::EOPNOTSUPP) => {
            "this filesystem cannot provide the lock (a network filesystem without lockd?) — put \
             the state directory on local storage (--state-dir), or retry with --force"
        }
        Some(libc::EROFS) => {
            "the state directory is on a read-only filesystem — point --state-dir at a writable one"
        }
        Some(libc::ENOSPC | libc::EDQUOT) => {
            "the filesystem of the state directory has no space or quota left — free space or \
             raise the quota"
        }
        Some(libc::EACCES | libc::EPERM) => {
            "permission denied — check the owner and mode of the state directory and its lock \
             file, and lsattr for an immutable or append-only flag (chattr -i, chattr -a)"
        }
        _ => "put the state directory on local storage (--state-dir), or retry with --force",
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

    /// A directory under the lock's name is not an unevaluable lock: it is a file that is not ours,
    /// and the advice for an unevaluable lock (move the state directory, or `--force`) would be
    /// wrong in both halves.
    #[test]
    fn a_directory_under_the_lock_name_is_refused_by_name() {
        let dir = temp_state_dir();
        std::fs::create_dir(lock_path(&dir)).unwrap();

        match try_acquire(&dir) {
            Err(err) => {
                assert!(is_not_our_lock_file(&err), "{err}");
                assert!(err.to_string().contains("is a directory"), "{err}");
            }
            Ok(_) => panic!("a directory cannot be the lock"),
        }
        assert!(lock_path(&dir).is_dir(), "and it is left as it was");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Each errno gets the advice that fixes it. Only a filesystem that cannot lock is told to move
    /// the state directory or use `--force`; neither does anything for a full or read-only one.
    #[test]
    fn an_unevaluable_lock_is_advised_by_its_errno() {
        for (errno, says) in [
            (libc::ENOLCK, "cannot provide the lock"),
            (libc::EOPNOTSUPP, "cannot provide the lock"),
            (libc::EROFS, "read-only"),
            (libc::ENOSPC, "no space or quota"),
            (libc::EDQUOT, "no space or quota"),
            (libc::EACCES, "permission denied"),
            (libc::EPERM, "permission denied"),
        ] {
            let advice = unknown_lock_advice(&std::io::Error::from_raw_os_error(errno));
            assert!(advice.contains(says), "errno {errno}: {advice}");
        }
        for errno in [
            libc::EROFS,
            libc::ENOSPC,
            libc::EDQUOT,
            libc::EACCES,
            libc::EPERM,
        ] {
            let advice = unknown_lock_advice(&std::io::Error::from_raw_os_error(errno));
            assert!(!advice.contains("--force"), "errno {errno}: {advice}");
        }
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

    fn the_lock_in(dir: &Path) -> InstanceLock {
        match try_acquire(dir).unwrap() {
            Acquire::Operator(lock) => lock,
            Acquire::Busy(_) => panic!("a fresh directory's lock is free"),
        }
    }

    /// What is asked of a name that is about to be renamed, an error as its kind.
    fn part(path: &Path) -> Result<Option<LockPart>, std::io::ErrorKind> {
        part_of_lock(path).map_err(|err| err.kind())
    }

    /// Every entry of the list is asked about, not the first alone: the file of a lock taken
    /// after another, a name kept after both, and the directory of each.
    #[test]
    fn every_lock_file_of_the_list_is_asked_about() {
        use LockPart::{Directory, File};
        let (first, second, third) = (temp_state_dir(), temp_state_dir(), temp_state_dir());
        let held_first = the_lock_in(&first);
        let held_second = the_lock_in(&second);
        std::fs::write(lock_path(&third), b"").unwrap();
        let kept_third = LockName::in_dir(&third);
        // Known by the file alone: another name of the second lock file, elsewhere.
        let link = third.join("another-name-of-the-second");
        std::fs::hard_link(lock_path(&second), &link).unwrap();

        assert_eq!(
            [
                part(&link),
                part(&lock_path(&third)),
                part(&second),
                part(&third)
            ],
            [
                Ok(Some(File)),
                Ok(Some(File)),
                Ok(Some(Directory)),
                Ok(Some(Directory))
            ],
            "the second lock's file under another name, the third's name, and their directories"
        );
        drop((held_first, held_second, kept_third));
        for dir in [first, second, third] {
            let _ = std::fs::remove_dir_all(&dir);
        }
    }

    /// While the lock is held, its file is known by the file itself — under whatever name — and
    /// every directory on the way to it as one it lies in. Nothing beside them is, and nothing
    /// at all once the lock is let go of.
    #[test]
    fn the_lock_file_and_the_directories_above_it_are_listed_while_the_lock_is_held() {
        use LockPart::{Directory, File};
        let root = temp_state_dir();
        let state = root.join("home").join("state");
        let beside = root.join("home").join("beside");
        std::fs::create_dir_all(&state).unwrap();
        std::fs::create_dir_all(&beside).unwrap();
        let settings = state.join("config.json");
        std::fs::write(&settings, b"{}").unwrap();
        let held = the_lock_in(&state);
        let lock = lock_path(&state);
        let link = beside.join("another-name");
        std::fs::hard_link(&lock, &link).unwrap();
        let symlink = beside.join("a-link-to-it");
        std::os::unix::fs::symlink(&lock, &symlink).unwrap();
        let home = root.join("home");
        let asked = || {
            [
                &lock, &link, &symlink, &settings, &state, &home, &root, &beside,
            ]
            .map(|path| part(path))
        };

        assert_eq!(
            asked(),
            [
                Ok(Some(File)),
                Ok(Some(File)),
                Ok(None),
                Ok(None),
                Ok(Some(Directory)),
                Ok(Some(Directory)),
                Ok(Some(Directory)),
                Ok(None),
            ],
            "the lock file, a hard link to it, a symbolic link to it, a file beside it, its \
             directory, the two above that, a directory beside its own"
        );
        assert_eq!(
            part(&root.join("absent")),
            Err(std::io::ErrorKind::NotFound),
            "what cannot be looked at is not passed"
        );

        drop(held);
        assert_eq!(asked(), [Ok(None); 8], "the lock is let go of");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// The name is what the next dedcom opens, so whatever lies at it stays there: a file that
    /// took the lock file's place behind this process's back is known by the name, and the file
    /// the lock is on by itself, wherever it has been carried.
    #[test]
    fn a_file_that_took_the_place_of_the_lock_file_is_listed_by_the_name() {
        let state = temp_state_dir();
        let held = the_lock_in(&state);
        let lock = lock_path(&state);
        let carried_off = state.join("carried-off");
        std::fs::rename(&lock, &carried_off).unwrap();
        std::fs::write(&lock, b"somebody else's\n").unwrap();

        assert_eq!(
            (part(&lock), part(&carried_off)),
            (Ok(Some(LockPart::File)), Ok(Some(LockPart::File))),
            "the newcomer at the name, and the file the lock is on"
        );
        drop(held);
        assert_eq!((part(&lock), part(&carried_off)), (Ok(None), Ok(None)));
        let _ = std::fs::remove_dir_all(&state);
    }

    /// A process that works in a state directory without the lock keeps the NAME: whatever lies
    /// at it, by whatever way its directory is reached, and the directories above it. It knows
    /// no file — a hard link elsewhere is nobody's, and so is the same name in another directory.
    #[test]
    fn a_lock_name_keeps_what_lies_at_the_name_and_knows_no_file() {
        use LockPart::{Directory, File};
        let root = temp_state_dir();
        let state = root.join("state");
        let other = root.join("other");
        std::fs::create_dir_all(&state).unwrap();
        std::fs::create_dir_all(&other).unwrap();
        let alias = root.join("alias");
        std::os::unix::fs::symlink(&state, &alias).unwrap();
        let lock = lock_path(&state);
        std::fs::write(&lock, b"another instance's\n").unwrap();
        let through_the_alias = lock_path(&alias);
        let namesake = lock_path(&other);
        std::fs::write(&namesake, b"of another state\n").unwrap();
        let link = other.join("another-name");
        std::fs::hard_link(&lock, &link).unwrap();
        let asked = || {
            [
                &lock,
                &through_the_alias,
                &link,
                &namesake,
                &state,
                &root,
                &other,
            ]
            .map(|path| part(path))
        };
        assert_eq!(asked(), [Ok(None); 7], "nothing is kept yet");

        let kept = LockName::in_dir(&state);
        assert_eq!(
            asked(),
            [
                Ok(Some(File)),
                Ok(Some(File)),
                Ok(None),
                Ok(None),
                Ok(Some(Directory)),
                Ok(Some(Directory)),
                Ok(None),
            ],
            "the name, the name through a link to its directory, a hard link elsewhere, the \
             same name in another directory, the directory, the one above, a directory beside"
        );

        drop(kept);
        assert_eq!(asked(), [Ok(None); 7], "the name is let go of");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// One lock is one entry: letting go of one leaves another's file listed.
    #[test]
    fn letting_go_of_one_lock_leaves_another_listed() {
        let (first, second) = (temp_state_dir(), temp_state_dir());
        let (held_first, held_second) = (the_lock_in(&first), the_lock_in(&second));

        drop(held_first);
        assert_eq!(
            (part(&lock_path(&first)), part(&lock_path(&second))),
            (Ok(None), Ok(Some(LockPart::File))),
            "the one let go of, the one still held"
        );
        drop(held_second);
        let _ = std::fs::remove_dir_all(&first);
        let _ = std::fs::remove_dir_all(&second);
    }

    /// A file and a directory are told by device and number together: the same number on
    /// another device is somebody else's.
    #[test]
    fn the_same_number_on_another_device_is_not_the_lock_file() {
        let state = temp_state_dir();
        let held = the_lock_in(&state);
        let own = |path: &Path| crate::paths::identity_at(path).unwrap();
        let on_another_device = |path: &Path| PathIdentity {
            device: own(path).device.wrapping_add(1),
            inode: own(path).inode,
        };
        let lock = lock_path(&state);

        let listed = lock_files();
        let told = (
            holds(&listed, own(&lock)),
            holds(&listed, on_another_device(&lock)),
            lies_above(&listed, own(&state)),
            lies_above(&listed, on_another_device(&state)),
        );
        drop(listed);

        assert_eq!(
            told,
            (true, false, true, false),
            "the lock file, its number on another device, its directory, that number on another"
        );
        drop(held);
        let _ = std::fs::remove_dir_all(&state);
    }

    /// The list is held from before a lock is taken until its file is entered: at the instant
    /// the lock is this process's and the entry is not there yet, nothing can be renamed. Were
    /// the list taken only for the entry, a rename could fall in between and carry the locked
    /// file from its name.
    #[test]
    fn the_list_is_held_from_the_taking_of_a_lock_to_its_entry() {
        use std::cell::Cell;
        use std::rc::Rc;
        let _alone = crate::paths::alone_with_the_list();
        let dir = temp_state_dir();
        // More than once: «held» can be another test's for an instant, and must not pass for ours.
        for round in 0..8 {
            let held = Rc::new(Cell::new(None));
            ONCE_THE_LOCK_IS_TAKEN.with(|slot| {
                let held = Rc::clone(&held);
                *slot.borrow_mut() = Some(Box::new(move || held.set(Some(lock_files_are_held()))));
            });
            let lock = the_lock_in(&dir);
            assert_eq!(held.get(), Some(true), "round {round}");
            drop(lock);
        }
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
