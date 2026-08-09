// SPDX-License-Identifier: Apache-2.0
use std::ffi::{CStr, CString, OsStr, OsString};
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd};
use std::path::{Component, Path, PathBuf};

use crate::cli::Cli;

const APP_DIR: &str = "dedcom";

/// Safely establishes the state directory `dir` (an absolute path): walks the components
/// FROM THE ROOT with `openat(O_NOFOLLOW|O_DIRECTORY)` (a symlink component → refusal),
/// creates missing ones at 0700, and on EVERY component checks the owner via `fstat` (our
/// euid or root). The final directory must STRICTLY NOT be group/other-writable
/// (`mode & 0o022 == 0`) and is tightened to 0700; ancestors are allowed a sticky bit when
/// world-writable (like `/tmp`). Any violation → error (fail-closed).
///
/// Why the whole chain and not just the leaf: the state-dir stores the checkpoint DB (the
/// paths of ALL files in the pool), the log, consent/lock. If an ancestor is writable by an
/// outsider, they can rename a component and slip in a symlink between the check and the
/// open — a single 0700 on the leaf is not enough. Earlier attempts missed
/// this: `create_dir_all` followed the symlink, `set_permissions` chmod'd the link target,
/// plus a TOCTOU before the open.
///
/// Residual risk: an attacker with the SAME uid (another of our processes) — outside the
/// "one admin per their own pool" model. An untrusted chain (`--state-dir` to a
/// foreign/shared path) → fail-closed.
pub fn establish_state_dir(dir: &Path) -> io::Result<()> {
    if !dir.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "the state directory must be an absolute path",
        ));
    }
    let mut names: Vec<&OsStr> = Vec::new();
    for comp in dir.components() {
        match comp {
            Component::RootDir => {}
            Component::Normal(n) => names.push(n),
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "invalid state-directory path component (. / .. / prefix)",
                ))
            }
        }
    }
    if names.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "the state directory cannot be the root \"/\" — a subdirectory is required",
        ));
    }
    let euid = unsafe { libc::geteuid() };
    let root_c = CString::new("/").expect("\"/\" without NUL");
    let root = open_verified_dir(None, &root_c, euid, false)?;
    establish_chain(root, &names, euid)
}

/// The core of the walk: from a trusted `base`, creates/verifies the components `names` (see
/// [`establish_state_dir`]). Factored out so tests can run the component check from their own
/// base, without tripping over world-writable `/tmp` ancestors.
fn establish_chain(base: OwnedFd, names: &[&OsStr], euid: libc::uid_t) -> io::Result<()> {
    let mut parent = base;
    let last = names.len().saturating_sub(1);
    for (i, name) in names.iter().enumerate() {
        let cname = CString::new(name.as_bytes()).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "a component name contains NUL")
        })?;
        // Create the missing component at 0700; EEXIST is normal (already exists), other errors propagate out.
        let rc = unsafe { libc::mkdirat(parent.as_raw_fd(), cname.as_ptr(), 0o700) };
        if rc != 0 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() != Some(libc::EEXIST) {
                return Err(err);
            }
        }
        parent = open_verified_dir(Some(&parent), &cname, euid, i == last)?;
    }
    Ok(())
}

/// Opens the directory `name` (`openat` from `parent`, or absolute when `parent=None`) with
/// `O_NOFOLLOW|O_DIRECTORY` and verifies the owner (euid|root) and the absence of write
/// access for group/others. When `tighten`, additionally tightens to 0700. Returns the
/// descriptor.
fn open_verified_dir(
    parent: Option<&OwnedFd>,
    name: &CStr,
    euid: libc::uid_t,
    is_final: bool,
) -> io::Result<OwnedFd> {
    // O_RDONLY (=0) is implied; no need to list it explicitly (and this is not an identity_op).
    let flags = libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC;
    let fd = match parent {
        Some(p) => unsafe { libc::openat(p.as_raw_fd(), name.as_ptr(), flags) },
        None => unsafe { libc::open(name.as_ptr(), flags) },
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fd >= 0 and just obtained from openat/open — we own it.
    let owned = unsafe { OwnedFd::from_raw_fd(fd) };
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(owned.as_raw_fd(), &mut st) } != 0 {
        return Err(io::Error::last_os_error());
    }
    if st.st_uid != euid && st.st_uid != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "a state-directory component is owned by an outsider — refusal",
        ));
    }
    // The final state-dir: STRICTLY not group/other-writable. We create lock/consent/db in
    // it, and the sticky bit does NOT remove already-PLANTED entries (e.g. a symlink
    // `dedcom.lock` → external file), and it is too late to tighten to 0700 — the write would
    // have gone through the planted symlink. For ancestor components the sticky bit is
    // allowed: we only traverse them, we do not create files in them, and sticky prevents an
    // outsider from substituting our component.
    let writable = st.st_mode & 0o022 != 0;
    let sticky = st.st_mode & 0o1000 != 0;
    let unsafe_perms = if is_final {
        writable
    } else {
        writable && !sticky
    };
    if unsafe_perms {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "the state directory is writable by group/others — refusal (entries may have been planted)",
        ));
    }
    if is_final && (st.st_mode & 0o777) != 0o700 {
        let rc = unsafe { libc::fchmod(owned.as_raw_fd(), 0o700) };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(owned)
}

/// Prepares the DB file: refuses if it is a symlink (opening via the link would write the
/// target OUTSIDE the protected state-dir), and creates the file at 0600 if absent.
/// `O_NOFOLLOW` on the final component; the ancestors are already verified by
/// [`establish_state_dir`] on entry into write mode, so there is no path race. `fchmod` 0600
/// is applied to an already-existing file too.
pub fn prepare_db_file(db_path: &Path) -> io::Result<()> {
    let c = cstring(db_path)?;
    let fd = unsafe {
        libc::open(
            c.as_ptr(),
            libc::O_RDWR | libc::O_CREAT | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
    };
    if fd < 0 {
        let err = io::Error::last_os_error();
        return Err(io::Error::new(
            err.kind(),
            format!(
                "failed to open the DB file safely (symlink?): {}: {err}",
                crate::textsan::terminal(&db_path.display().to_string())
            ),
        ));
    }
    // SAFETY: fd >= 0 and just obtained from open — we own it (closed on Drop).
    let owned = unsafe { OwnedFd::from_raw_fd(fd) };
    if unsafe { libc::fchmod(owned.as_raw_fd(), 0o600) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Sets 0600 on the DB file and its WAL/SHM companions: the contents (the paths of all files
/// in the pool) are owner-only. db is mandatory (the error propagates); WAL/SHM are by
/// existence (NotFound is normal before the first WAL write, other errors propagate, not
/// best-effort).
pub fn enforce_db_perms_0600(db_path: &Path) -> io::Result<()> {
    std::fs::set_permissions(db_path, std::fs::Permissions::from_mode(0o600))?;
    for suffix in ["-wal", "-shm"] {
        let mut p = db_path.as_os_str().to_owned();
        p.push(suffix);
        match std::fs::set_permissions(Path::new(&p), std::fs::Permissions::from_mode(0o600)) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// Verifies that `db_path` is an existing regular file whose final component is not a symlink,
/// without creating it, changing its mode, or blocking on a FIFO/device: `O_RDONLY | O_NONBLOCK
/// | O_NOFOLLOW | O_CLOEXEC` — no `O_CREAT`, no `fchmod` — then `fstat` on the already-open fd
/// and a refusal of everything but a regular file. The fd closes by RAII.
///
/// The three safety flags are written out here rather than borrowed from
/// `pipeline::safe_open::open_regular_nofollow` on purpose: `paths` is a leaf module that
/// `state::store` depends on, and reaching into `pipeline` would invert that layering for seven
/// lines whose error would then say «skipping» inside a database diagnostic. The duplication is
/// deliberate.
///
/// Staged by R4B-1; `ScanStore::open_for_apply_lease` is its only caller until R4B-2 wires the
/// worker route.
pub fn verify_existing_db_file(db_path: &Path) -> io::Result<()> {
    probe_existing_db_file(db_path).map(|_| ())
}

/// The regular-file identity — `(st_dev, st_ino)` — that the configured path names at the
/// moment of one probe, read through the same no-follow descriptor the verifier above uses and
/// returned instead of discarded.
///
/// One probe is a single observation. Its value is in comparing several: a pair taken before and
/// after an open, or a later pair against the retained one, shows whether the path still names
/// the same file. A changed identity — a replaced checkpoint (`unlink` + `rename`, a restored
/// backup) — is therefore detectable, and the store's answer to it is to refuse and require a
/// reopen.
///
/// **What this does not establish.** It says nothing about which inode SQLite's own private
/// descriptor holds: `rusqlite::Connection` exposes no portable OS descriptor at this version,
/// and reaching SQLite's internal `unixFile` layout to find one would be VFS- and
/// layout-dependent unsafe code. It is an observation of the path, at each probe. A replacement
/// that is undone again between two probes is likewise outside what comparing them can prove.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PathIdentity {
    pub device: u64,
    pub inode: u64,
}

pub fn probe_existing_db_file(db_path: &Path) -> io::Result<PathIdentity> {
    let c = cstring(db_path)?;
    let fd = unsafe {
        libc::open(
            c.as_ptr(),
            libc::O_RDONLY | libc::O_NONBLOCK | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        let err = io::Error::last_os_error();
        return Err(io::Error::new(
            err.kind(),
            format!(
                "cannot verify the DB file (missing? symlink?): {}: {err}",
                crate::textsan::terminal(&db_path.display().to_string())
            ),
        ));
    }
    // SAFETY: fd >= 0 and just obtained from open — we own it (closed on Drop).
    let owned = unsafe { OwnedFd::from_raw_fd(fd) };
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(owned.as_raw_fd(), &mut st) } != 0 {
        return Err(io::Error::last_os_error());
    }
    if (st.st_mode & libc::S_IFMT) != libc::S_IFREG {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "the DB path is not a regular file: {}",
                crate::textsan::terminal(&db_path.display().to_string())
            ),
        ));
    }
    Ok(PathIdentity {
        device: st.st_dev as u64,
        inode: st.st_ino as u64,
    })
}

fn cstring(path: &Path) -> io::Result<CString> {
    CString::new(path.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "the path contains NUL"))
}

/// The state directory: checkpoint DB and log file.
/// `--state-dir` overrides; otherwise the XDG state dir
/// (`~/.local/state/dedcom` on Linux).
pub fn state_dir(cli: &Cli) -> PathBuf {
    if let Some(dir) = &cli.state_dir {
        return dir.clone();
    }
    let base = xdg_state_base().unwrap_or_else(std::env::temp_dir);
    base.join(APP_DIR)
}

/// The Linux XDG base of the state directory — a replacement for
/// `dirs::state_dir()`/`data_local_dir()` (the `dirs` dependency was dropped to eliminate the
/// sole MPL-2.0 crate `option-ext`; the project is Linux-only). Behavior identical to `dirs`
/// on Linux: `$XDG_STATE_HOME` → `~/.local/state` → `$XDG_DATA_HOME` → `~/.local/share`.
/// Relative values of the XDG variables and a relative `$HOME` are ignored (XDG Base
/// Directory spec; `establish_state_dir`, which expects an absolute path, requires it anyway).
fn xdg_state_base() -> Option<PathBuf> {
    // A named NON-generic wrapper: `fn(&str) -> _` is higher-ranked over the lifetime (elision)
    // and fits `impl Fn(&str)`. `var_os::<&str>` fixed a CONCRETE lifetime →
    // "implementation of Fn is not general enough". A closure would also work but would invite
    // clippy::redundant_closure — the wrapper is cleaner.
    fn env_os(var: &str) -> Option<OsString> {
        std::env::var_os(var)
    }
    xdg_state_base_from(env_os)
}

/// The pure core of `xdg_state_base` with getenv injected — unit tests without mutating the
/// process's global environment (cargo tests run in parallel, `set_var` would race).
fn xdg_state_base_from(getenv: impl Fn(&str) -> Option<OsString>) -> Option<PathBuf> {
    let abs = |var: &str| getenv(var).map(PathBuf::from).filter(|p| p.is_absolute());
    let home_join = |suffix: &str| {
        getenv("HOME")
            .map(PathBuf::from)
            .filter(|p| p.is_absolute())
            .map(|h| h.join(suffix))
    };
    // Order 1:1 with `dirs::state_dir().or_else(dirs::data_local_dir)`. The last branch
    // (`~/.local/share`) structurally mirrors `dirs` and is practically unreachable (with
    // $HOME set it is intercepted by `~/.local/state`), kept for provable equivalence.
    abs("XDG_STATE_HOME")
        .or_else(|| home_join(".local/state"))
        .or_else(|| abs("XDG_DATA_HOME"))
        .or_else(|| home_join(".local/share"))
}

/// Path to the SQLite checkpoint file.
pub fn checkpoint_db(cli: &Cli) -> PathBuf {
    state_dir(cli).join("dedcom.db")
}

/// The entries in the state directory that ARE dedcom's live state: the checkpoint, the three
/// files SQLite may keep beside it, and the single-instance lock. Overwriting any of them is not
/// «replacing a file the operator named», it is losing the scan history or the lock the running
/// operator holds.
///
/// Deliberately short. Other names in the state directory — including a CSV the operator chose to
/// keep there — are ordinary destinations and stay writable.
pub const PROTECTED_STATE_ENTRIES: [&str; 5] = [
    "dedcom.db",
    "dedcom.db-wal",
    "dedcom.db-shm",
    "dedcom.db-journal",
    "dedcom.lock",
];

/// Whether `dest` names one of those entries in `state_dir`, and which one.
///
/// The comparison is the canonicalized **parent directory** plus the final basename, never the
/// canonicalized destination itself. That distinction is the whole point: `../dedcom/dedcom.db`
/// and a symlinked alias of the state directory both resolve to the same parent and are caught,
/// while an ordinary final symlink (`groups.csv -> elsewhere.csv`) keeps the accepted behaviour of
/// being replaced as a NAME, with its target never followed.
///
/// `None` when the basename is not one of the protected entries, when the path has no filename, or
/// when either directory cannot be canonicalized — a destination whose directory does not exist is
/// refused by the writer anyway.
pub fn protected_state_entry_name(name: &str) -> Option<&'static str> {
    PROTECTED_STATE_ENTRIES
        .iter()
        .find(|entry| entry.eq_ignore_ascii_case(name))
        .copied()
}

/// A directory opened once and kept open, so everything done in it afterwards is done to THAT
/// directory — not to whatever its pathname resolves to the next time somebody asks.
///
/// The export needs both halves of that at once. The protected-state check has to compare
/// directory OBJECTS: a bind mount gives one directory two canonical paths, `realpath` cannot see
/// through it, and comparing spellings therefore let an alias of the state directory pass. And the
/// temporary artifact has to be created, removed and renamed relative to this same handle, so the
/// parent cannot be re-pointed between the check and the publication.
pub struct DirHandle {
    fd: OwnedFd,
    shown: String,
}

impl DirHandle {
    /// Opens `dir` as a directory, resolving the operator's own path exactly once.
    ///
    /// Symlinks in that path are followed here deliberately — a destination reached through a
    /// linked directory is an ordinary thing to ask for. What matters is that it is resolved
    /// ONCE: from here on the handle IS the directory, whatever the name comes to mean.
    pub fn open(dir: &Path) -> io::Result<Self> {
        let c = cstring(dir)?;
        let fd = unsafe {
            libc::open(
                c.as_ptr(),
                libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_RDONLY,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: fd >= 0 and just obtained from open — we own it.
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        Ok(Self {
            fd,
            shown: crate::textsan::terminal(&dir.display().to_string()),
        })
    }

    /// The physical identity of the OPENED directory: `(st_dev, st_ino)` from `fstat` on the
    /// handle, never from a path. Every spelling of one directory — `..`, a symlink, a bind
    /// mount — answers with the same pair.
    pub fn identity(&self) -> io::Result<(u64, u64)> {
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstat(self.fd.as_raw_fd(), &mut st) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok((st.st_dev as u64, st.st_ino as u64))
    }

    /// Whether this handle and `other` are the same directory object.
    pub fn is_same_object(&self, other: &DirHandle) -> io::Result<bool> {
        Ok(self.identity()? == other.identity()?)
    }

    /// Creates a new file in this directory: `O_EXCL` (the cross-process claim on the name),
    /// `O_NOFOLLOW` (never write through a planted symlink) and mode 0600.
    pub fn create_new_file(&self, name: &OsStr) -> io::Result<std::fs::File> {
        let c = name_cstring(name)?;
        let fd = unsafe {
            libc::openat(
                self.fd.as_raw_fd(),
                c.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: fd >= 0 and just obtained from openat — we own it.
        Ok(unsafe { std::fs::File::from_raw_fd(fd) })
    }

    /// Removes a name from this directory.
    pub fn remove_file(&self, name: &OsStr) -> io::Result<()> {
        let c = name_cstring(name)?;
        if unsafe { libc::unlinkat(self.fd.as_raw_fd(), c.as_ptr(), 0) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// Renames one name to another WITHIN this directory — the atomic publication, aimed at the
    /// handle rather than at a pathname that may mean something else by now.
    pub fn rename(&self, from: &OsStr, to: &OsStr) -> io::Result<()> {
        let from_c = name_cstring(from)?;
        let to_c = name_cstring(to)?;
        let rc = unsafe {
            libc::renameat(
                self.fd.as_raw_fd(),
                from_c.as_ptr(),
                self.fd.as_raw_fd(),
                to_c.as_ptr(),
            )
        };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// The directory as the operator should see it (already terminal-sanitized).
    pub fn shown(&self) -> &str {
        &self.shown
    }
}

fn name_cstring(name: &OsStr) -> io::Result<CString> {
    CString::new(name.as_bytes()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "a file name contains an interior NUL",
        )
    })
}

#[cfg(test)]
mod dir_handle_tests {
    use super::*;

    fn temp_dir(tag: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|since| since.as_nanos())
            .unwrap_or(0);
        let mut dir = std::env::temp_dir();
        dir.push(format!("dedcom_dirh_{tag}_{}_{nanos}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// The whole point of the handle: one directory OBJECT reached through several spellings is
    /// one directory. A bind mount is the case this exists for and cannot be made unprivileged
    /// here, but `..` and a symlink exercise the same comparison — identity, not spelling.
    #[test]
    fn one_directory_object_is_the_same_through_every_spelling() {
        let dir = temp_dir("identity");
        std::fs::create_dir(dir.join("sub")).unwrap();
        std::os::unix::fs::symlink(&dir, dir.join("alias")).unwrap();

        let direct = DirHandle::open(&dir).unwrap();
        for spelling in [dir.join("sub").join(".."), dir.join("alias"), dir.join(".")] {
            let other = DirHandle::open(&spelling).unwrap();
            assert!(
                direct.is_same_object(&other).unwrap(),
                "{spelling:?} is the same directory"
            );
            assert_eq!(direct.identity().unwrap(), other.identity().unwrap());
        }

        let elsewhere = DirHandle::open(&dir.join("sub")).unwrap();
        assert!(!direct.is_same_object(&elsewhere).unwrap());
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Create, rename and remove all act on the handle, so a name pointing somewhere else by now
    /// cannot redirect them.
    #[test]
    fn the_handle_creates_renames_and_removes_in_its_own_directory() {
        let dir = temp_dir("ops");
        let handle = DirHandle::open(&dir).unwrap();

        let temp = OsStr::new(".tmp-artifact");
        let file = handle.create_new_file(temp).unwrap();
        drop(file);
        assert!(dir.join(".tmp-artifact").exists());
        assert!(
            handle.create_new_file(temp).is_err(),
            "O_EXCL is the claim on the name"
        );

        handle.rename(temp, OsStr::new("published")).unwrap();
        assert!(!dir.join(".tmp-artifact").exists());
        assert!(dir.join("published").exists());

        handle.remove_file(OsStr::new("published")).unwrap();
        assert!(!dir.join("published").exists());
        std::fs::remove_dir_all(&dir).ok();
    }

    /// A planted symlink at the temporary name is not written through.
    #[test]
    fn creation_refuses_to_follow_a_symlink_at_the_name() {
        let dir = temp_dir("nofollow");
        let target = dir.join("target");
        std::fs::write(&target, b"do not overwrite\n").unwrap();
        std::os::unix::fs::symlink(&target, dir.join("planted")).unwrap();

        let handle = DirHandle::open(&dir).unwrap();
        assert!(handle.create_new_file(OsStr::new("planted")).is_err());
        assert_eq!(std::fs::read(&target).unwrap(), b"do not overwrite\n");
        std::fs::remove_dir_all(&dir).ok();
    }

    /// The protected names are matched without case, because a case-insensitive dataset resolves
    /// `DEDCOM.DB` to the checkpoint.
    #[test]
    fn protected_names_are_matched_without_case() {
        for name in ["dedcom.db", "DEDCOM.DB", "Dedcom.Db", "DEDCOM.DB-WAL"] {
            assert!(
                protected_state_entry_name(name).is_some(),
                "{name} names live state"
            );
        }
        for name in ["groups.csv", "dedcom.db.bak", "dedcom", "mydedcom.db"] {
            assert!(
                protected_state_entry_name(name).is_none(),
                "{name} is an ordinary destination"
            );
        }
    }
}

/// Path to the log file.
pub fn log_file(cli: &Cli) -> PathBuf {
    state_dir(cli).join("dedcom.log")
}

/// Path to the separate benchmark file — timings of heavy operations
/// are not mixed with the ordinary log, so performance degradation is visible.
pub fn bench_file(cli: &Cli) -> PathBuf {
    state_dir(cli).join("benchmarks.log")
}

/// Path to the file of user presets for the type filter.
pub fn presets_file(cli: &Cli) -> PathBuf {
    state_dir(cli).join("presets.json")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_path(tag: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let dir = std::env::temp_dir().join(format!(
            "dedcom_statedir_{tag}_{}_{nanos}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// The base as a trusted reference point for `establish_chain` (without verifying
    /// ancestors — bypassing world-writable `/tmp` in tests; we verify components BELOW the
    /// base).
    fn open_base(dir: &Path) -> OwnedFd {
        let c = CString::new(dir.as_os_str().as_bytes()).unwrap();
        let flags = libc::O_DIRECTORY | libc::O_CLOEXEC;
        let fd = unsafe { libc::open(c.as_ptr(), flags) };
        assert!(fd >= 0, "open base: {}", io::Error::last_os_error());
        unsafe { OwnedFd::from_raw_fd(fd) }
    }

    fn mode_of(p: &Path) -> u32 {
        std::fs::metadata(p).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn establish_creates_components_0700() {
        let base = temp_path("new");
        let euid = unsafe { libc::geteuid() };
        establish_chain(open_base(&base), &[OsStr::new("a"), OsStr::new("b")], euid).unwrap();
        assert_eq!(mode_of(&base.join("a")), 0o700);
        assert_eq!(mode_of(&base.join("a/b")), 0o700);
        std::fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn establish_tightens_existing_final_to_0700() {
        let base = temp_path("loose");
        let sub = base.join("a");
        std::fs::create_dir_all(&sub).unwrap();
        // 0750: not group/other-writable (passes the check), but not 0700 → must be tightened.
        std::fs::set_permissions(&sub, std::fs::Permissions::from_mode(0o750)).unwrap();
        let euid = unsafe { libc::geteuid() };
        establish_chain(open_base(&base), &[OsStr::new("a")], euid).unwrap();
        assert_eq!(
            mode_of(&sub),
            0o700,
            "the final directory is tightened to 0700"
        );
        std::fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn establish_rejects_symlink_component() {
        let base = temp_path("sym");
        let target = base.join("real");
        std::fs::create_dir_all(&target).unwrap();
        std::os::unix::fs::symlink(&target, base.join("a")).unwrap();
        let euid = unsafe { libc::geteuid() };
        // openat(O_NOFOLLOW) on a symlink component → ELOOP → refusal.
        let r = establish_chain(open_base(&base), &[OsStr::new("a"), OsStr::new("b")], euid);
        assert!(r.is_err(), "a symlink component must be rejected");
        std::fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn establish_rejects_group_or_other_writable_component() {
        let base = temp_path("ww");
        let sub = base.join("a");
        std::fs::create_dir_all(&sub).unwrap();
        std::fs::set_permissions(&sub, std::fs::Permissions::from_mode(0o777)).unwrap();
        let euid = unsafe { libc::geteuid() };
        assert!(
            establish_chain(open_base(&base), &[OsStr::new("a")], euid).is_err(),
            "a group/other-writable ancestor must be rejected"
        );
        std::fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn establish_allows_sticky_world_writable_ancestor() {
        // The sticky bit (like /tmp) protects against component substitution → allowed as an
        // ancestor, despite being world-writable. The leaf 'b' under it is created at 0700.
        let base = temp_path("sticky");
        let sub = base.join("a");
        std::fs::create_dir_all(&sub).unwrap();
        std::fs::set_permissions(&sub, std::fs::Permissions::from_mode(0o1777)).unwrap();
        let euid = unsafe { libc::geteuid() };
        establish_chain(open_base(&base), &[OsStr::new("a"), OsStr::new("b")], euid).unwrap();
        assert_eq!(mode_of(&base.join("a/b")), 0o700);
        std::fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn establish_rejects_preexisting_world_writable_final_dir() {
        // Regression (review B4): a final state-dir pre-created as 1777 with a planted symlink
        // inside must NOT be accepted. Sticky is allowed only for ancestors — for the leaf it
        // does not save us: a planted `dedcom.lock` → symlink would remain, and the PID/time
        // write would go through it into an external file (tightening to 0700 is too late).
        let base = temp_path("evil_final");
        let evil = base.join("state");
        std::fs::create_dir_all(&evil).unwrap();
        let outside = base.join("outside.txt");
        std::fs::write(&outside, b"victim").unwrap();
        std::os::unix::fs::symlink(&outside, evil.join("dedcom.lock")).unwrap();
        std::fs::set_permissions(&evil, std::fs::Permissions::from_mode(0o1777)).unwrap();
        let euid = unsafe { libc::geteuid() };
        // 'state' is the final component (i == last), 1777 → strict refusal (sticky doesn't save it).
        let r = establish_chain(open_base(&base), &[OsStr::new("state")], euid);
        assert!(
            r.is_err(),
            "a world-writable final directory must be rejected"
        );
        // The external file is untouched — the write through the symlink never happened.
        assert_eq!(std::fs::read(&outside).unwrap(), b"victim");
        std::fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn establish_state_dir_rejects_relative_path() {
        assert!(establish_state_dir(Path::new("relative/path")).is_err());
    }

    #[test]
    fn establish_state_dir_rejects_root() {
        // "/" — an empty component list: no final 0700 directory, refusal.
        assert!(establish_state_dir(Path::new("/")).is_err());
    }

    // --- xdg_state_base: equivalence to `dirs` behavior on Linux (we dropped the `dirs` crate) ---

    #[test]
    fn xdg_prefers_absolute_state_home() {
        let env = |v: &str| match v {
            "XDG_STATE_HOME" => Some(OsString::from("/xdg/state")),
            "HOME" => Some(OsString::from("/home/u")),
            _ => None,
        };
        assert_eq!(xdg_state_base_from(env), Some(PathBuf::from("/xdg/state")));
    }

    #[test]
    fn xdg_ignores_relative_state_home() {
        // a relative XDG_STATE_HOME is ignored (XDG spec) → ~/.local/state
        let env = |v: &str| match v {
            "XDG_STATE_HOME" => Some(OsString::from("relative/state")),
            "HOME" => Some(OsString::from("/home/u")),
            _ => None,
        };
        assert_eq!(
            xdg_state_base_from(env),
            Some(PathBuf::from("/home/u/.local/state"))
        );
    }

    #[test]
    fn xdg_home_state_when_no_xdg() {
        let env = |v: &str| match v {
            "HOME" => Some(OsString::from("/home/u")),
            _ => None,
        };
        assert_eq!(
            xdg_state_base_from(env),
            Some(PathBuf::from("/home/u/.local/state"))
        );
    }

    #[test]
    fn xdg_data_home_when_no_state_and_no_home() {
        // no XDG_STATE_HOME and no $HOME → fall back to XDG_DATA_HOME (like dirs::data_local_dir)
        let env = |v: &str| match v {
            "XDG_DATA_HOME" => Some(OsString::from("/xdg/data")),
            _ => None,
        };
        assert_eq!(xdg_state_base_from(env), Some(PathBuf::from("/xdg/data")));
    }

    #[test]
    fn xdg_none_when_nothing_set() {
        // nothing set → None (the caller falls back to std::env::temp_dir)
        let env = |_v: &str| None::<OsString>;
        assert_eq!(xdg_state_base_from(env), None);
    }

    // --- verify_existing_db_file: the staged apply-lease path verifier (R4B-1) ---

    #[test]
    fn verify_db_accepts_a_regular_file() {
        let base = temp_path("vf_reg");
        let db = base.join("dedcom.db");
        std::fs::write(&db, b"sqlite?").unwrap();
        verify_existing_db_file(&db).unwrap();
        std::fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn verify_db_refuses_an_absent_path_without_creating_it() {
        let base = temp_path("vf_absent");
        let db = base.join("dedcom.db");
        assert!(verify_existing_db_file(&db).is_err());
        assert!(!db.exists(), "verification must not create the file");
        std::fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn verify_db_refuses_a_symlink_and_leaves_the_target_alone() {
        let base = temp_path("vf_link");
        let target = base.join("outside.bin");
        std::fs::write(&target, b"victim").unwrap();
        let db = base.join("dedcom.db");
        std::os::unix::fs::symlink(&target, &db).unwrap();
        assert!(
            verify_existing_db_file(&db).is_err(),
            "O_NOFOLLOW must refuse the link"
        );
        assert_eq!(std::fs::read(&target).unwrap(), b"victim");
        std::fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn verify_db_refuses_a_directory() {
        let base = temp_path("vf_dir");
        // open(O_RDONLY) on a directory succeeds on Linux — the S_ISREG check is what rejects it.
        assert!(verify_existing_db_file(&base).is_err());
        std::fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn verify_db_refuses_a_fifo_promptly_without_a_writer() {
        let base = temp_path("vf_fifo");
        let fifo = base.join("dedcom.db");
        let c = CString::new(fifo.as_os_str().as_bytes()).unwrap();
        // SAFETY: a valid C string for a child of an existing directory; mode 0600.
        let rc = unsafe { libc::mkfifo(c.as_ptr(), 0o600) };
        assert_eq!(rc, 0, "mkfifo did not create the FIFO");
        // No writer and no helper thread: O_NONBLOCK returns the fd immediately and the
        // S_ISREG check rejects it — the call comes back instead of hanging.
        assert!(verify_existing_db_file(&fifo).is_err());
        std::fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn verify_db_refuses_a_unix_socket() {
        let base = temp_path("vf_sock");
        let sock = base.join("dedcom.db");
        let _listener = std::os::unix::net::UnixListener::bind(&sock).unwrap();
        assert!(verify_existing_db_file(&sock).is_err());
        std::fs::remove_dir_all(&base).ok();
    }
}
