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
}
