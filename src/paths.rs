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
///
/// A final directory that already exists is taken only when it holds dedcom's live state (a name
/// from [`PROTECTED_STATE_ENTRIES`]) or is empty — dedcom's own logs aside ([`DEDCOMS_LOGS`]) — and
/// not directly under `/`. Anything else is somebody else's directory named by mistake —
/// `--state-dir /etc`, `--state-dir /home` — and is refused before its mode is changed or a file is
/// created in it.
///
/// It runs where the operator's choice of directory comes in — the log, the interface, the
/// headless modes that write. A store opening its checkpoint later only verifies
/// ([`verify_db_dir`]): whose directory it is is decided here and nowhere else.
pub fn establish_state_dir(dir: &Path) -> io::Result<()> {
    walk_state_dir(dir, Walk::Establish)
}

/// How a mode reaches the state directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StateAccess {
    /// A mode that writes to the state directory: [`establish_state_dir`].
    Writing,
    /// A mode that only reports on it — `--stats`, `--export-csv`: [`verify_state_dir`].
    ReadOnly,
}

/// The reporting modes' way into the state directory: the same walk from `/` and the same checks
/// of owner and permissions as [`establish_state_dir`], but nothing is created and no mode is
/// changed. The directory must exist and hold dedcom's live state; an empty one has nothing to
/// report on and is not dedcom's until a mode that writes adopts it.
pub fn verify_state_dir(dir: &Path) -> io::Result<()> {
    walk_state_dir(dir, Walk::Report)
}

/// The directory of a checkpoint about to be opened for writing: the same walk and checks, but
/// nothing is created or changed, and whose directory it is is not asked again — that was settled
/// by [`establish_state_dir`] where the directory was chosen.
pub fn verify_db_dir(dir: &Path) -> io::Result<()> {
    walk_state_dir(dir, Walk::OpenDb)
}

/// What a walk may do on its way and to the directory it ends in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Walk {
    /// Create what is missing; take an existing directory only if it is ours or empty; tighten
    /// it to 0700.
    Establish,
    /// Create and change nothing; the directory must hold something of ours.
    Report,
    /// Create and change nothing.
    OpenDb,
}

fn walk_state_dir(dir: &Path, walk: Walk) -> io::Result<()> {
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
    open_verified_dir(None, &root_c, euid, None)
        .and_then(|root| establish_chain(root, &names, euid, walk, dir, true))
        .map_err(|err| naming_the_directory(err, dir))
}

/// An error from the system names no directory — «No such file or directory» alone does not say
/// which one. The walk's own refusals name it already and pass unchanged.
fn naming_the_directory(err: io::Error, dir: &Path) -> io::Error {
    match err.raw_os_error() {
        Some(_) => io::Error::new(
            err.kind(),
            format!("the state directory {}: {err}", crate::textsan::path(dir)),
        ),
        None => err,
    }
}

/// The core of the walk: from a trusted `base`, creates/verifies the components `names` (see
/// [`establish_state_dir`]). Factored out so tests can run the component check from their own
/// base, without tripping over world-writable `/tmp` ancestors. `shown` is the whole directory as
/// the operator named it, for a refusal; `from_root` says `base` is `/`, which is what makes a
/// one-component walk end in a top-level directory.
fn establish_chain(
    base: OwnedFd,
    names: &[&OsStr],
    euid: libc::uid_t,
    walk: Walk,
    shown: &Path,
    from_root: bool,
) -> io::Result<()> {
    let mut parent = base;
    let last = names.len().saturating_sub(1);
    for (i, name) in names.iter().enumerate() {
        let cname = CString::new(name.as_bytes()).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "a component name contains NUL")
        })?;
        // Only a walk that establishes creates: the missing component at 0700, other errors than
        // EEXIST propagate out. EEXIST is normal, and for the final component it is kept: a
        // directory that was already there may hold somebody else's files, one created just now
        // holds nothing. The other walks create nothing, so a missing component fails the open
        // below.
        let existed = match walk {
            Walk::Establish => {
                let rc = unsafe { libc::mkdirat(parent.as_raw_fd(), cname.as_ptr(), 0o700) };
                if rc == 0 {
                    false
                } else {
                    let err = io::Error::last_os_error();
                    if err.raw_os_error() != Some(libc::EEXIST) {
                        return Err(err);
                    }
                    true
                }
            }
            Walk::Report | Walk::OpenDb => true,
        };
        let leaf = (i == last).then_some(Leaf {
            walk,
            existed,
            top_level: from_root && names.len() == 1,
            shown,
        });
        parent = open_verified_dir(Some(&parent), &cname, euid, leaf)?;
    }
    Ok(())
}

/// What [`open_verified_dir`] needs to know about the final component, the state directory.
#[derive(Clone, Copy)]
struct Leaf<'a> {
    walk: Walk,
    /// It was there before this walk (`mkdirat` answered `EEXIST`, or the walk creates nothing).
    existed: bool,
    /// It sits directly under `/`: `/home`, `/srv` and `/mnt` come empty on a fresh system.
    top_level: bool,
    /// The directory as the operator named it, for a refusal.
    shown: &'a Path,
}

/// Opens the directory `name` (`openat` from `parent`, or absolute when `parent=None`) with
/// `O_NOFOLLOW|O_DIRECTORY` and verifies the owner (euid|root) and the absence of write
/// access for group/others. For the final component (`leaf`), additionally checks whose
/// directory it is, as its walk asks, and — when establishing — tightens it to 0700. Returns the
/// descriptor.
fn open_verified_dir(
    parent: Option<&OwnedFd>,
    name: &CStr,
    euid: libc::uid_t,
    leaf: Option<Leaf<'_>>,
) -> io::Result<OwnedFd> {
    let is_final = leaf.is_some();
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
    if let Some(leaf) = leaf {
        // Before anything is changed: a directory that was already there becomes the state
        // directory only if it is ours, or empty and not a top-level one; it is reported on only
        // if it is ours. The names are read through this descriptor — the very directory the chmod
        // below would change — never through the path again.
        match leaf.walk {
            Walk::Establish if leaf.existed => match held_by(&owned)? {
                Held::Ours => {}
                Held::Nothing if !leaf.top_level => {}
                Held::Nothing => return Err(top_level_and_empty(leaf.shown, st.st_mode)),
                Held::Foreign(example) => return Err(not_ours(leaf.shown, &example, st.st_mode)),
            },
            Walk::Report => {
                if held_by(&owned)? != Held::Ours {
                    return Err(nothing_to_report(leaf.shown));
                }
            }
            Walk::Establish | Walk::OpenDb => {}
        }
        if leaf.walk == Walk::Establish && (st.st_mode & 0o777) != 0o700 {
            let rc = unsafe { libc::fchmod(owned.as_raw_fd(), 0o700) };
            if rc != 0 {
                return Err(io::Error::last_os_error());
            }
        }
    }
    Ok(owned)
}

/// What an existing directory holds, as far as taking it for the state directory goes.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Held {
    /// Nothing but `.` and `..` — and [`DEDCOMS_LOGS`], if any.
    Nothing,
    /// dedcom's live state: at least one of [`PROTECTED_STATE_ENTRIES`].
    Ours,
    /// Other entries and no live state — the first such entry read, to show in the refusal.
    Foreign(OsString),
}

/// dedcom's two logs, which count neither way. Not against a directory: every run opens its log
/// first, so the mode's own look at a directory it has just created finds them there. Not for it
/// either: they are what an older dedcom left in any directory `--stats` was pointed at, `/etc`
/// among them. A directory holding them and nothing else is treated as empty; beside anything
/// else, the rest decides.
const DEDCOMS_LOGS: [&str; 2] = ["dedcom.log", "benchmarks.log"];

/// Reads the names in the directory open at `dir`, up to the first one of dedcom's live state.
fn held_by(dir: &OwnedFd) -> io::Result<Held> {
    // `fdopendir` takes over the descriptor it is given and `closedir` closes it, so it is given a
    // duplicate. SAFETY: `dir` is an open descriptor; the call only makes a second one.
    let dup = unsafe { libc::fcntl(dir.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
    if dup < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `dup` is a descriptor of ours; on success the stream owns it.
    let stream = unsafe { libc::fdopendir(dup) };
    if stream.is_null() {
        let err = io::Error::last_os_error();
        // SAFETY: `fdopendir` failed, so `dup` is still ours to close.
        unsafe { libc::close(dup) };
        return Err(err);
    }
    // The duplicate shares its read position with `dir`. Nothing has read `dir` before this, so
    // the rewind is defensive: it keeps the listing whole if that ever changes.
    // SAFETY: `stream` is the open stream from `fdopendir`.
    unsafe { libc::rewinddir(stream) };
    let mut held = Held::Nothing;
    let outcome = loop {
        // `readdir` answers both the end and a failure with NULL; only errno tells them apart.
        // SAFETY: the calling thread's errno, then the open stream from `fdopendir`.
        unsafe { *libc::__errno_location() = 0 };
        let entry = unsafe { libc::readdir(stream) };
        if entry.is_null() {
            let err = io::Error::last_os_error();
            break match err.raw_os_error() {
                Some(0) => Ok(held),
                _ => Err(err),
            };
        }
        // SAFETY: `d_name` is NUL-terminated inside the entry `readdir` just returned, which stays
        // valid until the next call on `stream`.
        let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
        if name == b"." || name == b".." {
            continue;
        }
        if PROTECTED_STATE_ENTRIES
            .iter()
            .any(|live| live.as_bytes() == name)
        {
            break Ok(Held::Ours);
        }
        let a_log = DEDCOMS_LOGS.iter().any(|log| log.as_bytes() == name);
        if held == Held::Nothing && !a_log {
            held = Held::Foreign(OsStr::from_bytes(name).to_os_string());
        }
    };
    // SAFETY: `stream` came from `fdopendir` and is closed once; that closes `dup` as well.
    unsafe { libc::closedir(stream) };
    outcome
}

/// What taking a directory with `mode` for the state directory would do to it, for a refusal.
fn what_taking_would_do(mode: libc::mode_t) -> &'static str {
    if mode & 0o777 == 0o700 {
        "keep dedcom's database, lock and log in it"
    } else {
        "set its mode to 0700 and keep dedcom's database, lock and log in it"
    }
}

/// The refusal to take `shown` — an existing directory holding entries but no live state of
/// dedcom's — for the state directory. `example` is one of those entries: a dot-file does not show
/// in a plain `ls`, and a directory someone thinks is empty may not be.
fn not_ours(shown: &Path, example: &OsStr, mode: libc::mode_t) -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        format!(
            "{} already exists and holds entries such as «{}» but no dedcom database or lock. \
             Making it the state directory would {}, so dedcom refuses. Point --state-dir at a \
             directory that does not exist yet (dedcom creates it) or at an empty one made with \
             mkdir.",
            crate::textsan::path(shown),
            crate::textsan::os_str(example),
            what_taking_would_do(mode),
        ),
    )
}

/// The refusal to take `shown`, an empty directory directly under `/`. `/home`, `/srv` and `/mnt`
/// come empty on a fresh system, and setting one of them to 0700 cuts every other user off from
/// what is later put in it — so an empty top-level directory is taken only if dedcom makes it.
fn top_level_and_empty(shown: &Path, mode: libc::mode_t) -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        format!(
            "{} is an empty directory directly under /. Making it the state directory would {}, \
             so dedcom refuses. Point --state-dir at a new directory inside it, such as {} \
             (dedcom creates it).",
            crate::textsan::path(shown),
            what_taking_would_do(mode),
            crate::textsan::path(&shown.join("dedcom")),
        ),
    )
}

/// The refusal to report on `shown`, an existing directory holding no live state of dedcom's.
///
/// Today nobody reads it: the only caller, the log, turns any refusal into «log nowhere». It is
/// worded for the next caller of [`verify_state_dir`], and the tests read it.
fn nothing_to_report(shown: &Path) -> io::Error {
    io::Error::new(
        io::ErrorKind::NotFound,
        format!(
            "{} holds nothing of dedcom's; a mode that only reports creates nothing there",
            crate::textsan::path(shown)
        ),
    )
}

/// Prepares the DB file: refuses if it is a symlink (opening via the link would write the
/// target OUTSIDE the protected state-dir), and creates the file at 0600 if absent.
/// `O_NOFOLLOW` on the final component; the ancestors were walked by [`verify_db_dir`] just
/// before, in `ScanStore::open_writable`, and are not writable by anyone else, so there is no
/// path race. `fchmod` 0600 is applied to an already-existing file too.
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
///
/// The same names mark a directory as dedcom's when a mode is about to take it for its state
/// ([`establish_state_dir`]): every mode that writes creates the lock and never removes it, so a
/// directory dedcom has worked in holds at least that. Its other names do not mark it:
/// `config.json`, `plans` and the like are names anybody's directory may have (and dedcom rewrites
/// `config.json`), and the logs count neither way ([`DEDCOMS_LOGS`]). There these are matched
/// exactly, case included, unlike `protected_state_entry_name` below: both lean the safe way —
/// «not sure» means «refuse to overwrite» there and «do not take» here — and the spelling dedcom
/// writes is the only one it can vouch for.
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
/// while an ordinary final symlink (`groups.csv -> elsewhere.csv`) is REFUSED by
/// `refuse_symlink_destination` in `main.rs` — replacing it destroys the link, which on a system
/// path lasts until the next boot. Its target is never written through in either case.
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

    /// Whether `name` in this directory is a symbolic link.
    ///
    /// `Ok(false)` when the name does not exist — nothing is there to be a link. Any OTHER error
    /// is returned rather than swallowed: the caller uses this to decide whether it may replace
    /// the name, and "I could not look" is not "it is fine".
    pub fn is_symlink_at(&self, name: &OsStr) -> io::Result<bool> {
        let c = name_cstring(name)?;
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        let rc = unsafe {
            libc::fstatat(
                self.fd.as_raw_fd(),
                c.as_ptr(),
                &mut st,
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        if rc != 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::NotFound {
                return Ok(false);
            }
            return Err(err);
        }
        Ok(st.st_mode & libc::S_IFMT == libc::S_IFLNK)
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
    use crate::testfixtures::{mode_bits, names_in};

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
        let leaf = base.join("a/b");
        let names = [OsStr::new("a"), OsStr::new("b")];
        establish_chain(
            open_base(&base),
            &names,
            euid,
            Walk::Establish,
            &leaf,
            false,
        )
        .unwrap();
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
        let names = [OsStr::new("a")];
        establish_chain(open_base(&base), &names, euid, Walk::Establish, &sub, false).unwrap();
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
        let names = [OsStr::new("a"), OsStr::new("b")];
        let leaf = base.join("a/b");
        let r = establish_chain(
            open_base(&base),
            &names,
            euid,
            Walk::Establish,
            &leaf,
            false,
        );
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
        let names = [OsStr::new("a")];
        assert!(
            establish_chain(open_base(&base), &names, euid, Walk::Establish, &sub, false).is_err(),
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
        let names = [OsStr::new("a"), OsStr::new("b")];
        let leaf = base.join("a/b");
        establish_chain(
            open_base(&base),
            &names,
            euid,
            Walk::Establish,
            &leaf,
            false,
        )
        .unwrap();
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
        let names = [OsStr::new("state")];
        let r = establish_chain(
            open_base(&base),
            &names,
            euid,
            Walk::Establish,
            &evil,
            false,
        );
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

    // --- an existing directory becomes the state directory only if it is dedcom's ---

    /// A directory `name` under `base` holding `entries` (a trailing `/` makes a directory), then
    /// set to `mode`.
    fn existing_dir(base: &Path, name: &str, mode: u32, entries: &[&str]) -> PathBuf {
        let dir = base.join(name);
        std::fs::create_dir(&dir).unwrap();
        for entry in entries {
            match entry.strip_suffix('/') {
                Some(sub) => std::fs::create_dir(dir.join(sub)).unwrap(),
                None => std::fs::write(dir.join(entry), b"not dedcom's\n").unwrap(),
            }
        }
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(mode)).unwrap();
        dir
    }

    /// The walk for the one component `leaf` under `base`, the way a mode reaches its directory.
    fn settle(base: &Path, leaf: &str, walk: Walk) -> io::Result<()> {
        let euid = unsafe { libc::geteuid() };
        let names = [OsStr::new(leaf)];
        establish_chain(open_base(base), &names, euid, walk, &base.join(leaf), false)
    }

    /// The same for a mode that writes, as if `base` were `/`: `leaf` is then a top-level
    /// directory. The real `/` is not a place for a test to make directories in.
    fn settle_at_the_top(base: &Path, leaf: &str) -> io::Result<()> {
        let euid = unsafe { libc::geteuid() };
        let names = [OsStr::new(leaf)];
        let shown = base.join(leaf);
        establish_chain(open_base(base), &names, euid, Walk::Establish, &shown, true)
    }

    fn refusal_of(result: io::Result<()>, what: &str) -> String {
        match result {
            Ok(()) => panic!("{what} was taken for the state directory"),
            Err(err) => err.to_string(),
        }
    }

    /// `--state-dir /etc` by a slip of the finger: the directory exists and holds somebody else's
    /// files and no live state of dedcom's. It is refused before anything is changed — its mode to
    /// the bit, its listing, what it holds — and the refusal names it, says why, shows one of the
    /// entries and names the chmod it would have done.
    #[test]
    fn a_foreign_directory_is_refused_and_left_exactly_as_it_was() {
        let base = temp_path("foreign");
        for (i, mode) in [0o755, 0o750, 0o711, 0o2750].into_iter().enumerate() {
            let name = format!("srv{i}");
            let dir = existing_dir(&base, &name, mode, &["notes.txt"]);
            let before = (mode_bits(&dir), names_in(&dir));

            let refusal = refusal_of(settle(&base, &name, Walk::Establish), &format!("{mode:o}"));

            assert_eq!(
                (mode_bits(&dir), names_in(&dir)),
                before,
                "{mode:o}: the refused directory must be left as it was"
            );
            assert_eq!(
                std::fs::read(dir.join("notes.txt")).unwrap(),
                b"not dedcom's\n"
            );
            assert!(
                refusal.contains(&dir.display().to_string()),
                "names the directory: {refusal}"
            );
            assert!(
                refusal.contains("no dedcom database or lock"),
                "says why: {refusal}"
            );
            assert!(
                refusal.contains("«notes.txt»"),
                "shows what is there: {refusal}"
            );
            assert!(
                refusal.contains("set its mode to 0700"),
                "says what taking it would do: {refusal}"
            );
        }
        std::fs::remove_dir_all(&base).ok();
    }

    /// The rule does not lean on the mode. A foreign directory that is already 0700 — `/root` —
    /// loses nothing to a chmod, but it would still become the home of the database and the lock;
    /// and the refusal does not promise a chmod that would not have happened.
    #[test]
    fn a_foreign_directory_that_is_already_0700_is_refused_too() {
        let base = temp_path("foreign700");
        let dir = existing_dir(&base, "home", 0o700, &[".profile"]);
        let refusal = refusal_of(
            settle(&base, "home", Walk::Establish),
            "a 0700 foreign directory",
        );
        assert_eq!(mode_bits(&dir), 0o700);
        assert_eq!(
            names_in(&dir),
            [OsString::from(".profile")],
            "nothing was created in it"
        );
        assert!(refusal.contains("«.profile»"), "{refusal}");
        assert!(!refusal.contains("set its mode"), "{refusal}");
        std::fs::remove_dir_all(&base).ok();
    }

    /// dedcom's live state, spelled out rather than taken from the constant: a test iterating the
    /// constant would pass whatever the constant is narrowed to.
    const LIVE_STATE: [&str; 5] = [
        "dedcom.db",
        "dedcom.db-wal",
        "dedcom.db-shm",
        "dedcom.db-journal",
        "dedcom.lock",
    ];

    /// Any one of them makes an existing directory dedcom's — beside files of the operator's, too.
    /// Those are made both before and after it, so a listing that gave up at the first name that
    /// is not live state would miss it: always where the filesystem lists entries in the order
    /// they were made or in the reverse, and in all five directories at once only by a small
    /// chance where it lists them by hash.
    #[test]
    fn any_one_name_of_the_live_state_makes_a_directory_dedcoms() {
        let base = temp_path("ours");
        for (i, entry) in LIVE_STATE.into_iter().enumerate() {
            let name = format!("state{i}");
            let around = ["a.txt", "b.txt", "c.txt", entry, "x.txt", "y.txt", "z.txt"];
            let dir = existing_dir(&base, &name, 0o750, &around);
            settle(&base, &name, Walk::Establish)
                .unwrap_or_else(|err| panic!("{entry} makes the directory dedcom's: {err}"));
            assert_eq!(
                mode_bits(&dir),
                0o700,
                "{entry}: dedcom's, and tightened as before"
            );
        }
        std::fs::remove_dir_all(&base).ok();
    }

    /// The constants against the names the writers use: the checkpoint with its SQLite
    /// companions, the lock, and the two logs. All are named through functions, and a rename
    /// there would otherwise leave every existing state directory unrecognized — or refuse the
    /// very directory a run's own log has just been opened in.
    #[test]
    fn the_names_that_count_are_the_ones_dedcom_writes() {
        assert_eq!(PROTECTED_STATE_ENTRIES, LIVE_STATE);
        let dir = Path::new("/state");
        let cli = Cli {
            state_dir: Some(dir.to_path_buf()),
            ..Default::default()
        };
        let db = checkpoint_db(&cli);
        let db_name = db.file_name().and_then(OsStr::to_str).unwrap();
        let lock = crate::lock::lock_path(dir);
        let lock_name = lock.file_name().and_then(OsStr::to_str).unwrap();
        for name in [
            db_name.to_string(),
            format!("{db_name}-wal"),
            format!("{db_name}-shm"),
            format!("{db_name}-journal"),
            lock_name.to_string(),
        ] {
            assert!(PROTECTED_STATE_ENTRIES.contains(&name.as_str()), "{name}");
        }
        let logs = [log_file(&cli), bench_file(&cli)];
        let logs: Vec<&str> = logs
            .iter()
            .map(|path| path.file_name().and_then(OsStr::to_str).unwrap())
            .collect();
        assert_eq!(DEDCOMS_LOGS.as_slice(), logs.as_slice());
    }

    /// dedcom's settings and saved plans, which do not make a directory dedcom's.
    const SETTINGS_OF_DEDCOMS: [&str; 5] = [
        "consent.json",
        "config.json",
        "board.json",
        "presets.json",
        "plans/",
    ];

    /// `config.json`, `plans` and the like are names anybody's directory may have — and dedcom
    /// rewrites `config.json` on its first auto-vacuum. Each one alone is refused, and all of them
    /// together with the logs are still no database and no lock.
    #[test]
    fn dedcoms_other_names_do_not_make_a_directory_dedcoms() {
        let base = temp_path("others");
        for (i, entry) in SETTINGS_OF_DEDCOMS.into_iter().enumerate() {
            let name = format!("state{i}");
            let dir = existing_dir(&base, &name, 0o755, &[entry]);
            let before = names_in(&dir);
            assert!(settle(&base, &name, Walk::Establish).is_err(), "{entry}");
            assert_eq!(
                (mode_bits(&dir), names_in(&dir)),
                (0o755, before),
                "{entry}"
            );
        }
        let mut all = SETTINGS_OF_DEDCOMS.to_vec();
        all.extend(DEDCOMS_LOGS);
        let dir = existing_dir(&base, "all", 0o755, &all);
        let before = names_in(&dir);
        let refusal = refusal_of(
            settle(&base, "all", Walk::Establish),
            "a directory of logs and settings",
        );
        assert_eq!((mode_bits(&dir), names_in(&dir)), (0o755, before));
        assert!(refusal.contains("no dedcom database or lock"), "{refusal}");
        std::fs::remove_dir_all(&base).ok();
    }

    /// The logs count neither way. A directory holding them and nothing else is taken like an empty
    /// one — that is what a run's own log leaves in a directory it has just created, before the
    /// mode looks again, and what an older dedcom's `--stats` left. Beside somebody else's file
    /// they save nothing: that is `/etc` after such a run, refused, and the refusal shows the file
    /// rather than a log. At the top level they are an empty directory there, refused as one; and
    /// a reporting mode finds no state in them to report on.
    #[test]
    fn dedcoms_logs_count_neither_way() {
        let base = temp_path("logs");
        let dir = existing_dir(&base, "state", 0o755, &DEDCOMS_LOGS);
        settle(&base, "state", Walk::Establish).expect("a directory holding only dedcom's logs");
        assert_eq!(mode_bits(&dir), 0o700);

        let etc = existing_dir(
            &base,
            "etc",
            0o755,
            &["passwd", "dedcom.log", "benchmarks.log"],
        );
        let before = names_in(&etc);
        let refusal = refusal_of(settle(&base, "etc", Walk::Establish), "/etc after --stats");
        assert_eq!((mode_bits(&etc), names_in(&etc)), (0o755, before));
        assert!(refusal.contains("«passwd»"), "{refusal}");

        existing_dir(&base, "srv", 0o755, &DEDCOMS_LOGS);
        let refusal = refusal_of(
            settle_at_the_top(&base, "srv"),
            "a top-level directory of logs",
        );
        assert!(refusal.contains("directly under /"), "{refusal}");

        existing_dir(&base, "report", 0o755, &DEDCOMS_LOGS);
        assert!(settle(&base, "report", Walk::Report).is_err());
        std::fs::remove_dir_all(&base).ok();
    }

    /// Adoption is the case where «not sure» means «no», so a name counts only as dedcom spells
    /// it: another case, a suffix, a prefix or a backup copy is somebody else's file.
    #[test]
    fn a_name_that_only_resembles_the_live_state_does_not_count() {
        let base = temp_path("lookalike");
        let lookalikes = [
            "DEDCOM.DB",
            "Dedcom.Lock",
            "dedcom.db.bak",
            "old-dedcom.db",
            ".dedcom.lock",
            "dedcom.db ",
            "dedcom",
            "dedcom.lock~",
        ];
        for (i, entry) in lookalikes.into_iter().enumerate() {
            let name = format!("state{i}");
            let dir = existing_dir(&base, &name, 0o755, &[entry]);
            assert!(
                settle(&base, &name, Walk::Establish).is_err(),
                "{entry:?} counted as dedcom's"
            );
            assert_eq!(mode_bits(&dir), 0o755, "{entry:?}");
            assert_eq!(names_in(&dir), [OsString::from(entry)], "{entry:?}");
        }
        std::fs::remove_dir_all(&base).ok();
    }

    /// Everything but `.` and `..` counts: a dot-file or a directory is somebody's too — a freshly
    /// made ext4 filesystem holds `lost+found` and nothing else.
    #[test]
    fn a_dot_file_or_a_lone_subdirectory_is_somebody_elses() {
        let base = temp_path("dotfile");
        for (i, entry) in [".profile", "lost+found/", ".cache/"]
            .into_iter()
            .enumerate()
        {
            let name = format!("state{i}");
            let dir = existing_dir(&base, &name, 0o755, &[entry]);
            assert!(settle(&base, &name, Walk::Establish).is_err(), "{entry:?}");
            assert_eq!(mode_bits(&dir), 0o755, "{entry:?}");
        }
        std::fs::remove_dir_all(&base).ok();
    }

    /// `/home`, `/srv` and `/mnt` come empty on a fresh system, and `--state-dir /home` would set
    /// it to 0700 and cut every other user off from what is later made in it. An empty directory
    /// directly under `/` is refused, the refusal pointing inside it; one this walk makes there, or
    /// one holding dedcom's live state, is taken as before, and so is an empty one anywhere else.
    #[test]
    fn an_empty_directory_directly_under_the_root_is_not_taken() {
        let base = temp_path("toplevel");
        let empty = existing_dir(&base, "home", 0o755, &[]);
        let refusal = refusal_of(
            settle_at_the_top(&base, "home"),
            "an empty top-level directory",
        );
        assert_eq!(mode_bits(&empty), 0o755);
        assert!(names_in(&empty).is_empty());
        assert!(refusal.contains("directly under /"), "{refusal}");
        assert!(
            refusal.contains(&empty.join("dedcom").display().to_string()),
            "points at a directory inside it: {refusal}"
        );
        assert!(refusal.contains("set its mode to 0700"), "{refusal}");

        let used = existing_dir(&base, "dedcom", 0o750, &["dedcom.lock"]);
        settle_at_the_top(&base, "dedcom").expect("a top-level directory dedcom has worked in");
        assert_eq!(mode_bits(&used), 0o700);

        settle_at_the_top(&base, "fresh").expect("a top-level directory the walk makes itself");
        assert_eq!(mode_bits(&base.join("fresh")), 0o700);

        existing_dir(&base, "below", 0o755, &[]);
        settle(&base, "below", Walk::Establish).expect("an empty directory below the top");
        std::fs::remove_dir_all(&base).ok();
    }

    /// Only the directory itself is adopted. `--state-dir /etc/dedcom` creates `dedcom` inside a
    /// foreign `/etc` and leaves `/etc` alone.
    #[test]
    fn a_new_directory_inside_a_foreign_one_is_created_and_the_foreign_one_left_alone() {
        let base = temp_path("under");
        let etc = existing_dir(&base, "etc", 0o755, &["passwd"]);
        let euid = unsafe { libc::geteuid() };
        let names = [OsStr::new("etc"), OsStr::new("dedcom")];
        let leaf = etc.join("dedcom");
        establish_chain(
            open_base(&base),
            &names,
            euid,
            Walk::Establish,
            &leaf,
            false,
        )
        .unwrap();
        assert_eq!(mode_bits(&leaf), 0o700);
        assert_eq!(mode_bits(&etc), 0o755);
        assert_eq!(
            names_in(&etc),
            [OsString::from("dedcom"), OsString::from("passwd")]
        );
        std::fs::remove_dir_all(&base).ok();
    }

    /// The refusal quotes the operator's path and one of the entries it found, and either can
    /// carry an escape sequence.
    #[test]
    fn the_refusal_shows_the_directory_and_the_entry_without_raw_control_characters() {
        let base = temp_path("ctlname");
        let name = "srv\u{1b}]0;PWNED\u{7}";
        existing_dir(&base, name, 0o755, &["wipe\u{1b}[2Jme"]);
        let refusal = refusal_of(settle(&base, name, Walk::Establish), "a foreign directory");
        assert!(!refusal.chars().any(char::is_control), "{refusal:?}");
        assert!(
            refusal.contains("srv\\u{1b}]0;PWNED\\u{7}"),
            "the directory is spelled out: {refusal:?}"
        );
        assert!(
            refusal.contains("wipe\\u{1b}[2Jme"),
            "so is the entry: {refusal:?}"
        );
        std::fs::remove_dir_all(&base).ok();
    }

    /// A symlink in place of the directory is refused as before, whichever way the mode reaches
    /// it, and nothing looks through it: the directory it points to keeps its mode.
    #[test]
    fn a_symlink_in_place_of_the_directory_is_refused_and_its_target_left_alone() {
        let base = temp_path("leaflink");
        let real = existing_dir(&base, "real", 0o755, &["dedcom.db"]);
        std::os::unix::fs::symlink(&real, base.join("state")).unwrap();
        for walk in [Walk::Establish, Walk::Report, Walk::OpenDb] {
            assert!(settle(&base, "state", walk).is_err(), "{walk:?}");
            assert_eq!(mode_bits(&real), 0o755, "{walk:?}");
        }
        std::fs::remove_dir_all(&base).ok();
    }

    /// The same through the public entry, walked from `/` — what `--state-dir` reaches.
    #[test]
    fn establish_state_dir_refuses_a_foreign_directory() {
        let base = temp_path("public");
        let dir = existing_dir(&base, "srv", 0o755, &["notes.txt"]);
        let refusal = refusal_of(establish_state_dir(&dir), "a foreign directory");
        assert!(refusal.contains(&dir.display().to_string()), "{refusal}");
        assert_eq!(mode_bits(&dir), 0o755);
        assert_eq!(names_in(&dir), [OsString::from("notes.txt")]);
        std::fs::remove_dir_all(&base).ok();
    }

    /// An error from the system names the directory — «No such file or directory» alone does not
    /// say which one. A store opening its checkpoint meets it when the state directory has gone.
    #[test]
    fn a_system_error_names_the_directory() {
        let base = temp_path("named");
        let missing = base.join("missing/state");
        for err in [
            verify_state_dir(&missing).unwrap_err(),
            verify_db_dir(&missing).unwrap_err(),
        ] {
            assert_eq!(err.kind(), io::ErrorKind::NotFound, "{err}");
            assert!(
                err.to_string().contains(&missing.display().to_string()),
                "{err}"
            );
        }
        std::fs::remove_dir_all(&base).ok();
    }

    /// The manual says what the refusal says, and both say what the code does: an existing
    /// directory is taken only when it holds dedcom's live state or is empty and not at the top, a
    /// new or an empty one is the way past the refusal, and the reporting modes create and change
    /// nothing (their tests are below).
    #[test]
    fn the_manual_states_what_the_state_directory_refuses() {
        let manual = crate::testfixtures::manual("02-install.md");
        let flat = manual.split_whitespace().collect::<Vec<_>>().join(" ");
        for claim in [
            "it takes an existing directory only if it already holds dedcom's database or lock, \
             or is empty and not directly under `/` — dedcom's own logs aside",
            "Its settings files alone do not count",
            "is refused before anything in it changes, and the error names it",
            "name a directory that does not exist yet, or make an empty one with `mkdir` first",
            "`--stats` and `--export-csv` never create the state directory or change its mode",
        ] {
            assert!(
                flat.contains(claim),
                "02-install.md no longer says: {claim}"
            );
        }

        let base = temp_path("manual");
        existing_dir(&base, "etc", 0o755, &["passwd"]);
        let refusal = refusal_of(settle(&base, "etc", Walk::Establish), "a foreign directory");
        for advice in ["does not exist yet", "mkdir"] {
            assert!(
                refusal.contains(advice),
                "the refusal gives the manual's way past it: {refusal}"
            );
        }
        std::fs::remove_dir_all(&base).ok();
    }

    // --- a reporting mode reaches the state directory without changing anything ---

    /// Neither a missing directory nor a missing parent of it is created.
    #[test]
    fn verify_refuses_a_missing_directory_and_creates_nothing() {
        let base = temp_path("ro_missing");
        assert!(settle(&base, "state", Walk::Report).is_err());
        assert!(!base.join("state").exists());

        let euid = unsafe { libc::geteuid() };
        let names = [OsStr::new("a"), OsStr::new("b")];
        let leaf = base.join("a/b");
        assert!(
            establish_chain(open_base(&base), &names, euid, Walk::Report, &leaf, false).is_err()
        );
        assert!(!base.join("a").exists(), "not even the parent");
        std::fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn verify_refuses_a_foreign_directory_and_changes_nothing() {
        let base = temp_path("ro_foreign");
        let dir = existing_dir(&base, "srv", 0o755, &["notes.txt"]);
        assert!(settle(&base, "srv", Walk::Report).is_err());
        assert_eq!(mode_bits(&dir), 0o755);
        assert_eq!(names_in(&dir), [OsString::from("notes.txt")]);
        std::fs::remove_dir_all(&base).ok();
    }

    /// dedcom's own directory is taken as it is: a reporting mode does not tighten it.
    #[test]
    fn verify_takes_our_directory_without_changing_its_mode() {
        let base = temp_path("ro_ours");
        let dir = existing_dir(&base, "state", 0o750, &["dedcom.db"]);
        settle(&base, "state", Walk::Report).unwrap();
        assert_eq!(mode_bits(&dir), 0o750);
        assert_eq!(names_in(&dir), [OsString::from("dedcom.db")]);
        std::fs::remove_dir_all(&base).ok();
    }

    /// An empty directory has nothing to report on and is nobody's state yet. A mode that writes
    /// would adopt it; a reporting mode does not start one there. Nor does it take the logs an
    /// older run left as a state directory to report on.
    #[test]
    fn verify_refuses_an_empty_directory_and_one_of_old_logs() {
        let base = temp_path("ro_empty");
        let dir = existing_dir(&base, "state", 0o755, &[]);
        assert!(settle(&base, "state", Walk::Report).is_err());
        assert_eq!(mode_bits(&dir), 0o755);
        assert!(names_in(&dir).is_empty());

        let logs = existing_dir(&base, "logs", 0o700, &["dedcom.log", "benchmarks.log"]);
        assert!(settle(&base, "logs", Walk::Report).is_err());
        assert_eq!(names_in(&logs).len(), 2);
        std::fs::remove_dir_all(&base).ok();
    }

    /// The checks that do not write stay: dedcom's directory writable by others is still refused.
    #[test]
    fn verify_keeps_the_permission_check() {
        let base = temp_path("ro_perm");
        for (i, mode) in [0o770, 0o757, 0o1777].into_iter().enumerate() {
            let name = format!("state{i}");
            let dir = existing_dir(&base, &name, mode, &["dedcom.db"]);
            let before = mode_bits(&dir);
            assert!(settle(&base, &name, Walk::Report).is_err(), "{mode:o}");
            assert_eq!(mode_bits(&dir), before, "{mode:o}");
        }
        std::fs::remove_dir_all(&base).ok();
    }

    /// The public entry, walked from `/`.
    #[test]
    fn verify_state_dir_leaves_a_missing_path_missing() {
        let base = temp_path("ro_public");
        assert!(verify_state_dir(&base.join("missing/state")).is_err());
        assert!(!base.join("missing").exists());
        std::fs::remove_dir_all(&base).ok();
    }

    // --- a store opening its checkpoint verifies the directory and changes nothing ---

    /// The directory was chosen, created and taken where the mode began; a store opening the
    /// checkpoint does not make a missing one — which would be a state directory nobody checked.
    #[test]
    fn a_store_creates_no_directory() {
        let base = temp_path("db_missing");
        assert!(settle(&base, "state", Walk::OpenDb).is_err());
        assert!(!base.join("state").exists());
        assert!(verify_db_dir(&base.join("missing/state")).is_err());
        assert!(!base.join("missing").exists());
        std::fs::remove_dir_all(&base).ok();
    }

    /// Nor changes the mode of the directory it opens in, whoever's it is, and whatever it holds.
    #[test]
    fn a_store_changes_no_mode() {
        let base = temp_path("db_mode");
        for (i, (mode, entries)) in [
            (0o750, &["dedcom.db"][..]),
            (0o755, &[][..]),
            (0o755, &["notes.txt", "root/"][..]),
        ]
        .into_iter()
        .enumerate()
        {
            let name = format!("state{i}");
            let dir = existing_dir(&base, &name, mode, entries);
            let before = (mode_bits(&dir), names_in(&dir));
            settle(&base, &name, Walk::OpenDb).unwrap_or_else(|err| panic!("{entries:?}: {err}"));
            assert_eq!((mode_bits(&dir), names_in(&dir)), before, "{entries:?}");
        }
        std::fs::remove_dir_all(&base).ok();
    }

    /// The checks that do not write stay for a store as well.
    #[test]
    fn a_store_keeps_the_permission_check() {
        let base = temp_path("db_perm");
        for (i, mode) in [0o770, 0o757, 0o1777].into_iter().enumerate() {
            let name = format!("state{i}");
            let dir = existing_dir(&base, &name, mode, &["dedcom.db"]);
            let before = mode_bits(&dir);
            assert!(settle(&base, &name, Walk::OpenDb).is_err(), "{mode:o}");
            assert_eq!(mode_bits(&dir), before, "{mode:o}");
        }
        std::fs::remove_dir_all(&base).ok();
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
