// SPDX-License-Identifier: Apache-2.0
//! Safe opening of regular files on the read path (hashing, byte-for-byte comparison).
//!
//! A bare `File::open` on the scan worker is dangerous under root:
//! - it follows symlinks — `follow_symlinks=false` only covers the walk traversal, not the
//!   actual open during the hashing phase (walk→hash race: `unlink F; ln -s /etc/secret F`);
//! - it **blocks forever** on a FIFO with no writer (`open(O_RDONLY)` waits for an open for writing);
//!   the pipeline's cancel is only checked at the chunk boundary, so Esc is dead and the thread
//!   is unkillable without SIGKILL.
//!
//! `open_regular_nofollow` opens with `O_NOFOLLOW` (symlink → `ELOOP`) and `O_NONBLOCK`
//! (FIFO/device return an fd immediately, don't hang), then via `fstat` on the ALREADY-open
//! descriptor rejects everything but a regular file. The check is by fd, not by path,
//! so a path swap after `open` won't fool it. For a regular file Linux ignores `O_NONBLOCK`
//! on the subsequent `read` — the read proceeds as usual.
//!
//! One kind of regular file is refused all the same, and BEFORE the open: a file of the database
//! this process has open through SQLite. A read ends in a close, and the close of any descriptor
//! of a file drops every lock the process holds on it — SQLite's among them
//! ([`crate::paths::OpenDatabase`]). Every read of the content of a file a tree can name comes
//! through here (the program's own settings and lock are read elsewhere, at their fixed names),
//! so this is where the three files are known; the one opening this module cannot make — the
//! clone, which a library does — asks [`refuse_open_database`] first.
//!
//! The look before the open is not the whole of it, because the danger is the close and the
//! close comes later. So what `open_regular_nofollow` returns is a [`ReadFile`], which asks once
//! more when it is dropped and, should its file have become one of those three meanwhile, is not
//! closed at all. (Of the three, SQLite keeps locks on two — the database and the index of its
//! journal; the journal itself is refused with them because it is theirs, not for a lock.)

use std::fs::{File, Metadata, OpenOptions};
use std::io::{self, ErrorKind, Read};
use std::mem::ManuallyDrop;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;

use crate::paths::PathIdentity;

/// A regular file open for reading — and a descriptor that is never closed over a database this
/// process has open.
///
/// Closing a descriptor drops every lock the process holds on its file, whenever the locks were
/// taken. A file can become a file of an open database after it was opened here: a read of
/// `dedcom.db` begun while nothing had it open, a connection opened before the read is over. So
/// the question is asked again at the one moment it matters, the drop — asked and acted on as
/// one step, so that no connection can be opened between the answer and the close. If the
/// answer is yes, the descriptor stays with the process for good: one descriptor lost, the
/// locks kept.
#[derive(Debug)]
pub(crate) struct ReadFile {
    file: ManuallyDrop<File>,
    /// What the descriptor is of, read from the descriptor itself when it was opened.
    identity: PathIdentity,
}

impl ReadFile {
    pub(crate) fn metadata(&self) -> io::Result<Metadata> {
        self.file.metadata()
    }
}

impl Read for ReadFile {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.file.read(buf)
    }
}

impl Read for &ReadFile {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut file: &File = &self.file;
        file.read(buf)
    }
}

impl Drop for ReadFile {
    fn drop(&mut self) {
        let identity = self.identity;
        let file = &mut self.file;
        let closed = crate::paths::unless_open_database_file(identity, || {
            // SAFETY: the one place the file is dropped, and nothing reads the field after it.
            unsafe { ManuallyDrop::drop(file) }
        });
        if !closed {
            // Rare enough to be worth a line: a name changed hands under a read, or a database
            // was opened while one of its files was being read.
            tracing::warn!(
                "a descriptor is kept open until dedcom exits: its file (device {}, inode {}) \
                 is a file of dedcom's open database, and closing it would cost SQLite its locks",
                identity.device,
                identity.inode
            );
        }
    }
}

/// Opens a regular file for reading, without following a symlink and without hanging on a FIFO/device.
///
/// Errors (instead of hanging/following the link) if `path` is a symlink (`ELOOP`), FIFO,
/// socket, or device. What comes back is guaranteed to be a regular file — and never a file of
/// a database this process has open, which is refused, and as a rule without being opened.
pub(crate) fn open_regular_nofollow(path: &Path) -> io::Result<ReadFile> {
    // The look comes first, by name and without a descriptor — the `lstat` the list of open
    // databases itself takes: a file that is known to be one of those three is not opened, so
    // there is nothing to keep open afterwards. A name that cannot be looked at is left for the
    // open to report.
    if let Ok(looked) = crate::paths::identity_at(path) {
        refuse_if_open_database(looked)?;
    }
    #[cfg(test)]
    take_swap_after_the_look();
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let opened = file.metadata()?;
    let file = ReadFile {
        file: ManuallyDrop::new(file),
        identity: identity(&opened),
    };
    // The name may have been given to one of those files between the look and the open. Then
    // the descriptor is of that file, and the refusal below drops a `ReadFile` — which, for such
    // a file, closes nothing.
    refuse_if_open_database(file.identity)?;
    if !opened.file_type().is_file() {
        return Err(io::Error::new(
            ErrorKind::InvalidInput,
            "not a regular file (FIFO/device/socket) — skipping",
        ));
    }
    Ok(file)
}

/// Refuses `path` if it leads to a file of a database this process has open — the look
/// [`open_regular_nofollow`] takes before it opens anything, for the caller that hands the name
/// to a library to open. The library follows a link at the name, so this look does as well. A
/// name that cannot be looked at is not refused here: whatever opens it will say why.
pub(crate) fn refuse_open_database(path: &Path) -> io::Result<()> {
    match std::fs::metadata(path) {
        Ok(there) => refuse_if_open_database(identity(&there)),
        Err(_) => Ok(()),
    }
}

fn identity(of: &Metadata) -> PathIdentity {
    PathIdentity {
        device: of.dev(),
        inode: of.ino(),
    }
}

/// What a read of a file of an open database is told. The manual quotes it (chapter 7).
pub(crate) const OPEN_DATABASE_REFUSAL: &str =
    "a file of dedcom's open database, or a hard link to one — it is not read as a file";

/// The refusal itself.
fn refuse_if_open_database(file: PathIdentity) -> io::Result<()> {
    if crate::paths::is_open_database_file(file) {
        return Err(io::Error::new(
            ErrorKind::InvalidInput,
            OPEN_DATABASE_REFUSAL,
        ));
    }
    Ok(())
}

// Test-only one-shot seam between the look at a name and the open of it: the one instant at which
// a name can be given to another file with the look already taken. No sleep and no second thread
// could put a rename there. Thread-local, so it cannot fire in a parallel test; absent from every
// non-test build.
#[cfg(test)]
thread_local! {
    static SWAP_AFTER_THE_LOOK: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
fn take_swap_after_the_look() {
    if let Some(swap) = SWAP_AFTER_THE_LOOK.with(|slot| slot.borrow_mut().take()) {
        swap();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::store::{Closing, ClosingStage, ScanStore};
    use crate::testfixtures::{outside, Errand};
    use std::io::Write as _;
    use std::os::unix::ffi::OsStrExt;
    use std::path::PathBuf;

    fn temp_dir(tag: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let mut dir = std::env::temp_dir();
        dir.push(format!(
            "dedcom_safeopen_{tag}_{}_{nanos}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn opens_regular_file() {
        let root = temp_dir("reg");
        let path = root.join("a.bin");
        File::create(&path).unwrap().write_all(b"data").unwrap();

        let mut file = open_regular_nofollow(&path).unwrap();
        let mut buf = Vec::new();
        file.read_to_end(&mut buf).unwrap();
        assert_eq!(buf, b"data");

        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn refuses_symlink() {
        let root = temp_dir("link");
        let target = root.join("real.bin");
        File::create(&target).unwrap().write_all(b"r").unwrap();
        let link = root.join("link.bin");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        // O_NOFOLLOW → ELOOP: we don't follow the symbolic link.
        assert!(open_regular_nofollow(&link).is_err());

        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn refuses_fifo_without_blocking() {
        let root = temp_dir("fifo");
        let fifo = root.join("pipe");
        let cpath = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
        // SAFETY: cpath is a valid C-string from an existing path; mode 0o600.
        let rc = unsafe { libc::mkfifo(cpath.as_ptr(), 0o600) };
        assert_eq!(rc, 0, "mkfifo did not create the FIFO");

        // Without a writer a bare File::open(O_RDONLY) would hang forever; O_NONBLOCK
        // returns the fd immediately, and the S_ISREG check rejects the FIFO.
        let err = open_regular_nofollow(&fifo).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidInput);

        std::fs::remove_dir_all(&root).ok();
    }

    // --- the database this process has open is not read as a file ---

    /// The file beside the database whose name ends in `suffix`: its journal, or the index of it.
    fn beside(db: &Path, suffix: &str) -> PathBuf {
        let mut name = db.as_os_str().to_owned();
        name.push(suffix);
        PathBuf::from(name)
    }

    /// Who holds SQLite's lock on the database and who holds the one on its journal index, as
    /// another process sees it.
    fn locks(db: &Path) -> (String, String) {
        (
            outside(Errand::SharedLockHolder, db),
            outside(Errand::IndexLockHolder, db),
        )
    }

    /// How many descriptors this process has of the file at `path` — told by what each
    /// descriptor is of, the way the code under test knows a file, not by the name it was
    /// opened at.
    fn descriptors_of(path: &Path) -> usize {
        let file = identity(&std::fs::symlink_metadata(path).unwrap());
        std::fs::read_dir("/proc/self/fd")
            .unwrap()
            .filter_map(|entry| std::fs::metadata(entry.ok()?.path()).ok())
            .filter(|open| identity(open) == file)
            .count()
    }

    /// A read that reaches the database this process has open must not cost SQLite its locks.
    ///
    /// POSIX drops every lock a process holds on a file when the process closes ANY descriptor of
    /// that file, and SQLite's locks are of that kind. A scan whose root holds the state
    /// directory, or F4 on one of the three files, used to open the file, read it and close it
    /// like any other — and left the process without its lock on the database or on the journal
    /// index, for as long as it kept the database open.
    #[test]
    fn the_database_this_process_has_open_is_refused_and_keeps_its_locks() {
        let root = temp_dir("own_db");
        let db = root.join("dedcom.db");
        let store = ScanStore::open_writable(&db).unwrap();
        let me = format!("held by {}", std::process::id());
        let held = (me.clone(), me);
        assert_eq!(locks(&db), held, "the control: SQLite holds both");

        for suffix in ["", "-wal", "-shm"] {
            let file = beside(&db, suffix);
            let sqlites = descriptors_of(&file);
            assert!(
                sqlites >= 1,
                "the control: SQLite has {} open, and the count sees it",
                file.display()
            );
            // Opened and closed again, if it is opened at all: the close is what does the damage.
            let read = open_regular_nofollow(&file).map(drop);
            assert_eq!(locks(&db), held, "after the read of {}", file.display());
            let err = read.expect_err("a file of the open database is not opened");
            assert_eq!(err.kind(), ErrorKind::InvalidInput, "{err}");
            assert_eq!(err.to_string(), OPEN_DATABASE_REFUSAL);
            assert_eq!(
                descriptors_of(&file),
                sqlites,
                "refused at the look: no descriptor of {} was made, so none is left",
                file.display()
            );
        }

        // The control: a file that is none of the three is read as before, beside them.
        let other = root.join("other.bin");
        File::create(&other).unwrap().write_all(b"data").unwrap();
        open_regular_nofollow(&other).expect("an ordinary file beside the database");
        drop(store);
        std::fs::remove_dir_all(&root).ok();
    }

    /// Every way a store opens its database makes the files known: the observer's read-only
    /// connection and the connection of a batch of actions as much as the one that writes. And
    /// each has the journal index taken down by the time it is open — moved at once, the index
    /// is known where it went.
    #[test]
    fn every_way_a_store_opens_its_database_makes_its_files_known() {
        let _role = crate::state::store::role_guard();
        type Opener = fn(&Path) -> ScanStore;
        let openers: [(&str, Opener); 3] = [
            ("to write", |db| ScanStore::open_writable(db).unwrap()),
            ("to read only", |db| ScanStore::open_read_only(db).unwrap()),
            ("for a batch of actions", |db| {
                ScanStore::open_for_apply_lease(db).unwrap_or_else(|refusal| panic!("{refusal:?}"))
            }),
        ];
        for (how, open) in openers {
            let root = temp_dir("own_db_opener");
            let db = root.join("dedcom.db");
            drop(ScanStore::open_writable(&db).unwrap());
            let store = open(&db);
            let me = format!("held by {}", std::process::id());
            let held = (me.clone(), me);
            assert_eq!(locks(&db), held, "{how}: the control: SQLite holds both");

            let read = open_regular_nofollow(&db).map(drop);
            assert_eq!(locks(&db), held, "{how}: after the read of the database");
            assert!(read.is_err(), "{how}: the read is refused");

            let moved = root.join("moved-shm");
            std::fs::rename(beside(&db, "-shm"), &moved).unwrap();
            assert!(
                crate::paths::is_open_database_file(identity(
                    &std::fs::symlink_metadata(&moved).unwrap()
                )),
                "{how}: the index was taken down when the store opened"
            );
            drop(store);
            std::fs::remove_dir_all(&root).ok();
        }
    }

    /// The same file under another name — a hard link somewhere else in the tree — is the same
    /// file: it is known by what it is, not by what it is called.
    #[test]
    fn a_hard_link_to_the_open_database_is_refused_like_the_database() {
        let root = temp_dir("own_db_link");
        let state = root.join("state");
        std::fs::create_dir_all(&state).unwrap();
        let db = state.join("dedcom.db");
        let store = ScanStore::open_writable(&db).unwrap();
        let alias = root.join("alias.bin");
        std::fs::hard_link(beside(&db, "-shm"), &alias).unwrap();
        let me = format!("held by {}", std::process::id());
        let held = (me.clone(), me);
        assert_eq!(locks(&db), held, "the control: SQLite holds both");

        let read = open_regular_nofollow(&alias).map(drop);
        assert_eq!(locks(&db), held, "after the read through the link");
        assert!(read.is_err(), "the link is not opened either");
        drop(store);
        std::fs::remove_dir_all(&root).ok();
    }

    /// The refusal lasts exactly as long as the database is open: a second connection keeps it up
    /// after the first is gone, and a database nobody has open is a file like any other.
    #[test]
    fn a_database_that_is_no_longer_open_is_read_like_any_file() {
        let root = temp_dir("own_db_closed");
        let db = root.join("dedcom.db");
        let first = ScanStore::open_writable(&db).unwrap();
        let second = ScanStore::open_writable(&db).unwrap();
        drop(first);
        assert!(
            open_regular_nofollow(&db).is_err(),
            "one connection still has it open"
        );
        drop(second);
        open_regular_nofollow(&db).expect("nothing has it open now");
        std::fs::remove_dir_all(&root).ok();
    }

    /// The look and the open are two calls, and a name can change hands between them. Should it
    /// be given to a file of the open database just then, the descriptor that comes back is of
    /// that file — and is kept, not closed: the read is refused and SQLite still has its locks.
    #[test]
    fn a_name_given_to_the_open_database_after_the_look_costs_no_lock() {
        let root = temp_dir("own_db_swap");
        let state = root.join("state");
        std::fs::create_dir_all(&state).unwrap();
        let db = state.join("dedcom.db");
        let store = ScanStore::open_writable(&db).unwrap();
        let name = root.join("looked-at.bin");
        File::create(&name).unwrap().write_all(b"data").unwrap();
        let link = root.join("link.bin");
        std::fs::hard_link(beside(&db, "-shm"), &link).unwrap();
        let me = format!("held by {}", std::process::id());
        let held = (me.clone(), me);
        assert_eq!(locks(&db), held, "the control: SQLite holds both");
        let sqlites = descriptors_of(&link);
        assert!(
            sqlites >= 1,
            "the control: SQLite has the index open, and the count sees it"
        );

        let (from, to) = (link.clone(), name.clone());
        SWAP_AFTER_THE_LOOK.with(|slot| {
            *slot.borrow_mut() = Some(Box::new(move || std::fs::rename(&from, &to).unwrap()));
        });
        let read = open_regular_nofollow(&name).map(drop);
        assert!(
            SWAP_AFTER_THE_LOOK.with(|slot| slot.borrow().is_none()) && !link.exists(),
            "the control: the name changed hands between the look and the open"
        );
        assert_eq!(
            locks(&db),
            held,
            "after the read that found the index there"
        );
        assert!(read.is_err(), "and the read is refused");
        assert_eq!(
            descriptors_of(&name),
            sqlites + 1,
            "the one descriptor that was made is still open beside SQLite's"
        );
        drop(store);
        std::fs::remove_dir_all(&root).ok();
    }

    /// The look alone, for a caller that hands the name to something else to open.
    #[test]
    fn the_look_alone_refuses_the_open_database_and_nothing_else() {
        let root = temp_dir("own_db_look");
        let db = root.join("dedcom.db");
        let other = root.join("other.bin");
        File::create(&other).unwrap().write_all(b"data").unwrap();
        refuse_open_database(&db).expect("no database is open at that name, and no file is there");
        let store = ScanStore::open_writable(&db).unwrap();
        for suffix in ["", "-wal", "-shm"] {
            let err = refuse_open_database(&beside(&db, suffix)).unwrap_err();
            assert_eq!(err.to_string(), OPEN_DATABASE_REFUSAL);
        }
        refuse_open_database(&other).expect("an ordinary file beside the database");
        refuse_open_database(&root.join("absent.bin")).expect("a name that holds nothing");
        // Whatever opens the name after this look follows a link there, so the look does too.
        let link = root.join("link.bin");
        std::os::unix::fs::symlink(&db, &link).unwrap();
        refuse_open_database(&link).expect_err("a link to the open database");
        drop(store);
        refuse_open_database(&db).expect("nothing has it open now");
        std::fs::remove_dir_all(&root).ok();
    }

    /// The close is what costs the locks, and a close comes when the read is over — by which
    /// time the file may have become a file of an open database: here the read begins while
    /// nothing has the database open, and ends after a connection was made. The descriptor is
    /// then not closed at all.
    #[test]
    fn a_read_begun_before_the_database_was_opened_costs_no_lock_when_it_ends() {
        let root = temp_dir("own_db_late");
        let db = root.join("dedcom.db");
        drop(ScanStore::open_writable(&db).unwrap());
        let reading = open_regular_nofollow(&db).expect("nothing has it open: a file like any");

        let store = ScanStore::open_writable(&db).unwrap();
        let me = format!("held by {}", std::process::id());
        let held = (me.clone(), me);
        assert_eq!(locks(&db), held, "the control: SQLite holds both");
        let open = descriptors_of(&db);
        assert!(
            open >= 2,
            "the control: SQLite's descriptor and the read's are both counted"
        );
        drop(reading);
        assert_eq!(
            locks(&db),
            held,
            "after the read that began earlier was over"
        );
        assert_eq!(
            descriptors_of(&db),
            open,
            "its descriptor is still open beside SQLite's"
        );
        drop(store);
        std::fs::remove_dir_all(&root).ok();
    }

    /// SQLite keeps the file it opened, not the name. A file of the open database that is moved
    /// — this program's own move can do that — is the same file at its new name, and is refused
    /// there. Moved at once, before anything had asked about it: the store had taken it down
    /// when it opened.
    #[test]
    fn a_file_of_the_open_database_that_was_moved_is_refused_where_it_went() {
        let root = temp_dir("own_db_moved");
        let state = root.join("state");
        std::fs::create_dir_all(&state).unwrap();
        let db = state.join("dedcom.db");
        let store = ScanStore::open_writable(&db).unwrap();
        // The errand looks for the index beside the name it is given.
        let moved = root.join("moved.db");
        std::fs::rename(beside(&db, "-shm"), beside(&moved, "-shm")).unwrap();
        let me = format!("held by {}", std::process::id());
        let holder = || outside(Errand::IndexLockHolder, &moved);
        assert_eq!(holder(), me, "the control: the lock went with the file");

        let read = open_regular_nofollow(&beside(&moved, "-shm")).map(drop);
        assert_eq!(holder(), me, "after the read at its new name");
        assert!(read.is_err(), "and the read is refused");
        drop(store);
        std::fs::remove_dir_all(&root).ok();
    }

    /// A file is known by its number only for as long as SQLite holds it: once the connection
    /// has closed, the file may be deleted and its number given to a file of somebody's. So a
    /// store that is going does three things in this order, and the order is the point. It
    /// forgets the numbers while its connection is still open — from then on the names answer.
    /// It closes the connection. And only then does its database stop being listed: up to that
    /// moment a file at one of the three names is still refused to a read. (A file that was
    /// moved away from its name is not known between the first step and the second, as the
    /// first expectation below shows.)
    #[test]
    fn a_store_that_is_going_forgets_closes_and_only_then_lets_go() {
        let root = temp_dir("own_db_closing");
        let state = root.join("state");
        std::fs::create_dir_all(&state).unwrap();
        let db = state.join("dedcom.db");
        let store = ScanStore::open_writable(&db).unwrap();
        let database = identity(&std::fs::symlink_metadata(&db).unwrap());
        // Moved, so that only a number that was noted can still tell it for a file of the database.
        let moved = root.join("moved-shm");
        std::fs::rename(beside(&db, "-shm"), &moved).unwrap();
        let index = identity(&std::fs::symlink_metadata(&moved).unwrap());
        let known = move || {
            (
                crate::paths::is_open_database_file(database),
                crate::paths::is_open_database_file(index),
            )
        };
        assert_eq!(
            known(),
            (true, true),
            "the control: both known while it is open"
        );

        let seen = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
        let stages = seen.clone();
        let name = db.clone();
        let _hook = Closing::armed(move |stage| {
            stages
                .borrow_mut()
                .push((stage, known(), descriptors_of(&name)));
        });
        drop(store);
        assert_eq!(
            *seen.borrow(),
            [
                // Told that it closes: the moved index is forgotten, the database answers by
                // its name, and SQLite still has the file open.
                (ClosingStage::AboutToClose, (true, false), 1),
                // Closed: no descriptor is left, and the name is listed still.
                (ClosingStage::Closed, (true, false), 0),
            ]
        );
        assert_eq!(known(), (false, false), "and after that nothing is listed");
        std::fs::remove_dir_all(&root).ok();
    }

    /// An opener that fails after SQLite has opened the file lets go in the same order as a
    /// store that is dropped, and leaves nothing listed: the file it could not use is a file
    /// like any other again.
    #[test]
    fn an_opener_that_fails_leaves_nothing_listed() {
        let root = temp_dir("own_db_refused");
        let db = root.join("dedcom.db");
        // A database, but not one of dedcom's: opening it to write is refused once it is read.
        let foreign = rusqlite::Connection::open(&db).unwrap();
        foreign
            .execute_batch("CREATE TABLE notes(body TEXT); INSERT INTO notes VALUES ('kept');")
            .unwrap();
        drop(foreign);
        let file = identity(&std::fs::symlink_metadata(&db).unwrap());

        let seen = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
        let stages = seen.clone();
        let _hook = Closing::armed(move |stage| {
            stages
                .borrow_mut()
                .push((stage, crate::paths::is_open_database_file(file)));
        });
        assert!(
            ScanStore::open_writable(&db).is_err(),
            "the control: not a database dedcom opens"
        );
        assert_eq!(
            *seen.borrow(),
            [
                (ClosingStage::AboutToClose, true),
                (ClosingStage::Closed, true)
            ],
            "it went the way a store goes"
        );
        assert!(
            !crate::paths::is_open_database_file(file),
            "nothing is listed afterwards"
        );
        open_regular_nofollow(&db).expect("and the file is read like any other");
        std::fs::remove_dir_all(&root).ok();
    }

    /// The manual quotes what a refused read is told.
    #[test]
    fn the_manual_quotes_the_refusal() {
        assert!(
            crate::testfixtures::manual("07-scanning.md").contains(OPEN_DATABASE_REFUSAL),
            "07-scanning.md, «Permanent exclusions», must quote: {OPEN_DATABASE_REFUSAL}"
        );
    }
}
