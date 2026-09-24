// SPDX-License-Identifier: Apache-2.0
//! Maintenance of the checkpoint DB: trash cleanup + VACUUM and a deferred
//! auto-VACUUM on an interval. VACUUM rewrites the whole file — on a production 5+ GB DB
//! this is noticeable, so it runs only by the operator, when idle, in the background, or via the
//! explicit command `--compact-db`. Settings and the timestamp live in `<state_dir>/config.json`
//! (alongside `concurrency`); we write additively, without clobbering other fields. What dedcom
//! cannot read there it does not act on, and a file it cannot read it never writes.

use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{Map, Value};

use crate::error::{AppError, Result};
use crate::lock::ConcurrencyPolicy;
use crate::state::ScanStore;

/// Default auto-VACUUM interval, hours (0 — disabled).
pub const DEFAULT_VACUUM_INTERVAL_HOURS: u64 = 120;

const CONFIG_FILE: &str = "config.json";

fn config_path(state_dir: &Path) -> PathBuf {
    state_dir.join(CONFIG_FILE)
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// `config.json` as found, before any setting is taken from it.
enum ConfigFile {
    /// No file: every setting is its default, and recording a VACUUM creates one.
    Missing,
    /// A JSON object; each setting in it is read on its own.
    Object(Map<String, Value>),
    /// There, but nothing can be taken from it — and why. Nothing is decided from it and nothing
    /// is written over it: the operator's settings with a typo in them are still the operator's.
    Unreadable(String),
}

/// The most config.json is read to: it holds a handful of settings.
const CONFIG_LIMIT: u64 = 1 << 20;

/// Reads `config.json` once, whole. Any failure but «there is no file» is `Unreadable`: a file
/// that is there and cannot be read is not a file that is not there. Only a regular file is read,
/// opened without waiting: a FIFO left at the name would hang the run, and a link to a device
/// would be read without end. A link to a regular file is read through, like the file itself.
fn read_config_file(state_dir: &Path) -> ConfigFile {
    use std::io::Read;
    use std::os::unix::fs::OpenOptionsExt;
    let opened = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(config_path(state_dir));
    let file = match opened {
        Ok(file) => file,
        // A link whose file is gone is a name that is there: the settings behind it are not
        // known, and replacing the link would lose them for good when the file comes back.
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return match std::fs::symlink_metadata(config_path(state_dir)) {
                Ok(meta) if meta.file_type().is_symlink() => {
                    ConfigFile::Unreadable("is a symbolic link to a file that is not there".into())
                }
                _ => ConfigFile::Missing,
            };
        }
        Err(err) => return ConfigFile::Unreadable(format!("cannot be read ({err})")),
    };
    match file.metadata() {
        Ok(meta) if meta.is_file() => {}
        Ok(_) => return ConfigFile::Unreadable("is not a regular file".into()),
        Err(err) => return ConfigFile::Unreadable(format!("cannot be read ({err})")),
    }
    let mut bytes = Vec::new();
    if let Err(err) = file.take(CONFIG_LIMIT + 1).read_to_end(&mut bytes) {
        return ConfigFile::Unreadable(format!("cannot be read ({err})"));
    }
    if bytes.len() as u64 > CONFIG_LIMIT {
        return ConfigFile::Unreadable("is larger than 1 MiB".into());
    }
    match serde_json::from_slice(&bytes) {
        Ok(Value::Object(settings)) => ConfigFile::Object(settings),
        Ok(_) => ConfigFile::Unreadable("is not a JSON object".into()),
        Err(err) => ConfigFile::Unreadable(format!("is not valid JSON ({err})")),
    }
}

/// Why a setting cannot be used.
enum Unusable {
    /// The file as a whole.
    File(String),
    /// One field holds something other than what it has to be.
    Field {
        key: &'static str,
        kind: &'static str,
    },
}

impl Unusable {
    /// The reason, naming the file as `file`.
    fn describe(&self, file: &str) -> String {
        match self {
            Unusable::File(why) => format!("{file} {why}"),
            Unusable::Field { key, kind } => format!("\"{key}\" in {file} is not {kind}"),
        }
    }
}

/// One setting, read on its own: `None` when there is no file, no such field, or `null`.
fn setting<T>(
    file: &ConfigFile,
    key: &'static str,
    kind: &'static str,
    take: impl Fn(&Value) -> Option<T>,
) -> std::result::Result<Option<T>, Unusable> {
    match file {
        ConfigFile::Missing => Ok(None),
        ConfigFile::Unreadable(why) => Err(Unusable::File(why.clone())),
        ConfigFile::Object(settings) => match settings.get(key) {
            None | Some(Value::Null) => Ok(None),
            Some(value) => take(value).map(Some).ok_or(Unusable::Field { key, kind }),
        },
    }
}

fn interval_setting(file: &ConfigFile) -> std::result::Result<Option<u64>, Unusable> {
    setting(
        file,
        "vacuum_interval_hours",
        "a whole number of hours, written without quotes or a decimal point, such as 120",
        Value::as_u64,
    )
}

fn last_vacuum_setting(file: &ConfigFile) -> std::result::Result<Option<i64>, Unusable> {
    setting(
        file,
        "last_vacuum",
        "a unix time in whole seconds, written without quotes, such as 1716800000",
        Value::as_i64,
    )
}

fn history_keep_setting(file: &ConfigFile) -> std::result::Result<Option<usize>, Unusable> {
    setting(
        file,
        "history_keep",
        "a whole number, written without quotes or a decimal point, such as 2",
        |value| value.as_u64().and_then(|keep| usize::try_from(keep).ok()),
    )
}

fn concurrency_setting(file: &ConfigFile) -> std::result::Result<Option<String>, Unusable> {
    setting(
        file,
        "concurrency",
        "one of ask, allow, readonly and block",
        |value| {
            value
                .as_str()
                .filter(|policy| ConcurrencyPolicy::from_str_opt(policy).is_some())
                .map(str::to_string)
        },
    )
}

/// The lock policy config.json names. Whatever it cannot give — no file, no field, a file or a
/// value that cannot be read — is the default `ask`, never `allow` by accident.
pub fn concurrency_policy(state_dir: &Path) -> ConcurrencyPolicy {
    concurrency_setting(&read_config_file(state_dir))
        .ok()
        .flatten()
        .as_deref()
        .and_then(ConcurrencyPolicy::from_str_opt)
        .unwrap_or_default()
}

/// Whether auto-VACUUM is due. Everything it needs has to be read first: on a large database a
/// VACUUM takes minutes, and one nobody can say was wanted is not started.
fn auto_vacuum_due(file: &ConfigFile, now: i64) -> std::result::Result<bool, Unusable> {
    let interval = interval_setting(file)?.unwrap_or(DEFAULT_VACUUM_INTERVAL_HOURS);
    if interval == 0 {
        return Ok(false);
    }
    Ok(vacuum_due(interval, last_vacuum_setting(file)?, now))
}

/// Whether auto-VACUUM is due: interval>0 and enough time has passed since last time. A pure
/// function of its inputs — testable without a filesystem.
pub fn vacuum_due(interval_hours: u64, last_vacuum: Option<i64>, now: i64) -> bool {
    if interval_hours == 0 {
        return false;
    }
    // Saturating: an interval too long to count in seconds is one that has not passed yet.
    let interval = i64::try_from(interval_hours.saturating_mul(3600)).unwrap_or(i64::MAX);
    match last_vacuum {
        None => true,
        Some(last) => now.saturating_sub(last) >= interval,
    }
}

/// Decides from config.json whether auto-VACUUM is due now.
pub fn should_auto_vacuum(state_dir: &Path) -> bool {
    match auto_vacuum_due(&read_config_file(state_dir), now_unix()) {
        Ok(due) => due,
        Err(why) => {
            tracing::warn!("auto-VACUUM skipped: {}", why.describe(CONFIG_FILE));
            false
        }
    }
}

/// Default retention: how many of the newest completed scans of the same roots to keep active.
pub const DEFAULT_HISTORY_KEEP: usize = 2;

/// History limit for the same roots from config.json: the newest `keep`
/// completed ones stay, the rest go to the trash on a fresh Complete. `Err` with the reason when
/// the limit cannot be read — then nothing is trimmed: the number the operator meant is not
/// known, and the default could send scans that were meant to stay to the trash.
pub fn history_keep(state_dir: &Path) -> std::result::Result<usize, String> {
    history_keep_setting(&read_config_file(state_dir))
        .map(|keep| keep.unwrap_or(DEFAULT_HISTORY_KEEP))
        .map_err(|why| why.describe(CONFIG_FILE))
}

/// What the lock policy is when config.json cannot give one.
const DEFAULT_POLICY: &str =
    "the lock policy is the default \"ask\" (without the interface: refuse while another instance \
     holds the lock)";

/// What a writing mode tells the operator about config.json, once, before the interface takes
/// the terminal: the settings this run will not use, and what it does instead. Empty when every
/// one of them can be read.
pub fn config_warnings(state_dir: &Path) -> Vec<String> {
    let shown = crate::textsan::terminal(&config_path(state_dir).display().to_string());
    let file = read_config_file(state_dir);
    if let ConfigFile::Unreadable(why) = &file {
        return vec![format!(
            "{} — its settings are not used: no automatic VACUUM, no history trimming, and \
             {DEFAULT_POLICY}. The file is left as it is.",
            Unusable::File(why.clone()).describe(&shown)
        )];
    }
    // The VACUUM line comes from the decision itself, so a `last_vacuum` that nothing needs —
    // the interval is 0 — is not named.
    let vacuum = auto_vacuum_due(&file, now_unix()).err().map(|why| {
        let until = match &why {
            Unusable::Field {
                key: "last_vacuum", ..
            } => "until it is fixed or --compact-db records a new time",
            _ => "until it is fixed",
        };
        format!("{} — no automatic VACUUM {until}", why.describe(&shown))
    });
    let history = history_keep_setting(&file).err().map(|why| {
        format!(
            "{} — no history trimming until it is fixed",
            why.describe(&shown)
        )
    });
    let policy = concurrency_setting(&file)
        .err()
        .map(|why| format!("{} — {DEFAULT_POLICY}", why.describe(&shown)));
    [vacuum, history, policy].into_iter().flatten().collect()
}

/// Writes the last-VACUUM timestamp to config.json, keeping every other field as it was — one
/// dedcom cannot use included: it is still the operator's. A file it cannot read is left exactly
/// as it is: the VACUUM is done, only its time goes unrecorded.
fn record_vacuum(state_dir: &Path) -> Result<()> {
    let mut settings = match read_config_file(state_dir) {
        ConfigFile::Missing => Map::new(),
        ConfigFile::Object(settings) => settings,
        ConfigFile::Unreadable(why) => {
            tracing::warn!(
                "VACUUM done, its time not recorded: {}",
                Unusable::File(why).describe(CONFIG_FILE)
            );
            return Ok(());
        }
    };
    settings.insert("last_vacuum".into(), now_unix().into());
    replace_config(
        state_dir,
        serde_json::to_string_pretty(&settings)?.as_bytes(),
    )
}

/// Replaces config.json whole: a new file beside it, flushed, then renamed over the name. A crash
/// leaves the old file or the new one, never half of either — and half a file would stay that
/// way, since one that does not parse is never rewritten. The rename replaces the name itself: a
/// link left there is replaced as well, and whatever it points at is never written through.
fn replace_config(state_dir: &Path, text: &[u8]) -> Result<()> {
    let failed = |err: std::io::Error| {
        AppError::msg(format!(
            "cannot write {CONFIG_FILE} in {}: {err}",
            crate::textsan::terminal(&state_dir.display().to_string())
        ))
    };
    let dir = crate::paths::DirHandle::open(state_dir).map_err(failed)?;
    let (temp, mut file) = claim_temp(&dir, &temp_base()).map_err(failed)?;
    let name = OsStr::new(CONFIG_FILE);
    let was_link = dir.is_symlink_at(name).unwrap_or(false);
    let replaced = file
        .write_all(text)
        .and_then(|()| file.sync_data())
        .and_then(|()| dir.rename(&temp, name));
    if replaced.is_err() {
        // Ours: `claim_temp` created it a moment ago.
        let _ = dir.remove_file(&temp);
    } else if was_link {
        tracing::warn!(
            "{CONFIG_FILE} was a symbolic link; it is now a file of its own with the same \
             settings, and what the link pointed at is left as it was"
        );
    }
    replaced.map_err(failed)
}

/// The name of the new file `replace_config` writes, before `.tmp`: the pid and the time keep it
/// apart from one a run that died halfway left behind — under the same pid, which a container
/// gives every run.
fn temp_base() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|since| since.as_nanos())
        .unwrap_or(0);
    format!(".{CONFIG_FILE}.{}-{nanos}", std::process::id())
}

/// Creates that file under a name nothing else holds: `O_EXCL` claims it, and a name already
/// taken is stepped over rather than failed on.
fn claim_temp(dir: &crate::paths::DirHandle, base: &str) -> std::io::Result<(OsString, File)> {
    let mut attempt = 0u32;
    loop {
        let name = OsString::from(match attempt {
            0 => format!("{base}.tmp"),
            _ => format!("{base}-r{attempt}.tmp"),
        });
        match dir.create_new_file(&name) {
            Ok(file) => return Ok((name, file)),
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists && attempt < 1_000 => {
                attempt += 1;
            }
            Err(err) => return Err(err),
        }
    }
}

/// `--compact-db`: clears the trash (purge of all trashed) and compacts the DB (VACUUM).
/// Returns (number of purged sessions, size before, size after) in bytes.
pub fn compact(db_path: &Path, state_dir: &Path) -> Result<(usize, u64, u64)> {
    let before = file_size(db_path);
    let purged = {
        let mut store = ScanStore::open(db_path)?;
        let trashed = store.list_trashed()?;
        for info in &trashed {
            store.purge_scan(info.scan_id)?;
        }
        store.vacuum()?;
        trashed.len()
    };
    record_vacuum(state_dir)?;
    Ok((purged, before, file_size(db_path)))
}

/// VACUUM only (deferred auto-mode) + timestamp. Does not touch the trash.
pub fn vacuum_only(db_path: &Path, state_dir: &Path) -> Result<()> {
    {
        let store = ScanStore::open(db_path)?;
        store.vacuum()?;
    }
    record_vacuum(state_dir)
}

/// DB size on disk: main file + WAL — the single source for
/// `--stats` and the F12 header.
pub fn db_size_bytes(db_path: &Path) -> u64 {
    // From the bytes: `display()` would name another file when the state directory is not UTF-8.
    let mut wal = db_path.as_os_str().to_os_string();
    wal.push("-wal");
    file_size(db_path) + file_size(Path::new(&wal))
}

fn file_size(path: &Path) -> u64 {
    std::fs::metadata(path).map(|m| m.len()).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn off_when_interval_zero() {
        assert!(!vacuum_due(0, None, 1_000_000));
        assert!(!vacuum_due(0, Some(0), 1_000_000));
    }

    /// The size counts the log beside the database under the database's own bytes: in a state
    /// directory whose name is not UTF-8, `--stats` used to look for the log under another name
    /// and count it as nothing.
    #[test]
    fn the_size_counts_the_log_in_a_directory_that_is_not_utf8() {
        use std::os::unix::ffi::OsStrExt;
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|since| since.as_nanos())
            .unwrap_or(0);
        let base =
            std::env::temp_dir().join(format!("dedcom_maint_wal_{}_{nanos}", std::process::id()));
        let dir = base.join(std::ffi::OsStr::from_bytes(b"st\xffate"));
        std::fs::create_dir_all(&dir).unwrap();
        let db = dir.join("dedcom.db");
        std::fs::write(&db, [0u8; 100]).unwrap();
        std::fs::write(dir.join("dedcom.db-wal"), [0u8; 1000]).unwrap();
        let size = db_size_bytes(&db);
        std::fs::remove_dir_all(&base).ok();
        assert_eq!(size, 1100);
    }

    /// Retention runs unasked on every completed scan, so the number it keeps is a promise about
    /// the user's sessions — and a default that only the code knows is a default nobody agreed to.
    #[test]
    fn the_manual_states_the_retention_default_the_code_uses() {
        let configured = format!("\"history_keep\": {DEFAULT_HISTORY_KEEP}");
        assert!(
            crate::testfixtures::manual("12-maintenance.md").contains(&configured),
            "12-maintenance.md must show the default as {configured}"
        );

        let stated = format!("(default: {DEFAULT_HISTORY_KEEP})");
        assert!(
            crate::testfixtures::manual("10-diff-trash.md").contains(&stated),
            "10-diff-trash.md must name the retention default as {stated}"
        );
    }

    /// The backup and restore scripts in §12 exist for the way back to a build that wrote an older
    /// schema, so the number they compare with is the schema this build writes. Pinned to the
    /// constant: a schema bump the manual did not follow fails here, not on a user's upgrade.
    #[test]
    fn the_manual_backup_scripts_accept_every_schema_before_the_current_one() {
        let chapter = crate::testfixtures::manual("12-maintenance.md");
        let check = format!("[ \"$V\" -lt {} ]", crate::state::schema::SCHEMA_VERSION);
        for script in ["# backup-dedcom-db.sh", "# restore-dedcom-db.sh"] {
            let body = chapter
                .lines()
                .skip_while(|line| !line.starts_with(script))
                .take_while(|line| !line.starts_with("```"))
                .collect::<Vec<_>>()
                .join("\n");
            assert!(!body.is_empty(), "12-maintenance.md has no {script}");
            assert_eq!(
                body.matches(&check).count(),
                1,
                "{script} must compare the schema as {check} exactly once"
            );
            let fixed = body
                .match_indices("\" = ")
                .any(|(at, sep)| body[at + sep.len()..].starts_with(|c: char| c.is_ascii_digit()));
            assert!(
                !fixed,
                "{script} must not compare the schema with a fixed number"
            );
        }
    }

    #[test]
    fn due_when_never_run() {
        assert!(vacuum_due(120, None, 1_000_000));
    }

    #[test]
    fn due_only_after_full_interval() {
        let last = 1_000_000i64;
        let hour = 3600;
        assert!(!vacuum_due(120, Some(last), last + 119 * hour));
        assert!(vacuum_due(120, Some(last), last + 120 * hour));
    }

    use crate::state::store::role_guard;
    use crate::testfixtures::ScratchDir;

    /// The operator's settings with one stray comma: nothing in it can be read.
    const BROKEN: &[u8] =
        b"{\n  \"concurrency\": \"block\",\n  \"vacuum_interval_hours\": 0,\n  \"history_keep\": 7,\n}\n";

    fn state_with_config(tag: &str, config: &[u8]) -> ScratchDir {
        let dir = ScratchDir::new(tag);
        std::fs::write(dir.path().join("config.json"), config).unwrap();
        dir
    }

    /// A state directory with a database of ours in it, for the two paths that run a VACUUM.
    fn with_checkpoint(dir: &ScratchDir) -> PathBuf {
        let db = dir.path().join("dedcom.db");
        drop(ScanStore::open(&db).unwrap());
        db
    }

    fn compact_db(db: &Path, state: &Path) -> Result<()> {
        compact(db, state).map(|_| ())
    }

    type VacuumRun = fn(&Path, &Path) -> Result<()>;

    const BOTH_VACUUMS: [(&str, VacuumRun); 2] =
        [("auto-VACUUM", vacuum_only), ("--compact-db", compact_db)];

    /// Recording a VACUUM used to replace a file it could not parse with `{"last_vacuum": …}`:
    /// every other setting gone, and no copy kept. Now the file is left exactly as it is.
    #[test]
    fn a_vacuum_leaves_a_config_that_does_not_parse_as_it_is() {
        let _role = role_guard();
        for (run, vacuum) in BOTH_VACUUMS {
            let dir = state_with_config("maint-broken-vacuum", BROKEN);
            let db = with_checkpoint(&dir);
            vacuum(&db, dir.path()).unwrap_or_else(|err| panic!("{run}: the VACUUM runs: {err}"));
            assert_eq!(
                std::fs::read(dir.path().join("config.json")).unwrap(),
                BROKEN,
                "{run} rewrote a config.json it could not parse"
            );
        }
    }

    /// What decides the automatic VACUUM has to be read before one is started: on a large
    /// database it takes minutes. A file that does not parse used to read as «never vacuumed, every
    /// 120 hours» — even when the operator had turned it off with 0.
    #[test]
    fn no_automatic_vacuum_on_settings_that_cannot_be_read() {
        for (tag, config) in [
            ("broken with 0", BROKEN),
            ("broken", &b"{\"history_keep\": 3,}"[..]),
            (
                "0 beside a bad time",
                br#"{"vacuum_interval_hours": 0, "last_vacuum": "yesterday"}"#,
            ),
            ("interval as text", br#"{"vacuum_interval_hours": "0"}"#),
            ("negative interval", br#"{"vacuum_interval_hours": -1}"#),
            (
                "bad time",
                br#"{"vacuum_interval_hours": 120, "last_vacuum": "yesterday"}"#,
            ),
            ("not an object", b"[]"),
        ] {
            let dir = state_with_config("maint-unreadable-auto", config);
            assert!(
                !should_auto_vacuum(dir.path()),
                "{tag}: an automatic VACUUM was due"
            );
        }
    }

    /// What a readable file says still holds, one setting at a time: no file and `null` are the
    /// defaults, and recording a VACUUM keeps every other field as it was.
    #[test]
    fn readable_settings_still_decide() {
        let _role = role_guard();
        let none = ScratchDir::new("maint-no-config");
        assert!(
            should_auto_vacuum(none.path()),
            "no file: never vacuumed, so due"
        );
        let null = state_with_config("maint-null-interval", br#"{"vacuum_interval_hours": null}"#);
        assert!(
            should_auto_vacuum(null.path()),
            "null is the default interval"
        );
        let off = state_with_config("maint-off", br#"{"vacuum_interval_hours": 0}"#);
        assert!(!should_auto_vacuum(off.path()), "0 is off");

        let db = with_checkpoint(&none);
        vacuum_only(&db, none.path()).unwrap();
        assert!(
            !should_auto_vacuum(none.path()),
            "the VACUUM recorded its time"
        );

        let dir = state_with_config(
            "maint-keep-fields",
            br#"{"concurrency": "block", "history_keep": "5", "vacuum_interval_hours": 1}"#,
        );
        let db = with_checkpoint(&dir);
        vacuum_only(&db, dir.path()).unwrap();
        let settings: serde_json::Value =
            serde_json::from_slice(&std::fs::read(dir.path().join("config.json")).unwrap())
                .unwrap();
        assert_eq!(settings["concurrency"], "block");
        assert_eq!(
            settings["history_keep"], "5",
            "a field dedcom cannot use is kept as written"
        );
        assert_eq!(settings["vacuum_interval_hours"], 1);
        assert!(settings["last_vacuum"].is_i64());
        let left: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .filter(|name| name.to_string_lossy().starts_with(".config.json"))
            .collect();
        assert!(left.is_empty(), "the replacement left {left:?} behind");
    }

    /// A config.json that is there but cannot be read is not a config.json that is not there.
    #[test]
    fn a_config_that_cannot_be_read_is_not_a_missing_one() {
        let _role = role_guard();
        let dir = ScratchDir::new("maint-config-dir");
        std::fs::create_dir(dir.path().join("config.json")).unwrap();
        assert!(!should_auto_vacuum(dir.path()));
        assert!(history_keep(dir.path()).is_err());
        let db = with_checkpoint(&dir);
        vacuum_only(&db, dir.path()).expect("the VACUUM runs; only its time goes unrecorded");
        assert!(dir.path().join("config.json").is_dir());
    }

    /// The retention limit, one setting at a time: no file and `null` are the default, a whole
    /// number is taken whatever else the file holds, and anything else is a reason not to trim.
    #[test]
    fn the_history_limit_is_read_or_refused() {
        let none = ScratchDir::new("maint-keep-none");
        assert_eq!(history_keep(none.path()), Ok(DEFAULT_HISTORY_KEEP));
        for (config, expected) in [
            (
                &br#"{"history_keep": null}"#[..],
                Some(DEFAULT_HISTORY_KEEP),
            ),
            (br#"{"history_keep": 0}"#, Some(0)),
            (
                br#"{"history_keep": 5, "last_vacuum": "yesterday"}"#,
                Some(5),
            ),
            (br#"{"history_keep": "5"}"#, None),
            (br#"{"history_keep": 1.5}"#, None),
            (br#"{"history_keep": 2.0}"#, None),
            (br#"{"history_keep": -1}"#, None),
            (BROKEN, None),
        ] {
            let dir = state_with_config("maint-keep", config);
            let read = history_keep(dir.path());
            let shown = String::from_utf8_lossy(config);
            match expected {
                Some(keep) => assert_eq!(read, Ok(keep), "{shown}"),
                None => assert!(read.is_err(), "{shown}: read as {read:?}"),
            }
        }
    }

    /// What the operator is told: the file by its full name, what is wrong, and what this run does
    /// instead. A file that can be read — or no file — says nothing.
    #[test]
    fn the_warning_names_the_file_and_what_is_not_done() {
        assert!(config_warnings(ScratchDir::new("maint-warn-none").path()).is_empty());
        let quiet = state_with_config(
            "maint-warn-quiet",
            br#"{"history_keep": 3, "vacuum_interval_hours": 0, "concurrency": "block"}"#,
        );
        assert!(config_warnings(quiet.path()).is_empty());

        let broken = state_with_config("maint-warn-broken", BROKEN);
        let file = broken.path().join("config.json").display().to_string();
        assert_eq!(
            config_warnings(broken.path()),
            vec![format!(
                "{file} is not valid JSON (trailing comma at line 5 column 1) — its settings are \
                 not used: no automatic VACUUM, no history trimming, and the lock policy is the \
                 default \"ask\" (without the interface: refuse while another instance holds the \
                 lock). The file is left as it is."
            )]
        );

        let fields = state_with_config(
            "maint-warn-fields",
            br#"{"history_keep": "5", "vacuum_interval_hours": -1, "last_vacuum": "yesterday",
                 "concurrency": "alow"}"#,
        );
        let file = fields.path().join("config.json").display().to_string();
        assert_eq!(
            config_warnings(fields.path()),
            vec![
                format!(
                    "\"vacuum_interval_hours\" in {file} is not a whole number of hours, written \
                     without quotes or a decimal point, such as 120 — no automatic VACUUM until \
                     it is fixed"
                ),
                format!(
                    "\"history_keep\" in {file} is not a whole number, written without quotes or \
                     a decimal point, such as 2 — no history trimming until it is fixed"
                ),
                format!(
                    "\"concurrency\" in {file} is not one of ask, allow, readonly and block — the \
                     lock policy is the default \"ask\" (without the interface: refuse while \
                     another instance holds the lock)"
                ),
            ]
        );

        let time = state_with_config(
            "maint-warn-time",
            br#"{"vacuum_interval_hours": 120, "last_vacuum": 1716800000.5}"#,
        );
        let file = time.path().join("config.json").display().to_string();
        assert_eq!(
            config_warnings(time.path()),
            vec![format!(
                "\"last_vacuum\" in {file} is not a unix time in whole seconds, written without \
                 quotes, such as 1716800000 — no automatic VACUUM until it is fixed or \
                 --compact-db records a new time"
            )]
        );
        let off = state_with_config(
            "maint-warn-off",
            br#"{"vacuum_interval_hours": 0, "last_vacuum": "yesterday"}"#,
        );
        assert!(
            config_warnings(off.path()).is_empty(),
            "with the interval at 0 nothing needs the time"
        );
    }

    /// The file is named in the warning as the terminal will show it: a state directory whose name
    /// carries an escape sequence does not get to drive the terminal through it.
    #[test]
    fn the_warning_escapes_the_path_it_names() {
        let dir = state_with_config("maint-warn-\u{1b}[2J", BROKEN);
        let said = config_warnings(dir.path());
        assert_eq!(said.len(), 1);
        assert!(!said[0].contains('\u{1b}'), "{said:?}");
    }

    /// A FIFO or a device left at the name is not read: opening waits for nothing, and a device
    /// is not taken for settings. Nor is a file larger than any config.json dedcom writes.
    #[test]
    fn a_config_that_is_not_a_regular_file_is_not_read() {
        let dir = ScratchDir::new("maint-config-device");
        std::os::unix::fs::symlink("/dev/null", dir.path().join("config.json")).unwrap();
        assert!(!should_auto_vacuum(dir.path()));
        let said = config_warnings(dir.path());
        assert!(
            said[0].contains("config.json is not a regular file"),
            "{said:?}"
        );

        let mut huge = b"{\"history_keep\": 7}".to_vec();
        huge.resize(usize::try_from(CONFIG_LIMIT).unwrap() + 1, b' ');
        let dir = state_with_config("maint-config-huge", &huge);
        assert!(history_keep(dir.path()).is_err());
        let said = config_warnings(dir.path());
        assert!(
            said[0].contains("config.json is larger than 1 MiB"),
            "{said:?}"
        );
    }

    /// A link whose file is gone — a volume not mounted, a state directory moved to another host —
    /// is a name that is there, not a missing file: nothing is decided from defaults, and the link
    /// stays, so the settings come back with the file.
    #[test]
    fn a_link_to_a_file_that_is_gone_is_not_a_missing_config() {
        let _role = role_guard();
        let dir = ScratchDir::new("maint-config-dangling");
        let gone = dir.path().join("elsewhere").join("config.json");
        std::os::unix::fs::symlink(&gone, dir.path().join("config.json")).unwrap();
        assert!(!should_auto_vacuum(dir.path()));
        assert!(history_keep(dir.path()).is_err());
        let said = config_warnings(dir.path());
        assert!(
            said[0].contains("config.json is a symbolic link to a file that is not there"),
            "{said:?}"
        );
        let db = with_checkpoint(&dir);
        vacuum_only(&db, dir.path()).expect("the VACUUM runs; only its time goes unrecorded");
        let link = std::fs::symlink_metadata(dir.path().join("config.json")).unwrap();
        assert!(link.file_type().is_symlink(), "the link was replaced");

        std::fs::create_dir(dir.path().join("elsewhere")).unwrap();
        std::fs::write(
            &gone,
            br#"{"history_keep": 10, "vacuum_interval_hours": 0}"#,
        )
        .unwrap();
        assert_eq!(
            history_keep(dir.path()),
            Ok(10),
            "the file is back, and so are its settings"
        );
        assert!(!should_auto_vacuum(dir.path()));
    }

    /// The lock policy is read by the same reader, so what the warning says is what the lock does:
    /// a file that cannot be read never yields `allow`, not even from an array `serde` would once
    /// have taken for the settings.
    #[test]
    fn the_lock_policy_comes_from_the_same_reader() {
        for (config, policy) in [
            (
                &br#"{"concurrency": "ALLOW"}"#[..],
                ConcurrencyPolicy::Allow,
            ),
            (br#"{"concurrency": "block"}"#, ConcurrencyPolicy::Block),
            (br#"["allow"]"#, ConcurrencyPolicy::Ask),
            (br#"{"concurrency": "alow"}"#, ConcurrencyPolicy::Ask),
            (br#"{"concurrency": 5}"#, ConcurrencyPolicy::Ask),
            (BROKEN, ConcurrencyPolicy::Ask),
        ] {
            let dir = state_with_config("maint-policy", config);
            assert_eq!(
                crate::lock::load_policy(dir.path()),
                policy,
                "{}",
                String::from_utf8_lossy(config)
            );
        }
    }

    /// An interval too long to count in seconds is one that has not passed: no overflow, no
    /// VACUUM on every start.
    #[test]
    fn a_huge_interval_is_never_due() {
        assert!(!vacuum_due(u64::MAX, Some(0), i64::MAX - 1));
        assert!(!vacuum_due(u64::MAX / 2, Some(1_000_000), 2_000_000_000));
    }

    /// A file left behind by a run that died between writing and renaming — under the name that
    /// run would have used, the one a container gives every run — does not stop the time of the
    /// next VACUUM from being recorded.
    #[test]
    fn a_leftover_temporary_file_does_not_stop_the_time_being_recorded() {
        let _role = role_guard();
        let dir = ScratchDir::new("maint-leftover-temp");
        let leftover = dir
            .path()
            .join(format!(".config.json.{}.tmp", std::process::id()));
        std::fs::write(&leftover, b"half").unwrap();
        let db = with_checkpoint(&dir);
        vacuum_only(&db, dir.path()).expect("the time is recorded");
        assert!(
            !should_auto_vacuum(dir.path()),
            "the VACUUM recorded its time"
        );
    }

    /// The name of the new file steps over names already taken rather than failing on them.
    #[test]
    fn the_new_file_steps_over_names_already_taken() {
        let dir = ScratchDir::new("maint-claim");
        std::fs::write(dir.path().join("x.1-2.tmp"), b"").unwrap();
        std::fs::write(dir.path().join("x.1-2-r1.tmp"), b"").unwrap();
        let handle = crate::paths::DirHandle::open(dir.path()).unwrap();
        let (name, _) = claim_temp(&handle, "x.1-2").unwrap();
        assert_eq!(name, "x.1-2-r2.tmp");
    }

    /// A replacement that fails takes its new file away with it: the directory holds what it held.
    #[test]
    fn a_failed_replacement_leaves_no_new_file_behind() {
        let dir = ScratchDir::new("maint-failed-replace");
        std::fs::create_dir(dir.path().join("config.json")).unwrap();
        std::fs::write(dir.path().join("config.json").join("inside"), b"").unwrap();
        assert!(
            replace_config(dir.path(), b"{}").is_err(),
            "a file cannot replace a directory"
        );
        let left: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert_eq!(left, ["config.json"]);
    }

    /// The time of a VACUUM is written by replacing the file, never through it: a link left at
    /// `config.json` becomes a file of dedcom's own, and what it pointed at keeps its bytes.
    #[test]
    fn recording_a_vacuum_never_writes_through_a_link() {
        let _role = role_guard();
        let dir = ScratchDir::new("maint-config-link");
        let elsewhere = dir.path().join("elsewhere.json");
        let theirs = br#"{"history_keep": 7}"#;
        std::fs::write(&elsewhere, theirs).unwrap();
        std::os::unix::fs::symlink(&elsewhere, dir.path().join("config.json")).unwrap();
        let db = with_checkpoint(&dir);
        vacuum_only(&db, dir.path()).unwrap();
        assert_eq!(
            std::fs::read(&elsewhere).unwrap(),
            theirs,
            "the link's target was written"
        );
        let config = dir.path().join("config.json");
        assert!(!std::fs::symlink_metadata(&config)
            .unwrap()
            .file_type()
            .is_symlink());
        let settings: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&config).unwrap()).unwrap();
        assert_eq!(
            settings["history_keep"], 7,
            "the settings read through the link are kept"
        );
        assert!(settings["last_vacuum"].is_i64());
    }
}
