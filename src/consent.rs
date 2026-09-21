// SPDX-License-Identifier: Apache-2.0
//! Startup disclaimer consent gate: persists the "don't show again"
//! choice and the pure logic for whether to show the notice at startup.
//!
//! The file `<state_dir>/consent.json` stores `{suppressed, disclaimer_version}`.
//! The notice is shown until the user has checked "don't show" for the CURRENT
//! version of the text. When the disclaimer text changes, [`DISCLAIMER_VERSION`]
//! is bumped — and consent is requested again.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Version of the disclaimer TEXT. Bump it on any change to the wording —
/// then a previously given "don't show" stops applying and consent is
/// requested again. Not to be confused with the application version (`VERSION`).
pub const DISCLAIMER_VERSION: u32 = 1;

/// The user's saved decision about the startup notice.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Consent {
    /// The user checked "don't show again at startup".
    pub suppressed: bool,
    /// The text version for which "don't show" was given.
    pub disclaimer_version: u32,
}

/// Path of the consent file: `<state_dir>/consent.json`.
pub fn consent_path(state_dir: &Path) -> PathBuf {
    state_dir.join("consent.json")
}

/// Reads the consent if the file exists and is valid; otherwise `None`.
pub fn load(state_dir: &Path) -> Option<Consent> {
    let json = std::fs::read_to_string(consent_path(state_dir)).ok()?;
    serde_json::from_str(&json).ok()
}

/// Saves the consent to disk. Returns whether it succeeded (like `board.json`).
///
/// `O_NOFOLLOW` and `O_TRUNC` rather than `fs::write`, which is the same primitive without the
/// first flag: this is the same hazard the lock file has, in the same directory. `--state-dir`
/// takes any pathname the operator types, and a link left at `consent.json` would send the
/// truncation to whatever it points at. Every other writer under the state directory already
/// refuses to follow one — the checkpoint (`prepare_db_file`), the logs (`logging::make_writer`),
/// the export temp (`DirHandle::create_new_file`) — and this was the last one that did not.
///
/// Still best-effort: a consent that cannot be written is a notice shown again next time, not a
/// reason to stop, so the refusal comes back as `false` exactly like every other failure here.
pub fn save(state_dir: &Path, consent: &Consent) -> bool {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let path = consent_path(state_dir);
    let Ok(json) = serde_json::to_string_pretty(consent) else {
        return false;
    };
    let opened = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&path);
    match opened {
        Ok(mut file) => file.write_all(json.as_bytes()).is_ok(),
        Err(_) => false,
    }
}

/// Pure display logic: show the notice until "suppressed AND for the current
/// text version" holds.
pub fn should_show_disclaimer(saved: Option<&Consent>, current_version: u32) -> bool {
    match saved {
        Some(c) => !(c.suppressed && c.disclaimer_version == current_version),
        None => true,
    }
}

#[cfg(test)]
mod symlink_tests {
    use super::*;

    /// The consent file is truncated and rewritten in place, so a link left under its name would
    /// empty whatever it points at — the same hazard as the lock file, in the same directory and
    /// reachable by the same `--state-dir` typo. Saving must refuse and leave both alone.
    #[test]
    fn a_symlinked_consent_file_is_not_followed() {
        let dir = std::env::temp_dir().join(format!("dedcom_consent_link_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let victim = dir.join("precious.txt");
        std::fs::write(&victim, b"keep me\n").unwrap();
        std::os::unix::fs::symlink(&victim, consent_path(&dir)).unwrap();

        let saved = save(
            &dir,
            &Consent {
                suppressed: true,
                disclaimer_version: 1,
            },
        );

        assert!(!saved, "saving through a symlink must not report success");
        assert_eq!(
            std::fs::read(&victim).unwrap(),
            b"keep me\n",
            "the link's target must not be truncated"
        );
        assert!(
            std::fs::symlink_metadata(consent_path(&dir))
                .unwrap()
                .file_type()
                .is_symlink(),
            "and the link itself must still be a link"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// And the ordinary case still round-trips, or "refuse everything" would pass the test above.
    #[test]
    fn an_ordinary_consent_file_is_written_and_read_back() {
        let dir = std::env::temp_dir().join(format!("dedcom_consent_ok_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        assert!(save(
            &dir,
            &Consent {
                suppressed: true,
                disclaimer_version: 7,
            }
        ));
        let back = load(&dir).expect("what was just written must read back");
        assert!(back.suppressed);
        assert_eq!(back.disclaimer_version, 7);

        // And a second save replaces it rather than appending to it.
        assert!(save(
            &dir,
            &Consent {
                suppressed: false,
                disclaimer_version: 8,
            }
        ));
        let back = load(&dir).expect("the replacement must read back too");
        assert!(!back.suppressed);
        assert_eq!(back.disclaimer_version, 8);
        let _ = std::fs::remove_dir_all(&dir);
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
            std::env::temp_dir().join(format!("dedcom_consent_test_{}_{}", std::process::id(), n));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn roundtrip_persists_consent() {
        let dir = temp_state_dir();
        let c = Consent {
            suppressed: true,
            disclaimer_version: 3,
        };
        assert!(save(&dir, &c));
        let loaded = load(&dir).expect("the consent must read back");
        assert!(loaded.suppressed);
        assert_eq!(loaded.disclaimer_version, 3);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_absent_is_none() {
        let dir = temp_state_dir();
        assert!(load(&dir).is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn show_when_no_consent_file() {
        assert!(should_show_disclaimer(None, 1));
    }

    #[test]
    fn hidden_when_suppressed_for_current_version() {
        let c = Consent {
            suppressed: true,
            disclaimer_version: 1,
        };
        assert!(!should_show_disclaimer(Some(&c), 1));
    }

    #[test]
    fn shown_again_after_version_bump() {
        let c = Consent {
            suppressed: true,
            disclaimer_version: 1,
        };
        assert!(should_show_disclaimer(Some(&c), 2));
    }

    #[test]
    fn shown_when_not_suppressed() {
        let c = Consent {
            suppressed: false,
            disclaimer_version: 1,
        };
        assert!(should_show_disclaimer(Some(&c), 1));
    }
}
