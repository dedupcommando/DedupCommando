// SPDX-License-Identifier: Apache-2.0
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

use ignore::overrides::OverrideBuilder;
use ignore::WalkBuilder;

use crate::error::{AppError, Result};
use crate::model::scan::ScanConfig;

/// A file discovered during the walk.
pub struct WalkedFile {
    pub path: PathBuf,
    pub size: u64,
    pub mtime: i64,
    /// The sub-second and ctime components of the identity (walk snapshot).
    pub mtime_nsec: i64,
    pub ctime_sec: i64,
    pub ctime_nsec: i64,
    pub device: u64,
    pub inode: u64,
}

/// Walks all roots from `config` and returns the matching files plus the number of files
/// skipped because of a non-UTF8 name.
/// The `.zfs` and quarantine directories are excluded. Aborts on `cancel`.
/// `on_progress` periodically receives (entries scanned, files found).
///
/// **Non-UTF8 guard:** a path that cannot be represented as
/// UTF-8 is skipped. Otherwise `to_string_lossy` would collapse different byte names
/// (`a\xFFb`, `a\xFEb`) into a single `a�b` → silent loss/corruption of the string in the PK
/// `(scan_id, path)`; and a `�`-path read back would miss the
/// real file on the action path. It is safer not to touch such a file at all.
pub fn walk(
    config: &ScanConfig,
    cancel: &AtomicBool,
    mut on_progress: impl FnMut(u64, u64, Option<&Path>),
) -> Result<(Vec<WalkedFile>, u64)> {
    let mut roots = config.roots.iter();
    let first = roots
        .next()
        .ok_or_else(|| AppError::msg("no scan root specified"))?;

    let mut builder = WalkBuilder::new(first);
    for root in roots {
        builder.add(root);
    }
    builder
        .standard_filters(false)
        .hidden(false)
        .follow_links(config.follow_symlinks);

    // Exclusions via Override: a glob with a "!" prefix means "ignore".
    let mut overrides = OverrideBuilder::new("/");
    for glob in &config.exclude_globs {
        overrides
            .add(&format!("!{glob}"))
            .map_err(|err| AppError::msg(format!("invalid glob '{glob}': {err}")))?;
    }
    let overrides = overrides
        .build()
        .map_err(|err| AppError::msg(format!("error building exclusions: {err}")))?;
    builder.overrides(overrides);

    let mut files: Vec<WalkedFile> = Vec::new();
    let mut entries: u64 = 0;
    let mut skipped_non_utf8: u64 = 0;
    for result in builder.build() {
        if entries % 1024 == 0 {
            if cancel.load(Ordering::Relaxed) {
                break;
            }
            on_progress(
                entries,
                files.len() as u64,
                files.last().map(|file| file.path.as_path()),
            );
        }
        entries += 1;

        let entry = match result {
            Ok(entry) => entry,
            Err(_) => continue, // no access / broken link — skip
        };
        match entry.file_type() {
            Some(file_type) if file_type.is_file() => {}
            _ => continue,
        }
        let meta = match entry.metadata() {
            Ok(meta) => meta,
            Err(_) => continue,
        };

        let size = meta.size();
        if size < config.min_size {
            continue;
        }
        if let Some(max) = config.max_size {
            if size > max {
                continue;
            }
        }

        if !config.include_extensions.is_empty() {
            let ext = entry
                .path()
                .extension()
                .and_then(|ext| ext.to_str())
                .map(|ext| ext.to_ascii_lowercase());
            match ext {
                Some(ext) if config.include_extensions.contains(&ext) => {}
                _ => continue,
            }
        }

        // Non-UTF8 guard: skip files whose path cannot be represented
        // as UTF-8 (see the function doc comment). Count it last — after all the
        // other filters, so the counter means "would have made it into the manifest, but the name cannot
        // be saved without loss", not files filtered out by size/extension.
        if entry.path().to_str().is_none() {
            skipped_non_utf8 += 1;
            continue;
        }

        files.push(WalkedFile {
            path: entry.into_path(),
            size,
            mtime: meta.mtime(),
            mtime_nsec: meta.mtime_nsec(),
            ctime_sec: meta.ctime(),
            ctime_nsec: meta.ctime_nsec(),
            device: meta.dev(),
            inode: meta.ino(),
        });
    }

    on_progress(
        entries,
        files.len() as u64,
        files.last().map(|file| file.path.as_path()),
    );
    Ok((files, skipped_non_utf8))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsStr;
    use std::fs;
    use std::os::unix::ffi::OsStrExt;

    fn temp_dir(tag: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let mut dir = std::env::temp_dir();
        dir.push(format!("dedcom_walk_{tag}_{}_{nanos}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// Non-UTF8 guard: a file with a non-UTF8 name is skipped and counted,
    /// a valid one makes it into the manifest.
    #[test]
    fn skips_and_counts_non_utf8_paths() {
        let root = temp_dir("nonutf8");

        let good = root.join("ok.bin");
        fs::write(&good, b"data").unwrap();

        // A name with byte 0xFF — valid UTF-8 cannot be made from it.
        let bad = root.join(OsStr::from_bytes(b"bad\xffname.bin"));
        fs::write(&bad, b"data").unwrap();
        assert!(
            bad.exists(),
            "the FS did not accept the non-UTF8 name — test not applicable"
        );

        let mut config = ScanConfig::new(vec![root.clone()]);
        config.min_size = 0; // don't filter out by size
        config.exclude_globs.clear(); // no default exclusions — determinism

        let cancel = AtomicBool::new(false);
        let (files, skipped) = walk(&config, &cancel, |_, _, _| {}).unwrap();

        assert_eq!(skipped, 1, "exactly one non-UTF8 file must be skipped");
        assert_eq!(
            files.len(),
            1,
            "the valid file must make it into the manifest"
        );
        assert_eq!(
            files[0].path, good,
            "the manifest holds exactly the valid file"
        );

        fs::remove_dir_all(&root).ok();
    }
}
