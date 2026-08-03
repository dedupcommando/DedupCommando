// SPDX-License-Identifier: Apache-2.0
use std::fs::File;
use std::io::{self, Read};
use std::path::Path;

use super::safe_open::open_regular_nofollow;
use crate::error::{AppError, Result};
use crate::model::duplicate::{DuplicateGroup, FileEntry};

const BUFFER_SIZE: usize = 64 * 1024;

/// Byte-for-byte verification of the candidate groups — confirms that files sharing a blake3
/// digest really are identical (protection against a hash collision).
///
/// Every input group is partitioned into ALL byte-equal populations. The first pathname has no
/// privileged truth status: members equal to each other survive independently of member one. A
/// population keeps the input member order, populations appear in the order their
/// representatives were first encountered, and only those with at least two pathnames become
/// groups — whether those pathnames are also at least two allocations stays the decision of
/// `record_file_results`' physical-object accounting alone. Every surviving population keeps
/// the original digest (several populations may share it) and takes `size_bytes` from its own
/// first member; ids are reassigned consecutively across the returned vector.
///
/// A clean unequal comparison is ordinary flow — the member tries the next population or
/// starts its own. Any safe-open or read failure aborts the WHOLE verification with an error
/// naming both compared paths: an explicit `--verify` must prove its result, so a member it
/// cannot read is a failed proof — never «differs», never a silently smaller result.
pub fn verify_groups(groups: Vec<DuplicateGroup>) -> Result<Vec<DuplicateGroup>> {
    let mut verified = Vec::new();
    for group in groups {
        // `populations[i][0]` is the representative every later member is compared against.
        // The scan over representatives keeps the ordinary one-population case at the same
        // n-1 comparisons as before — extra comparisons happen only when the bytes actually
        // split. An empty or singleton input group requires no comparison at all, and an
        // unreadable first member is discovered by the first comparison that needs it.
        let mut populations: Vec<Vec<FileEntry>> = Vec::new();
        for file in group.files {
            let mut placed = None;
            for (index, population) in populations.iter().enumerate() {
                let representative = &population[0];
                if files_equal(&representative.path, &file.path).map_err(|source| {
                    comparison_failure(&representative.path, &file.path, source)
                })? {
                    placed = Some(index);
                    break;
                }
            }
            match placed {
                Some(index) => populations[index].push(file),
                None => populations.push(vec![file]),
            }
        }
        for population in populations {
            if population.len() >= 2 {
                verified.push(DuplicateGroup {
                    id: 0, // reassigned below, consecutively across all surviving populations
                    size_bytes: population[0].size,
                    hash: group.hash.clone(),
                    files: population,
                });
            }
        }
    }
    for (index, group) in verified.iter_mut().enumerate() {
        group.id = index;
    }
    Ok(verified)
}

/// The error of a failed required comparison: names both pathnames (terminal-sanitized — a
/// hostile file name must not reach the terminal raw) and keeps the underlying I/O cause.
fn comparison_failure(a: &Path, b: &Path, source: io::Error) -> AppError {
    AppError::msg(format!(
        "byte verification failed: cannot compare '{}' and '{}': {source}",
        crate::textsan::terminal(&a.display().to_string()),
        crate::textsan::terminal(&b.display().to_string()),
    ))
}

/// Compares the contents of two files byte for byte.
fn files_equal(a: &Path, b: &Path) -> io::Result<bool> {
    let mut file_a = open_regular_nofollow(a)?;
    let mut file_b = open_regular_nofollow(b)?;
    let mut buf_a = [0u8; BUFFER_SIZE];
    let mut buf_b = [0u8; BUFFER_SIZE];

    loop {
        let read_a = read_chunk(&mut file_a, &mut buf_a)?;
        let read_b = read_chunk(&mut file_b, &mut buf_b)?;
        if read_a != read_b {
            return Ok(false);
        }
        if read_a == 0 {
            return Ok(true);
        }
        if buf_a[..read_a] != buf_b[..read_b] {
            return Ok(false);
        }
    }
}

/// Reads into the buffer until it is full or EOF; returns the number of bytes read.
fn read_chunk(file: &mut File, buf: &mut [u8]) -> io::Result<usize> {
    let mut filled = 0;
    while filled < buf.len() {
        let read = file.read(&mut buf[filled..])?;
        if read == 0 {
            break;
        }
        filled += read;
    }
    Ok(filled)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    /// A unique temporary directory (as in pipeline::safe_open::tests) — without tempfile.
    fn temp_dir(tag: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let mut dir = std::env::temp_dir();
        dir.push(format!(
            "dedcom_verify_{tag}_{}_{nanos}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// A member entry with the real manifest identity of an existing regular file.
    fn entry(path: &Path) -> FileEntry {
        use std::os::unix::fs::MetadataExt;
        let meta = std::fs::metadata(path).unwrap();
        FileEntry {
            path: path.to_path_buf(),
            size: meta.size(),
            mtime: meta.mtime(),
            mtime_nsec: meta.mtime_nsec(),
            ctime_sec: meta.ctime(),
            ctime_nsec: meta.ctime_nsec(),
            device: meta.dev(),
            inode: meta.ino(),
            nlink: meta.nlink(),
            is_keeper: false,
            action: None,
        }
    }

    /// A member whose pathname cannot be safely opened; the identity fields play no role in
    /// the byte comparison, so defaults are enough.
    fn unopenable_entry(path: &Path) -> FileEntry {
        FileEntry {
            path: path.to_path_buf(),
            ..FileEntry::default()
        }
    }

    fn group(id: usize, size_bytes: u64, hash: &str, files: Vec<FileEntry>) -> DuplicateGroup {
        DuplicateGroup {
            id,
            size_bytes,
            hash: hash.into(),
            files,
        }
    }

    fn paths(group: &DuplicateGroup) -> Vec<PathBuf> {
        group.files.iter().map(|file| file.path.clone()).collect()
    }

    /// Matrix 1: the ordinary all-equal group survives whole, with the input member order,
    /// the original digest, the population's own size and a reassigned consecutive id — and
    /// the member entries pass through unchanged.
    #[test]
    fn all_equal_group_survives_with_order_and_fields() {
        let dir = temp_dir("all_equal");
        let a = dir.join("a.bin");
        let b = dir.join("b.bin");
        let c = dir.join("c.bin");
        for path in [&a, &b, &c] {
            std::fs::write(path, b"same-bytes").unwrap();
        }

        let input_b = entry(&b);
        let out = verify_groups(vec![group(
            7,
            10,
            "aa11",
            vec![entry(&a), entry(&b), entry(&c)],
        )])
        .unwrap();

        assert_eq!(out.len(), 1);
        assert_eq!(out[0].id, 0, "ids are reassigned consecutively from zero");
        assert_eq!(out[0].hash, "aa11", "the original digest is retained");
        assert_eq!(out[0].size_bytes, 10);
        assert_eq!(paths(&out[0]), vec![a, b, c], "input member order is kept");
        let passed_b = &out[0].files[1];
        assert_eq!(passed_b.size, input_b.size);
        assert_eq!(passed_b.device, input_b.device);
        assert_eq!(
            passed_b.inode, input_b.inode,
            "entries pass through unchanged"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    /// Matrix 2: member A differs while B and C are byte-equal — the B/C population survives
    /// even though A was first. (The parent one-anchor implementation fails exactly this; see
    /// the R4-V1 red evidence.)
    #[test]
    fn later_twins_survive_a_differing_first_member() {
        let dir = temp_dir("twins");
        let a = dir.join("a.bin");
        let b = dir.join("b.bin");
        let c = dir.join("c.bin");
        std::fs::write(&a, b"AAAA").unwrap();
        std::fs::write(&b, b"BBBB").unwrap();
        std::fs::write(&c, b"BBBB").unwrap();

        let out = verify_groups(vec![group(
            3,
            4,
            "beef",
            vec![entry(&a), entry(&b), entry(&c)],
        )])
        .unwrap();

        assert_eq!(out.len(), 1, "the b/c population must survive");
        assert_eq!(paths(&out[0]), vec![b, c]);
        assert_eq!(out[0].id, 0);
        assert_eq!(out[0].hash, "beef");
        assert_eq!(
            out[0].size_bytes, 4,
            "size comes from the population's first member"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    /// Matrix 3: two byte populations under ONE supplied digest become two output groups with
    /// the same digest, each with its own per-population size, in representative
    /// first-encounter order — and ids stay consecutive across the whole returned vector,
    /// including a following group from a different digest.
    #[test]
    fn same_digest_populations_become_two_groups() {
        let dir = temp_dir("split");
        let a1 = dir.join("a1.bin");
        let b1 = dir.join("b1.bin");
        let a2 = dir.join("a2.bin");
        let b2 = dir.join("b2.bin");
        std::fs::write(&a1, b"XXX").unwrap();
        std::fs::write(&b1, b"YYYYY").unwrap();
        std::fs::write(&a2, b"XXX").unwrap();
        std::fs::write(&b2, b"YYYYY").unwrap();
        let e1 = dir.join("e1.bin");
        let e2 = dir.join("e2.bin");
        std::fs::write(&e1, b"EE").unwrap();
        std::fs::write(&e2, b"EE").unwrap();

        // The input size (999) is deliberately wrong: each output size must come from the
        // population's own first member, not from the input aggregate.
        let out = verify_groups(vec![
            group(
                0,
                999,
                "feed",
                vec![entry(&a1), entry(&b1), entry(&a2), entry(&b2)],
            ),
            group(1, 2, "cafe", vec![entry(&e1), entry(&e2)]),
        ])
        .unwrap();

        assert_eq!(out.len(), 3);
        assert_eq!(out[0].hash, "feed");
        assert_eq!(
            out[1].hash, "feed",
            "both populations retain the shared digest"
        );
        assert_eq!(out[2].hash, "cafe");
        assert_eq!(
            paths(&out[0]),
            vec![a1, a2],
            "first-encountered representative first"
        );
        assert_eq!(
            paths(&out[1]),
            vec![b1, b2],
            "input order inside the population"
        );
        assert_eq!(paths(&out[2]), vec![e1, e2]);
        assert_eq!(out[0].size_bytes, 3);
        assert_eq!(out[1].size_bytes, 5);
        assert_eq!(out[2].size_bytes, 2);
        assert_eq!(
            (out[0].id, out[1].id, out[2].id),
            (0, 1, 2),
            "consecutive ids across the complete returned vector"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    /// Matrix 4: a singleton population is discarded without deleting the valid population
    /// from the same input group.
    #[test]
    fn singleton_population_is_discarded_without_the_valid_one() {
        let dir = temp_dir("singleton");
        let a1 = dir.join("a1.bin");
        let a2 = dir.join("a2.bin");
        let b = dir.join("b.bin");
        std::fs::write(&a1, b"XXX").unwrap();
        std::fs::write(&a2, b"XXX").unwrap();
        std::fs::write(&b, b"ZZZZ").unwrap();

        let out = verify_groups(vec![group(
            0,
            3,
            "dada",
            vec![entry(&a1), entry(&a2), entry(&b)],
        )])
        .unwrap();

        assert_eq!(out.len(), 1, "only the two-member population survives");
        assert_eq!(paths(&out[0]), vec![a1, a2]);

        std::fs::remove_dir_all(&dir).ok();
    }

    /// Matrix 5a: a first member that cannot be safely opened fails the whole verification —
    /// discovered naturally by the first comparison that needs it.
    #[test]
    fn unopenable_first_member_is_an_error() {
        let dir = temp_dir("first_bad");
        let b = dir.join("b.bin");
        let c = dir.join("c.bin");
        std::fs::write(&b, b"twin-bytes").unwrap();
        std::fs::write(&c, b"twin-bytes").unwrap();
        let link = dir.join("first.bin");
        std::os::unix::fs::symlink(&b, &link).unwrap();
        // The fixture is not inert: the safe open really rejects the symlink.
        assert!(open_regular_nofollow(&link).is_err());

        let result = verify_groups(vec![group(
            0,
            10,
            "0101",
            vec![unopenable_entry(&link), entry(&b), entry(&c)],
        )]);

        assert!(
            result.is_err(),
            "an unreadable first member must fail the operation, not shrink the result"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    /// Matrix 5b: an unopenable LATER member equally fails the whole verification — here a
    /// pathname that no longer exists.
    #[test]
    fn unopenable_later_member_is_an_error() {
        let dir = temp_dir("later_bad");
        let a = dir.join("a.bin");
        let b = dir.join("b.bin");
        std::fs::write(&a, b"twin-bytes").unwrap();
        std::fs::write(&b, b"twin-bytes").unwrap();
        let missing = dir.join("gone.bin");
        assert!(open_regular_nofollow(&missing).is_err());

        let result = verify_groups(vec![group(
            0,
            10,
            "0202",
            vec![entry(&a), entry(&b), unopenable_entry(&missing)],
        )]);

        assert!(
            result.is_err(),
            "an unreadable later member must fail the operation, not be silently dropped"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    /// Matrix 6 (the one display-inspecting test): the surfaced error names BOTH compared
    /// paths in terminal-sanitized form, leaks no raw control byte from a hostile file name,
    /// and retains the underlying I/O cause.
    #[test]
    fn comparison_failure_is_sanitized_and_keeps_the_io_cause() {
        let dir = temp_dir("sanitize");
        let ok = dir.join("ok.bin");
        std::fs::write(&ok, b"fine").unwrap();
        let bad = dir.join("bad\u{1b}[31m.bin");
        std::os::unix::fs::symlink(&ok, &bad).unwrap();
        let cause = open_regular_nofollow(&bad).unwrap_err().to_string();

        let err = verify_groups(vec![group(
            0,
            4,
            "0303",
            vec![entry(&ok), unopenable_entry(&bad)],
        )])
        .unwrap_err();
        let text = err.to_string();

        assert!(
            text.contains(&crate::textsan::terminal(&ok.display().to_string())),
            "the readable side of the comparison is named: {text}"
        );
        assert!(
            text.contains(&crate::textsan::terminal(&bad.display().to_string())),
            "the failing side is named in sanitized form: {text}"
        );
        assert!(
            !text.contains('\u{1b}'),
            "no raw control byte may reach the terminal: {text:?}"
        );
        assert!(
            text.contains(&cause),
            "the underlying I/O cause is retained: {text} / {cause}"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    /// Matrix 8: two pathnames of ONE allocation (hardlink aliases) compare byte-equal and
    /// pass through this layer — which invents no reclaim or eligibility. Whether the
    /// population is at least two allocations is decided, unchanged, by
    /// `record_file_results`' physical-object accounting (`physical_reclaim`,
    /// `object_count >= 2`), which drops an alias-only group at publication.
    #[test]
    fn hardlink_aliases_pass_through_to_the_physical_object_filter() {
        let dir = temp_dir("aliases");
        let a = dir.join("a.bin");
        std::fs::write(&a, b"alias-bytes").unwrap();
        let a2 = dir.join("a2.bin");
        std::fs::hard_link(&a, &a2).unwrap();

        let out = verify_groups(vec![group(0, 11, "abab", vec![entry(&a), entry(&a2)])]).unwrap();

        assert_eq!(out.len(), 1, "byte-equal aliases survive this layer");
        assert_eq!(paths(&out[0]), vec![a, a2]);
        assert_eq!(
            out[0].files[0].inode, out[0].files[1].inode,
            "one allocation — the publication filter, not verify, is what rejects it"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    /// Empty and singleton INPUT groups produce no output and no artificial I/O: a singleton
    /// with an unopenable pathname still succeeds, because no comparison is required.
    #[test]
    fn empty_and_singleton_input_groups_need_no_io() {
        let dir = temp_dir("no_io");
        let missing = dir.join("gone.bin");
        assert!(open_regular_nofollow(&missing).is_err());

        let out = verify_groups(vec![
            group(0, 0, "0404", Vec::new()),
            group(1, 0, "0505", vec![unopenable_entry(&missing)]),
        ])
        .unwrap();

        assert!(out.is_empty(), "nothing to verify, nothing to emit");

        std::fs::remove_dir_all(&dir).ok();
    }
}
