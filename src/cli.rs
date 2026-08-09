// SPDX-License-Identifier: Apache-2.0
use std::path::PathBuf;

/// Parsed command-line arguments.
#[derive(Debug, Clone, Default)]
pub struct Cli {
    /// Override the state directory (checkpoint DB + log).
    pub state_dir: Option<PathBuf>,
    /// Start a fresh scan, ignoring the saved checkpoint.
    pub no_resume: bool,
    /// Add a byte-by-byte comparison after hashing.
    pub verify: bool,
    /// Strict re-validation before a destructive action (`--strict-verify`): re-hash
    /// both target AND keeper before EVERY action. The default is Hybrid (keeper is read
    /// once per batch; changes within the batch are caught by re-stat).
    pub strict_verify: bool,
    /// Purge the quarantine and exit (no TUI).
    pub purge_quarantine: bool,
    /// Confirm a destructive headless operation non-interactively (`--yes`).
    /// Required for `--purge-quarantine`: without it the size is printed and the program
    /// exits WITHOUT deleting (gated by a flag, not stdin — headless is pipe-safe).
    pub assume_yes: bool,
    /// Roots for headless scanning (the `--scan` flag, repeatable).
    /// If non-empty, the no-TUI mode is started.
    pub scan_roots: Vec<PathBuf>,
    /// Export the published duplicate groups of the newest active scan to CSV and exit.
    /// The scan has to be finished: an unfinished newest scan is a refusal, never a silent
    /// fallback to an older session.
    pub export_csv: Option<PathBuf>,
    /// Include-filter by extensions for a headless scan (the `--include-ext` flag,
    /// comma-separated list, flag repeatable). Empty — no filter.
    pub include_extensions: Vec<String>,
    /// Manual override of the storage type (`--storage-type hdd|ssd|nvme`).
    pub storage_type: Option<String>,
    /// Show statistics for all scans and exit (`--stats`).
    pub stats: bool,
    /// Disable reuse of hashes from previous scans (`--no-hash-reuse`).
    pub no_hash_reuse: bool,
    /// Force-open the commando multi-pane interface (`--commando`);
    /// it is the default anyway.
    pub force_commando: bool,
    /// Force-open the classic step-by-step wizard (`--classic`).
    pub force_classic: bool,
    /// Open in read-only mode — an observer with no scanning or operations
    /// (`--read-only`); useful for a second window while the operator works.
    pub read_only: bool,
    /// Become the operator even if another instance holds the lock
    /// (`--force`); dangerous — two operators on the same state.
    pub force: bool,
    /// Empty the session trash and compact the DB (VACUUM), then exit (`--compact-db`).
    pub compact_db: bool,
    /// Opt-in streaming-Merkle directory signature (`--merkle-dirs`).
    /// Default = off (top-down `build_dir_groups`); the opt-in enables O(depth) memory.
    /// Persisted in the checkpoint's `ScanConfig.dir_sig_algo` — resume uses the same
    /// algorithm even if the flag is not passed again.
    pub merkle_dirs: bool,
}

impl Cli {
    /// Parse `std::env::args`. `--help` / `--version` print and terminate the process.
    pub fn parse() -> std::result::Result<Cli, String> {
        let mut cli = Cli::default();
        let mut args = std::env::args().skip(1);

        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--state-dir" => {
                    let value = args
                        .next()
                        .ok_or_else(|| "--state-dir requires a path".to_string())?;
                    cli.state_dir = Some(PathBuf::from(value));
                }
                "--scan" => {
                    let value = args
                        .next()
                        .ok_or_else(|| "--scan requires a path".to_string())?;
                    cli.scan_roots.push(PathBuf::from(value));
                }
                "--export-csv" => {
                    let value = args
                        .next()
                        .ok_or_else(|| "--export-csv requires a path".to_string())?;
                    cli.export_csv = Some(PathBuf::from(value));
                }
                "--include-ext" => {
                    let value = args
                        .next()
                        .ok_or_else(|| "--include-ext requires a list of extensions".to_string())?;
                    for ext in value.split(',') {
                        let ext = ext.trim().trim_start_matches('.').to_ascii_lowercase();
                        if !ext.is_empty() {
                            cli.include_extensions.push(ext);
                        }
                    }
                }
                "--storage-type" => {
                    let value = args.next().ok_or_else(|| {
                        "--storage-type requires a value (hdd|ssd|nvme)".to_string()
                    })?;
                    cli.storage_type = Some(value.trim().to_ascii_lowercase());
                }
                "--stats" => cli.stats = true,
                "--no-hash-reuse" => cli.no_hash_reuse = true,
                "--commando" => cli.force_commando = true,
                "--classic" => cli.force_classic = true,
                "--read-only" => cli.read_only = true,
                "--force" => cli.force = true,
                "--compact-db" => cli.compact_db = true,
                "--merkle-dirs" => cli.merkle_dirs = true,
                "--no-resume" => cli.no_resume = true,
                "--verify" => cli.verify = true,
                "--strict-verify" => cli.strict_verify = true,
                "--purge-quarantine" => cli.purge_quarantine = true,
                "--yes" => cli.assume_yes = true,
                "-h" | "--help" => {
                    print_help();
                    std::process::exit(0);
                }
                "-V" | "--version" => {
                    println!("dedcom {}", crate::version());
                    std::process::exit(0);
                }
                other => return Err(format!("unknown argument: {other}")),
            }
        }

        Ok(cli)
    }
}

fn print_help() {
    println!("{}", help_text());
}

/// The help text as a value, so the wording of a contract can be pinned by a test rather than
/// only by review. `--export-csv` is here for exactly that reason: «the last scan» read as if an
/// unfinished newest scan would be skipped in favour of an older finished one, which is not what
/// the export does.
fn help_text() -> String {
    format!(
        "dedcom {} — TUI search for identical files in a ZFS pool

USAGE:
    dedcom [OPTIONS]

OPTIONS:
    --scan <PATH>         Scan a root without the TUI (may be given several times;
                          enables headless mode — for testing the pipeline)
    --state-dir <PATH>    Directory for the checkpoint DB and log
                          (default ~/.local/state/dedcom)
    --no-resume           Start a fresh scan, ignoring the checkpoint
    --verify              Byte-by-byte comparison after hashing
    --strict-verify       Re-validate before an action: re-hash target and keeper
                          every time (default Hybrid — keeper once per batch)
    --purge-quarantine    Purge the quarantine and exit (by default only
                          shows the size; deletes only with the --yes flag)
    --yes                 Confirm deletion for --purge-quarantine
    --export-csv <PATH>   Export the newest active scan's published duplicate groups to
                          CSV and exit; refuses if that scan has not finished
    --include-ext <LIST>  Scan only files with these extensions
                          (comma-separated: jpg,png,gif; flag repeatable)
    --storage-type <TYPE> Storage type for statistics: hdd | ssd | nvme
                          (overrides auto-detection)
    --stats               Show statistics for all scans and exit
    --compact-db          Empty the session trash and compact the DB (VACUUM), then exit
    --no-hash-reuse       Disable the hash cache — re-hash all files
    --merkle-dirs         (opt-in) streaming-Merkle directory signature:
                          O(depth) memory instead of ~2.5 KiB/file. Group membership
                          is identical to the default; per-row hex differs. Persisted
                          in the checkpoint — resume uses the same algorithm.
    --commando            Open the multi-pane interface (default)
    --classic             Open the classic step-by-step wizard
    --read-only           Observer: no scanning or operations (for a 2nd window)
    --force               Become the operator when the lock is held (dangerous)
    -h, --help            Show this help
    -V, --version         Show the version",
        crate::version()
    )
}

#[cfg(test)]
mod help_tests {
    use super::help_text;

    /// The export line states the selection rule the code actually implements.
    #[test]
    fn the_export_line_says_newest_and_says_it_refuses_an_unfinished_scan() {
        let help = help_text();
        let line = help
            .lines()
            .find(|line| line.contains("--export-csv"))
            .expect("the help lists --export-csv");
        assert!(
            line.contains("newest active scan"),
            "the selection rule must be in the help: {line}"
        );
        assert!(
            help.contains("refuses if that scan has not finished"),
            "an unfinished newest scan is a refusal, not a fallback to an older one:\n{help}"
        );
        assert!(
            !help.contains("duplicates of the last scan"),
            "«the last scan» reads as «the last FINISHED scan», which is not the contract"
        );
    }
}
