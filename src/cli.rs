// SPDX-License-Identifier: Apache-2.0
use std::ffi::OsString;
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
    /// Parse the process's arguments. `--help` / `--version` print and terminate the process.
    ///
    /// They are read as `OsString`: `std::env::args` makes a `String` of each one and panics on
    /// the first that is not UTF-8, the program's own name included, and a pathname can be any
    /// bytes. No test can call this — the test harness reads its own arguments as text — so
    /// `clippy.toml` refuses `std::env::args` anywhere in the tree, by its path.
    pub fn parse() -> std::result::Result<Cli, String> {
        Self::parse_from(std::env::args_os().skip(1))
    }

    /// The same over any argument list, so a refusal can be tested.
    fn parse_from(mut args: impl Iterator<Item = OsString>) -> std::result::Result<Cli, String> {
        let mut cli = Cli::default();
        // `--include-ext ""` leaves no extension behind, and is still the flag.
        let mut include_ext_given = false;

        while let Some(arg) = args.next() {
            // Every refusal of bytes that are not UTF-8 spells them the way `Debug` does: the byte
            // itself (`\xFF`) rather than a replacement character, and a control or bidi character
            // escaped.
            let Some(flag) = arg.to_str() else {
                return Err(format!("unknown argument: {arg:?}"));
            };
            match flag {
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
                    // Roots are kept as text with the scan, and the walk leaves out every file
                    // whose path is not UTF-8: by this spelling there would be nothing to find.
                    if value.to_str().is_none() {
                        return Err(format!(
                            "--scan {value:?} is not valid UTF-8. dedcom leaves out every file \
                             whose path is not UTF-8, so nothing under this path could be \
                             scanned. Rename what is not UTF-8 in it, or scan a directory above \
                             that part: its files are then counted under Omissions."
                        ));
                    }
                    cli.scan_roots.push(PathBuf::from(value));
                }
                "--export-csv" => {
                    let value = args
                        .next()
                        .ok_or_else(|| "--export-csv requires a path".to_string())?;
                    // A run writes one file, so the other destination would be dropped — and a
                    // script would read whatever an earlier run left there.
                    if cli.export_csv.is_some() {
                        return Err("--export-csv is given twice, and a run writes one file. \
                                    Run one export after the other."
                            .to_string());
                    }
                    cli.export_csv = Some(PathBuf::from(value));
                }
                "--include-ext" => {
                    include_ext_given = true;
                    let value = args
                        .next()
                        .ok_or_else(|| "--include-ext requires a list of extensions".to_string())?;
                    let value = value.into_string().map_err(|value| {
                        format!(
                            "--include-ext {value:?} is not valid UTF-8, and an extension like \
                             that matches no file: the scan leaves out every name that is not"
                        )
                    })?;
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
                    // The value is stored with the scan and printed back by `--stats`, so it is
                    // one of the three words the help names and nothing else.
                    let Some(value) = value.to_str() else {
                        return Err(format!(
                            "--storage-type takes hdd, ssd or nvme, not {value:?}"
                        ));
                    };
                    let value = value.trim().to_ascii_lowercase();
                    if !matches!(value.as_str(), "hdd" | "ssd" | "nvme") {
                        return Err(format!(
                            "--storage-type takes hdd, ssd or nvme, not «{}»",
                            crate::textsan::terminal(&value)
                        ));
                    }
                    cli.storage_type = Some(value);
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
                other => {
                    return Err(format!(
                        "unknown argument: {}",
                        crate::textsan::terminal(other)
                    ))
                }
            }
        }

        refuse_what_a_run_would_ignore(&cli, include_ext_given)?;
        Ok(cli)
    }
}

/// The flags that each decide what a run does, in the order the help lists them.
const MODES: [&str; 5] = [
    "--scan",
    "--stats",
    "--compact-db",
    "--export-csv",
    "--purge-quarantine",
];

/// A run is one of the five modes, or one of the two interfaces: the Commando interface, or the
/// classic wizard with `--classic`. Two modes in one run, two flags that undo each other, and a
/// flag the run would not read are refused. `main` used to run one mode by a fixed order and drop
/// the other without a word, and a flag given to a run that does not read it went the same way:
/// `--include-ext jpg` without `--scan` opened the interface, whose scan then took every extension.
///
/// `--state-dir` serves every run. `--read-only` keeps its word in every run, and `--force` has
/// nothing to do in a report that takes no lock, so neither is refused on its own. One case is
/// left as it was: an observer (`--read-only`) opens an interface that neither scans nor applies,
/// yet takes that interface's scan and apply flags.
fn refuse_what_a_run_would_ignore(
    cli: &Cli,
    include_ext_given: bool,
) -> std::result::Result<(), String> {
    // The runs that read a flag, by the names a refusal gives them.
    const COMMANDO: &str = "the Commando interface";
    const CLASSIC: &str = "the classic wizard";
    const INTERFACES: &[&str] = &[COMMANDO, CLASSIC];
    const SCAN: &[&str] = &["--scan"];
    const SCAN_OR_INTERFACES: &[&str] = &["--scan", COMMANDO, CLASSIC];
    // Only the wizard offers the saved scans at start; the Commando interface loads them when asked.
    const SCAN_OR_CLASSIC: &[&str] = &["--scan", CLASSIC];
    const PURGE: &[&str] = &["--purge-quarantine"];

    let chosen = [
        !cli.scan_roots.is_empty(),
        cli.stats,
        cli.compact_db,
        cli.export_csv.is_some(),
        cli.purge_quarantine,
    ];
    let modes: Vec<&str> = MODES
        .into_iter()
        .zip(chosen)
        .filter_map(|(flag, given)| given.then_some(flag))
        .collect();
    if modes.len() > 1 {
        return Err(format!(
            "{} cannot be combined: a run does one of {}. Run them one after another.",
            listed(&modes),
            MODES.join(", ")
        ));
    }
    // Each pair used to be settled by a fixed order, the loser dropped: the Commando interface
    // over the wizard, the observer over the operator's lock.
    if cli.read_only && cli.force {
        return Err(
            "--read-only and --force cannot be combined: an observer never takes the operator's \
             lock"
                .to_string(),
        );
    }
    let run =
        match modes.first() {
            Some(mode) => *mode,
            None if cli.force_classic && cli.force_commando => return Err(
                "--classic and --commando cannot be combined: they open two different interfaces"
                    .to_string(),
            ),
            None if cli.force_classic => CLASSIC,
            None => COMMANDO,
        };

    let flags: [(&str, bool, &[&str]); 10] = [
        ("--no-resume", cli.no_resume, SCAN_OR_CLASSIC),
        ("--verify", cli.verify, SCAN_OR_INTERFACES),
        ("--merkle-dirs", cli.merkle_dirs, SCAN_OR_INTERFACES),
        ("--strict-verify", cli.strict_verify, INTERFACES),
        ("--classic", cli.force_classic, INTERFACES),
        ("--commando", cli.force_commando, INTERFACES),
        ("--include-ext", include_ext_given, SCAN),
        ("--storage-type", cli.storage_type.is_some(), SCAN),
        ("--no-hash-reuse", cli.no_hash_reuse, SCAN),
        ("--yes", cli.assume_yes, PURGE),
    ];
    let ignored: Vec<String> = flags
        .into_iter()
        .filter(|(_, given, readers)| *given && !readers.contains(&run))
        .map(|(flag, _, readers)| format!("{flag} (it applies to {} only)", listed(readers)))
        .collect();
    if !ignored.is_empty() {
        return Err(format!("{run} would ignore {}", listed(&ignored)));
    }
    Ok(())
}

/// `a`, `a and b`, `a, b and c`.
fn listed<T: AsRef<str>>(items: &[T]) -> String {
    let items: Vec<&str> = items.iter().map(AsRef::as_ref).collect();
    match items.split_last() {
        Some((last, head)) if !head.is_empty() => format!("{} and {last}", head.join(", ")),
        _ => items.concat(),
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

--scan, --stats, --compact-db, --export-csv and --purge-quarantine are modes: a run
does one of them (--scan may name several roots), or without one opens the Commando
interface, or the classic wizard with --classic. A flag the run would ignore is
refused: --include-ext, --storage-type and --no-hash-reuse apply to --scan only,
--yes to --purge-quarantine only, --no-resume to --scan and the classic wizard,
--verify and --merkle-dirs to --scan and both interfaces, --strict-verify to both
interfaces. --classic and --commando do not go together, nor --read-only and --force.

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
            .find(|line| line.trim_start().starts_with("--export-csv"))
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

#[cfg(test)]
mod storage_type_tests {
    use super::Cli;

    fn parse(args: &[&str]) -> Result<Cli, String> {
        Cli::parse_from(args.iter().map(|&arg| arg.into()))
    }

    #[test]
    fn the_three_documented_values_are_taken_in_any_case() {
        for (given, stored) in [("hdd", "hdd"), ("SSD", "ssd"), (" NVMe ", "nvme")] {
            let cli = parse(&["--scan", "/tank", "--storage-type", given]).expect(given);
            assert_eq!(cli.storage_type.as_deref(), Some(stored));
        }
    }

    /// The value goes into the checkpoint and `--stats` prints it back, so anything else is
    /// refused at the door — and the refusal does not itself print what it refuses raw.
    #[test]
    fn anything_else_is_refused_without_being_echoed_raw() {
        for given in ["", "sata", "hdd,ssd", "\u{1b}]0;PWNED\u{7}"] {
            let refusal = parse(&["--storage-type", given]).expect_err(given);
            assert!(refusal.contains("hdd, ssd or nvme"), "{refusal:?}");
            assert!(!refusal.chars().any(char::is_control), "{refusal:?}");
        }
        let refusal = parse(&["--no-such-\u{1b}[2Jflag"]).expect_err("an unknown flag");
        assert!(!refusal.chars().any(char::is_control), "{refusal:?}");
    }
}

#[cfg(test)]
mod mode_tests {
    use super::Cli;

    fn parse(args: &[&str]) -> Result<Cli, String> {
        Cli::parse_from(args.iter().map(|&arg| arg.into()))
    }

    /// The five flags that each decide what a run does, in the order the help lists them, each
    /// with the value it takes.
    const MODES: [&[&str]; 5] = [
        &["--scan", "/tank"],
        &["--stats"],
        &["--compact-db"],
        &["--export-csv", "/tmp/groups.csv"],
        &["--purge-quarantine"],
    ];

    /// Two modes in one run used to go by a fixed order, and the one that lost was dropped without
    /// a word: `--scan /tank --export-csv out.csv` exported an older scan and scanned nothing.
    /// Every pair, typed in either order, is refused, and the refusal names the two it got.
    #[test]
    fn two_modes_in_one_run_are_refused_by_name() {
        for (at, first) in MODES.iter().enumerate() {
            for second in &MODES[at + 1..] {
                let named = format!("{} and {} cannot be combined", first[0], second[0]);
                for args in [[*first, *second].concat(), [*second, *first].concat()] {
                    let refusal = parse(&args).expect_err(&args.join(" "));
                    assert!(refusal.starts_with(&named), "{args:?}: {refusal}");
                    assert!(refusal.contains("one after another"), "{refusal}");
                }
            }
        }
        let refusal = parse(&MODES.concat()).expect_err("all five");
        assert!(
            refusal.starts_with(
                "--scan, --stats, --compact-db, --export-csv and --purge-quarantine cannot be \
                 combined"
            ),
            "{refusal}"
        );
    }

    const COMMANDO: &str = "the Commando interface";
    const CLASSIC: &str = "the classic wizard";

    /// The seven runs, each by its name in a refusal and the arguments that start it. The modes
    /// come last.
    const RUNS: [(&str, &[&str]); 7] = [
        (COMMANDO, &[]),
        (CLASSIC, &["--classic"]),
        ("--scan", &["--scan", "/tank"]),
        ("--stats", &["--stats"]),
        ("--compact-db", &["--compact-db"]),
        ("--export-csv", &["--export-csv", "/tmp/groups.csv"]),
        ("--purge-quarantine", &["--purge-quarantine"]),
    ];

    const EVERY_RUN: &[&str] = &[
        COMMANDO,
        CLASSIC,
        "--scan",
        "--stats",
        "--compact-db",
        "--export-csv",
        "--purge-quarantine",
    ];

    /// Every flag that is neither a mode nor the choice of an interface, and the runs that read it
    /// — written out here, apart from the parser's own table, so a slip in that table cannot also
    /// be the expectation. Where the code reads each one: `src/main.rs` — `run_tui` (and in it
    /// `boot_session_load`, the one reader of `--no-resume`, which only the wizard waits for),
    /// `run_headless_scan`, `acquire_write_lock`, `run_purge_quarantine`.
    const READERS: [(&[&str], &[&str]); 11] = [
        (&["--state-dir", "/srv/dedcom"], EVERY_RUN),
        (&["--read-only"], EVERY_RUN),
        (&["--force"], EVERY_RUN),
        (&["--no-resume"], &[CLASSIC, "--scan"]),
        (&["--verify"], &[COMMANDO, CLASSIC, "--scan"]),
        (&["--merkle-dirs"], &[COMMANDO, CLASSIC, "--scan"]),
        (&["--strict-verify"], &[COMMANDO, CLASSIC]),
        (&["--include-ext", "jpg"], &["--scan"]),
        (&["--storage-type", "hdd"], &["--scan"]),
        (&["--no-hash-reuse"], &["--scan"]),
        (&["--yes"], &["--purge-quarantine"]),
    ];

    /// A flag given to a run that does not read it was dropped the same way: `dedcom --include-ext
    /// jpg` opened the interface, and its scan took every extension. Each run takes each flag it
    /// reads — alone and all together — and refuses each one it does not, by name.
    #[test]
    fn every_run_takes_the_flags_it_reads_and_refuses_the_rest() {
        for (run, starts) in RUNS {
            for (flag, readers) in READERS {
                let args = [starts, flag].concat();
                if readers.contains(&run) {
                    parse(&args).unwrap_or_else(|refusal| panic!("{args:?}: {refusal}"));
                } else {
                    let refusal = parse(&args).expect_err(&args.join(" "));
                    let named = format!("{run} would ignore {}", flag[0]);
                    assert!(refusal.starts_with(&named), "{args:?}: {refusal}");
                }
            }
            // All its own together — but `--force`, which does not go with `--read-only`.
            let own: Vec<&str> = READERS
                .iter()
                .filter(|(flag, readers)| readers.contains(&run) && flag[0] != "--force")
                .flat_map(|(flag, _)| flag.iter().copied())
                .collect();
            let args = [starts, own.as_slice()].concat();
            parse(&args).unwrap_or_else(|refusal| panic!("{args:?}: {refusal}"));
        }
        let scan = parse(&["--scan", "/tank", "--scan", "/home"]).expect("two roots, one mode");
        assert_eq!(scan.scan_roots.len(), 2);
    }

    /// `--classic` and `--commando` pick an interface: each is taken without a mode and refused
    /// with one. Two pairs used to be settled by a fixed order, the loser dropped — the Commando
    /// interface over the wizard, the observer over the operator's lock — and are refused now, in
    /// every run.
    #[test]
    fn flags_that_undo_each_other_are_refused_together() {
        for alone in [["--classic"], ["--commando"]] {
            parse(&alone).unwrap_or_else(|refusal| panic!("{alone:?}: {refusal}"));
        }
        let refusal = parse(&["--classic", "--commando"]).expect_err("two interfaces");
        assert!(
            refusal.starts_with("--classic and --commando cannot be combined"),
            "{refusal}"
        );
        for (mode, starts) in &RUNS[2..] {
            for flag in ["--classic", "--commando"] {
                let args = [*starts, &[flag][..]].concat();
                let refusal = parse(&args).expect_err(&args.join(" "));
                let named = format!(
                    "{mode} would ignore {flag} (it applies to the Commando interface and the \
                     classic wizard only)"
                );
                assert_eq!(refusal, named, "{args:?}");
            }
        }
        for (run, starts) in RUNS {
            let args = [starts, &["--read-only", "--force"][..]].concat();
            let refusal = parse(&args).expect_err(run);
            assert!(
                refusal.starts_with("--read-only and --force cannot be combined"),
                "{args:?}: {refusal}"
            );
        }
    }

    /// The refusal names the run, every flag it would ignore, and what each one applies to.
    #[test]
    fn a_refusal_names_each_ignored_flag_and_where_it_applies() {
        let cases: [(&[&str], &str); 6] = [
            (
                &["--include-ext", "jpg"],
                "the Commando interface would ignore --include-ext (it applies to --scan only)",
            ),
            (
                &["--scan", "/tank", "--yes", "--strict-verify"],
                "--scan would ignore --strict-verify (it applies to the Commando interface and the \
                 classic wizard only) and --yes (it applies to --purge-quarantine only)",
            ),
            (
                &["--export-csv", "/tmp/groups.csv", "--verify"],
                "--export-csv would ignore --verify (it applies to --scan, the Commando interface \
                 and the classic wizard only)",
            ),
            // The Commando interface offers the saved scans when asked, not at start.
            (
                &["--no-resume"],
                "the Commando interface would ignore --no-resume (it applies to --scan and the \
                 classic wizard only)",
            ),
            (
                &["--commando", "--no-resume"],
                "the Commando interface would ignore --no-resume (it applies to --scan and the \
                 classic wizard only)",
            ),
            // An empty list leaves no extension behind, and is still the flag.
            (
                &["--include-ext", ""],
                "the Commando interface would ignore --include-ext (it applies to --scan only)",
            ),
        ];
        for (args, says) in cases {
            assert_eq!(parse(args).expect_err(says), says, "{args:?}");
        }
    }

    /// The coarser mistake is the one a refusal names: two modes before anything else, and with a
    /// mode given, the flags that pick an interface are just flags that mode would ignore.
    #[test]
    fn the_coarser_mistake_is_named_first() {
        for args in [
            &["--stats", "--compact-db", "--include-ext", "jpg"][..],
            &["--stats", "--compact-db", "--read-only", "--force"],
        ] {
            let refusal = parse(args).expect_err(&args.join(" "));
            assert!(
                refusal.starts_with("--stats and --compact-db cannot be combined"),
                "{args:?}: {refusal}"
            );
        }
        let refusal = parse(&["--scan", "/tank", "--classic", "--commando"])
            .expect_err("a scan and both interfaces");
        assert!(
            refusal.starts_with("--scan would ignore --classic"),
            "{refusal}"
        );
    }

    /// A run writes one file, so a second destination is refused rather than kept in place of the
    /// first. A second state directory still wins, the way an option given later overrides one
    /// given earlier — a wrapper that sets it can be overridden by hand.
    #[test]
    fn a_second_export_destination_is_refused_and_a_second_state_directory_wins() {
        let refusal = parse(&["--export-csv", "/tmp/a.csv", "--export-csv", "/tmp/b.csv"])
            .expect_err("two destinations");
        assert!(
            refusal.starts_with("--export-csv is given twice"),
            "{refusal}"
        );
        let cli = parse(&["--state-dir", "/srv/a", "--state-dir", "/srv/b", "--stats"])
            .expect("the later state directory");
        assert_eq!(
            cli.state_dir.as_deref(),
            Some(std::path::Path::new("/srv/b"))
        );
    }
}

#[cfg(test)]
mod argument_bytes_tests {
    use super::Cli;
    use std::ffi::OsString;
    use std::os::unix::ffi::{OsStrExt, OsStringExt};
    use std::path::Path;

    fn parse(args: &[&[u8]]) -> Result<Cli, String> {
        Cli::parse_from(args.iter().map(|arg| OsString::from_vec(arg.to_vec())))
    }

    /// A state directory and an export destination are pathnames, and a pathname is bytes: they
    /// arrive exactly as they were given.
    #[test]
    fn a_state_directory_and_an_export_name_keep_their_bytes() {
        let cli = parse(&[
            b"--state-dir",
            b"/srv/st\xffate",
            b"--export-csv",
            b"/tmp/gr\xfe\x80.csv",
        ])
        .expect("both are pathnames");
        let bytes = |path: Option<&Path>| path.map(|path| path.as_os_str().as_bytes().to_vec());
        assert_eq!(
            bytes(cli.state_dir.as_deref()),
            Some(b"/srv/st\xffate".to_vec())
        );
        assert_eq!(
            bytes(cli.export_csv.as_deref()),
            Some(b"/tmp/gr\xfe\x80.csv".to_vec())
        );
    }

    /// The walk leaves out every file whose path is not UTF-8, so under a root spelled like that a
    /// scan could only ever find nothing — wherever in the path the byte stands. It is refused
    /// before anything starts, with the byte shown and the way out named, and a control character
    /// in it spelled out.
    #[test]
    fn a_scan_root_that_is_not_utf8_is_refused_with_the_reason() {
        let cases: [&[&[u8]]; 3] = [
            &[b"--scan", b"/tank/\xff"],
            &[b"--scan", b"/tank/\xff/photos"],
            &[b"--scan", b"/tank", b"--scan", b"/tank/\xff\x1b[2J"],
        ];
        for args in cases {
            let refusal = parse(args).expect_err("a root that is not UTF-8");
            assert!(refusal.starts_with("--scan \"/tank/\\xFF"), "{refusal}");
            assert!(refusal.contains("is not valid UTF-8"), "{refusal}");
            assert!(refusal.contains("Omissions"), "{refusal}");
            assert!(!refusal.chars().any(char::is_control), "{refusal:?}");
        }
    }

    /// A value that has to be text, and a flag, that is not UTF-8 is refused, and every refusal
    /// spells the byte the same way — as itself, with a control character escaped.
    #[test]
    fn a_text_value_or_a_flag_that_is_not_utf8_is_refused_escaped() {
        let cases: [(&[&[u8]], &str); 3] = [
            (
                &[b"--scan", b"/tank", b"--include-ext", b"jp\xff\x1b[2Jg"],
                "--include-ext \"jp\\xFF\\u{1b}[2Jg\" is not valid UTF-8",
            ),
            (
                &[b"--scan", b"/tank", b"--storage-type", b"hd\xffd"],
                "--storage-type takes hdd, ssd or nvme, not \"hd\\xFFd\"",
            ),
            (
                &[b"--no-such-\xff\x1b[2Jflag"],
                "unknown argument: \"--no-such-\\xFF\\u{1b}[2Jflag\"",
            ),
        ];
        for (args, says) in cases {
            let refusal = parse(args).expect_err(says);
            assert!(refusal.starts_with(says), "{refusal}");
            assert!(!refusal.chars().any(char::is_control), "{refusal:?}");
        }
    }
}
