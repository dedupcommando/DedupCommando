// SPDX-License-Identifier: Apache-2.0
//! F11 — building and executing deduplication actions from panel marks.

use crate::app::{App, AppMode};
use crate::model::dataset::Dataset;
use crate::model::plan::{ActionPlan, MarkIntent, RequestedMark};

use super::state::{ConfirmScript, ConfirmScroll, ConfirmTab, Mark, Overlay};

/// F11: submits the panels' marks to the one plan authority and opens the confirmation.
///
/// The plan is built by the store over the COMPLETE persisted evidence of every referenced group.
/// The commander used to assemble it from the marked pathnames alone, which structurally cannot
/// contain the unmarked alias that decides whether removing its sibling releases anything — the
/// panel would promise one allocation's worth of space that no purge would ever return. Files whose
/// hash could not be resolved used to be dropped into a status-line count; now nothing is dropped:
/// the whole plan is refused and the pathname is named.
///
/// Panels with no marks are not «nothing marked»: the plan is built from every mark the database
/// holds for the scan, a panel shows only those of the files it lists, and only the database can
/// say there are none — so without a loaded scan nothing can be said about marks at all.
pub fn prepare_execution(app: &mut App) {
    if app.deny_if_read_only("executing actions") {
        return;
    }
    if app.commander.dedup_scan_id.is_none() {
        app.commander.status =
            "No scan is loaded — load one (F2/F12) before executing actions".to_string();
        return;
    }
    let requested = requested_marks(app);
    // A plan may not overtake a mark the database has not accepted yet.
    if let Some(reason) = app.plan_gate_refusal() {
        app.commander.status = reason;
        return;
    }
    // The plan is built by the ONE store owner, over the complete persisted evidence of every
    // referenced group. The answer arrives as an event and seats itself; nothing is shown in
    // the meantime that could be confirmed.
    if app.request_commander_plan(requested) {
        app.commander.status = "Building the plan…".to_string();
    }
}

/// Seats a plan the authority just built: its script, its digest and its overlay, together. The
/// digest sets aside what the plan's own reading says cannot run where its files are.
pub(crate) fn seat_plan(app: &mut App, plan: ActionPlan) {
    // Shell-script preview — datasets are needed for quarantine and snapshot paths, as in the
    // batch itself.
    let datasets: Vec<Dataset> = app
        .zfs
        .pools
        .iter()
        .flat_map(|pool| pool.datasets.iter().cloned())
        .collect();
    let script = crate::actions::script_preview::render_script(
        &plan,
        &datasets,
        crate::zfs::trusted_zfs_bin(),
    );
    // A fresh confirmation always opens at the top of its own script — a leftover offset
    // from a previous plan would point into a script that no longer exists.
    app.commander.confirm_scroll = ConfirmScroll {
        offset: 0,
        total: script.lines().count(),
        rows: 0,
    };
    app.commander.confirm_script = ConfirmScript::Ready(script);
    app.commander.confirm_digest = plan.digest();
    app.commander.pending_plan = Some(plan);
    app.commander.status.clear();
    app.commander.overlay = Overlay::Confirm {
        tab: ConfirmTab::Summary,
    };
}

/// F11 confirmation: applies the plan and moves to the summary screen.
pub fn confirm_execution(app: &mut App) {
    if app.deny_if_read_only("executing actions") {
        clear_pending(app);
        app.commander.overlay = Overlay::None;
        return;
    }
    // A seat whose evidence moved may not be executed. The plan stays visible with the reason
    // beside it, so the operator sees what was invalidated rather than a batch that silently
    // did not run.
    if let Some(reason) = app.commander.confirm_script.invalidated() {
        app.commander.status = format!("The confirmation is no longer valid: {reason}");
        return;
    }
    let plan = app.commander.pending_plan.take();
    app.commander.confirm_script = ConfirmScript::None;
    app.commander.overlay = Overlay::None;
    let Some(plan) = plan else {
        return;
    };
    // Application runs in the BACKGROUND — the UI does not freeze. The
    // Applying/Summary screens belong to the wizard, so we switch to Wizard and flag
    // the return to commander; re-reading the panels after success happens in
    // `App::on_apply_finished`.
    app.mode = AppMode::Wizard;
    app.commander.return_to_commander = true;
    app.start_apply(plan);
}

/// Cancels the F11 confirmation.
pub fn cancel_execution(app: &mut App) {
    clear_pending(app);
    app.commander.overlay = Overlay::None;
}

/// Drops everything that describes a plan, together. A script left beside a plan that is gone is a
/// screen quoting something nobody can execute.
pub(crate) fn clear_pending(app: &mut App) {
    app.commander.pending_plan = None;
    app.commander.confirm_script = ConfirmScript::None;
    app.commander.confirm_digest = crate::model::plan::PlanDigest::default();
    app.commander.confirm_scroll = ConfirmScroll::default();
}

/// The marks the panels believe they hold, exactly as they stand.
///
/// One pathname may be marked in two panels; the store refuses a request that means two different
/// things for one pathname, so a window that has lost track of its own state cannot plan.
fn requested_marks(app: &App) -> Vec<RequestedMark> {
    let mut marks = Vec::new();
    for panel in &app.commander.panels {
        for (path, mark) in &panel.marks {
            let intent = match mark {
                Mark::Keeper => MarkIntent::Keeper,
                other => match other.action() {
                    Some(kind) => MarkIntent::Act(kind),
                    None => continue,
                },
            };
            marks.push(RequestedMark {
                path: path.clone(),
                intent,
            });
        }
    }
    marks.sort_by(|left, right| left.path.cmp(&right.path));
    marks
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::{drain, open_and_settle, pump_until, test_app_with_db, OpenIntent};
    use crate::model::action::ActionKind;
    use crate::state::store::role_guard;
    use crate::testfixtures::PlanScenario;
    use crate::tui::event::AppEvent;
    use crossbeam_channel::Receiver;
    use std::path::{Path, PathBuf};

    /// A commander over a scenario's database, with the same marks in the panel and in the DB —
    /// which is what F11 now requires: the window submits what it believes, and the store checks
    /// it against what is durable.
    ///
    /// The scan is opened through the actor, because since R4B-2c that is the only thing that
    /// gives the commander a scan to plan against: the id, the summaries and the browsing store
    /// all arrive in one payload.
    fn commander_over(
        tag: &str,
        marks: &[(&str, Mark)],
        extra: &[&str],
    ) -> (PlanScenario, App, Receiver<AppEvent>, Vec<PathBuf>) {
        let scenario = PlanScenario::new(tag);
        let mut paths: Vec<PathBuf> = marks.iter().map(|(name, _)| scenario.file(name)).collect();
        paths.extend(extra.iter().map(|name| scenario.file(name)));
        let mut store = scenario.store();
        let scan_id = scenario.seed(&mut store, &paths);
        for ((_, mark), path) in marks.iter().zip(paths.iter()) {
            scenario.mark(
                &mut store,
                scan_id,
                path,
                *mark == Mark::Keeper,
                mark.action(),
            );
        }
        drop(store);

        let (mut app, rx) = test_app_with_db(scenario.db_path.clone());
        root_dataset(&mut app, &scenario.root);
        open_and_settle(&mut app, &rx, scan_id, OpenIntent::Commander);
        assert_eq!(
            app.commander.dedup_scan_id,
            Some(scan_id),
            "the fixture's scan must open: {}",
            app.commander.status
        );
        drain(&mut app, &rx);
        for ((_, mark), path) in marks.iter().zip(paths.iter()) {
            app.commander.panels[0].marks.insert(path.clone(), *mark);
        }
        (scenario, app, rx, paths)
    }

    /// Asks for the plan exactly as F11 does, and settles the actor's answer.
    ///
    /// `prepare_execution` sends `BuildPlan` and returns; the plan — or its refusal — arrives as
    /// `PlanReady`/`PlanRefused`. A local gate refusal sends nothing, and then there is nothing
    /// to wait for, which is why the predicate is «no plan in flight» rather than «a plan».
    fn prepare_and_settle(app: &mut App, rx: &Receiver<AppEvent>) {
        prepare_execution(app);
        pump_until(app, rx, "the plan reply", |app| app.routes.plan.is_none());
    }

    /// The review's failure scenario: F8 landed where F7 was meant, so the batch deletes the
    /// two files the operator wanted to keep. «Actions: 2» reads as expected — the digest is
    /// what makes the mistake visible before Y.
    #[test]
    fn the_confirmation_digest_names_a_mis_marked_batch() {
        let _role = role_guard();
        let (_scenario, mut app, rx, paths) = commander_over(
            "mismarked",
            &[
                ("keeper.bin", Mark::Keeper),
                ("dup1.bin", Mark::Delete),
                ("dup2.bin", Mark::Delete),
            ],
            &[],
        );

        prepare_and_settle(&mut app, &rx);

        assert!(
            matches!(app.commander.overlay, Overlay::Confirm { .. }),
            "the plan is two deletions: {:?} — {}",
            app.commander.overlay,
            app.commander.status
        );
        let digest = &app.commander.confirm_digest;
        assert_eq!(
            digest.counts,
            vec![(ActionKind::Delete, 2)],
            "the confirmation must be able to say «delete 2»"
        );
        let named: Vec<&PathBuf> = digest.samples.iter().map(|(_, path)| path).collect();
        assert!(
            named.contains(&&paths[1]) && named.contains(&&paths[2]),
            "both targets are named: {named:?}"
        );
        assert_eq!(digest.hidden, 0);
        assert_eq!(digest.covered_objects, 2, "two independent allocations");
    }

    /// A stale digest is worse than none: the overlay would describe the previous plan.
    #[test]
    fn a_second_plan_replaces_the_first_digest() {
        let _role = role_guard();
        let (scenario, mut app, rx, paths) = commander_over(
            "replace",
            &[
                ("keeper.bin", Mark::Keeper),
                ("dup1.bin", Mark::Delete),
                ("dup2.bin", Mark::Delete),
            ],
            &[],
        );
        prepare_and_settle(&mut app, &rx);
        assert_eq!(app.commander.confirm_digest.counts.len(), 1);

        // The operator backs out and re-marks one file as a hardlink instead.
        cancel_execution(&mut app);
        assert!(app.commander.pending_plan.is_none());
        assert!(app.commander.confirm_script.ready().is_none());
        {
            let scan_id = app.commander.dedup_scan_id.unwrap();
            let mut store = scenario.store();
            scenario.mark(&mut store, scan_id, &paths[2], false, None);
            scenario.mark(
                &mut store,
                scan_id,
                &paths[1],
                false,
                Some(ActionKind::Hardlink),
            );
        }
        app.commander.panels[0].marks.remove(&paths[2]);
        app.commander.panels[0]
            .marks
            .insert(paths[1].clone(), Mark::Hardlink);
        prepare_and_settle(&mut app, &rx);

        assert_eq!(
            app.commander.confirm_digest.counts,
            vec![(ActionKind::Hardlink, 1)],
            "the digest describes the plan on screen now, not the one that was cancelled"
        );
    }

    /// The blind spot C5 exists for: the panel holds one alias of an allocation and cannot see the
    /// other, so a plan built from its marks promised space no purge would ever return. The store
    /// sees both, and the confirmation now says zero.
    #[test]
    fn a_marked_alias_whose_sibling_is_unmarked_promises_nothing() {
        let _role = role_guard();
        let scenario = PlanScenario::new("commander_alias");
        let keeper = scenario.file("keeper.bin");
        let alias_a = scenario.file("alias_a.bin");
        let alias_b = scenario.link(&alias_a, "alias_b.bin");
        let mut store = scenario.store();
        let scan_id = scenario.seed(
            &mut store,
            &[keeper.clone(), alias_a.clone(), alias_b.clone()],
        );
        scenario.mark(&mut store, scan_id, &keeper, true, None);
        scenario.mark(
            &mut store,
            scan_id,
            &alias_a,
            false,
            Some(ActionKind::Delete),
        );
        drop(store);

        let (mut app, rx) = test_app_with_db(scenario.db_path.clone());
        root_dataset(&mut app, &scenario.root);
        open_and_settle(&mut app, &rx, scan_id, OpenIntent::Commander);
        drain(&mut app, &rx);
        app.commander.panels[0].marks.insert(keeper, Mark::Keeper);
        app.commander.panels[0].marks.insert(alias_a, Mark::Delete);

        prepare_and_settle(&mut app, &rx);

        let plan = app
            .commander
            .pending_plan
            .as_ref()
            .expect("a plan is allowed, it is simply worth nothing");
        assert_eq!(plan.summary().guaranteed_bytes(), 0);
        assert_eq!(plan.summary().potential_bytes(), Some(0));
        assert_eq!(
            app.commander.confirm_digest.warnings.len(),
            1,
            "and the confirmation has to say why"
        );
        assert!(app.commander.confirm_digest.warnings[0]
            .message()
            .starts_with("zero guaranteed reclaim"));
    }

    /// Row 10: identical marks through classic and the commander are identical everywhere — the
    /// plan value, the confirmation digest and the bytes of the saved script.
    #[test]
    fn both_windows_produce_the_same_plan_digest_and_script() {
        let _role = role_guard();
        let scenario = PlanScenario::new("parity_windows");
        let keeper = scenario.file("keeper.bin");
        let first = scenario.file("dup1.bin");
        let second = scenario.file("dup2.bin");
        let mut store = scenario.store();
        let scan_id = scenario.seed(&mut store, &[keeper.clone(), first.clone(), second.clone()]);
        scenario.mark(&mut store, scan_id, &keeper, true, None);
        scenario.mark(&mut store, scan_id, &first, false, Some(ActionKind::Delete));
        scenario.mark(
            &mut store,
            scan_id,
            &second,
            false,
            Some(ActionKind::Hardlink),
        );
        drop(store);

        // The classic browser submits the group it has open; the commander submits its panels'
        // marks. Different vectors, one database, one answer.
        let classic = vec![
            RequestedMark::keeper(keeper.clone()),
            RequestedMark::acting(first.clone(), ActionKind::Delete),
            RequestedMark::acting(second.clone(), ActionKind::Hardlink),
        ];
        let commander = vec![
            RequestedMark::acting(second.clone(), ActionKind::Hardlink),
            RequestedMark::keeper(keeper.clone()),
            RequestedMark::acting(first.clone(), ActionKind::Delete),
        ];
        let store = scenario.store();
        let from_classic = store.build_action_plan(scan_id, &classic).unwrap();
        let from_commander = store.build_action_plan(scan_id, &commander).unwrap();
        assert_eq!(from_classic, from_commander, "the whole owning value");
        assert_eq!(from_classic.digest(), from_commander.digest());

        let datasets = vec![crate::model::dataset::Dataset {
            name: "tank".to_string(),
            mountpoint: scenario.root.clone(),
            device_id: Some(std::os::unix::fs::MetadataExt::dev(
                &std::fs::symlink_metadata(&scenario.root).unwrap(),
            )),
            snapdir_visible: false,
            block_cloning: None,
        }];
        let render = |plan: &_| {
            let script = crate::actions::script_preview::render_script(
                plan,
                &datasets,
                Some("/usr/sbin/zfs"),
            );
            // The rendering stamp is the wall clock, so two renders a second apart differ in a
            // way that has nothing to do with the plan. Normalising it is what leaves the
            // comparison about the plan.
            let stamp = script
                .lines()
                .find_map(|line| line.strip_prefix("# Plan snapshot from "))
                .map(|rest| rest.trim_end_matches('.').to_string())
                .expect("the header carries the stamp");
            script.replace(&stamp, "TS")
        };
        assert_eq!(
            render(&from_classic),
            render(&from_commander),
            "the saved script must be the same bytes from either window"
        );

        // And a stale mark refuses both with the same sentence.
        let stale = vec![RequestedMark::acting(first.clone(), ActionKind::Hardlink)];
        let classic_refusal = store.build_action_plan(scan_id, &stale).unwrap_err();
        let commander_refusal = store.build_action_plan(scan_id, &stale).unwrap_err();
        assert_eq!(classic_refusal, commander_refusal);
        assert!(
            classic_refusal.to_string().contains("re-mark it"),
            "{classic_refusal}"
        );
    }

    /// A store that cannot be read leaves the commander with nothing pending — and says so,
    /// rather than reporting the operator's marks as absent.
    ///
    /// The checkpoint is replaced under the live view, so the failure is met where it really
    /// happens: at the door of the actor that owns the connection. Pointing `db_path` at an
    /// unopenable file would prove nothing now — the actor is already open on the real one.
    #[test]
    fn an_unreadable_store_leaves_no_pending_plan_and_no_script() {
        let _role = role_guard();
        let (scenario, mut app, rx, _paths) = commander_over(
            "store_error",
            &[("keeper.bin", Mark::Keeper), ("dup1.bin", Mark::Delete)],
            &[],
        );
        prepare_and_settle(&mut app, &rx);
        assert!(app.commander.pending_plan.is_some(), "the fixture plans");
        cancel_execution(&mut app);

        // The file the view was opened over is replaced by one nothing can identify.
        std::fs::remove_file(&scenario.db_path).unwrap();
        std::fs::create_dir(&scenario.db_path).unwrap();

        prepare_and_settle(&mut app, &rx);

        assert!(matches!(app.commander.overlay, Overlay::None));
        assert!(app.commander.pending_plan.is_none());
        assert!(app.commander.confirm_script.ready().is_none());
        assert!(app.apply.is_none(), "no worker may have been dispatched");
        assert!(
            app.commander.status.contains("could not be read")
                && app.commander.status.contains("dedcom.db"),
            "the operator is told what happened: {}",
            app.commander.status
        );
        assert!(
            !app.commander.status.contains("No marked files"),
            "a store failure is not an absence of marks: {}",
            app.commander.status
        );
        assert!(
            !app.commander.status.contains("Building the plan"),
            "and the in-flight line is not the answer: {}",
            app.commander.status
        );
    }

    /// A pathname the manifest never heard of is not silently dropped into a status-line count any
    /// more: the whole plan is refused, nothing is left pending, and the pathname is named.
    #[test]
    fn a_mark_outside_the_manifest_refuses_the_whole_plan() {
        let _role = role_guard();
        let (scenario, mut app, rx, _paths) = commander_over(
            "outside",
            &[("keeper.bin", Mark::Keeper), ("dup1.bin", Mark::Delete)],
            &[],
        );
        let stranger = scenario.outside.join("stranger.bin");
        std::fs::write(&stranger, b"not in this scan").unwrap();
        app.commander.panels[0]
            .marks
            .insert(stranger.clone(), Mark::Delete);

        prepare_and_settle(&mut app, &rx);

        assert!(
            matches!(app.commander.overlay, Overlay::None),
            "no confirmation may open over a plan that was refused"
        );
        assert!(app.commander.pending_plan.is_none());
        assert!(app.commander.confirm_script.ready().is_none());
        assert!(
            app.commander
                .status
                .contains(&stranger.display().to_string()),
            "the refusal names the pathname: {}",
            app.commander.status
        );
    }

    /// A refusal is a sentence written by the plan, and it quotes the pathname. The file here
    /// was scanned and marked under a name that holds a terminal sequence, and then removed — a
    /// thing anybody who can write to the tree can do between the scan and F11.
    #[test]
    fn a_refused_plan_names_a_hostile_pathname_escaped() {
        use crate::tui::hostile::{RETITLE, RETITLE_SHOWN};
        let _role = role_guard();
        let (_scenario, mut app, rx, paths) = commander_over(
            "refused_hostile",
            &[("keeper.bin", Mark::Keeper), (RETITLE, Mark::Delete)],
            &[],
        );
        std::fs::remove_file(&paths[1]).unwrap();

        prepare_and_settle(&mut app, &rx);

        assert!(
            matches!(app.commander.overlay, Overlay::None),
            "the plan is refused: {}",
            app.commander.status
        );
        let status = &app.commander.status;
        assert!(!status.chars().any(char::is_control), "{status:?}");
        assert!(status.contains(RETITLE_SHOWN), "{status:?}");
    }

    /// Points panel `index` at `dir` and settles the refresh: the directory read, then the
    /// database's answer about every file it lists.
    fn list_in_panel(app: &mut App, rx: &Receiver<AppEvent>, index: usize, dir: &Path) {
        super::super::navigate_panel(app, index, dir.to_path_buf());
        pump_until(app, rx, "the panel listing and its answer", |app| {
            !app.commander.panels[index].loading && app.routes.panels.is_empty()
        });
    }

    /// A scan whose keeper and one copy an earlier session marked, and nothing of it in memory:
    /// what a restart leaves behind.
    fn marked_before_a_restart(tag: &str) -> (PlanScenario, i64, PathBuf, PathBuf) {
        let scenario = PlanScenario::new(tag);
        let keeper = scenario.file("keeper.bin");
        let copy = scenario.file("copy.bin");
        let mut store = scenario.store();
        let scan_id = scenario.seed(&mut store, &[keeper.clone(), copy.clone()]);
        scenario.mark(&mut store, scan_id, &keeper, true, None);
        scenario.mark(&mut store, scan_id, &copy, false, Some(ActionKind::Delete));
        drop(store);
        (scenario, scan_id, keeper, copy)
    }

    /// The marks outlive the program: a panel that lists the marked files after a restart shows
    /// what the database kept, and F11 plans it.
    #[test]
    fn a_restarted_commander_shows_the_saved_marks_and_plans_them() {
        let _role = role_guard();
        let (scenario, scan_id, keeper, copy) = marked_before_a_restart("restart_shows");
        let (mut app, rx) = test_app_with_db(scenario.db_path.clone());
        root_dataset(&mut app, &scenario.root);
        open_and_settle(&mut app, &rx, scan_id, OpenIntent::Commander);
        list_in_panel(&mut app, &rx, 0, &scenario.root);

        let marks = &app.commander.panels[0].marks;
        assert_eq!(marks.get(&keeper), Some(&Mark::Keeper), "{marks:?}");
        assert_eq!(marks.get(&copy), Some(&Mark::Delete), "{marks:?}");

        prepare_and_settle(&mut app, &rx);
        assert!(
            matches!(app.commander.overlay, Overlay::Confirm { .. }),
            "the saved marks are planned: {}",
            app.commander.status
        );
        assert_eq!(
            app.commander.confirm_digest.counts,
            vec![(ActionKind::Delete, 1)]
        );
    }

    /// F11 plans the saved marks even when no panel lists them. The plan is built from the
    /// database anyway; «No marked files» over a database that holds marks tells the operator
    /// they are gone.
    #[test]
    fn f11_plans_saved_marks_that_no_panel_lists() {
        let _role = role_guard();
        let (scenario, scan_id, _keeper, copy) = marked_before_a_restart("restart_unlisted");
        let (mut app, rx) = test_app_with_db(scenario.db_path.clone());
        root_dataset(&mut app, &scenario.root);
        open_and_settle(&mut app, &rx, scan_id, OpenIntent::Commander);
        drain(&mut app, &rx);
        assert!(
            app.commander
                .panels
                .iter()
                .all(|panel| panel.marks.is_empty()),
            "no panel lists the scanned folder"
        );

        prepare_and_settle(&mut app, &rx);
        assert!(
            matches!(app.commander.overlay, Overlay::Confirm { .. }),
            "{}",
            app.commander.status
        );
        let named: Vec<&PathBuf> = app
            .commander
            .confirm_digest
            .samples
            .iter()
            .map(|(_, path)| path)
            .collect();
        assert_eq!(named, vec![&copy]);
    }

    /// A saved mark whose file has left the disk since is planned like any other, and the plan
    /// refuses it by name — the answer the operator got when the panel still held the mark.
    #[test]
    fn a_saved_mark_on_a_vanished_file_refuses_the_plan_by_name() {
        let _role = role_guard();
        let (scenario, scan_id, _keeper, copy) = marked_before_a_restart("restart_vanished");
        std::fs::remove_file(&copy).unwrap();
        let (mut app, rx) = test_app_with_db(scenario.db_path.clone());
        open_and_settle(&mut app, &rx, scan_id, OpenIntent::Commander);
        list_in_panel(&mut app, &rx, 0, &scenario.root);

        prepare_and_settle(&mut app, &rx);
        assert!(
            matches!(app.commander.overlay, Overlay::None),
            "{}",
            app.commander.status
        );
        assert!(
            app.commander.status.contains(&copy.display().to_string()),
            "the refusal names the file: {}",
            app.commander.status
        );
    }

    /// Marks belong to their scan. Opening another one leaves none of the first one's on screen —
    /// F11 would refuse them as never saved — and the panels show what the new one holds.
    #[test]
    fn opening_another_scan_shows_its_marks_not_the_ones_before() {
        let _role = role_guard();
        let (scenario, first, keeper, copy) = marked_before_a_restart("switch_scans");
        let second = {
            let mut store = scenario.store();
            let second = scenario.seed(&mut store, &[keeper.clone(), copy.clone()]);
            scenario.mark(&mut store, second, &copy, true, None);
            scenario.mark(&mut store, second, &keeper, false, Some(ActionKind::Delete));
            second
        };
        let (mut app, rx) = test_app_with_db(scenario.db_path.clone());
        root_dataset(&mut app, &scenario.root);
        open_and_settle(&mut app, &rx, first, OpenIntent::Commander);
        list_in_panel(&mut app, &rx, 0, &scenario.root);
        assert_eq!(
            app.commander.panels[0].marks.get(&keeper),
            Some(&Mark::Keeper)
        );
        // A Space/Insert selection is not a mark of either scan.
        let picked = scenario.outside.clone();
        app.commander.panels[0]
            .marks
            .insert(picked.clone(), Mark::Selected);

        // Installed, every panel asked again, no answer in yet: nothing of the first scan is
        // left even before the panels hear from the second.
        open_and_settle(&mut app, &rx, second, OpenIntent::Commander);
        let held: Vec<(&PathBuf, &Mark)> = app
            .commander
            .panels
            .iter()
            .flat_map(|panel| panel.marks.iter())
            .collect();
        assert_eq!(held, vec![(&picked, &Mark::Selected)]);

        pump_until(&mut app, &rx, "the panels' answers", |app| {
            app.routes.panels.is_empty()
        });
        let marks = &app.commander.panels[0].marks;
        assert_eq!(marks.get(&copy), Some(&Mark::Keeper), "{marks:?}");
        assert_eq!(marks.get(&keeper), Some(&Mark::Delete), "{marks:?}");
        assert_eq!(marks.get(&picked), Some(&Mark::Selected), "{marks:?}");
        prepare_and_settle(&mut app, &rx);
        let named: Vec<&PathBuf> = app
            .commander
            .confirm_digest
            .samples
            .iter()
            .map(|(_, path)| path)
            .collect();
        assert_eq!(named, vec![&keeper], "{}", app.commander.status);
    }

    /// A refresh the database answered before a keystroke's write reached it leaves the glyph on
    /// the panel that took the keystroke — the write's own answer settles that row — while another
    /// panel listing the same folder shows what the database holds meanwhile.
    #[test]
    fn a_keystroke_keeps_its_glyph_until_its_write_answers() {
        let _role = role_guard();
        let (scenario, scan_id, _keeper, copy) = marked_before_a_restart("refresh_in_flight");
        let (mut app, rx) = test_app_with_db(scenario.db_path.clone());
        open_and_settle(&mut app, &rx, scan_id, OpenIntent::Commander);
        list_in_panel(&mut app, &rx, 0, &scenario.root);

        // Panel 1 lists the folder and asks about it; then the operator, on panel 0, turns the copy
        // into a hardlink.
        super::super::navigate_panel(&mut app, 1, scenario.root.clone());
        pump_until(&mut app, &rx, "panel 1's listing", |app| {
            !app.commander.panels[1].loading
        });
        assert!(!app.routes.panels.is_empty(), "panel 1's refresh is asked");
        app.commander.panels[0]
            .marks
            .insert(copy.clone(), Mark::Hardlink);
        let file = crate::model::duplicate::FileEntry {
            path: copy.clone(),
            action: Some(ActionKind::Hardlink),
            ..Default::default()
        };
        app.send_commander_mark(0, file, Some(Mark::Delete), Some(Mark::Hardlink))
            .unwrap();

        pump_until(&mut app, &rx, "the refresh", |app| {
            app.routes.panels.is_empty()
        });
        assert_eq!(
            app.commander.panels[0].marks.get(&copy),
            Some(&Mark::Hardlink),
            "the refresh was answered before the write"
        );
        assert_eq!(
            app.commander.panels[1].marks.get(&copy),
            Some(&Mark::Delete),
            "the other panel shows the database"
        );
        pump_until(&mut app, &rx, "the write's answer", |app| {
            app.pending_marks.is_empty()
        });
        for panel in &app.commander.panels {
            assert_eq!(panel.marks.get(&copy), Some(&Mark::Hardlink));
        }
        assert!(
            app.commander.status.starts_with("Mark saved"),
            "{}",
            app.commander.status
        );
    }

    /// Every file a panel lists shows what the database holds for it: a mark the database no
    /// longer has goes, as it does when a write's answer says so. A Space/Insert selection is not
    /// the database's and stays.
    #[test]
    fn a_listed_file_loses_a_mark_the_database_no_longer_holds() {
        let _role = role_guard();
        let (scenario, scan_id, keeper, copy) = marked_before_a_restart("mark_gone");
        let loose = scenario.file("loose.bin");
        let (mut app, rx) = test_app_with_db(scenario.db_path.clone());
        open_and_settle(&mut app, &rx, scan_id, OpenIntent::Commander);
        list_in_panel(&mut app, &rx, 0, &scenario.root);
        app.commander.panels[0]
            .marks
            .insert(loose.clone(), Mark::Selected);
        {
            // Another writer clears the copy's mark.
            let mut store = scenario.store();
            scenario.mark(&mut store, scan_id, &copy, false, None);
        }

        list_in_panel(&mut app, &rx, 0, &scenario.root);
        let marks = &app.commander.panels[0].marks;
        assert_eq!(marks.get(&copy), None, "{marks:?}");
        assert_eq!(marks.get(&keeper), Some(&Mark::Keeper), "{marks:?}");
        assert_eq!(marks.get(&loose), Some(&Mark::Selected), "{marks:?}");
    }

    /// Every panel that shows a folder shows its saved marks, and a panel keeps none from a folder
    /// it no longer lists: the panels hold the marks on screen, not every mark ever browsed.
    #[test]
    fn panels_hold_the_saved_marks_of_the_folders_they_list() {
        let _role = role_guard();
        let (scenario, scan_id, keeper, copy) = marked_before_a_restart("two_panels");
        let (mut app, rx) = test_app_with_db(scenario.db_path.clone());
        open_and_settle(&mut app, &rx, scan_id, OpenIntent::Commander);
        list_in_panel(&mut app, &rx, 0, &scenario.root);
        list_in_panel(&mut app, &rx, 1, &scenario.root);
        {
            // Another writer turns the copy into a hardlink.
            let mut store = scenario.store();
            scenario.mark(
                &mut store,
                scan_id,
                &copy,
                false,
                Some(ActionKind::Hardlink),
            );
        }

        // One panel's refresh is the folder's answer for both.
        list_in_panel(&mut app, &rx, 0, &scenario.root);
        for panel in &app.commander.panels {
            assert_eq!(panel.marks.get(&keeper), Some(&Mark::Keeper));
            assert_eq!(panel.marks.get(&copy), Some(&Mark::Hardlink));
        }

        list_in_panel(&mut app, &rx, 1, &scenario.outside);
        // And the folder's next answer is not news to a panel showing another one.
        list_in_panel(&mut app, &rx, 0, &scenario.root);
        assert!(
            app.commander.panels[1].marks.is_empty(),
            "{:?}",
            app.commander.panels[1].marks
        );
        let marks = &app.commander.panels[0].marks;
        assert_eq!(marks.get(&keeper), Some(&Mark::Keeper), "{marks:?}");
        assert_eq!(marks.get(&copy), Some(&Mark::Hardlink), "{marks:?}");
    }

    /// A panel that lists no file of the folder — here a «directories» panel — answers about none,
    /// and that is no news about the marks a files panel on the same folder shows.
    #[test]
    fn a_directories_panel_on_the_same_folder_leaves_the_saved_marks() {
        let _role = role_guard();
        let (scenario, scan_id, keeper, copy) = marked_before_a_restart("dirs_neighbour");
        let (mut app, rx) = test_app_with_db(scenario.db_path.clone());
        open_and_settle(&mut app, &rx, scan_id, OpenIntent::Commander);
        list_in_panel(&mut app, &rx, 0, &scenario.root);
        list_in_panel(&mut app, &rx, 1, &scenario.root);
        app.commander.active = 1;
        super::super::cycle_view(&mut app);
        pump_until(&mut app, &rx, "panel 1's reload and its answer", |app| {
            !app.commander.panels[1].loading && app.routes.panels.is_empty()
        });

        let marks = &app.commander.panels[0].marks;
        assert_eq!(marks.get(&keeper), Some(&Mark::Keeper), "{marks:?}");
        assert_eq!(marks.get(&copy), Some(&Mark::Delete), "{marks:?}");
    }

    /// A keystroke made before its folder's answer arrived, whose write then fails with nothing
    /// read back, does not hide the saved mark: the panel asks the database again.
    #[test]
    fn a_failed_write_before_the_folders_answer_asks_again() {
        let _role = role_guard();
        let (scenario, scan_id, keeper, _copy) = marked_before_a_restart("failed_write");
        let (mut app, rx) = test_app_with_db(scenario.db_path.clone());
        open_and_settle(&mut app, &rx, scan_id, OpenIntent::Commander);
        rusqlite::Connection::open(&scenario.db_path)
            .unwrap()
            .execute_batch(
                "CREATE TRIGGER refuse_marks BEFORE INSERT ON file_mark
                 BEGIN SELECT RAISE(ABORT, 'refused'); END;",
            )
            .unwrap();
        super::super::navigate_panel(&mut app, 0, scenario.root.clone());
        pump_until(&mut app, &rx, "panel 0's listing", |app| {
            !app.commander.panels[0].loading
        });
        assert!(
            !app.routes.panels.is_empty(),
            "the folder's answer is on its way"
        );
        // The panel has not heard the database yet: to it the keeper is unmarked.
        app.commander.panels[0]
            .marks
            .insert(keeper.clone(), Mark::Delete);
        let file = crate::model::duplicate::FileEntry {
            path: keeper.clone(),
            action: Some(ActionKind::Delete),
            ..Default::default()
        };
        app.send_commander_mark(0, file, None, Some(Mark::Delete))
            .unwrap();
        // The folder's answer, read before the write, lands on the panel that asked for it: the
        // glyph of the keystroke stays until the write is answered.
        pump_until(&mut app, &rx, "the folder's answer", |app| {
            app.routes.panels.is_empty()
        });
        assert!(!app.pending_marks.is_empty(), "the write is still out");
        assert_eq!(
            app.commander.panels[0].marks.get(&keeper),
            Some(&Mark::Delete)
        );
        pump_until(
            &mut app,
            &rx,
            "the refused write and the asking again",
            |app| app.pending_marks.is_empty() && app.routes.panels.is_empty(),
        );

        assert!(
            app.commander.status.contains("not saved"),
            "{}",
            app.commander.status
        );
        assert_eq!(
            app.commander.panels[0].marks.get(&keeper),
            Some(&Mark::Keeper)
        );
    }

    /// When the active panel enters a folder no scan covers, the scan is set aside and its marks
    /// leave the panels with it: with no scan, Space would clear one on screen only.
    #[test]
    fn setting_the_scan_aside_takes_its_marks_off_the_panels() {
        let _role = role_guard();
        let (scenario, scan_id, keeper, _copy) = marked_before_a_restart("scan_aside");
        let (mut app, rx) = test_app_with_db(scenario.db_path.clone());
        open_and_settle(&mut app, &rx, scan_id, OpenIntent::Commander);
        list_in_panel(&mut app, &rx, 0, &scenario.root);
        assert_eq!(
            app.commander.panels[0].marks.get(&keeper),
            Some(&Mark::Keeper)
        );

        super::super::apply_auto_switch(&mut app, &scenario.outside, None);
        assert!(app.commander.dedup_scan_id.is_none());
        assert!(
            app.commander
                .panels
                .iter()
                .all(|panel| panel.marks.is_empty()),
            "{:?}",
            app.commander.panels[0].marks
        );
    }

    /// After a batch stopped with Esc, the panel showing the folder shows what the database kept:
    /// every mark of the group the batch never reached — the work F11 still does — and none of the
    /// group it changed.
    #[test]
    fn a_stopped_batch_leaves_the_unreached_marks_on_the_panel() {
        let _role = role_guard();
        let scenario = PlanScenario::new("stopped_batch");
        let keeper = scenario.file("keeper.bin");
        let done = scenario.file("done.bin");
        let other_keeper = scenario.root.join("other_keeper.bin");
        let left = scenario.root.join("left.bin");
        for path in [&other_keeper, &left] {
            std::fs::write(path, vec![9u8; 8192]).unwrap();
        }
        let paths = [
            keeper.clone(),
            done.clone(),
            other_keeper.clone(),
            left.clone(),
        ];
        let mut store = scenario.store();
        let scan_id = scenario.seed(&mut store, &paths);
        for pair in paths.chunks(2) {
            scenario.mark(&mut store, scan_id, &pair[0], true, None);
            scenario.mark(
                &mut store,
                scan_id,
                &pair[1],
                false,
                Some(ActionKind::Delete),
            );
        }
        drop(store);
        let (mut app, rx) = test_app_with_db(scenario.db_path.clone());
        open_and_settle(&mut app, &rx, scan_id, OpenIntent::Commander);
        list_in_panel(&mut app, &rx, 0, &scenario.root);
        app.commander.return_to_commander = true;

        // The batch deleted the first group's copy, then Esc: that group is spent, the other one
        // was never reached.
        let reached = crate::model::action::ActionOutcome {
            kind: ActionKind::Delete,
            target: done.clone(),
            quarantine: None,
            result: Ok(()),
        };
        app.handle_event(AppEvent::ApplyFinished(Box::new(
            crate::actions::ApplyOutcome::Finished(crate::model::action::BatchResult {
                outcomes: vec![reached],
                planned: 2,
                cancelled: true,
                settlement: Box::new(crate::model::plan::MarkSettlement {
                    spent: vec![keeper.clone(), done.clone()],
                    left_marked: 1,
                    left_unmarked: 0,
                }),
                ..Default::default()
            }),
        )));
        pump_until(
            &mut app,
            &rx,
            "the settlement and the panels' answers",
            |app| {
                app.routes.reconcile.is_none()
                    && app.commander.panels.iter().all(|panel| !panel.loading)
                    && app.routes.panels.is_empty()
            },
        );

        let marks = &app.commander.panels[0].marks;
        assert_eq!(marks.get(&keeper), None, "{marks:?}");
        assert_eq!(marks.get(&done), None, "{marks:?}");
        assert_eq!(marks.get(&other_keeper), Some(&Mark::Keeper), "{marks:?}");
        assert_eq!(marks.get(&left), Some(&Mark::Delete), "{marks:?}");
    }

    /// The Summary tab as an 80×40 terminal shows it, borders out and whitespace collapsed, so a
    /// sentence the box wrapped still reads as one.
    fn summary_text(app: &mut App) -> String {
        use ratatui::{backend::TestBackend, Terminal};
        let (width, height) = (80u16, 40u16);
        let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
        terminal
            .draw(|frame| {
                super::super::overlay::render_confirm(
                    frame,
                    ConfirmTab::Summary,
                    &app.commander.confirm_script,
                    &app.commander.confirm_digest,
                    &mut app.commander.confirm_scroll,
                )
            })
            .unwrap();
        let buffer = terminal.backend().buffer().clone();
        let text: String = (0..height)
            .flat_map(|y| (0..width).map(move |x| (x, y)))
            .map(|(x, y)| buffer[(x, y)].symbol().to_string())
            .collect::<Vec<_>>()
            .join("");
        text.replace(['│', '─', '┌', '┐', '└', '┘'], " ")
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// The scenario's root as one dataset of pool `tank` — what a ZFS host reports at startup.
    fn root_dataset(app: &mut App, root: &Path) {
        app.zfs.pools = vec![crate::model::dataset::Pool {
            name: "tank".to_string(),
            datasets: vec![crate::actions::tests::dataset_over(root, "tank/a")],
        }];
    }

    /// One of two copies is on a filesystem no dataset covers, so the batch would refuse it
    /// before its snapshot: the confirmation says so before Y, and does not count it.
    #[test]
    fn the_confirmation_names_what_cannot_run_and_leaves_it_out() {
        let _role = role_guard();
        let shm = crate::actions::tests::ShmDir::new("cannot_run");
        let scenario = PlanScenario::new("cannot_run");
        let keeper = scenario.file("keeper.bin");
        let here = scenario.file("here.bin");
        let there = shm.path.join("there.bin");
        std::fs::copy(&keeper, &there).unwrap();
        let mut store = scenario.store();
        let scan_id = scenario.seed(&mut store, &[keeper.clone(), here.clone(), there.clone()]);
        scenario.mark(&mut store, scan_id, &keeper, true, None);
        for copy in [&here, &there] {
            scenario.mark(&mut store, scan_id, copy, false, Some(ActionKind::Delete));
        }
        drop(store);
        let (mut app, rx) = test_app_with_db(scenario.db_path.clone());
        root_dataset(&mut app, &scenario.root);
        open_and_settle(&mut app, &rx, scan_id, OpenIntent::Commander);
        drain(&mut app, &rx);

        prepare_and_settle(&mut app, &rx);
        assert!(
            matches!(app.commander.overlay, Overlay::Confirm { .. }),
            "{}",
            app.commander.status
        );
        let text = summary_text(&mut app);
        assert!(text.contains("Actions to be executed: 1 of 2"), "{text}");
        let plan = app.commander.pending_plan.as_ref().unwrap();
        let aside: Vec<&Path> = (0..plan.actions().len())
            .filter(|index| plan.is_set_aside(*index))
            .map(|index| plan.actions()[index].target())
            .collect();
        assert_eq!(
            aside,
            vec![there.as_path()],
            "and the plan Y runs keeps it out"
        );
        assert!(text.contains("1 cannot run here"), "{text}");
        assert!(
            text.contains("target file's dataset could not be determined"),
            "{text}"
        );
    }

    /// When nothing of the plan can run where its files are, no confirmation opens: the status
    /// line says what the batch would have said after Y.
    #[test]
    fn a_plan_where_nothing_can_run_opens_no_confirmation() {
        let _role = role_guard();
        let (scenario, scan_id, _keeper, copy) = marked_before_a_restart("cannot_run_all");
        // No dataset covers the scenario: the host reported none.
        let (mut app, rx) = test_app_with_db(scenario.db_path.clone());
        open_and_settle(&mut app, &rx, scan_id, OpenIntent::Commander);
        drain(&mut app, &rx);

        prepare_and_settle(&mut app, &rx);
        assert_eq!(
            app.commander.overlay,
            Overlay::None,
            "{}",
            app.commander.status
        );
        assert!(app.commander.pending_plan.is_none());
        assert_eq!(
            app.commander.status,
            format!(
                "nothing done — 1 action cannot run: target file's dataset could not be \
                 determined; no snapshot taken, marks kept; first: {}",
                copy.display()
            )
        );
    }

    /// Reopening the same scan shows what the database holds now — the classic interface's
    /// auto-select comes back to the commander this way — and drops the panels' marks before
    /// they hear from it again.
    #[test]
    fn a_reopen_shows_the_marks_the_database_holds_now() {
        let _role = role_guard();
        let (scenario, scan_id, keeper, copy) = marked_before_a_restart("reopen_same");
        let (mut app, rx) = test_app_with_db(scenario.db_path.clone());
        open_and_settle(&mut app, &rx, scan_id, OpenIntent::Commander);
        list_in_panel(&mut app, &rx, 0, &scenario.root);
        {
            let mut store = scenario.store();
            scenario.mark(&mut store, scan_id, &copy, false, Some(ActionKind::Reflink));
        }

        open_and_settle(&mut app, &rx, scan_id, OpenIntent::Commander);
        assert!(
            app.commander
                .panels
                .iter()
                .all(|panel| panel.marks.is_empty()),
            "{:?}",
            app.commander.panels[0].marks
        );
        pump_until(&mut app, &rx, "the panels' answers", |app| {
            app.routes.panels.is_empty()
        });
        let marks = &app.commander.panels[0].marks;
        assert_eq!(marks.get(&keeper), Some(&Mark::Keeper), "{marks:?}");
        assert_eq!(marks.get(&copy), Some(&Mark::Reflink), "{marks:?}");
    }

    /// A refresh answered while «Clear all marks» is on its way is settled like any other: a clear
    /// the database refuses changes nothing, and the panel goes on showing the saved marks.
    #[test]
    fn a_refused_clear_leaves_the_saved_marks_on_the_panels() {
        let _role = role_guard();
        let (scenario, scan_id, keeper, copy) = marked_before_a_restart("refused_clear");
        let (mut app, rx) = test_app_with_db(scenario.db_path.clone());
        open_and_settle(&mut app, &rx, scan_id, OpenIntent::Commander);
        list_in_panel(&mut app, &rx, 0, &scenario.root);
        rusqlite::Connection::open(&scenario.db_path)
            .unwrap()
            .execute_batch(
                "CREATE TRIGGER refuse_clear BEFORE DELETE ON file_mark
                 BEGIN SELECT RAISE(ABORT, 'clearing refused'); END;",
            )
            .unwrap();
        // A reopen drops the panels' marks and asks every panel again; the clear queues behind.
        app.open_via_actor(scan_id, OpenIntent::Commander);
        pump_until(&mut app, &rx, "the reopen", |app| app.routes.open.is_none());
        app.send_commander_clear().unwrap();
        pump_until(&mut app, &rx, "the refreshes and the clear", |app| {
            app.routes.panels.is_empty() && app.pending_marks.is_empty()
        });

        assert!(
            app.commander.status.contains("not cleared"),
            "{}",
            app.commander.status
        );
        let marks = &app.commander.panels[0].marks;
        assert_eq!(marks.get(&keeper), Some(&Mark::Keeper), "{marks:?}");
        assert_eq!(marks.get(&copy), Some(&Mark::Delete), "{marks:?}");
    }

    /// A database replaced under the open view takes its marks off the panels with the rest of
    /// it: a mark left on screen could be cleared there only, and the next open would bring it
    /// back. F11 then says there is no scan — not that nothing is marked: the marks are in a
    /// database nobody can read now.
    #[test]
    fn a_replaced_database_takes_its_marks_off_the_panels() {
        let _role = role_guard();
        let (scenario, scan_id, keeper, _copy) = marked_before_a_restart("replaced_db");
        let (mut app, rx) = test_app_with_db(scenario.db_path.clone());
        open_and_settle(&mut app, &rx, scan_id, OpenIntent::Commander);
        list_in_panel(&mut app, &rx, 0, &scenario.root);
        assert_eq!(
            app.commander.panels[0].marks.get(&keeper),
            Some(&Mark::Keeper)
        );

        std::fs::remove_file(&scenario.db_path).unwrap();
        std::fs::create_dir(&scenario.db_path).unwrap();
        list_in_panel(&mut app, &rx, 0, &scenario.root);

        assert!(
            app.commander.dedup_scan_id.is_none(),
            "the view is uninstalled: {}",
            app.commander.status
        );
        assert!(
            app.commander
                .panels
                .iter()
                .all(|panel| panel.marks.is_empty()),
            "{:?}",
            app.commander.panels[0].marks
        );
        prepare_execution(&mut app);
        assert_eq!(
            app.commander.status,
            "No scan is loaded — load one (F2/F12) before executing actions"
        );
    }

    /// A saved mark this program could not have written — keeper and action at once — stays off
    /// the panel, the rest of the panel's answer still lands, and F11 refuses it by name.
    #[test]
    fn a_corrupt_saved_mark_stays_off_the_panel_and_refuses_by_name() {
        let _role = role_guard();
        let scenario = PlanScenario::new("corrupt_saved_mark");
        let keeper = scenario.file("keeper.bin");
        let copy = scenario.file("copy.bin");
        let mut store = scenario.store();
        let scan_id = scenario.seed(&mut store, &[keeper.clone(), copy.clone()]);
        scenario.mark(&mut store, scan_id, &keeper, true, None);
        scenario.mark(&mut store, scan_id, &copy, true, Some(ActionKind::Delete));
        drop(store);
        let (mut app, rx) = test_app_with_db(scenario.db_path.clone());
        open_and_settle(&mut app, &rx, scan_id, OpenIntent::Commander);
        list_in_panel(&mut app, &rx, 0, &scenario.root);

        let marks = &app.commander.panels[0].marks;
        assert_eq!(marks.get(&keeper), Some(&Mark::Keeper), "{marks:?}");
        assert_eq!(marks.get(&copy), None, "{marks:?}");
        assert!(
            app.commander.dedup.dir(&scenario.root).is_some(),
            "the panel's answer landed: {}",
            app.commander.status
        );

        prepare_and_settle(&mut app, &rx);
        assert!(
            matches!(app.commander.overlay, Overlay::None),
            "{}",
            app.commander.status
        );
        assert!(
            app.commander.status.contains(&copy.display().to_string()),
            "the refusal names the file: {}",
            app.commander.status
        );
    }
}
