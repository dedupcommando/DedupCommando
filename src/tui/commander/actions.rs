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
pub fn prepare_execution(app: &mut App) {
    if app.deny_if_read_only("executing actions") {
        return;
    }
    let requested = requested_marks(app);
    if requested.is_empty() {
        app.commander.status = "No marked files (F5/F6/F7/F8)".to_string();
        return;
    }
    if app.commander.dedup_scan_id.is_none() {
        app.commander.status =
            "No scan is loaded — load one (F2/F12) before executing actions".to_string();
        return;
    }
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

/// Seats a plan the authority just built: its script, its digest and its overlay, together.
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
    use std::path::PathBuf;

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
}
