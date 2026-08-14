use std::collections::VecDeque;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::{Arc, Mutex, mpsc};
use std::thread;

use super::*;

const SCHEDULER_INCOMPLETE: &str =
    "parallel scheduler stopped before every selected Matrix plan was launched";

struct PlanWork {
    index: usize,
    group_index: usize,
    matrix_plan_id: String,
    group: GroupProgress,
    report: PlanReport,
    plan: PlannedPlan,
    lane: OidfDriverLane,
}

enum WorkerMessage {
    Progress {
        index: usize,
        snapshot: Box<ProgressSnapshot>,
    },
    Finished {
        index: usize,
        summary: Box<RunSummary>,
    },
    Panicked,
    Stopped,
}

struct ChannelSink {
    index: usize,
    sender: mpsc::Sender<WorkerMessage>,
}

impl ProgressSink for ChannelSink {
    fn update(&mut self, event: &ProgressEvent) {
        let _ = self.sender.send(WorkerMessage::Progress {
            index: self.index,
            snapshot: Box::new(event.snapshot.clone()),
        });
    }
}

pub(super) fn run<S: ProgressSink>(runner: &ConformanceRunner, sink: &mut S) -> RunSummary {
    // Phase 1 is single-owner and completes before any worker is launched.
    // This freezes the complete denominator and gives cleanup one inventory
    // containing every Suite plan, including plans never dequeued after a
    // later worker failure or interruption.
    let prepared = runner.prepare_run();
    sink.update(&ProgressEvent {
        snapshot: snapshot(
            &prepared.groups,
            prepared.current_profile.clone(),
            prepared.current_variant.clone(),
            None,
        ),
    });
    if !prepared.errors.is_empty() || prepared.planned.is_empty() {
        return runner.run_prepared(sink, prepared);
    }

    let mut prepared = prepared;
    let work = plan_work(&mut prepared);
    let worker_count = runner.config.jobs.min(work.len());
    let queue = Arc::new(Mutex::new(VecDeque::from(
        (0..work.len()).collect::<Vec<_>>(),
    )));
    let stop_launching = Arc::new(AtomicBool::new(false));
    let ciba_lane = Arc::new(Mutex::new(()));
    let mut snapshots = vec![None::<ProgressSnapshot>; work.len()];
    let mut finished = vec![false; work.len()];
    let mut results = vec![None::<RunSummary>; work.len()];
    let mut worker_panicked = false;

    let work_ref = &work;
    thread::scope(|scope| {
        let (sender, receiver) = mpsc::channel::<WorkerMessage>();
        for worker_index in 0..worker_count {
            let sender = sender.clone();
            let queue = Arc::clone(&queue);
            let stop_launching = Arc::clone(&stop_launching);
            let ciba_lane = Arc::clone(&ciba_lane);
            scope.spawn(move || {
                let worker = catch_unwind(AssertUnwindSafe(|| {
                    loop {
                        if stop_launching.load(Ordering::SeqCst)
                            || runner.config.control.is_interrupted()
                        {
                            break;
                        }
                        let next = match queue.lock() {
                            Ok(mut queue) => queue.pop_front(),
                            Err(_) => None,
                        };
                        let Some(next_index) = next else {
                            break;
                        };
                        let child = ConformanceRunner {
                            config: ConformanceRunConfig {
                                client: runner.config.client.clone(),
                                matrix: runner.config.matrix.clone(),
                                target_origin: runner.config.target_origin.clone(),
                                binding: runner.config.binding.clone(),
                                poll_timeout: runner.config.poll_timeout,
                                control: runner.config.control.clone(),
                                plan_lanes: runner.config.plan_lanes.clone(),
                                jobs: 1,
                                automation: runner
                                    .config
                                    .automation
                                    .get(worker_index)
                                    .cloned()
                                    .into_iter()
                                    .collect(),
                            },
                        };
                        let mut progress = ChannelSink {
                            index: next_index,
                            sender: sender.clone(),
                        };
                        let _ciba_guard = if work_ref[next_index].lane == OidfDriverLane::Ciba {
                            Some(ciba_lane.lock().map_err(|_| ()).expect("CIBA lane lock"))
                        } else {
                            None
                        };
                        let summary = child
                            .run_prepared(&mut progress, worker_prepared(&work_ref[next_index]));
                        if has_fatal_orchestration_failure(&summary.report) {
                            stop_launching.store(true, Ordering::SeqCst);
                        }
                        if sender
                            .send(WorkerMessage::Finished {
                                index: next_index,
                                summary: Box::new(summary),
                            })
                            .is_err()
                        {
                            break;
                        }
                    }
                }));
                if worker.is_err() {
                    stop_launching.store(true, Ordering::SeqCst);
                    let _ = sender.send(WorkerMessage::Panicked);
                }
                let _ = sender.send(WorkerMessage::Stopped);
            });
        }
        drop(sender);

        let mut stopped_workers = 0usize;
        while stopped_workers < worker_count {
            match receiver.recv() {
                Ok(WorkerMessage::Progress { index, snapshot }) => {
                    snapshots[index] = Some(*snapshot);
                    sink.update(&ProgressEvent {
                        snapshot: aggregate_progress(
                            &prepared.groups,
                            &work,
                            &snapshots,
                            &finished,
                        ),
                    });
                }
                Ok(WorkerMessage::Finished { index, summary }) => {
                    snapshots[index] = Some(summary.report.progress.clone());
                    finished[index] = true;
                    results[index] = Some(*summary);
                    sink.update(&ProgressEvent {
                        snapshot: aggregate_progress(
                            &prepared.groups,
                            &work,
                            &snapshots,
                            &finished,
                        ),
                    });
                }
                Ok(WorkerMessage::Panicked) => {
                    stop_launching.store(true, Ordering::SeqCst);
                    worker_panicked = true;
                }
                Ok(WorkerMessage::Stopped) => stopped_workers += 1,
                Err(_) => break,
            }
        }
    });

    merge_reports(
        runner,
        prepared,
        &work,
        snapshots,
        finished,
        results,
        worker_panicked,
    )
}

fn plan_work(prepared: &mut PreparedRun) -> Vec<PlanWork> {
    std::mem::take(&mut prepared.planned)
        .into_iter()
        .enumerate()
        .map(|(index, plan)| {
            let lane = plan.lane;
            PlanWork {
                index,
                group_index: plan.group_index,
                matrix_plan_id: plan.matrix_plan_id.clone(),
                group: prepared.groups[plan.group_index].clone(),
                report: prepared.plans[plan.report_index].clone(),
                plan,
                lane,
            }
        })
        .collect()
}

fn worker_prepared(work: &PlanWork) -> PreparedRun {
    let mut group = work.group.clone();
    group.completed = 0;
    group.total = work.plan.modules.len();
    group.status = GroupStatus::Remaining;
    group.passed = 0;
    group.reviewed = 0;
    group.skipped = 0;
    group.failed = 0;
    group.running = 0;
    group.remaining = group.total;
    let mut plan = work.plan.clone();
    plan.group_index = 0;
    plan.report_index = 0;
    let mut report = work.report.clone();
    report.created_instances = 0;
    PreparedRun {
        groups: vec![group.clone()],
        plans: vec![report],
        planned: vec![plan],
        // Workers cancel their runner modules, while the phase-1 owner
        // deletes every plan after all workers have drained.
        suite_plan_ids: Vec::new(),
        errors: Vec::new(),
        auth_probe: None,
        current_profile: Some(group.profile),
        current_variant: Some(redacted_variant(&work.plan.variant)),
    }
}

fn aggregate_progress(
    base_groups: &[GroupProgress],
    work: &[PlanWork],
    snapshots: &[Option<ProgressSnapshot>],
    finished: &[bool],
) -> ProgressSnapshot {
    let mut groups = base_groups.to_vec();
    for group in &mut groups {
        group.completed = 0;
        group.status = GroupStatus::Remaining;
        group.passed = 0;
        group.reviewed = 0;
        group.skipped = 0;
        group.failed = 0;
        group.running = 0;
        group.remaining = group.total;
    }
    for (index, worker_snapshot) in snapshots.iter().enumerate() {
        let Some(source) = worker_snapshot
            .as_ref()
            .and_then(|snapshot| snapshot.groups.first())
        else {
            continue;
        };
        let target = &mut groups[work[index].group_index];
        target.completed += source.completed;
        target.passed += source.passed;
        target.reviewed += source.reviewed;
        target.skipped += source.skipped;
        target.failed += source.failed;
        target.running += source.running;
    }
    for (group_index, group) in groups.iter_mut().enumerate() {
        group.remaining = group
            .total
            .saturating_sub(group.completed.saturating_add(group.running));
        let indices = work
            .iter()
            .filter(|work| work.group_index == group_index)
            .map(|work| work.index)
            .collect::<Vec<_>>();
        let any_failed = indices.iter().any(|index| {
            snapshots[*index]
                .as_ref()
                .and_then(|snapshot| snapshot.groups.first())
                .is_some_and(|group| group.status == GroupStatus::Failed)
        });
        let any_review = indices.iter().any(|index| {
            snapshots[*index]
                .as_ref()
                .and_then(|snapshot| snapshot.groups.first())
                .is_some_and(|group| group.status == GroupStatus::Review)
        });
        let any_skipped = indices.iter().any(|index| {
            snapshots[*index]
                .as_ref()
                .and_then(|snapshot| snapshot.groups.first())
                .is_some_and(|group| group.status == GroupStatus::Skipped)
        });
        group.status = if any_failed {
            GroupStatus::Failed
        } else if indices.iter().all(|index| finished[*index]) {
            if any_review {
                GroupStatus::Review
            } else if any_skipped {
                GroupStatus::Skipped
            } else {
                GroupStatus::Passed
            }
        } else if indices.iter().any(|index| snapshots[*index].is_some()) {
            GroupStatus::Running
        } else {
            GroupStatus::Remaining
        };
    }
    let current = snapshots
        .iter()
        .enumerate()
        .find(|(index, snapshot)| !finished[*index] && snapshot.is_some())
        .and_then(|(_, snapshot)| snapshot.as_ref());
    snapshot(
        &groups,
        current.and_then(|snapshot| snapshot.current_profile.clone()),
        current.and_then(|snapshot| snapshot.current_variant.clone()),
        current.and_then(|snapshot| snapshot.current_test.clone()),
    )
}

fn merge_reports(
    runner: &ConformanceRunner,
    prepared: PreparedRun,
    work: &[PlanWork],
    snapshots: Vec<Option<ProgressSnapshot>>,
    finished: Vec<bool>,
    results: Vec<Option<RunSummary>>,
    worker_panicked: bool,
) -> RunSummary {
    let all_plans_finished = results.iter().all(Option::is_some);
    let progress = aggregate_progress(&prepared.groups, work, &snapshots, &finished);
    let mut errors = prepared.errors;
    let mut plans = prepared.plans;
    let mut modules = Vec::new();
    let mut cleanup = CleanupReport::default();
    if worker_panicked {
        errors.push("parallel plan worker panicked".to_owned());
    }
    for (index, summary) in results.into_iter().enumerate() {
        let Some(summary) = summary else {
            continue;
        };
        let report = summary.report;
        if let Some(plan_report) = report.plans.first() {
            plans[work[index].plan.report_index].created_instances = plan_report.created_instances;
        }
        for error in report.errors {
            if error == "run interrupted" {
                if !errors.iter().any(|existing| existing == &error) {
                    errors.push(error);
                }
            } else {
                errors.push(format!("{}: {error}", work[index].matrix_plan_id));
            }
        }
        modules.extend(report.modules);
        cleanup.cancelled.extend(report.cleanup.cancelled);
        cleanup.failures.extend(report.cleanup.failures);
    }

    // Phase 1 owns every Suite plan. Deletion is deliberately centralized
    // after all workers stop so one worker can never delete a plan another
    // worker still needs, and queued plans are cleaned even if never run.
    cleanup_all(
        &runner.config.client,
        &[],
        &prepared.suite_plan_ids,
        &mut cleanup,
    );

    if !all_plans_finished && !errors.iter().any(|error| error == "run interrupted") {
        errors.push(SCHEDULER_INCOMPLETE.to_owned());
    }
    let defined_modules = plans.iter().map(|plan| plan.defined_modules).sum();
    let created_instances = plans.iter().map(|plan| plan.created_instances).sum();
    let terminal_modules = modules.iter().filter(|module| module.terminal).count();
    let cleanup_complete = cleanup.failures.is_empty();
    let all_modules_instantiated = all_plans_finished && defined_modules == created_instances;
    let all_modules_terminal = all_modules_instantiated && terminal_modules == defined_modules;
    let outcomes = summarize_module_outcomes(&modules);
    let suite_pass = defined_modules > 0 && all_modules_terminal && outcomes.all_passed;
    let orchestration_integrity = OrchestrationIntegrity {
        defined_modules,
        created_instances,
        terminal_modules,
        all_modules_instantiated,
        all_modules_terminal,
        cleanup_complete,
    };
    let local_success =
        errors.is_empty() && all_modules_instantiated && all_modules_terminal && cleanup_complete;
    RunSummary {
        report: ConformanceReport {
            schema: 3,
            matrix_digest: runner.config.matrix.digest.clone(),
            suite_origin: runner.config.client.origin().to_string(),
            auth_probe: prepared.auth_probe,
            errors,
            local_success,
            suite_pass,
            human_review_required: !outcomes.human_review_modules.is_empty(),
            human_review_modules: outcomes.human_review_modules,
            skipped_modules: outcomes.skipped_modules,
            failed_modules: outcomes.failed_modules,
            incomplete_modules: outcomes.incomplete_modules,
            orchestration_integrity,
            progress,
            plans,
            modules,
            cleanup,
        },
    }
}

fn has_fatal_orchestration_failure(report: &ConformanceReport) -> bool {
    !report.orchestration_integrity.cleanup_complete || !report.errors.is_empty()
}

#[cfg(test)]
mod tests;
