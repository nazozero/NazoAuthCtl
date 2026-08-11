use std::collections::VecDeque;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::{Arc, Mutex, mpsc};
use std::thread;

use super::*;
use crate::matrix::{MatrixDocument, SelectedMatrix};

const SUITE_NON_SUCCESS: &str = "Suite reported a non-success or incomplete module result";
const SCHEDULER_INCOMPLETE: &str =
    "parallel scheduler stopped before every selected Matrix plan was launched";

#[derive(Clone)]
struct PlanWork {
    index: usize,
    group_index: usize,
    matrix_plan_id: String,
    matrix: SelectedMatrix,
    serialized_ciba: bool,
}

enum WorkerMessage {
    Progress {
        index: usize,
        snapshot: ProgressSnapshot,
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
            snapshot: event.snapshot.clone(),
        });
    }
}

pub(super) fn run<S: ProgressSink>(runner: &ConformanceRunner, sink: &mut S) -> RunSummary {
    let work = plan_work(&runner.config.matrix);
    let worker_count = runner.config.jobs.min(work.len());
    let queue = Arc::new(Mutex::new(VecDeque::from(work.clone())));
    let stop_launching = Arc::new(AtomicBool::new(false));
    let ciba_lane = Arc::new(Mutex::new(()));
    let mut snapshots = vec![None::<ProgressSnapshot>; work.len()];
    let mut finished = vec![false; work.len()];
    let mut results = vec![None::<RunSummary>; work.len()];
    let mut worker_panicked = false;

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
                        let Some(next) = next else {
                            break;
                        };
                        let child = ConformanceRunner {
                            config: ConformanceRunConfig {
                                client: runner.config.client.clone(),
                                matrix: next.matrix.clone(),
                                target_origin: runner.config.target_origin.clone(),
                                binding: runner.config.binding.clone(),
                                poll_timeout: runner.config.poll_timeout,
                                control: runner.config.control.clone(),
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
                            index: next.index,
                            sender: sender.clone(),
                        };
                        // The validated Python runner keeps CIBA globally
                        // serial. Browser/VCI/VP plans use this worker's own
                        // automation lane and may overlap other workers.
                        let _ciba_guard = if next.serialized_ciba {
                            Some(ciba_lane.lock().map_err(|_| ()).expect("CIBA lane lock"))
                        } else {
                            None
                        };
                        let summary = child.run_serial(&mut progress);
                        if has_fatal_orchestration_failure(&summary.report) {
                            stop_launching.store(true, Ordering::SeqCst);
                        }
                        if sender
                            .send(WorkerMessage::Finished {
                                index: next.index,
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
                    snapshots[index] = Some(snapshot);
                    sink.update(&ProgressEvent {
                        snapshot: aggregate_progress(
                            &runner.config.matrix,
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
                            &runner.config.matrix,
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

    merge_reports(runner, &work, snapshots, finished, results, worker_panicked)
}

fn plan_work(matrix: &SelectedMatrix) -> Vec<PlanWork> {
    let mut work = Vec::new();
    for (group_index, group) in matrix.document.groups.iter().enumerate() {
        for plan in &group.plans {
            work.push(PlanWork {
                index: work.len(),
                group_index,
                matrix_plan_id: plan.id.clone(),
                serialized_ciba: plan.plan.contains("ciba"),
                matrix: SelectedMatrix {
                    document: MatrixDocument {
                        schema: matrix.document.schema,
                        name: matrix.document.name.clone(),
                        groups: vec![crate::matrix::MatrixGroup {
                            id: group.id.clone(),
                            profile: group.profile.clone(),
                            variant: group.variant.clone(),
                            plans: vec![plan.clone()],
                        }],
                    },
                    digest: matrix.digest.clone(),
                },
            });
        }
    }
    work
}

fn aggregate_progress(
    matrix: &SelectedMatrix,
    work: &[PlanWork],
    snapshots: &[Option<ProgressSnapshot>],
    finished: &[bool],
) -> ProgressSnapshot {
    let mut groups = matrix
        .document
        .groups
        .iter()
        .map(|group| GroupProgress {
            id: group.id.clone(),
            profile: group.profile.clone(),
            completed: 0,
            total: 0,
            status: GroupStatus::Remaining,
            passed: 0,
            failed: 0,
            running: 0,
            remaining: 0,
        })
        .collect::<Vec<_>>();
    for (index, snapshot) in snapshots.iter().enumerate() {
        let Some(source) = snapshot
            .as_ref()
            .and_then(|snapshot| snapshot.groups.first())
        else {
            continue;
        };
        let target = &mut groups[work[index].group_index];
        target.completed += source.completed;
        target.total += source.total;
        target.passed += source.passed;
        target.failed += source.failed;
        target.running += source.running;
        target.remaining += source.remaining;
    }
    for (group_index, group) in groups.iter_mut().enumerate() {
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
        group.status = if any_failed {
            GroupStatus::Failed
        } else if indices.iter().all(|index| finished[*index]) {
            GroupStatus::Passed
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
    work: &[PlanWork],
    snapshots: Vec<Option<ProgressSnapshot>>,
    finished: Vec<bool>,
    results: Vec<Option<RunSummary>>,
    worker_panicked: bool,
) -> RunSummary {
    let all_plans_finished = results.iter().all(Option::is_some);
    let progress = aggregate_progress(&runner.config.matrix, work, &snapshots, &finished);
    let mut auth_probe = None;
    let mut errors = Vec::new();
    let mut plans = Vec::new();
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
        auth_probe = auth_probe.or(report.auth_probe);
        for error in report.errors {
            if error == SUITE_NON_SUCCESS {
                continue;
            }
            if error == "run interrupted" {
                if !errors.iter().any(|existing| existing == &error) {
                    errors.push(error);
                }
            } else {
                errors.push(format!("{}: {error}", work[index].matrix_plan_id));
            }
        }
        plans.extend(report.plans);
        modules.extend(report.modules);
        cleanup.cancelled.extend(report.cleanup.cancelled);
        cleanup.deleted_plans.extend(report.cleanup.deleted_plans);
        cleanup
            .immutable_plans
            .extend(report.cleanup.immutable_plans);
        cleanup.failures.extend(report.cleanup.failures);
    }

    if !all_plans_finished && !errors.iter().any(|error| error == "run interrupted") {
        errors.push(SCHEDULER_INCOMPLETE.to_owned());
    }
    let defined_modules = plans.iter().map(|plan| plan.defined_modules).sum();
    let created_instances = plans.iter().map(|plan| plan.created_instances).sum();
    let terminal_modules = modules.iter().filter(|module| module.terminal).count();
    let cleanup_complete = cleanup.failures.is_empty();
    let all_modules_instantiated = all_plans_finished && defined_modules == created_instances;
    let all_modules_terminal = all_modules_instantiated && terminal_modules == defined_modules;
    let suite_pass = all_modules_terminal && modules.iter().all(accepted_module_outcome);
    if !suite_pass && !errors.iter().any(|error| error == SUITE_NON_SUCCESS) {
        errors.push(SUITE_NON_SUCCESS.to_owned());
    }
    let human_review_modules = modules
        .iter()
        .filter(|module| module.human_review_required)
        .map(|module| format!("{}/{}", module.matrix_plan_id, module.test_name))
        .collect::<Vec<_>>();
    let orchestration_integrity = OrchestrationIntegrity {
        defined_modules,
        created_instances,
        terminal_modules,
        all_modules_instantiated,
        all_modules_terminal,
        cleanup_complete,
    };
    let local_success = errors.is_empty()
        && suite_pass
        && all_modules_instantiated
        && all_modules_terminal
        && cleanup_complete;
    RunSummary {
        report: ConformanceReport {
            schema: 2,
            matrix_digest: runner.config.matrix.digest.clone(),
            suite_origin: runner.config.client.origin().to_string(),
            auth_probe,
            errors,
            local_success,
            suite_pass,
            human_review_required: !human_review_modules.is_empty(),
            human_review_modules,
            orchestration_integrity,
            progress,
            plans,
            modules,
            cleanup,
        },
    }
}

fn has_fatal_orchestration_failure(report: &ConformanceReport) -> bool {
    !report.orchestration_integrity.cleanup_complete
        || report.errors.iter().any(|error| error != SUITE_NON_SUCCESS)
}

#[cfg(test)]
mod tests;
