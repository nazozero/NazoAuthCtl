use std::io::Write;

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Matrix variants are normally short public labels. Still, a malformed or
/// private artifact must not turn a token-like value into terminal output.
pub fn redacted_variant(values: &BTreeMap<String, String>) -> BTreeMap<String, String> {
    values
        .iter()
        .map(|(key, value)| {
            let lower = key.to_ascii_lowercase();
            let sensitive_key = [
                "token",
                "secret",
                "password",
                "authorization",
                "private",
                "credential",
                "key",
            ]
            .iter()
            .any(|needle| lower.contains(needle));
            let safe_value = if sensitive_key
                || value.len() > 256
                || value.bytes().any(|byte| byte.is_ascii_control())
            {
                "<redacted>".to_owned()
            } else {
                value.clone()
            };
            (key.clone(), safe_value)
        })
        .collect()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum GroupStatus {
    Passed,
    Failed,
    Running,
    Remaining,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GroupProgress {
    pub id: String,
    pub profile: String,
    pub completed: usize,
    pub total: usize,
    pub status: GroupStatus,
    /// Item-level counters. `completed == passed + failed`; `running` is the
    /// currently instantiated Suite module (the runner is serial by design).
    #[serde(default)]
    pub passed: usize,
    #[serde(default)]
    pub failed: usize,
    #[serde(default)]
    pub running: usize,
    #[serde(default)]
    pub remaining: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProgressSnapshot {
    pub completed: usize,
    pub total: usize,
    pub groups: Vec<GroupProgress>,
    pub passed_groups: usize,
    pub failed_groups: usize,
    pub running_groups: usize,
    pub remaining_groups: usize,
    /// Item-level counters used for the overall progress contract. The
    /// denominator is frozen from the Matrix modules defined during phase 1.
    #[serde(default)]
    pub passed: usize,
    #[serde(default)]
    pub failed: usize,
    #[serde(default)]
    pub running: usize,
    #[serde(default)]
    pub remaining: usize,
    /// The currently executing Matrix context. This is deliberately a
    /// summary; Suite configuration and logs are never emitted here.
    pub current_profile: Option<String>,
    pub current_variant: Option<BTreeMap<String, String>>,
    pub current_test: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProgressEvent {
    pub snapshot: ProgressSnapshot,
}

pub trait ProgressSink {
    fn update(&mut self, event: &ProgressEvent);
}

impl ProgressSink for () {
    fn update(&mut self, _event: &ProgressEvent) {}
}

pub struct StableRenderer<W: Write> {
    writer: W,
}

impl<W: Write> StableRenderer<W> {
    pub fn new(writer: W) -> Self {
        Self { writer }
    }

    pub fn into_inner(self) -> W {
        self.writer
    }
}

impl<W: Write> ProgressSink for StableRenderer<W> {
    fn update(&mut self, event: &ProgressEvent) {
        let _ = writeln!(
            self.writer,
            "NazoAuth OIDF Conformance: {}/{} ({:>3}%) Passed {} · Failed {} · Running {} · Remaining {}{}",
            event.snapshot.completed,
            event.snapshot.total,
            percent(event.snapshot.completed, event.snapshot.total),
            event.snapshot.passed,
            event.snapshot.failed,
            event.snapshot.running,
            event.snapshot.remaining,
            current_label(&event.snapshot)
        );
        let _ = self.writer.flush();
    }
}

pub struct TtyRenderer<W: Write> {
    writer: W,
}

impl<W: Write> TtyRenderer<W> {
    pub fn new(writer: W) -> Self {
        Self { writer }
    }

    pub fn into_inner(self) -> W {
        self.writer
    }
}

impl<W: Write> ProgressSink for TtyRenderer<W> {
    fn update(&mut self, event: &ProgressEvent) {
        // Clear the previous compact frame. Progress is item based and never
        // estimates duration, so no ETA is printed.
        let _ = write!(self.writer, "\x1b[2J\x1b[H");
        let (filled, empty) = bar(event.snapshot.completed, event.snapshot.total, 20);
        let _ = writeln!(self.writer, "NazoAuth OIDF Conformance");
        let _ = writeln!(
            self.writer,
            "Overall  {}{}  {:>3}%",
            "█".repeat(filled),
            "░".repeat(empty),
            percent(event.snapshot.completed, event.snapshot.total)
        );
        let _ = writeln!(
            self.writer,
            "         {} / {}",
            event.snapshot.completed, event.snapshot.total
        );
        let _ = writeln!(self.writer);
        for group in &event.snapshot.groups {
            let symbol = match group.status {
                GroupStatus::Passed => '✓',
                GroupStatus::Failed => '✗',
                GroupStatus::Running => '●',
                GroupStatus::Remaining => '○',
            };
            let _ = writeln!(
                self.writer,
                "{} {:<32} {:>4} / {:<4}",
                symbol,
                format!("{} · {}", group.profile, group.id),
                group.completed,
                group.total
            );
        }
        let _ = writeln!(self.writer);
        let _ = writeln!(self.writer, "Current:");
        let _ = writeln!(
            self.writer,
            "  {}",
            current_matrix_label(
                event.snapshot.current_profile.as_deref(),
                event.snapshot.current_variant.as_ref()
            )
        );
        let _ = writeln!(
            self.writer,
            "  {}",
            event.snapshot.current_test.as_deref().unwrap_or("-")
        );
        let _ = writeln!(self.writer);
        let _ = writeln!(
            self.writer,
            "Passed {} · Failed {} · Running {} · Remaining {}",
            event.snapshot.passed,
            event.snapshot.failed,
            event.snapshot.running,
            event.snapshot.remaining
        );
        let _ = self.writer.flush();
    }
}

fn current_label(snapshot: &ProgressSnapshot) -> String {
    format!(
        " current={}/{}",
        current_matrix_label(
            snapshot.current_profile.as_deref(),
            snapshot.current_variant.as_ref()
        ),
        snapshot.current_test.as_deref().unwrap_or("-")
    )
}

fn current_matrix_label(
    profile: Option<&str>,
    variant: Option<&BTreeMap<String, String>>,
) -> String {
    let profile = profile.unwrap_or("-");
    let variant = variant
        .map(|values| {
            values
                .iter()
                .map(|(key, value)| format!("{key}={value}"))
                .collect::<Vec<_>>()
                .join(",")
        })
        .unwrap_or_default();
    if variant.is_empty() {
        profile.to_owned()
    } else {
        format!("{profile}/{variant}")
    }
}

fn percent(completed: usize, total: usize) -> usize {
    completed
        .saturating_mul(100)
        .checked_div(total)
        .unwrap_or(0)
}

fn bar(completed: usize, total: usize, width: usize) -> (usize, usize) {
    let filled = completed
        .saturating_mul(width)
        .checked_div(total)
        .unwrap_or(0)
        .min(width);
    (filled, width - filled)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stable_renderer_has_no_escape_sequences() {
        let mut output = Vec::new();
        let mut renderer = StableRenderer::new(&mut output);
        renderer.update(&ProgressEvent {
            snapshot: ProgressSnapshot {
                completed: 1,
                total: 2,
                groups: vec![],
                passed_groups: 0,
                failed_groups: 0,
                running_groups: 0,
                remaining_groups: 0,
                passed: 1,
                failed: 0,
                running: 0,
                remaining: 1,
                current_profile: None,
                current_variant: None,
                current_test: None,
            },
        });
        assert!(!String::from_utf8(output).expect("utf8").contains('\u{1b}'));
    }

    #[test]
    fn renderer_includes_current_matrix_context_without_config() {
        let mut output = Vec::new();
        let mut renderer = StableRenderer::new(&mut output);
        let mut variant = BTreeMap::new();
        variant.insert("mode".to_owned(), "plain".to_owned());
        renderer.update(&ProgressEvent {
            snapshot: ProgressSnapshot {
                completed: 0,
                total: 1,
                groups: vec![GroupProgress {
                    id: "g".to_owned(),
                    profile: "oidc".to_owned(),
                    completed: 0,
                    total: 1,
                    status: GroupStatus::Running,
                    passed: 0,
                    failed: 0,
                    running: 1,
                    remaining: 0,
                }],
                passed_groups: 0,
                failed_groups: 0,
                running_groups: 1,
                remaining_groups: 0,
                passed: 0,
                failed: 0,
                running: 1,
                remaining: 0,
                current_profile: Some("oidc".to_owned()),
                current_variant: Some(variant),
                current_test: Some("test".to_owned()),
            },
        });
        let text = String::from_utf8(output).expect("utf8");
        assert!(text.contains("oidc/mode=plain/test"));
        assert!(!text.contains("config"));
    }

    #[test]
    fn tty_renderer_is_item_based_and_has_no_eta() {
        let mut output = Vec::new();
        let mut renderer = TtyRenderer::new(&mut output);
        renderer.update(&ProgressEvent {
            snapshot: ProgressSnapshot {
                completed: 2,
                total: 3,
                groups: vec![GroupProgress {
                    id: "fapi".to_owned(),
                    profile: "FAPI 2.0".to_owned(),
                    completed: 2,
                    total: 3,
                    status: GroupStatus::Running,
                    passed: 2,
                    failed: 0,
                    running: 1,
                    remaining: 0,
                }],
                passed_groups: 0,
                failed_groups: 0,
                running_groups: 1,
                remaining_groups: 0,
                passed: 2,
                failed: 0,
                running: 1,
                remaining: 0,
                current_profile: Some("FAPI 2.0".to_owned()),
                current_variant: Some(BTreeMap::from([("mode".to_owned(), "mTLS".to_owned())])),
                current_test: Some("fapi-test".to_owned()),
            },
        });
        let text = String::from_utf8(output).expect("utf8");
        assert!(text.contains("NazoAuth OIDF Conformance"));
        assert!(text.contains("Overall"));
        assert!(text.contains("Passed 2 · Failed 0 · Running 1 · Remaining 0"));
        assert!(text.contains("FAPI 2.0/mode=mTLS"));
        assert!(!text.contains("ETA"));
    }
}
