//! Controller key expiry UX and local guard rails (goal plan 04 §2, task
//! D09).
//!
//! The NazoAuth server owns the 30-day clock: `issued_at` is stamped at
//! enrollment and `expires_at = issued_at + 2_592_000s`, judged with server
//! time. Nothing in ctl may decide authorization from a local clock, so this
//! module only renders and *pre-screens* the authoritative facts the server
//! reported:
//!
//! * status/doctor/fleet surfaces show per-instance days-to-expiry warnings
//!   (>7d info, ≤7d warning, ≤24h urgent, expired error) sourced from the
//!   server slot snapshot cached in the instance observation;
//! * new application-level operations fail early — before signing — when the
//!   cached authority says the active identity is already expired, with the
//!   rotate command spelled out. The server remains the final authority; a
//!   stale cache can only cause an unnecessary refusal that refresh clears.
//!
//! Resumed operations never consult these helpers again: once accepted, the
//! journal authorization snapshot (goal plan 05 §5) owns the decision.

use chrono::{DateTime, Utc};

use crate::controller_identity::admin_api::{ControllerSlotView, SlotStatus, SlotsSnapshot};

/// Warning threshold in days (D02/D09): remaining validity at or below this
/// is surfaced as a warning.
pub const WARNING_WINDOW_DAYS: i64 = 7;

/// Urgent threshold in hours (D02/D09).
pub const URGENT_WINDOW_HOURS: i64 = 24;

/// Fixed controller key lifetime per goal plan 04 §2 (30 days, not a natural
/// month, not configurable).
pub const KEY_LIFETIME_SECONDS: i64 = 2_592_000;

/// Classification of remaining validity relative to `now`.
///
/// The thresholds follow the task table exactly:
/// `remaining > 7d` → [`ExpiryStatus::Ok`], `0 < remaining ≤ 7d` → warning,
/// `0 < remaining ≤ 24h` → urgent, `remaining ≤ 0` → expired.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExpiryStatus {
    Ok { seconds_remaining: i64 },
    Warning { seconds_remaining: i64 },
    Urgent { seconds_remaining: i64 },
    Expired { seconds_overdue: i64 },
}

impl ExpiryStatus {
    pub fn classify(now: DateTime<Utc>, expires_at: DateTime<Utc>) -> Self {
        let seconds_remaining = (expires_at - now).num_seconds();
        if seconds_remaining <= 0 {
            Self::Expired {
                seconds_overdue: -seconds_remaining,
            }
        } else if seconds_remaining <= URGENT_WINDOW_HOURS * 3_600 {
            Self::Urgent { seconds_remaining }
        } else if seconds_remaining <= WARNING_WINDOW_DAYS * 86_400 {
            Self::Warning { seconds_remaining }
        } else {
            Self::Ok { seconds_remaining }
        }
    }

    pub fn is_expired(self) -> bool {
        matches!(self, Self::Expired { .. })
    }

    /// Human-readable single-line rendering used by fleet/status output.
    pub fn render(self) -> String {
        match self {
            Self::Ok { seconds_remaining } => {
                format!("valid ({} remaining)", human_duration(seconds_remaining))
            }
            Self::Warning { seconds_remaining } => format!(
                "WARNING: expires in {} — plan a rotation",
                human_duration(seconds_remaining)
            ),
            Self::Urgent { seconds_remaining } => format!(
                "URGENT: expires in {} — rotate now",
                human_duration(seconds_remaining)
            ),
            Self::Expired { seconds_overdue } => format!(
                "EXPIRED {} ago — new operations require rotation",
                human_duration(seconds_overdue)
            ),
        }
    }

    /// Stable machine code for scripted consumers.
    pub fn code(self) -> &'static str {
        match self {
            Self::Ok { .. } => "ok",
            Self::Warning { .. } => "expiring_7d",
            Self::Urgent { .. } => "urgent_24h",
            Self::Expired { .. } => "expired",
        }
    }
}

/// Compact duration rendering for diagnostics (`3d`, `5h`, `42s`).
pub fn human_duration(seconds: i64) -> String {
    let seconds = seconds.max(0);
    if seconds < 60 {
        format!("{seconds}s")
    } else if seconds < 3_600 {
        format!("{}m", seconds / 60)
    } else if seconds < 86_400 {
        format!("{}h", seconds / 3_600)
    } else {
        let days = seconds / 86_400;
        let hours = (seconds % 86_400) / 3_600;
        if hours == 0 {
            format!("{days}d")
        } else {
            format!("{days}d{hours}h")
        }
    }
}

/// Rotate guidance appended to early failures (D09.3).
pub fn rotate_guidance(alias: &str) -> String {
    format!(
        "run `nazauthctl controller rotate --instance {alias}` and have an administrator \
         approve the new key with fresh 2FA"
    )
}

/// One cached slot fact embedded into the instance observation summary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CachedSlotFact {
    pub controller_id: String,
    pub kid: String,
    pub status: SlotStatus,
    pub expires_at: DateTime<Utc>,
}

/// Encode a server slot snapshot into the observation-cache summary line.
/// The cache is display data only; nothing authorizes off it.
pub fn summarize_slots(snapshot: &SlotsSnapshot) -> String {
    let mut line = format!(
        "controller-slots n={} max={}",
        snapshot.items.len(),
        snapshot.max_active_slots
    );
    for slot in &snapshot.items {
        line.push_str(&format!(
            " | {}:{}:{}:{}",
            slot.controller_id,
            slot.kid,
            slot.status.as_str(),
            slot.expires_at.to_rfc3339()
        ));
    }
    line
}

/// Recover the cached slot facts from an observation summary produced by
/// [`summarize_slots`]. Anything not matching the exact format yields `None`;
/// partial corruption degrades to "no cached knowledge", never to guessed
/// facts.
pub fn parse_cached_slots(summary: &str) -> Option<Vec<CachedSlotFact>> {
    let mut segments = summary.split(" | ");
    let mut head = segments.next()?.split_whitespace();
    if head.next()? != "controller-slots" {
        return None;
    }
    // Head carries two numeric attributes: n=<len> and max=<max>.
    let mut count: Option<usize> = None;
    for token in head {
        if let Some(value) = token.strip_prefix("n=") {
            count = value.parse().ok();
        } else if token.starts_with("max=") && token[4..].bytes().all(|byte| byte.is_ascii_digit())
        {
            continue;
        } else {
            return None;
        }
    }
    let count = count?;
    let mut facts = Vec::new();
    for segment in segments {
        let mut parts = segment.splitn(4, ':');
        let controller_id = parts.next()?.to_owned();
        let kid = parts.next()?.to_owned();
        let status = SlotStatus::parse(parts.next()?).ok()?;
        let expires_at = DateTime::parse_from_rfc3339(parts.next()?)
            .ok()?
            .with_timezone(&Utc);
        facts.push(CachedSlotFact {
            controller_id,
            kid,
            status,
            expires_at,
        });
    }
    if facts.len() != count {
        return None;
    }
    Some(facts)
}

/// Render one slot row for `controller slots` output including the live
/// classification against `now`.
pub fn render_slot_line(slot: &ControllerSlotView, now: DateTime<Utc>) -> String {
    let status = ExpiryStatus::classify(now, slot.expires_at);
    let warning = match slot.warning {
        Some(kind) => match kind {
            crate::controller_identity::admin_api::ExpiryWarningKind::Expiring7d => {
                " server-warning=expiring_7d"
            }
            crate::controller_identity::admin_api::ExpiryWarningKind::Urgent24h => {
                " server-warning=urgent_24h"
            }
        },
        None => "",
    };
    format!(
        "slot {} controller {} label '{}' {} [{}]{}\n",
        slot.slot_index,
        slot.controller_id,
        slot.label,
        crate::controller_identity::admin_api::short_kid(&slot.kid),
        slot.status.as_str(),
        warning,
    )
    .trim_end()
    .to_owned()
        + &format!("\n  expiry: {}", status.render())
}

/// Find the cached fact for one kid.
pub fn cached_fact_for<'a>(facts: &'a [CachedSlotFact], kid: &str) -> Option<&'a CachedSlotFact> {
    facts.iter().find(|fact| fact.kid == kid)
}

/// Slots of one snapshot restricted to active entries (helper shared by
/// flows).
pub fn active_slot_for_controller_id<'a>(
    snapshot: &'a SlotsSnapshot,
    controller_id: &str,
) -> Option<&'a ControllerSlotView> {
    snapshot
        .active_slots()
        .into_iter()
        .find(|slot| slot.controller_id == controller_id)
}

/// True when any active slot exists for the deployment (bind/add decisions).
pub fn has_active_slot(snapshot: &SlotsSnapshot) -> bool {
    !snapshot.active_slots().is_empty()
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    fn at(days: i64, seconds: i64) -> DateTime<Utc> {
        Utc::now() + Duration::days(days) + Duration::seconds(seconds)
    }

    #[test]
    fn classification_matches_the_task_table_exactly() {
        let now = Utc::now();
        // > 7d → ok
        assert!(matches!(
            ExpiryStatus::classify(
                now,
                now + Duration::seconds(WARNING_WINDOW_DAYS * 86_400 + 1)
            ),
            ExpiryStatus::Ok { .. }
        ));
        assert!(matches!(
            ExpiryStatus::classify(now, now + Duration::days(29)),
            ExpiryStatus::Ok { .. }
        ));
        // exactly 7d → warning boundary
        assert!(matches!(
            ExpiryStatus::classify(now, now + Duration::seconds(WARNING_WINDOW_DAYS * 86_400)),
            ExpiryStatus::Warning { .. }
        ));
        // between 24h and 7d → warning
        assert!(matches!(
            ExpiryStatus::classify(now, now + Duration::hours(25)),
            ExpiryStatus::Warning { .. }
        ));
        // exactly 24h → urgent boundary
        assert!(matches!(
            ExpiryStatus::classify(now, now + Duration::hours(URGENT_WINDOW_HOURS)),
            ExpiryStatus::Urgent { .. }
        ));
        // 1s before expiry → urgent
        assert!(matches!(
            ExpiryStatus::classify(now, now + Duration::seconds(1)),
            ExpiryStatus::Urgent { .. }
        ));
        // exactly at expiry → expired
        assert!(matches!(
            ExpiryStatus::classify(now, now),
            ExpiryStatus::Expired { .. }
        ));
        // past expiry → expired with positive overdue measure
        match ExpiryStatus::classify(now, now - Duration::seconds(3600)) {
            ExpiryStatus::Expired { seconds_overdue } => assert_eq!(seconds_overdue, 3600),
            other => panic!("expected expired, got {other:?}"),
        }
    }

    #[test]
    fn codes_and_renderings_are_stable() {
        let now = Utc::now();
        assert_eq!(
            ExpiryStatus::classify(now, now + Duration::days(20)).code(),
            "ok"
        );
        assert_eq!(
            ExpiryStatus::classify(now, now + Duration::days(3)).code(),
            "expiring_7d"
        );
        assert_eq!(
            ExpiryStatus::classify(now, now + Duration::hours(2)).code(),
            "urgent_24h"
        );
        assert_eq!(ExpiryStatus::classify(now, now).code(), "expired");

        let rendered = ExpiryStatus::classify(now, now + Duration::days(12)).render();
        assert!(rendered.starts_with("valid ("), "{rendered}");
        let rendered = ExpiryStatus::classify(now, now + Duration::days(3)).render();
        assert!(rendered.contains("WARNING"), "{rendered}");
        let rendered = ExpiryStatus::classify(now, now + Duration::hours(5)).render();
        assert!(rendered.contains("URGENT"), "{rendered}");
        let rendered = ExpiryStatus::classify(now, now - Duration::days(1)).render();
        assert!(rendered.contains("EXPIRED"), "{rendered}");
    }

    #[test]
    fn human_duration_is_compact() {
        assert_eq!(human_duration(59), "59s");
        assert_eq!(human_duration(120), "2m");
        assert_eq!(human_duration(7_200), "2h");
        assert_eq!(human_duration(86_400), "1d");
        assert_eq!(human_duration(90_000), "1d1h");
        assert_eq!(human_duration(-5), "0s");
    }

    #[test]
    fn slot_summary_round_trips_through_the_cache_format() {
        let expires_first = at(30, 0);
        let expires_second = at(10, 0);
        let snapshot = SlotsSnapshot {
            deployment_id: "deploy-alpha".to_owned(),
            total: 2,
            max_active_slots: 3,
            items: vec![
                ControllerSlotView {
                    deployment_id: "deploy-alpha".to_owned(),
                    controller_id: "c-1".to_owned(),
                    label: "ops".to_owned(),
                    kid: "kid-one".to_owned(),
                    slot_index: 0,
                    issued_at: at(0, 0),
                    expires_at: expires_first,
                    status: SlotStatus::Active,
                    warning: None,
                },
                ControllerSlotView {
                    deployment_id: "deploy-alpha".to_owned(),
                    controller_id: "c-2".to_owned(),
                    label: "backup".to_owned(),
                    kid: "kid-two".to_owned(),
                    slot_index: 1,
                    issued_at: at(0, 0),
                    expires_at: expires_second,
                    status: SlotStatus::Revoked,
                    warning: None,
                },
            ],
        };
        let summary = summarize_slots(&snapshot);
        assert!(
            summary.starts_with("controller-slots n=2 max=3 | "),
            "{summary}"
        );

        let facts = parse_cached_slots(&summary).expect("round trip");
        assert_eq!(facts.len(), 2);
        assert_eq!(facts[0].controller_id, "c-1");
        assert_eq!(facts[0].status, SlotStatus::Active);
        assert_eq!(facts[1].status, SlotStatus::Revoked);

        let fact = cached_fact_for(&facts, "kid-two").expect("found");
        assert_eq!(fact.expires_at, expires_second);
        assert!(cached_fact_for(&facts, "missing").is_none());

        // Corruption degrades to None, never to guessed facts.
        assert!(parse_cached_slots("something else").is_none());
        assert!(parse_cached_slots("controller-slots n=5 max=3").is_none());
        let truncated = summary.split(" | ").take(2).collect::<Vec<_>>().join(" | ");
        assert!(parse_cached_slots(&truncated).is_none());
    }

    #[test]
    fn slot_lines_carry_expiry_classification_and_server_warning() {
        let now = Utc::now();
        let slot = ControllerSlotView {
            deployment_id: "deploy-alpha".to_owned(),
            controller_id: "c-1".to_owned(),
            label: "ops".to_owned(),
            kid: "kid-one-value".to_owned(),
            slot_index: 0,
            issued_at: now - Duration::days(27),
            expires_at: now + Duration::days(3),
            status: SlotStatus::Active,
            warning: Some(crate::controller_identity::admin_api::ExpiryWarningKind::Urgent24h),
        };
        let line = render_slot_line(&slot, now);
        assert!(line.contains("server-warning=urgent_24h"), "{line}");
        assert!(line.contains("expiry: WARNING"), "{line}");
        assert!(line.contains("[active]"), "{line}");

        let plain = ControllerSlotView {
            warning: None,
            ..slot
        };
        let line = render_slot_line(&plain, now);
        assert!(!line.contains("server-warning"), "{line}");
    }

    #[test]
    fn guidance_names_the_rotate_command() {
        let text = rotate_guidance("prod");
        assert!(text.contains("controller rotate --instance prod"), "{text}");
        assert!(text.to_lowercase().contains("fresh 2fa"), "{text}");
    }
}
