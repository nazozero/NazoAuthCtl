//! Controller key expiry rendering for explicit live slot results (goal plan
//! 04 §2, task D09).
//!
//! The NazoAuth server owns the 30-day clock: `issued_at` is stamped at
//! enrollment and `expires_at = issued_at + 2_592_000s`, judged with server
//! time. Nothing in ctl may decide authorization from a local clock, so this
//! module only renders the live slot snapshot returned by the explicit
//! controller-list request. Display caches never participate in signing,
//! admission, or expiry decisions.

use chrono::{DateTime, Utc};

use crate::controller_identity::admin_api::{ControllerSlotView, SlotsSnapshot};

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

    /// Human-readable single-line rendering used by fleet/status output.
    pub fn render(self) -> String {
        match self {
            Self::Ok { seconds_remaining } => {
                crate::ui::message!(
                    "valid ({} remaining)",
                    "有效（剩余 {}）",
                    human_duration(seconds_remaining)
                )
            }
            Self::Warning { seconds_remaining } => crate::ui::message!(
                "WARNING: expires in {} — plan a rotation",
                "将在 {} 后到期，请安排更换密钥",
                human_duration(seconds_remaining)
            ),
            Self::Urgent { seconds_remaining } => crate::ui::message!(
                "URGENT: expires in {} — rotate now",
                "将在 {} 后到期，请立即更换密钥",
                human_duration(seconds_remaining)
            ),
            Self::Expired { seconds_overdue } => crate::ui::message!(
                "EXPIRED {} ago — new operations require rotation",
                "已过期 {}，执行新操作前需更换密钥",
                human_duration(seconds_overdue)
            ),
        }
    }
}

/// Compact duration rendering for diagnostics (`3d`, `5h`, `42s`).
pub fn human_duration(seconds: i64) -> String {
    let seconds = seconds.max(0);
    if seconds < 60 {
        crate::ui::message!("{seconds}s", "{seconds} 秒")
    } else if seconds < 3_600 {
        crate::ui::message!("{}m", "{} 分钟", seconds / 60)
    } else if seconds < 86_400 {
        crate::ui::message!("{}h", "{} 小时", seconds / 3_600)
    } else {
        let days = seconds / 86_400;
        let hours = (seconds % 86_400) / 3_600;
        if hours == 0 {
            crate::ui::message!("{days}d", "{days} 天")
        } else {
            crate::ui::message!("{days}d{hours}h", "{days} 天 {hours} 小时")
        }
    }
}

pub(super) fn server_warning(slot: &ControllerSlotView) -> &'static str {
    match slot.warning {
        Some(kind) => match kind {
            crate::controller_identity::admin_api::ExpiryWarningKind::Expiring7d => {
                crate::ui::text(" server-warning=expiring_7d", " 服务端提醒：7 天内到期")
            }
            crate::controller_identity::admin_api::ExpiryWarningKind::Urgent24h => {
                crate::ui::text(" server-warning=urgent_24h", " 服务端提醒：24 小时内到期")
            }
        },
        None => "",
    }
}

/// Render one slot row for `controller slots` output including the live
/// classification against `now`.
pub fn render_slot_line(slot: &ControllerSlotView, now: DateTime<Utc>) -> String {
    let status = ExpiryStatus::classify(now, slot.expires_at);
    let warning = server_warning(slot);
    crate::ui::message!(
        "slot {} controller {} label '{}' {} [{}]{}\n",
        "槽位 {} | 控制器 {} | 名称“{}” | 密钥 {} | 状态 {}{}\n",
        slot.slot_index,
        slot.controller_id,
        slot.label,
        crate::controller_identity::admin_api::short_kid(&slot.kid),
        slot.status.as_str(),
        warning,
    )
    .trim_end()
    .to_owned()
        + &crate::ui::message!("\n  expiry: {}", "\n  有效期：{}", status.render())
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
    use crate::controller_identity::admin_api::SlotStatus;
    use chrono::Duration;

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
    fn live_renderings_are_stable() {
        let now = Utc::now();
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
}
