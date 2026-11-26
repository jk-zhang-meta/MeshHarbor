// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! FR-139 — Owner-only, edge-triggered GPU alert engine (§7.6, D4).
//!
//! Invariants:
//! - Alerts fire ONLY for `Agent.owner_user_id` AND ONLY while that user is
//!   still a member of `Agent.tenant_id` (NEVER alert share viewers or non-owners!).
//! - Edge-triggered with a 10 min (`cooldown_secs`) per-(host, event) cooldown:
//!   - Free-GPU rule: fires after `free_hold_secs` (2 min) continuous match.
//!   - `held_idle`: enter / leave edges.
//!   - Faults: Xid coalesced 3 min, ECC uncorrected or remapped rows increase,
//!     GPU count drop / `lost`, throttle `hw_slowdown`/`thermal` > 60 s.
//!   - Machine: offline > 5 min (via timer), `driver_reboot_pending`,
//!     `sampler_stalled` / `driver_hung` / `unavailable`.

use std::collections::{HashMap, HashSet};

use bson::{DateTime, oid::ObjectId};
use meshharbor_config::GpuSettings;
use meshharbor_remote_control::gpu::{
    GpuHostStatus, GpuReport, GpuState, GpuStateThresholds, classify_gpu_state,
};
use serde::{Deserialize, Serialize};

use super::bots::BotAlertItem;

pub const RULES_COLLECTION: &str = "gpu_alert_rules";

/// Maximum distinct GPU UUIDs tracked per host inside [`AlertEvaluator`].
const MAX_CARDS_PER_HOST: usize = 64;
/// Maximum cooldown keys retained per host inside [`AlertEvaluator`].
const MAX_COOLDOWNS_PER_HOST: usize = 256;

fn gpu_host_link(tenant_id: ObjectId, agent_id: ObjectId) -> String {
    format!("/tenant/{}/gpu?host={}", tenant_id.to_hex(), agent_id.to_hex())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GpuAlertRule {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,
    pub tenant_id: ObjectId,
    pub user_id: ObjectId,
    #[serde(default)]
    pub enabled: bool,
    /// Fire when at least `N` GPUs on a host are continuously free for 2 min.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub free_gpus_min: Option<u16>,
    /// Minimum free VRAM per card (GiB) to count toward `free_gpus_min`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub free_min_mem_gb: Option<u32>,
    #[serde(default = "default_true")]
    pub held_idle_alert: bool,
    #[serde(default = "default_true")]
    pub fault_alert: bool,
    #[serde(default = "default_true")]
    pub machine_alert: bool,
    #[serde(default = "default_lang")]
    pub lang: String,
    pub updated_at: DateTime,
}

fn default_true() -> bool {
    true
}
fn default_lang() -> String {
    "en".to_string()
}

impl GpuAlertRule {
    pub fn default_for(tenant_id: ObjectId, user_id: ObjectId) -> Self {
        Self {
            id: None,
            tenant_id,
            user_id,
            enabled: false,
            free_gpus_min: None,
            free_min_mem_gb: None,
            held_idle_alert: true,
            fault_alert: true,
            machine_alert: true,
            lang: "en".to_string(),
            updated_at: DateTime::now(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct FiredAlert {
    pub event_key: String,
    pub item: BotAlertItem,
}

#[derive(Default)]
struct CardTrack {
    held_idle: bool,
    throttle_since: Option<i64>,
    throttle_active: bool,
    last_ecc: Option<u64>,
    last_remapped: Option<u32>,
    last_xid_at: Option<i64>,
    last_xids: Vec<u32>,
    xid_coalesce_until: i64,
    lost_active: bool,
    vendor_health_bad: Option<String>,
    vendor_health_delivered_sev: Option<u8>,
}

#[derive(Default)]
struct HostTrack {
    free_rule_since: Option<i64>,
    free_rule_active: bool,
    last_gpu_count: Option<usize>,
    count_drop_active: bool,
    machine_status_bad: Option<GpuHostStatus>,
    offline_since: Option<i64>,
    offline_active: bool,
    cards: HashMap<String, CardTrack>,
    cooldowns: HashMap<String, i64>,
}

/// Pure, in-memory edge-triggered alert state machine.
#[derive(Default)]
pub struct AlertEvaluator {
    hosts: HashMap<ObjectId, HostTrack>,
}

impl AlertEvaluator {
    /// Remove all tracked state for a host (e.g. unmarked or deleted).
    pub fn remove_host(&mut self, agent_id: ObjectId) {
        self.hosts.remove(&agent_id);
    }

    /// Evict retired hosts no longer present in the marked GPU fleet.
    pub fn prune_stale_hosts(&mut self, active: &HashSet<ObjectId>) {
        self.hosts.retain(|aid, _| active.contains(aid));
    }

    /// Evaluate one fresh report against `rule` and return any newly fired edges.
    #[allow(clippy::too_many_arguments)]
    pub fn evaluate_report(
        &mut self,
        tenant_id: ObjectId,
        agent_id: ObjectId,
        host_name: &str,
        report: &GpuReport,
        now_s: i64,
        settings: &GpuSettings,
        rule: &GpuAlertRule,
    ) -> Vec<FiredAlert> {
        let mut fired = Vec::new();
        let host = self.hosts.entry(agent_id).or_default();
        let host_link = gpu_host_link(tenant_id, agent_id);
        // Prune expired cooldown entries to keep per-host memory strictly bounded.
        host.cooldowns
            .retain(|_, ts| now_s.saturating_sub(*ts) < settings.cooldown_secs);

        // Receiving a report clears any pending/active offline state.
        if host.offline_active && rule.enabled && rule.machine_alert {
            let key = "machine:offline_clear".to_string();
            if can_fire(host, &key, now_s, settings.cooldown_secs) {
                fired.push(FiredAlert {
                    event_key: key,
                    item: BotAlertItem {
                        severity: "info".into(),
                        title_en: format!("{host_name} back online"),
                        title_zh: format!("{host_name} 已恢复在线"),
                        body_en: format!("GPU telemetry resumed on {host_name}."),
                        body_zh: format!("{host_name} 的 GPU 遥测已恢复。"),
                        users_summary: None,
                        link: host_link.clone(),
                    },
                });
            }
        }
        host.offline_since = None;
        host.offline_active = false;

        if !rule.enabled {
            return fired;
        }

        let thresholds = GpuStateThresholds {
            free_mem_max_mb: settings.free_mem_max_mb,
            idle_util_pct: settings.idle_util_pct,
            held_idle_secs: settings.held_idle_secs,
        };

        // 1. Machine status problems (`driver_missing` with detected hardware,
        // `driver_reboot_pending`, `sampler_stalled`, `driver_hung`,
        // `unavailable`) — enter / clear edges. Only emit recovery when the
        // host affirmatively returns to `Ok` or `Limited` (never when moving
        // from `sampler_stalled` to `off_local` or `driver_missing`).
        let bad_status = match report.status {
            GpuHostStatus::DriverRebootPending
            | GpuHostStatus::SamplerStalled
            | GpuHostStatus::DriverHung
            | GpuHostStatus::Unavailable => Some(report.status),
            GpuHostStatus::DriverMissing
                if report
                    .status_detail
                    .as_deref()
                    .is_some_and(|s| !s.trim().is_empty())
                    || !report.gpus.is_empty() =>
            {
                Some(GpuHostStatus::DriverMissing)
            }
            _ => None,
        };
        let affirmatively_recovered =
            matches!(report.status, GpuHostStatus::Ok | GpuHostStatus::Limited);

        if rule.machine_alert {
            if let Some(st) = bad_status {
                if host.machine_status_bad != Some(st) {
                    host.machine_status_bad = Some(st);
                    let key = format!("machine:{}", st.wire());
                    if can_fire(host, &key, now_s, settings.cooldown_secs) {
                        let detail_en = report
                            .status_detail
                            .as_deref()
                            .filter(|s| !s.trim().is_empty())
                            .map(|s| format!(" ({s})"))
                            .unwrap_or_default();
                        fired.push(FiredAlert {
                            event_key: key,
                            item: BotAlertItem {
                                severity: "critical".into(),
                                title_en: format!("{host_name}: GPU sampler {}", st.wire()),
                                title_zh: format!("{host_name}: GPU 采样异常 ({})", st.wire()),
                                body_en: format!(
                                    "Host {host_name} reported status {}{detail_en}.",
                                    st.wire()
                                ),
                                body_zh: format!(
                                    "主机 {host_name} 报告状态 {}{detail_en}。",
                                    st.wire()
                                ),
                                users_summary: None,
                                link: host_link.clone(),
                            },
                        });
                    }
                }
            } else if affirmatively_recovered
                && let Some(prev) = host.machine_status_bad.take()
            {
                let key = format!("machine:clear:{}", prev.wire());
                if can_fire(host, &key, now_s, settings.cooldown_secs) {
                    fired.push(FiredAlert {
                        event_key: key,
                        item: BotAlertItem {
                            severity: "info".into(),
                            title_en: format!("{host_name}: GPU telemetry recovered"),
                            title_zh: format!("{host_name}: GPU 遥测已恢复"),
                            body_en: format!("Host {host_name} recovered from {}.", prev.wire()),
                            body_zh: format!("主机 {host_name} 已从 {} 恢复。", prev.wire()),
                            users_summary: None,
                            link: host_link.clone(),
                        },
                    });
                }
            } else if !affirmatively_recovered {
                // Transitioned to `off_local` / `no_gpu` / `unknown` — clear
                // active bad flag quietly without emitting a false recovery.
                host.machine_status_bad = None;
            }
        }

        // 2. GPU count drop (only when status == Ok so a stalled sampler doesn't
        // double-fire as a count drop).
        let capped_gpus = &report.gpus[..report.gpus.len().min(MAX_CARDS_PER_HOST)];
        if rule.fault_alert && report.status == GpuHostStatus::Ok {
            let cur_count = capped_gpus.len();
            if let Some(prev_count) = host.last_gpu_count {
                if cur_count < prev_count && !host.count_drop_active {
                    host.count_drop_active = true;
                    let key = "fault:gpu_count_drop".to_string();
                    if can_fire(host, &key, now_s, settings.cooldown_secs) {
                        fired.push(FiredAlert {
                            event_key: key,
                            item: BotAlertItem {
                                severity: "critical".into(),
                                title_en: format!("{host_name}: GPU count dropped ({prev_count} -> {cur_count})"),
                                title_zh: format!("{host_name}: GPU 数量减少 ({prev_count} -> {cur_count})"),
                                body_en: format!("Visible GPUs on {host_name} dropped from {prev_count} to {cur_count}."),
                                body_zh: format!("{host_name} 可见 GPU 数量从 {prev_count} 降至 {cur_count}。"),
                                users_summary: None,
                                link: host_link.clone(),
                            },
                        });
                    }
                } else if cur_count >= prev_count {
                    host.count_drop_active = false;
                }
            }
            if cur_count > host.last_gpu_count.unwrap_or(0) {
                host.last_gpu_count = Some(cur_count);
            }
        }

        // 3. Per-card edges: free count, held_idle, faults (lost / ECC / remapped / Xid / throttle).
        let min_free_mb = rule.free_min_mem_gb.unwrap_or(0).saturating_mul(1024);
        let mut qualifying_free: u16 = 0;
        let mut present_uuids: HashSet<String> = HashSet::with_capacity(capped_gpus.len());

        for g in capped_gpus {
            present_uuids.insert(g.uuid.clone());
            let st = classify_gpu_state(report.status, g, now_s, thresholds);
            if meshharbor_remote_control::gpu::is_card_allocatable_free(
                report.status,
                g,
                now_s,
                thresholds,
                min_free_mb,
            ) {
                qualifying_free = qualifying_free.saturating_add(1);
            }

            let users_str = collect_card_users(g);
            let card_label = format!("GPU #{} ({})", g.idx, g.name.as_deref().unwrap_or(&g.uuid));
            let mut card = host.cards.remove(&g.uuid).unwrap_or_default();

            // 3a. held_idle enter / leave
            if rule.held_idle_alert {
                if st == GpuState::HeldIdle && !card.held_idle {
                    card.held_idle = true;
                    let key = format!("held_idle:{}", g.uuid);
                    if can_fire(host, &key, now_s, settings.cooldown_secs) {
                        fired.push(FiredAlert {
                            event_key: key,
                            item: BotAlertItem {
                                severity: "warning".into(),
                                title_en: format!("{host_name} {card_label} held idle"),
                                title_zh: format!("{host_name} {card_label} 占卡空闲"),
                                body_en: format!(
                                    "{card_label} holds {} MiB VRAM at {}% util for >= {} min.",
                                    g.mem_used_mb.unwrap_or(0),
                                    g.util_pct.unwrap_or(0),
                                    settings.held_idle_secs / 60
                                ),
                                body_zh: format!(
                                    "{card_label} 占用 {} MiB 显存但利用率仅 {}% 已超过 {} 分钟。",
                                    g.mem_used_mb.unwrap_or(0),
                                    g.util_pct.unwrap_or(0),
                                    settings.held_idle_secs / 60
                                ),
                                users_summary: users_str.clone(),
                                link: host_link.clone(),
                            },
                        });
                    }
                } else if st != GpuState::HeldIdle && card.held_idle {
                    card.held_idle = false;
                }
            }

            // 3b. Faults: lost, vendor health, ECC increase, remapped increase, Xid edge (3 min coalesce), throttle > 60 s
            if rule.fault_alert {
                if g.lost && !card.lost_active {
                    card.lost_active = true;
                    let key = format!("fault:lost:{}", g.uuid);
                    if can_fire(host, &key, now_s, settings.cooldown_secs) {
                        fired.push(FiredAlert {
                            event_key: key,
                            item: BotAlertItem {
                                severity: "critical".into(),
                                title_en: format!("{host_name} {card_label} fell off the bus"),
                                title_zh: format!("{host_name} {card_label} 掉卡（设备无响应）"),
                                body_en: format!(
                                    "Accelerator {card_label} on {host_name} is no longer responding (lost)."
                                ),
                                body_zh: format!(
                                    "{host_name} 上的 {card_label} 失去响应（掉卡）。"
                                ),
                                users_summary: None,
                                link: host_link.clone(),
                            },
                        });
                    }
                } else if !g.lost {
                    card.lost_active = false;
                }

                let bad_vh = g.vendor_health.as_deref().and_then(|raw| {
                    meshharbor_remote_control::gpu::vendor_health_severity(raw)
                        .map(|sev| (raw.trim(), sev))
                });
                if let Some((vh, sev_str)) = bad_vh {
                    let sev_rank: u8 = if sev_str == "critical" { 2 } else { 1 };
                    let prev_sev = card.vendor_health_delivered_sev.unwrap_or(0);
                    let escalated_to_critical = sev_rank > prev_sev && sev_rank == 2;
                    let state_changed = card.vendor_health_bad.as_deref() != Some(vh);
                    if escalated_to_critical || state_changed {
                        let key = format!("fault:vendor_health:{}", g.uuid);
                        let allowed = escalated_to_critical
                            || can_fire(host, &key, now_s, settings.cooldown_secs);
                        if allowed {
                            if escalated_to_critical {
                                host.cooldowns.insert(key.clone(), now_s);
                            }
                            card.vendor_health_bad = Some(vh.to_string());
                            card.vendor_health_delivered_sev = Some(sev_rank);
                            fired.push(FiredAlert {
                                event_key: key,
                                item: BotAlertItem {
                                    severity: sev_str.into(),
                                    title_en: format!("{host_name} {card_label} health: {vh}"),
                                    title_zh: format!("{host_name} {card_label} 健康状态异常：{vh}"),
                                    body_en: format!(
                                        "{card_label} on {host_name} reported vendor health '{vh}'."
                                    ),
                                    body_zh: format!(
                                        "{host_name} 上的 {card_label} 报告健康状态为「{vh}」。"
                                    ),
                                    users_summary: users_str.clone(),
                                    link: host_link.clone(),
                                },
                            });
                        }
                    }
                } else {
                    card.vendor_health_bad = None;
                    card.vendor_health_delivered_sev = None;
                }

                if let Some(ecc) = g.ecc_uncorrected {
                    if let Some(prev) = card.last_ecc
                        && ecc > prev
                    {
                        let key = format!("fault:ecc:{}", g.uuid);
                        if can_fire(host, &key, now_s, settings.cooldown_secs) {
                            fired.push(FiredAlert {
                                event_key: key,
                                item: BotAlertItem {
                                    severity: "critical".into(),
                                    title_en: format!("{host_name} {card_label} uncorrected ECC ({prev} -> {ecc})"),
                                    title_zh: format!("{host_name} {card_label} 不可纠正 ECC 错误增加 ({prev} -> {ecc})"),
                                    body_en: format!("Uncorrected ECC errors increased on {host_name} {card_label}."),
                                    body_zh: format!("{host_name} {card_label} 出现新的不可纠正 ECC 错误。"),
                                    users_summary: users_str.clone(),
                                    link: host_link.clone(),
                                },
                            });
                        }
                    }
                    card.last_ecc = Some(ecc);
                }

                if let Some(rem) = g.remapped_rows {
                    if let Some(prev) = card.last_remapped
                        && rem > prev
                    {
                        let key = format!("fault:remapped:{}", g.uuid);
                        if can_fire(host, &key, now_s, settings.cooldown_secs) {
                            fired.push(FiredAlert {
                                event_key: key,
                                item: BotAlertItem {
                                    severity: "warning".into(),
                                    title_en: format!("{host_name} {card_label} remapped rows increased ({prev} -> {rem})"),
                                    title_zh: format!("{host_name} {card_label} 坏行重映射增加 ({prev} -> {rem})"),
                                    body_en: format!("Remapped memory rows increased on {host_name} {card_label}."),
                                    body_zh: format!("{host_name} {card_label} 显存重映射行数增加。"),
                                    users_summary: None,
                                    link: host_link.clone(),
                                },
                            });
                        }
                    }
                    card.last_remapped = Some(rem);
                }

                if let Some(xids) = g.xid_errors.as_ref().filter(|v| !v.is_empty()) {
                    let is_new_xid = match g.xid_last_at {
                        Some(ts) => card.last_xid_at.is_none_or(|prev| ts > prev),
                        None => xids.iter().any(|c| !card.last_xids.contains(c)),
                    };
                    let xid_sev = if xids.iter().any(|&c| {
                        meshharbor_remote_control::gpu::xid_severity(c) == "critical"
                    }) {
                        "critical"
                    } else {
                        "warning"
                    };
                    let escalated_hw_xid = is_new_xid
                        && xid_sev == "critical"
                        && !card.last_xids.iter().any(|&c| {
                            meshharbor_remote_control::gpu::xid_severity(c) == "critical"
                        });
                    if is_new_xid && (now_s >= card.xid_coalesce_until || escalated_hw_xid) {
                        let key = format!("fault:xid:{}", g.uuid);
                        let allowed = escalated_hw_xid
                            || can_fire(host, &key, now_s, settings.cooldown_secs);
                        if allowed {
                            if escalated_hw_xid {
                                host.cooldowns.insert(key.clone(), now_s);
                            }
                            card.xid_coalesce_until = now_s + 180; // 3-minute Xid coalesce window
                            let list = xids
                                .iter()
                                .map(|&c| match meshharbor_remote_control::gpu::decode_nvidia_xid(c) {
                                    Some(desc) => format!("{c} ({desc})"),
                                    None => c.to_string(),
                                })
                                .collect::<Vec<_>>()
                                .join(", ");
                            fired.push(FiredAlert {
                                event_key: key,
                                item: BotAlertItem {
                                    severity: xid_sev.into(),
                                    title_en: format!("{host_name} {card_label} Xid error(s): {list}"),
                                    title_zh: format!("{host_name} {card_label} 发生 Xid 故障: {list}"),
                                    body_en: format!("Xid error(s) [{list}] observed on {host_name} {card_label}."),
                                    body_zh: format!("{host_name} {card_label} 检测到 Xid 错误 [{list}]。"),
                                    users_summary: users_str.clone(),
                                    link: host_link.clone(),
                                },
                            });
                            // Advance last-delivered Xid watermark ONLY when an alert actually fired
                            // so newly arriving Xids inside coalesce/cooldown are never permanently lost.
                            if let Some(ts) = g.xid_last_at {
                                card.last_xid_at = Some(card.last_xid_at.map_or(ts, |p| p.max(ts)));
                            }
                            card.last_xids = xids.clone();
                        }
                    }
                } else {
                    card.last_xids.clear();
                }

                let severe_throttle = g.throttle.as_ref().is_some_and(|reasons| {
                    reasons.iter().any(|r| {
                        matches!(
                            r.to_ascii_lowercase().as_str(),
                            "hw_slowdown" | "thermal" | "sw_thermal" | "power_brake"
                        )
                    })
                });
                if severe_throttle {
                    let since = *card.throttle_since.get_or_insert(now_s);
                    if !card.throttle_active && now_s.saturating_sub(since) >= 60 {
                        card.throttle_active = true;
                        let key = format!("fault:throttle:{}", g.uuid);
                        if can_fire(host, &key, now_s, settings.cooldown_secs) {
                            let (temp_en, temp_zh) = match g.temp_c {
                                Some(t) => (format!(" ({t} °C)"), format!("（当前 {t} °C）")),
                                None => (String::new(), String::new()),
                            };
                            fired.push(FiredAlert {
                                event_key: key,
                                item: BotAlertItem {
                                    severity: "warning".into(),
                                    title_en: format!("{host_name} {card_label} thermal/HW throttling"),
                                    title_zh: format!("{host_name} {card_label} 持续硬件/过温降频"),
                                    body_en: format!("{card_label} throttled for > 60 s{temp_en}."),
                                    body_zh: format!("{card_label} 已持续降频超过 60 秒{temp_zh}。"),
                                    users_summary: users_str.clone(),
                                    link: host_link.clone(),
                                },
                            });
                        }
                    }
                } else {
                    card.throttle_since = None;
                    card.throttle_active = false;
                }
            }

            host.cards.insert(g.uuid.clone(), card);
        }

        // Evict disappeared cards so churning/malicious UUID reports cannot leak memory.
        host.cards.retain(|uuid, _| present_uuids.contains(uuid));

        // 4. Free-GPU rule with continuous `free_hold_secs` (default 2 min) hold.
        if let Some(need) = rule.free_gpus_min.filter(|n| *n > 0) {
            if qualifying_free >= need {
                let since = *host.free_rule_since.get_or_insert(now_s);
                if !host.free_rule_active && now_s.saturating_sub(since) >= settings.free_hold_secs
                {
                    host.free_rule_active = true;
                    let key = "free:available".to_string();
                    if can_fire(host, &key, now_s, settings.cooldown_secs) {
                        fired.push(FiredAlert {
                            event_key: key,
                            item: BotAlertItem {
                                severity: "info".into(),
                                title_en: format!("{host_name}: {qualifying_free} GPU(s) free"),
                                title_zh: format!("{host_name}: {qualifying_free} 张 GPU 空闲可用"),
                                body_en: format!(
                                    "{qualifying_free} GPU(s) on {host_name} have been continuously free for >= {} s.",
                                    settings.free_hold_secs
                                ),
                                body_zh: format!(
                                    "{host_name} 上已有 {qualifying_free} 张 GPU 连续空闲超过 {} 秒。",
                                    settings.free_hold_secs
                                ),
                                users_summary: None,
                                link: host_link.clone(),
                            },
                        });
                    }
                }
            } else {
                host.free_rule_since = None;
                host.free_rule_active = false;
            }
        }

        fired
    }

    /// Server timer check for hosts that have been offline > 5 minutes.
    pub fn evaluate_offline(
        &mut self,
        tenant_id: ObjectId,
        agent_id: ObjectId,
        host_name: &str,
        now_s: i64,
        settings: &GpuSettings,
        rule: &GpuAlertRule,
    ) -> Option<FiredAlert> {
        if !rule.enabled || !rule.machine_alert {
            return None;
        }
        let host = self.hosts.entry(agent_id).or_default();
        host.cooldowns
            .retain(|_, ts| now_s.saturating_sub(*ts) < settings.cooldown_secs);
        let since = *host.offline_since.get_or_insert(now_s);
        if !host.offline_active && now_s.saturating_sub(since) >= 300 {
            host.offline_active = true;
            let key = "machine:offline".to_string();
            if can_fire(host, &key, now_s, settings.cooldown_secs) {
                return Some(FiredAlert {
                    event_key: key,
                    item: BotAlertItem {
                        severity: "critical".into(),
                        title_en: format!("{host_name} GPU server offline"),
                        title_zh: format!("{host_name} GPU 服务器离线"),
                        body_en: format!("{host_name} has been offline for > 5 minutes."),
                        body_zh: format!("{host_name} 已离线超过 5 分钟。"),
                        users_summary: None,
                        link: gpu_host_link(tenant_id, agent_id),
                    },
                });
            }
        }
        None
    }
}

fn can_fire(host: &mut HostTrack, key: &str, now_s: i64, cooldown_secs: i64) -> bool {
    if let Some(&last) = host.cooldowns.get(key)
        && now_s.saturating_sub(last) < cooldown_secs
    {
        return false;
    }
    if host.cooldowns.len() >= MAX_COOLDOWNS_PER_HOST {
        host.cooldowns
            .retain(|_, ts| now_s.saturating_sub(*ts) < cooldown_secs);
        if host.cooldowns.len() >= MAX_COOLDOWNS_PER_HOST
            && let Some(oldest) = host
                .cooldowns
                .iter()
                .min_by_key(|(_, ts)| **ts)
                .map(|(k, _)| k.clone())
        {
            host.cooldowns.remove(&oldest);
        }
    }
    host.cooldowns.insert(key.to_string(), now_s);
    true
}

fn collect_card_users(g: &meshharbor_remote_control::gpu::GpuSample) -> Option<String> {
    let procs = g.procs.as_ref()?;
    let mut set: HashSet<&str> = HashSet::new();
    for p in procs {
        if let Some(u) = p.user.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
            set.insert(u);
        }
    }
    if set.is_empty() {
        None
    } else {
        let mut v: Vec<&str> = set.into_iter().collect();
        v.sort_unstable();
        Some(v.join(", "))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use meshharbor_remote_control::gpu::{GpuProc, GpuSample, ProcsState};

    fn free_report() -> GpuReport {
        GpuReport {
            seq: 1,
            interval_ms: 30_000,
            status: GpuHostStatus::Ok,
            status_detail: None,
            backend: Some("nvml".into()),
            driver_version: Some("550.90".into()),
            host: Default::default(),
            gpus: vec![GpuSample {
                uuid: "GPU-0".into(),
                idx: 0,
                name: Some("A100".into()),
                mem_used_mb: Some(128),
                mem_total_mb: Some(81_920),
                util_pct: Some(0),
                procs_state: ProcsState::Ok,
                procs: Some(vec![]),
                ..Default::default()
            }],
        }
    }

    #[test]
    fn fr139_free_alert_requires_2min_hold_and_respects_10min_cooldown() {
        let mut eval = AlertEvaluator::default();
        let aid = ObjectId::new();
        let tid = ObjectId::new();
        let uid = ObjectId::new();
        let settings = GpuSettings::default();
        let mut rule = GpuAlertRule::default_for(tid, uid);
        assert!(!rule.enabled, "alert rule must default opt-in");
        assert!(rule.free_gpus_min.is_none());
        rule.enabled = true;
        rule.free_gpus_min = Some(1);
        let rep = free_report();

        // t=0: starts hold timer, no alert yet
        assert!(eval.evaluate_report(tid, aid, "gpu-01", &rep, 1000, &settings, &rule).is_empty());
        // t=60: still under 120s hold
        assert!(eval.evaluate_report(tid, aid, "gpu-01", &rep, 1060, &settings, &rule).is_empty());
        // t=120: fires once!
        let f = eval.evaluate_report(tid, aid, "gpu-01", &rep, 1120, &settings, &rule);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].event_key, "free:available");
        assert!(f[0].item.link.starts_with(&format!("/tenant/{}/gpu", tid.to_hex())));
        // t=150: stays free -> edge already active -> does NOT repeat
        assert!(eval.evaluate_report(tid, aid, "gpu-01", &rep, 1150, &settings, &rule).is_empty());

        // Busy briefly, then free again within 10 min cooldown -> suppressed!
        let mut busy = rep.clone();
        busy.gpus[0].mem_used_mb = Some(40_000);
        busy.gpus[0].util_pct = Some(80);
        busy.gpus[0].procs = Some(vec![GpuProc {
            pid: 99,
            user: Some("alice".into()),
            mem_mb: Some(40_000),
            ..Default::default()
        }]);
        assert!(eval.evaluate_report(tid, aid, "gpu-01", &busy, 1200, &settings, &rule).is_empty());
        assert!(eval.evaluate_report(tid, aid, "gpu-01", &rep, 1250, &settings, &rule).is_empty());
        assert!(eval.evaluate_report(tid, aid, "gpu-01", &rep, 1400, &settings, &rule).is_empty());

        // Past 10 min cooldown -> fires again!
        assert!(eval.evaluate_report(tid, aid, "gpu-01", &busy, 1750, &settings, &rule).is_empty());
        assert!(eval.evaluate_report(tid, aid, "gpu-01", &rep, 1800, &settings, &rule).is_empty());
        let f2 = eval.evaluate_report(tid, aid, "gpu-01", &rep, 1925, &settings, &rule);
        assert_eq!(f2.len(), 1);
    }

    #[test]
    fn fr139_fault_ecc_throttle_and_offline_edges() {
        let mut eval = AlertEvaluator::default();
        let aid = ObjectId::new();
        let tid = ObjectId::new();
        let uid = ObjectId::new();
        let settings = GpuSettings::default();
        let mut rule = GpuAlertRule::default_for(tid, uid);
        rule.enabled = true;
        rule.free_gpus_min = None;

        let mut rep = free_report();
        rep.gpus[0].ecc_uncorrected = Some(0);
        rep.gpus[0].throttle = Some(vec!["thermal".into()]);
        assert!(eval.evaluate_report(tid, aid, "gpu-01", &rep, 1000, &settings, &rule).is_empty());

        // ECC increases + throttle > 60s
        rep.gpus[0].ecc_uncorrected = Some(2);
        let f = eval.evaluate_report(tid, aid, "gpu-01", &rep, 1065, &settings, &rule);
        let keys: Vec<&str> = f.iter().map(|x| x.event_key.as_str()).collect();
        assert!(keys.contains(&"fault:ecc:GPU-0"), "{keys:?}");
        assert!(keys.contains(&"fault:throttle:GPU-0"), "{keys:?}");

        // Offline > 5 min
        assert!(eval.evaluate_offline(tid, aid, "gpu-01", 2000, &settings, &rule).is_none());
        let off = eval.evaluate_offline(tid, aid, "gpu-01", 2305, &settings, &rule);
        assert!(off.is_some());
        assert_eq!(off.unwrap().event_key, "machine:offline");
    }

    #[test]
    fn fr139_stalled_to_off_local_does_not_fire_false_recovery_and_vendor_health_alerts() {
        let mut eval = AlertEvaluator::default();
        let aid = ObjectId::new();
        let tid = ObjectId::new();
        let uid = ObjectId::new();
        let settings = GpuSettings::default();
        let mut rule = GpuAlertRule::default_for(tid, uid);
        rule.enabled = true;

        // 1. SamplerStalled fires alert
        let mut stalled = free_report();
        stalled.status = GpuHostStatus::SamplerStalled;
        stalled.gpus.clear();
        let f1 = eval.evaluate_report(tid, aid, "node-1", &stalled, 1000, &settings, &rule);
        assert!(f1.iter().any(|x| x.event_key == "machine:sampler_stalled"), "{f1:?}");

        // 2. Transition to OffLocal must NOT fire "recovered"
        let mut off_local = stalled.clone();
        off_local.status = GpuHostStatus::OffLocal;
        let f2 = eval.evaluate_report(tid, aid, "node-1", &off_local, 1060, &settings, &rule);
        assert!(
            !f2.iter().any(|x| x.event_key.starts_with("machine:clear:")),
            "OffLocal must not claim recovery: {f2:?}"
        );

        // 3. DriverMissing with detected hardware fires critical alert
        let mut drv = free_report();
        drv.status = GpuHostStatus::DriverMissing;
        drv.status_detail = Some("Detected 2 NVIDIA GPUs without driver".into());
        let f3 = eval.evaluate_report(tid, aid, "node-1", &drv, 1120, &settings, &rule);
        assert!(f3.iter().any(|x| x.event_key == "machine:driver_missing"), "{f3:?}");

        // 4. Ascend vendor_health warning fires separate alert, and throttle with temp_c=None omits 0°C
        let mut ascend = free_report();
        ascend.backend = Some("ascend".into());
        ascend.gpus[0].uuid = "ASCEND-0-0".into();
        ascend.gpus[0].name = Some("Ascend 910B".into());
        ascend.gpus[0].vendor_health = Some("Warning".into());
        ascend.gpus[0].temp_c = None;
        ascend.gpus[0].throttle = Some(vec!["thermal".into()]);
        let f4a = eval.evaluate_report(tid, aid, "npu-1", &ascend, 2000, &settings, &rule);
        assert!(f4a.iter().any(|x| x.event_key == "fault:vendor_health:ASCEND-0-0"));
        let f4b = eval.evaluate_report(tid, aid, "npu-1", &ascend, 2070, &settings, &rule);
        let th = f4b
            .iter()
            .find(|x| x.event_key == "fault:throttle:ASCEND-0-0")
            .expect("throttle alert");
        assert!(!th.item.body_en.contains("0 °C"), "must not fabricate 0 °C: {}", th.item.body_en);
    }
}
