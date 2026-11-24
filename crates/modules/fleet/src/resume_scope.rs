// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! FR-130 — `GET` / `PUT /api/admin/rc-resume-scope`: the orgs and devices a
//! remote session may outlive its device's control socket on (spec §4.1, D4).
//!
//! A platform admin's list. Anyone else gets the 404 every `/api/admin/*`
//! route gives (`require_platform_admin`), and gets it before the body is
//! read, so a malformed body does not tell them the route exists either. The
//! GET answers the list beside `rc.session_resume_secs`, the window it is
//! announced under, so the operator reads both halves at once; the PUT
//! replaces the list and answers the GET's shape.
//!
//! The store lives here, in `fleet`, because the agent hub that reads it when
//! a device registers is fleet's: `remote` and `network` reach fleet, fleet
//! reaches neither, so no hook is needed.
//!
//! With the window at 0, the default, the server behaves as it did whatever
//! the list holds, and nothing reads it. From P1b-1 the agent socket reads it
//! at a device's registration ([`resume_hello`], through
//! [`RcResumeScopeDao::covers`](meshharbor_services::dao::rc_resume_scope::RcResumeScopeDao::covers)),
//! for a device that advertises `rc-resume`; P1b-2 re-announces the window
//! when the list changes ([`scope_changed`]), and while the window is on
//! every pod reads the list again on a cadence ([`spawn_reconciler`]).

use axum::{
    Json,
    extract::{State, rejection::JsonRejection},
};
use bson::{DateTime, oid::ObjectId};
use meshharbor_core::{ApiError, extractors::auth::AuthUser, guards::require_platform_admin};
use meshharbor_remote_control::models::{AgentCaps, RpcCap};
use meshharbor_services::dao::rc_resume_scope::{ResumeScopeEntry, ResumeScopeKind};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use crate::FleetState;
use crate::hub::ResumeHello;

/// The longest note an entry keeps.
pub const MAX_NOTE_LEN: usize = 200;
/// The most entries the list holds: a ceiling, not a page size.
pub const MAX_ENTRIES: usize = 1_000;

/// One entry as the route answers it: ids as hex, the time as RFC 3339.
#[derive(Debug, Serialize, PartialEq)]
pub struct ScopeRow {
    pub kind: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    pub by: String,
    pub at: String,
}

#[derive(Debug, Serialize, PartialEq)]
pub struct ScopeResponse {
    /// `rc.session_resume_secs`. 0 is off, whatever the list holds.
    pub window_secs: u64,
    pub entries: Vec<ScopeRow>,
}

impl ScopeResponse {
    fn of(window_secs: u64, entries: &[ResumeScopeEntry]) -> Self {
        Self {
            window_secs,
            entries: entries
                .iter()
                .map(|e| ScopeRow {
                    kind: e.kind.as_str(),
                    id: e.id.map(|id| id.to_hex()),
                    note: e.note.clone(),
                    by: e.by.to_hex(),
                    at: e.at.try_to_rfc3339_string().unwrap_or_default(),
                })
                .collect(),
        }
    }
}

/// `GET /api/admin/rc-resume-scope`
pub async fn get_scope(
    State(state): State<FleetState>,
    auth: AuthUser,
) -> Result<Json<ScopeResponse>, ApiError> {
    require_platform_admin(&state, &auth)?;
    let entries = state.rc_resume_scope.list().await?;
    Ok(Json(ScopeResponse::of(
        state.settings.rc.session_resume_secs,
        &entries,
    )))
}

#[derive(Debug, Deserialize)]
pub struct PutEntry {
    pub kind: String,
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub note: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct PutBody {
    pub entries: Vec<PutEntry>,
}

/// `PUT /api/admin/rc-resume-scope` — replace the list:
/// `{"entries": [{"kind": "all" | "org" | "device", "id": "<hex>", "note": "…"}]}`.
pub async fn put_scope(
    State(state): State<FleetState>,
    auth: AuthUser,
    body: Result<Json<PutBody>, JsonRejection>,
) -> Result<Json<ScopeResponse>, ApiError> {
    require_platform_admin(&state, &auth)?;
    let Json(body) = body.map_err(|e| ApiError::BadRequest(e.body_text()))?;
    let entries = validate_entries(body.entries, auth.user_id, DateTime::now())?;
    let before = state.rc_resume_scope.list().await?;
    state.rc_resume_scope.replace(&entries).await?;
    let after = state.rc_resume_scope.list().await?;
    scope_changed(&state, auth.user_id, &before, &after).await;
    Ok(Json(ScopeResponse::of(
        state.settings.rc.session_resume_secs,
        &after,
    )))
}

/// The one place a change to the scope goes out from (spec §4.1). Every
/// connected device that advertises `rc-resume` is told its window again:
/// this pod's at once, every other pod's over the rc ctrl lane, as FR-92's
/// keep-busy deny reaches them. A device the scope now covers is told the
/// window, one it no longer covers is told 0, which withdraws it, so a change
/// needs no roll and reverses at once.
///
/// The event is only a nudge (review 2, N2): it carries no list and no
/// window. Each pod that hears it reads the store itself and applies its OWN
/// window ([`reconcile`]), so an event that arrives late or twice applies
/// the newest list, and a pod at 0 announces nothing whatever the sender
/// holds. One that is lost is caught by the next cadence ([`spawn_reconciler`]).
/// With the window at 0 nobody holds one and nobody is told, so nothing is
/// published either.
async fn scope_changed(
    state: &FleetState,
    admin: ObjectId,
    before: &[ResumeScopeEntry],
    after: &[ResumeScopeEntry],
) {
    let added = after
        .iter()
        .filter(|e| !before.iter().any(|b| b.same_target(e)))
        .count();
    let removed = before
        .iter()
        .filter(|b| !after.iter().any(|e| e.same_target(b)))
        .count();
    let told = reconcile(state).await;
    info!(
        %admin,
        added,
        removed,
        entries = after.len(),
        told,
        "rc resume scope saved"
    );
    if capped_window(state.settings.rc.session_resume_secs) > 0 {
        crate::ctrl::publish_rc_ctrl(state, "resume_scope", serde_json::json!({})).await;
    }
}

/// FR-130 P1b-2 (review 2, N2) — tell every connection on THIS pod that
/// advertises `rc-resume` its window again ([`reannounce`]), from the store
/// as it reads now and under this pod's OWN window (`rc.session_resume_secs`,
/// capped): a device is told what its pod announces at a registration. At
/// window 0 it reads nothing and tells nobody. Readings on one pod take turns
/// (`FleetState::rc_resume_reconcile`), so the last one applies the newest
/// list. A store that cannot be read changes nothing: the next reading
/// tries again. How many were told.
pub async fn reconcile(state: &FleetState) -> usize {
    let window = capped_window(state.settings.rc.session_resume_secs);
    if window == 0 {
        return 0;
    }
    let _turn = state.rc_resume_reconcile.lock().await;
    let entries = match state.rc_resume_scope.list().await {
        Ok(entries) => entries,
        Err(e) => {
            warn!(%e, "rc resume scope unreadable: every window stays as announced until the next reading");
            return 0;
        }
    };
    let targets: Vec<ScopeTarget> = entries.iter().map(|e| (e.kind, e.id)).collect();
    reannounce(&state.rc_hub, window, &targets)
}

/// FR-130 P1b-2 (review 2, N2) — another pod saved the scope (`resume_scope`
/// on the rc ctrl lane, through [`crate::ctrl::apply_rc_ctrl_on`]): read it
/// here and tell this pod's connections ([`reconcile`]). Whatever the event
/// carries is ignored. Nothing at window 0.
pub fn nudge(state: &FleetState) {
    if capped_window(state.settings.rc.session_resume_secs) == 0 {
        return;
    }
    let state = state.clone();
    tokio::spawn(async move {
        let told = reconcile(&state).await;
        if told > 0 {
            info!(
                told,
                "rc ctrl: the resume scope read again after another pod saved it"
            );
        }
    });
}

/// FR-130 P1b-2 (review 2, N2) — while the window is on, read the scope again
/// on the presence sweep's cadence (`rc.presence_sweep_secs`) and tell each
/// connection whose window changed: a change whose event was lost reaches the
/// device all the same. Not spawned at window 0, which the setting fixes for
/// the process. Every pod runs its own: each tells only its own connections.
pub fn spawn_reconciler(state: FleetState) {
    if capped_window(state.settings.rc.session_resume_secs) == 0 {
        return;
    }
    let every = std::time::Duration::from_secs(state.settings.rc.presence_sweep_secs.max(5));
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(every).await;
            let told = reconcile(&state).await;
            if told > 0 {
                info!(told, "rc resume scope read again: windows told");
            }
        }
    });
}

/// One entry of the scope as the re-announce reads it: what it names.
pub type ScopeTarget = (ResumeScopeKind, Option<ObjectId>);

/// FR-130 P1b-2 — whether `targets` cover a device, as
/// [`RcResumeScopeDao::covers`](meshharbor_services::dao::rc_resume_scope::RcResumeScopeDao::covers)
/// answers it for the stored list: `all`, the device's org, or the device.
pub fn covered_by(targets: &[ScopeTarget], tenant_id: ObjectId, agent_id: ObjectId) -> bool {
    targets.iter().any(|(kind, id)| match kind {
        ResumeScopeKind::All => true,
        ResumeScopeKind::Org => *id == Some(tenant_id),
        ResumeScopeKind::Device => *id == Some(agent_id),
    })
}

/// FR-130 P1b-2 — tell every connection on THIS pod that advertises
/// `rc-resume` its window again after a scope change: `window` when
/// `targets` cover its device, 0 when they no longer do. Only a connection
/// whose window changes is told. With the window at 0 nobody is. How many
/// were told.
pub fn reannounce(hub: &crate::hub::Hub, window: u32, targets: &[ScopeTarget]) -> usize {
    let mut told = 0;
    for (agent_id, tenant_id, held) in hub.resume_connections() {
        let want = (window > 0 && covered_by(targets, tenant_id, agent_id)).then_some(window);
        if want != held && hub.announce_resume_window(agent_id, want.unwrap_or(0)) {
            told += 1;
        }
    }
    told
}

/// The PUT's contract, pure so it is testable without a server: at most
/// [`MAX_ENTRIES`]; a known kind; a 24-hex id for `org` and `device` and none
/// for `all`; a note of at most [`MAX_NOTE_LEN`] printable characters, or
/// none; a target named twice is folded (the first wins) rather than refused.
/// Whether an id names a live org or device is not checked: one that names
/// nothing matches nothing.
pub fn validate_entries(
    rows: Vec<PutEntry>,
    by: ObjectId,
    at: DateTime,
) -> Result<Vec<ResumeScopeEntry>, ApiError> {
    if rows.len() > MAX_ENTRIES {
        return Err(ApiError::BadRequest(format!(
            "at most {MAX_ENTRIES} entries"
        )));
    }
    let mut out: Vec<ResumeScopeEntry> = Vec::with_capacity(rows.len());
    for (i, row) in rows.into_iter().enumerate() {
        let kind = ResumeScopeKind::parse(row.kind.trim()).ok_or_else(|| {
            ApiError::BadRequest(format!(
                "entries[{i}].kind must be all, org or device, got {:?}",
                row.kind
            ))
        })?;
        let raw_id = row.id.as_deref().map(str::trim).filter(|s| !s.is_empty());
        let id = match (kind, raw_id) {
            (ResumeScopeKind::All, None) => None,
            (ResumeScopeKind::All, Some(_)) => {
                return Err(ApiError::BadRequest(format!(
                    "entries[{i}]: `all` names no id"
                )));
            }
            (_, None) => {
                return Err(ApiError::BadRequest(format!(
                    "entries[{i}].id is required for {}",
                    kind.as_str()
                )));
            }
            (_, Some(raw)) => Some(ObjectId::parse_str(raw).map_err(|_| {
                ApiError::BadRequest(format!(
                    "entries[{i}].id must be a 24-hex ObjectId, got {raw:?}"
                ))
            })?),
        };
        let note = match row.note.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
            None => None,
            Some(n) if n.chars().count() > MAX_NOTE_LEN => {
                return Err(ApiError::BadRequest(format!(
                    "entries[{i}].note is longer than {MAX_NOTE_LEN} characters"
                )));
            }
            Some(n) if n.chars().any(char::is_control) => {
                return Err(ApiError::BadRequest(format!(
                    "entries[{i}].note must be printable text"
                )));
            }
            Some(n) => Some(n.to_string()),
        };
        let entry = ResumeScopeEntry {
            kind,
            id,
            note,
            by,
            at,
        };
        if out.iter().any(|e| e.same_target(&entry)) {
            continue;
        }
        out.push(entry);
    }
    Ok(out)
}

/// FR-130 P1b — what a device's hello is told about resuming, decided at its
/// registration (spec §4.1): the window is `rc.session_resume_secs`, the
/// ceiling and the fleet-wide off, announced only to a device that advertises
/// `rc-resume` (equality-matched) and that the scope covers. With the window
/// at 0, or without the verb, nothing is read. A scope that cannot be read
/// announces nothing: the session then ends at a socket loss as it always
/// has, never kept on a guess.
pub async fn resume_hello(
    state: &FleetState,
    tenant_id: ObjectId,
    agent_id: ObjectId,
    caps: &AgentCaps,
    kept: Vec<ObjectId>,
) -> ResumeHello {
    let advertised = caps.has_rpc(RpcCap::RcResume);
    let setting = state.settings.rc.session_resume_secs;
    let covered = if advertised && setting > 0 {
        match state.rc_resume_scope.covers(tenant_id, agent_id).await {
            Ok(covered) => covered,
            Err(e) => {
                warn!(%agent_id, %e, "rc resume scope unreadable at the hello: no window announced");
                false
            }
        }
    } else {
        false
    };
    ResumeHello {
        advertised,
        window: window_for(setting, advertised, covered),
        kept,
    }
}

/// The longest window the server announces, in seconds: the device caps what
/// it is told at the same value (`WINDOW_CAP` in the agent's session table),
/// so the `resume_by` a detach writes never outlives the device's own
/// deadline, whatever `rc.session_resume_secs` says.
pub const MAX_WINDOW_SECS: u32 = 120;

/// The window the setting gives, capped at [`MAX_WINDOW_SECS`]; 0 is off.
pub fn capped_window(setting: u64) -> u32 {
    u32::try_from(setting.min(u64::from(MAX_WINDOW_SECS))).unwrap_or(MAX_WINDOW_SECS)
}

/// The window a connection is announced, in seconds: the setting, capped,
/// when it is above 0, the device advertises the verb and the scope covers
/// it.
pub fn window_for(setting: u64, advertised: bool, covered: bool) -> Option<u32> {
    (setting > 0 && advertised && covered).then(|| capped_window(setting))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The three gates, each alone enough to announce nothing.
    #[test]
    fn a_window_needs_the_setting_the_verb_and_the_scope() {
        assert_eq!(window_for(60, true, true), Some(60));
        assert_eq!(window_for(0, true, true), None, "0 is off");
        assert_eq!(window_for(60, false, true), None, "no verb");
        assert_eq!(window_for(60, true, false), None, "outside the scope");
        // P1b-2 (the review's L4) — capped as the device caps it.
        assert_eq!(window_for(120, true, true), Some(120));
        assert_eq!(window_for(121, true, true), Some(MAX_WINDOW_SECS));
        assert_eq!(window_for(u64::MAX, true, true), Some(MAX_WINDOW_SECS));
        assert_eq!(capped_window(0), 0, "0 stays off");
    }

    /// P1b-2 — the re-announce reads a scope as the store's `covers` does.
    #[test]
    fn a_scope_covers_as_the_store_does() {
        let (org, dev, other) = (ObjectId::new(), ObjectId::new(), ObjectId::new());
        assert!(covered_by(&[(ResumeScopeKind::All, None)], org, dev));
        assert!(covered_by(&[(ResumeScopeKind::Org, Some(org))], org, dev));
        assert!(covered_by(
            &[(ResumeScopeKind::Device, Some(dev))],
            org,
            dev
        ));
        assert!(!covered_by(
            &[
                (ResumeScopeKind::Org, Some(other)),
                (ResumeScopeKind::Device, Some(other)),
            ],
            org,
            dev
        ));
        assert!(!covered_by(&[], org, dev), "an empty scope covers nothing");
    }

    /// P1b-2 — a scope change tells only the connections whose window
    /// changes: one newly covered is told the window, one no longer covered is
    /// told 0, one without the verb is never told, and the same change again
    /// tells nobody.
    #[tokio::test]
    async fn a_scope_change_tells_only_the_connections_whose_window_changes() {
        use crate::hub::{Hub, ResumeHello};
        use meshharbor_remote_control::models::OsKind;
        use meshharbor_remote_control::signaling::ServerMsg;

        let client = mongodb::Client::with_uri_str("mongodb://localhost:27017")
            .await
            .expect("mongo for tests");
        let (audit, _h) =
            meshharbor_remote_control::audit::AuditSink::spawn(client.database("rc_test"));
        let hub = Hub::new(audit, None);
        let org = ObjectId::new();
        let register = |agent: ObjectId, advertised: bool, window: Option<u32>| {
            hub.register_agent_resuming(
                agent,
                org,
                ObjectId::new(),
                OsKind::Linux,
                2,
                true,
                false,
                ResumeHello {
                    advertised,
                    window,
                    kept: Vec::new(),
                },
            )
            .rx
        };
        let told = |rx: &mut tokio::sync::mpsc::Receiver<ServerMsg>| -> Vec<u32> {
            let mut out = Vec::new();
            while let Ok(m) = rx.try_recv() {
                if let ServerMsg::AgentResumeWindow { secs } = m {
                    out.push(secs);
                }
            }
            out
        };
        let (a, b, c) = (ObjectId::new(), ObjectId::new(), ObjectId::new());
        let mut rx_a = register(a, true, None);
        let mut rx_b = register(b, true, Some(60));
        let mut rx_c = register(c, false, None);

        let only_a = [(ResumeScopeKind::Device, Some(a))];
        assert_eq!(reannounce(&hub, 60, &only_a), 2);
        assert_eq!(told(&mut rx_a), vec![60], "newly covered");
        assert_eq!(told(&mut rx_b), vec![0], "no longer covered: withdrawn");
        assert!(told(&mut rx_c).is_empty(), "never sent blind");
        assert_eq!(hub.agent_resume_window(a), Some(60));
        assert_eq!(hub.agent_resume_window(b), None);

        assert_eq!(reannounce(&hub, 60, &only_a), 0, "nothing changed");
        assert!(told(&mut rx_a).is_empty() && told(&mut rx_b).is_empty());
    }

    const ORG: &str = "6a975e17971e2d55ddcdedb2";
    const DEVICE: &str = "6a975e17971e2d55ddcdedb3";

    fn row(kind: &str, id: Option<&str>, note: Option<&str>) -> PutEntry {
        PutEntry {
            kind: kind.into(),
            id: id.map(str::to_string),
            note: note.map(str::to_string),
        }
    }

    fn check(rows: Vec<PutEntry>) -> Result<Vec<ResumeScopeEntry>, ApiError> {
        validate_entries(rows, ObjectId::new(), DateTime::now())
    }

    fn refused(rows: Vec<PutEntry>) -> String {
        match check(rows) {
            Err(ApiError::BadRequest(msg)) => msg,
            other => panic!("expected a 400, got {other:?}"),
        }
    }

    #[test]
    fn the_three_kinds_are_taken_as_they_name_their_targets() {
        let got = check(vec![
            row(" all ", None, Some("  P4: the whole fleet ")),
            row("org", Some(ORG), None),
            row("device", Some(&format!(" {DEVICE} ")), Some("   ")),
        ])
        .unwrap();
        assert_eq!(got.len(), 3);
        assert_eq!((got[0].kind, got[0].id), (ResumeScopeKind::All, None));
        assert_eq!(got[0].note.as_deref(), Some("P4: the whole fleet"));
        assert_eq!(got[1].id, Some(ObjectId::parse_str(ORG).unwrap()));
        assert_eq!(got[2].kind, ResumeScopeKind::Device);
        assert_eq!(got[2].id, Some(ObjectId::parse_str(DEVICE).unwrap()));
        assert_eq!(got[2].note, None, "a blank note is no note");
        assert!(check(vec![]).unwrap().is_empty(), "an empty list is valid");
    }

    #[test]
    fn a_wrong_kind_a_missing_or_stray_id_and_a_bad_note_are_refused() {
        assert!(refused(vec![row("tenant", Some(ORG), None)]).contains("entries[0].kind"));
        assert!(refused(vec![row("Org", Some(ORG), None)]).contains("entries[0].kind"));
        assert!(refused(vec![row("all", Some(ORG), None)]).contains("`all` names no id"));
        assert!(refused(vec![row("org", None, None)]).contains("required for org"));
        assert!(refused(vec![row("device", Some(" "), None)]).contains("required for device"));
        assert!(refused(vec![row("device", Some("not-hex"), None)]).contains("24-hex"));
        let long = "x".repeat(MAX_NOTE_LEN + 1);
        assert!(refused(vec![row("all", None, Some(&long))]).contains("longer than"));
        assert!(refused(vec![row("all", None, Some("a\nb"))]).contains("printable"));
        let many = (0..=MAX_ENTRIES).map(|_| row("all", None, None)).collect();
        assert!(refused(many).contains("at most"));
    }

    #[test]
    fn a_target_named_twice_is_kept_once_with_its_first_note() {
        let got = check(vec![
            row("device", Some(DEVICE), Some("first")),
            row("org", Some(DEVICE), None),
            row("device", Some(DEVICE), Some("second")),
            row("all", None, None),
            row("all", None, Some("again")),
        ])
        .unwrap();
        assert_eq!(got.len(), 3, "{got:?}");
        assert_eq!(got[0].note.as_deref(), Some("first"));
        assert_eq!(
            got[1].kind,
            ResumeScopeKind::Org,
            "the same id under another kind is another target"
        );
        assert_eq!(got[2].note, None);
    }

    #[test]
    fn the_answer_names_ids_as_hex_and_leaves_absent_parts_out() {
        let by = ObjectId::parse_str(ORG).unwrap();
        let entries = check(vec![
            row("all", None, None),
            row("device", Some(DEVICE), Some("n")),
        ])
        .unwrap()
        .into_iter()
        .map(|e| ResumeScopeEntry { by, ..e })
        .collect::<Vec<_>>();
        let v = serde_json::to_value(ScopeResponse::of(60, &entries)).unwrap();
        assert_eq!(v["window_secs"], 60);
        assert_eq!(v["entries"][0]["kind"], "all");
        assert!(v["entries"][0].get("id").is_none() && v["entries"][0].get("note").is_none());
        assert_eq!(v["entries"][1]["id"], DEVICE);
        assert_eq!(v["entries"][1]["by"], ORG);
        assert!(v["entries"][1]["at"].as_str().unwrap().contains('T'));
    }
}
