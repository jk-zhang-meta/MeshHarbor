// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-92 — the control-DC wire: `rc:keep-busy.set` / `.get` in,
//! `rc:keep-busy.state` out (to every viewer, on change and on open).
//!
//! JSON on the existing `control` channel, switched on `t` like every other
//! control verb. A viewer that predates FR-92 drops the unknown `t`; an
//! agent that predates it logs and ignores the verb — and the viewer only
//! shows the control when the agent advertises `keep-busy` in
//! `AgentCaps.input`.

use std::time::Duration;

use serde_json::{Value, json};

use super::engine::{Settings, Snapshot};
use super::patterns::{Pattern, Size, Speed};

/// A viewer's `rc:keep-busy.set`, parsed.
#[derive(Debug, Clone, PartialEq)]
pub struct SetRequest {
    pub on: bool,
    /// Ignored when `on` is false.
    pub settings: Settings,
}

/// Parse `rc:keep-busy.set`. `wall_ms` turns a relative `auto_off_min`
/// into the absolute deadline the engine keeps (it survives restarts).
///
/// Unknown keys are ignored (a newer viewer may send more); a known key with
/// an unknown VALUE is refused — "circel" must not quietly draw a circle.
pub fn parse_set(val: &Value, wall_ms: u64) -> Result<SetRequest, &'static str> {
    let on = val
        .get("on")
        .and_then(Value::as_bool)
        .ok_or("missing `on`")?;
    let mut s = Settings::default();
    if !on {
        return Ok(SetRequest { on, settings: s });
    }
    if let Some(p) = val.get("pattern") {
        s.pattern = p
            .as_str()
            .and_then(Pattern::from_wire)
            .ok_or("unknown pattern")?;
    }
    if let Some(v) = val.get("size") {
        s.size = v.as_str().and_then(Size::from_wire).ok_or("unknown size")?;
    }
    if let Some(v) = val.get("speed") {
        s.speed = v
            .as_str()
            .and_then(Speed::from_wire)
            .ok_or("unknown speed")?;
    }
    if let Some(v) = val.get("resume_after_s") {
        let secs = v.as_u64().ok_or("resume_after_s must be a whole number")?;
        s.resume_after = Duration::from_secs(secs);
    }
    match val.get("auto_off_min") {
        None | Some(Value::Null) => s.auto_off_at_ms = None,
        Some(v) => {
            let mins = v.as_u64().ok_or("auto_off_min must be a whole number")?;
            // 0 = never; anything beyond a week is a typo, not a plan.
            s.auto_off_at_ms = match mins {
                0 => None,
                m => Some(wall_ms.saturating_add(m.min(7 * 24 * 60).saturating_mul(60_000))),
            };
        }
    }
    Ok(SetRequest { on, settings: s })
}

/// The `rc:keep-busy.state` payload. `refused` names why THIS viewer's
/// request was not applied (sent to that viewer only); `None` on a broadcast.
pub fn state_payload(s: &Snapshot, refused: Option<&str>) -> Value {
    let mut v = json!({
        "t": "rc:keep-busy.state",
        "rev": s.rev,
        "available": s.available,
        "on": s.on,
        "phase": s.phase.wire(),
        "reason": s.reason.map(|r| r.wire()),
        // Composed here, once, so the viewer, the tray and the CLI read the
        // same words.
        "sentence": s.reason.map(|r| r.sentence()),
        "paused_by": s.paused_by.map(|p| p.wire()),
        "resumes_in_ms": s.resumes_in.map(|d| d.as_millis() as u64),
        "pattern": s.settings.pattern.wire(),
        "size": s.settings.size.wire(),
        "speed": s.settings.speed.wire(),
        "resume_after_s": s.settings.resume_after.as_secs(),
        "auto_off_at_ms": s.settings.auto_off_at_ms,
        "set_by": s.set_by,
        "set_at_ms": s.set_at_ms,
        "detector": s.detector,
        "warn": s.warn,
    });
    if let Some(r) = refused
        && let Some(obj) = v.as_object_mut()
    {
        obj.insert("refused".into(), json!(r));
    }
    v
}

#[cfg(test)]
mod tests {
    use super::super::engine::{Engine, Phase};
    use super::*;
    use std::time::Instant;

    #[test]
    fn a_full_set_parses() {
        let v = json!({
            "t": "rc:keep-busy.set", "on": true, "pattern": "spirograph", "size": "l",
            "speed": "fast", "resume_after_s": 60, "auto_off_min": 120
        });
        let r = parse_set(&v, 1_000).unwrap();
        assert!(r.on);
        assert_eq!(r.settings.pattern, Pattern::Spirograph);
        assert_eq!(r.settings.size, Size::L);
        assert_eq!(r.settings.speed, Speed::Fast);
        assert_eq!(r.settings.resume_after, Duration::from_secs(60));
        assert_eq!(r.settings.auto_off_at_ms, Some(1_000 + 120 * 60_000));
    }

    #[test]
    fn defaults_fill_what_is_missing_and_off_needs_nothing_else() {
        let r = parse_set(&json!({"on": true}), 0).unwrap();
        assert_eq!(r.settings, Settings::default());
        let r = parse_set(&json!({"on": false, "pattern": "nonsense"}), 0).unwrap();
        assert!(!r.on, "an off ignores the rest — it must always work");
    }

    #[test]
    fn bad_values_are_refused_not_guessed() {
        assert!(parse_set(&json!({}), 0).is_err());
        assert!(parse_set(&json!({"on": "yes"}), 0).is_err());
        assert!(parse_set(&json!({"on": true, "pattern": "circel"}), 0).is_err());
        assert!(parse_set(&json!({"on": true, "pattern": "Circle"}), 0).is_err());
        assert!(parse_set(&json!({"on": true, "size": "xl"}), 0).is_err());
        assert!(parse_set(&json!({"on": true, "resume_after_s": -5}), 0).is_err());
        // Unknown KEYS from a newer viewer are fine.
        assert!(parse_set(&json!({"on": true, "glitter": true}), 0).is_ok());
    }

    #[test]
    fn auto_off_zero_or_null_is_never_and_a_huge_value_is_capped() {
        let r = parse_set(&json!({"on": true, "auto_off_min": 0}), 5).unwrap();
        assert_eq!(r.settings.auto_off_at_ms, None);
        let r = parse_set(&json!({"on": true, "auto_off_min": null}), 5).unwrap();
        assert_eq!(r.settings.auto_off_at_ms, None);
        let r = parse_set(&json!({"on": true, "auto_off_min": u64::MAX}), 5).unwrap();
        assert_eq!(r.settings.auto_off_at_ms, Some(5 + 7 * 24 * 60 * 60_000));
    }

    #[test]
    fn the_state_payload_carries_the_sentence_and_a_refusal_only_when_given() {
        let now = Instant::now();
        let mut e = Engine::new(1);
        e.set_org_denied(true, now);
        let s = e.snapshot(now);
        let v = state_payload(&s, None);
        assert_eq!(v["t"], "rc:keep-busy.state");
        assert_eq!(v["available"], false);
        assert_eq!(v["phase"], Phase::Off.wire());
        assert_eq!(v["reason"], "org_denied");
        assert_eq!(v["sentence"], "Disabled by your organization.");
        assert!(v.get("refused").is_none());
        let v = state_payload(&s, Some("not_floor_holder"));
        assert_eq!(v["refused"], "not_floor_holder");
    }
}
