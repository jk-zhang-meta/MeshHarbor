//! Bounded owner-local observations, not routing inputs or authorization.
use serde::{Deserialize, Deserializer, Serialize};
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PathTrialPhase {
    Binding,
    Measuring,
    Ready,
    Committed,
    Finalized,
    ReturnPreparing,
    ReturnReady,
    Returned,
}
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PathTrialEvent {
    Start,
    Commit,
    Finalize,
    Abort,
    ReturnPrepare,
    ReturnCommit,
    ReturnFinalize,
    ReturnAbort,
    Tick,
    Cleanup,
}
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct PathTrialSample {
    pub direct_rtt_ns: Option<u64>,
    pub candidate_rtt_ns: Option<u64>,
    pub age_ms: u64,
}
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct PathTrialInfo {
    pub trial_id: String,
    pub peer_node_id: String,
    pub phase: PathTrialPhase,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub return_id: Option<String>,
    #[serde(default, deserialize_with = "samples")]
    pub samples: Vec<PathTrialSample>,
    pub age_ms: u64,
    pub windows: u8,
    pub direct_success: u8,
    pub candidate_success: u8,
    pub direct_median_ms: Option<u64>,
    pub candidate_median_ms: Option<u64>,
    pub newest_sample_age_ms: Option<u64>,
}
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct PathTrialTransition {
    pub sequence: u64,
    pub trial_id: String,
    pub peer_node_id: String,
    pub from: Option<PathTrialPhase>,
    pub to: Option<PathTrialPhase>,
    pub event: PathTrialEvent,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub return_id: Option<String>,
    pub age_ms: u64,
}
/// Fixed diagnostic labels only; never an authorization or routing input.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PathTrialResetReason {
    Reattach,
    FullNetmap,
    NetmapDelta,
    HandleLocalDisabled,
    HandleServerUnsupported,
    HandleNonPrimary,
    TickLocalDisabled,
    TickServerUnsupported,
    TickNonPrimary,
}
/// Cumulative for one Engine lifetime, including its observation epoch resets.
/// A replaced Engine starts at zero. There are exactly nine bounded counters.
#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq, Eq)]
#[serde(default)]
pub struct PathTrialResetDiagnostics {
    pub reattach: u64,
    pub full_netmap: u64,
    pub netmap_delta: u64,
    pub handle_local_disabled: u64,
    pub handle_server_unsupported: u64,
    pub handle_non_primary: u64,
    pub tick_local_disabled: u64,
    pub tick_server_unsupported: u64,
    pub tick_non_primary: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_reason: Option<PathTrialResetReason>,
}
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct PathTrialStatus {
    /// Owner-local diagnostics; absent from old peers, omitted when unavailable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reset_diagnostics: Option<PathTrialResetDiagnostics>,
    /// Stable for one Engine lifecycle; fences delayed old publisher teardown.
    pub runtime_id: u64,
    /// Changes on runtime/observation epoch reset. Never an authorization generation.
    pub epoch: u64,
    pub observed_at_ms: u64,
    /// Transitions older than this are omitted; ring eviction may occur earlier.
    pub history_ttl_ms: u64,
    #[serde(deserialize_with = "active")]
    pub active: Vec<PathTrialInfo>,
    #[serde(deserialize_with = "history")]
    pub transitions: Vec<PathTrialTransition>,
}
fn active<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<PathTrialInfo>, D::Error> {
    let v = Vec::<PathTrialInfo>::deserialize(d)?;
    if v.len() > 4 {
        return Err(serde::de::Error::custom("path trial active limit exceeded"));
    }
    Ok(v)
}
fn history<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<PathTrialTransition>, D::Error> {
    let v = Vec::<PathTrialTransition>::deserialize(d)?;
    if v.len() > 32 {
        return Err(serde::de::Error::custom(
            "path trial transition limit exceeded",
        ));
    }
    Ok(v)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn path_trial_observation_wire_bounds_and_privacy_shape() {
        let s = PathTrialStatus {
            reset_diagnostics: None,
            runtime_id: 1,
            epoch: 1,
            observed_at_ms: 2,
            history_ttl_ms: 30000,
            active: vec![],
            transitions: vec![],
        };
        let value = serde_json::to_value(&s).unwrap();
        assert_eq!(
            serde_json::from_value::<PathTrialStatus>(value.clone()).unwrap(),
            s
        );
        let mut bad = value;
        bad["transitions"] = serde_json::json!(vec![
            PathTrialTransition {
                sequence: 1,
                trial_id: "trial".into(),
                peer_node_id: "peer".into(),
                from: None,
                to: Some(PathTrialPhase::Binding),
                event: PathTrialEvent::Start,
                return_id: None,
                age_ms: 0
            };
            33
        ]);
        assert!(serde_json::from_value::<PathTrialStatus>(bad).is_err());
        let info = serde_json::json!({"trial_id":"trial","peer_node_id":"peer","phase":"measuring","samples":[],"age_ms":0,"windows":0,"direct_success":0,"candidate_success":0,"direct_median_ms":null,"candidate_median_ms":null,"newest_sample_age_ms":null});
        let mut too_many = serde_json::to_value(&s).unwrap();
        too_many["active"] = serde_json::json!(vec![info.clone(); 5]);
        assert!(serde_json::from_value::<PathTrialStatus>(too_many).is_err());
        let mut oversamples = info;
        oversamples["samples"] = serde_json::json!(vec![
            PathTrialSample {
                direct_rtt_ns: None,
                candidate_rtt_ns: Some(1000),
                age_ms: 1
            };
            10
        ]);
        let mut bad_samples = serde_json::to_value(&s).unwrap();
        bad_samples["active"] = serde_json::json!([oversamples]);
        assert!(serde_json::from_value::<PathTrialStatus>(bad_samples).is_err());
        let encoded = serde_json::to_string(&s).unwrap();
        for field in [
            "wg_public_key",
            "bind_secret",
            "token",
            "endpoint",
            "nonce",
            "overlay_ip",
        ] {
            assert!(!encoded.contains(field));
        }
    }
}

fn samples<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<PathTrialSample>, D::Error> {
    let v = Vec::<PathTrialSample>::deserialize(d)?;
    if v.len() > 9 {
        return Err(serde::de::Error::custom("path trial sample limit exceeded"));
    }
    Ok(v)
}

// Semantic RED oracle: compiles against the pre-diagnostics wire type too.
#[cfg(test)]
mod reset_wire_semantic_tests {
    use super::*;
    #[test]
    fn path_trial_reset_wire_roundtrip_preserves_optional_diagnostics() {
        let value = serde_json::json!({
            "runtime_id": 1, "epoch": 2, "observed_at_ms": 3,
            "history_ttl_ms": 30000, "active": [], "transitions": [],
            "reset_diagnostics": {
                "reattach": 1, "full_netmap": 2, "netmap_delta": 3,
                "handle_local_disabled": 4, "handle_server_unsupported": 5,
                "handle_non_primary": 6, "tick_local_disabled": 7,
                "tick_server_unsupported": 8, "tick_non_primary": 9,
                "last_reason": "netmap_delta"
            }
        });
        let decoded: PathTrialStatus = serde_json::from_value(value.clone()).unwrap();
        let encoded = serde_json::to_value(decoded).unwrap();
        assert_eq!(encoded["reset_diagnostics"], value["reset_diagnostics"]);
    }
    #[test]
    fn path_trial_reset_wire_legacy_absent_stays_absent() {
        let value = serde_json::json!({
            "runtime_id": 1, "epoch": 2, "observed_at_ms": 3,
            "history_ttl_ms": 30000, "active": [], "transitions": []
        });
        let decoded: PathTrialStatus = serde_json::from_value(value.clone()).unwrap();
        assert_eq!(serde_json::to_value(decoded).unwrap(), value);
    }
}

#[cfg(test)]
mod reset_diagnostic_wire_tests {
    use super::*;
    #[test]
    fn path_trial_reset_wire_defaults_unknown_reason_and_fixed_privacy_shape() {
        let d: PathTrialResetDiagnostics = serde_json::from_value(serde_json::json!({})).unwrap();
        assert_eq!(d, PathTrialResetDiagnostics::default());
        assert!(
            serde_json::from_value::<PathTrialResetDiagnostics>(
                serde_json::json!({"last_reason": "unknown_control_text"})
            )
            .is_err()
        );
        let mut d = d;
        d.last_reason = Some(PathTrialResetReason::TickNonPrimary);
        let value = serde_json::to_value(d).unwrap();
        assert_eq!(value.as_object().unwrap().len(), 10);
        for key in [
            "token",
            "key",
            "endpoint",
            "nonce",
            "peer_id",
            "reason_text",
        ] {
            assert!(!value.as_object().unwrap().contains_key(key));
        }
        assert!(
            serde_json::from_value::<PathTrialResetDiagnostics>(
                serde_json::json!({"reattach": -1})
            )
            .is_err()
        );
        assert!(
            serde_json::from_str::<PathTrialResetDiagnostics>(
                r#"{"reattach":18446744073709551616}"#
            )
            .is_err()
        );
    }
}
