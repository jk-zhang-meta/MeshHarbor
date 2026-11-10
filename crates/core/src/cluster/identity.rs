// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! C-1 — stable pod identity + process epoch.
//!
//! `pod_id` must be STABLE across process restarts (it names the pod's
//! per-pod bus channel and appears in every ownership record), and unique
//! per concurrently-running pod. Under hostNetwork there is at most one
//! API pod per node, so the node host IP — already injected as
//! `MESHHARBOR__POD_HOST_IP` (Downward API `status.hostIP`) and already the
//! key the LB upstream list and the mediasoup announced-ip map speak — is
//! the natural identity. `epoch` is a per-process fencing token: a
//! restarted pod re-subscribes to the same channel but must NOT be
//! mistaken for the process that owned the previous epoch's entities.

#[derive(Debug, Clone)]
pub struct PodIdentity {
    /// Stable across restarts: settings override (`MESHHARBOR__APP__POD_ID`,
    /// per-TestApp in tests) → node host IP (`MESHHARBOR__POD_HOST_IP`) →
    /// machine hostname → random dev id.
    pub pod_id: String,
    /// Random per-process token (uuid, first 8 hex chars).
    pub epoch: String,
}

impl PodIdentity {
    pub fn resolve(explicit: Option<String>) -> Self {
        let pod_id = explicit
            .filter(|s| !s.trim().is_empty())
            .or_else(|| non_empty_env("MESHHARBOR__POD_HOST_IP"))
            // Dev convenience only — in k8s HOSTNAME is the (per-restart)
            // pod name, but POD_HOST_IP always wins there.
            .or_else(|| non_empty_env("COMPUTERNAME"))
            .or_else(|| non_empty_env("HOSTNAME"))
            .unwrap_or_else(|| format!("dev-{}", &uuid::Uuid::new_v4().simple().to_string()[..8]));
        let epoch = uuid::Uuid::new_v4().simple().to_string()[..8].to_string();
        Self { pod_id, epoch }
    }

    /// The bus origin string stamped on every published envelope —
    /// `<pod_id>/<epoch>`. The stable prefix makes per-pod channels
    /// survive restarts; the epoch keeps the self-echo guard correct
    /// across a same-pod restart racing its own stale messages.
    pub fn origin(&self) -> String {
        format!("{}/{}", self.pod_id, self.epoch)
    }
}

fn non_empty_env(key: &str) -> Option<String> {
    std::env::var(key).ok().filter(|s| !s.trim().is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_override_wins_and_origin_shape() {
        let id = PodIdentity::resolve(Some("pod-x".into()));
        assert_eq!(id.pod_id, "pod-x");
        assert_eq!(id.epoch.len(), 8);
        assert_eq!(id.origin(), format!("pod-x/{}", id.epoch));
    }

    #[test]
    fn two_processes_same_pod_differ_by_epoch() {
        let a = PodIdentity::resolve(Some("pod-x".into()));
        let b = PodIdentity::resolve(Some("pod-x".into()));
        assert_eq!(a.pod_id, b.pod_id);
        assert_ne!(a.epoch, b.epoch);
    }
}
