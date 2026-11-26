// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-139 — Agent-side signed local netmap cache persistence, debounce,
//! synchronous authority-narrowing flush, and auth-suspension/revocation rules.
//!
//! Files live at `<config_dir>/overlay/netmap-<tenant_id>.json`, written via
//! owner-only atomic temp-file + `sync_all` + rename (`0o600` in a `0o700`
//! directory on Unix).
//!
//! Lifecycle rules:
//! * **Ordinary netmap / learned-endpoint updates**: debounced by 30 s to
//!   avoid flash wear during endpoint trickle bursts.
//! * **Authority-reducing updates** (`NetmapSnapshot::urgent_flush == true`,
//!   e.g. removed peer, tighter `ingress_rules`, newly `backbone_only`, lost
//!   route, tighter network flag): cancel any pending debounced write and flush
//!   SYNCHRONOUSLY so a crash cannot resurrect a revoked peer.
//! * **Non-authoritative learned-endpoint updates**: update `learned_endpoints`
//!   and advance `monotonic_clock_floor_ms`, NEVER extending
//!   `last_authoritative_at_ms` or `last_authoritative_revision`.
//! * **HTTP 401 `AuthRejected`**: suspend cold-boot seeding in memory without
//!   deleting the on-disk file (preserves recovery from transient token/server
//!   blips while refusing cold cache replay while auth is rejected).
//! * **`ServerMsg::Goodbye` (`AgentDeleted` / `PolicyRejected`) and terminal
//!   `OverlayJoinRefused`**: cancel any pending flush and DELETE the cache file.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tracing::{debug, info, warn};
use tunnel_core::overlay::WgKeypair;
use tunnel_core::overlay::netmap_cache::{
    CACHE_SCHEMA_VERSION, CacheIdentity, DEFAULT_MAX_CACHE_AGE_DAYS, NetmapCachePayload,
    SignedNetmapCache, open_and_verify, seal,
};
use tunnel_core::overlay::runtime::{NetmapSnapshot, NetmapSnapshotSink};

use crate::config::AgentConfig;

/// Default debounce delay for non-urgent netmap / learned-endpoint cache writes.
const WRITE_DEBOUNCE: Duration = Duration::from_secs(30);

struct TenantWriteState {
    last_authoritative_at_ms: u64,
    last_authoritative_revision: u64,
    monotonic_clock_floor_ms: u64,
    generation: u64,
    pending_timer: Option<tokio::task::JoinHandle<()>>,
}

#[derive(Default)]
struct CacheRegistry {
    writers: HashMap<String, TenantWriteState>,
    /// Tenants whose control-WS auth was rejected (HTTP 401). Cold cache
    /// seeding is skipped while present, without deleting the file on disk.
    suspended: HashSet<String>,
}

fn registry() -> &'static Mutex<CacheRegistry> {
    static REG: OnceLock<Mutex<CacheRegistry>> = OnceLock::new();
    REG.get_or_init(|| Mutex::new(CacheRegistry::default()))
}

fn now_epoch_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Sanitize `tenant_id` for a safe single filename component.
fn sanitize_tenant_id(tenant_id: &str) -> String {
    let clean: String = tenant_id
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
        .collect();
    if clean.is_empty() {
        "default".to_string()
    } else {
        clean
    }
}

/// Canonical cache file path: `<config_dir>/overlay/netmap-<tenant>.json`.
pub fn cache_path(config_path: &Path, tenant_id: &str) -> Option<PathBuf> {
    let dir = config_path.parent()?.join("overlay");
    Some(dir.join(format!("netmap-{}.json", sanitize_tenant_id(tenant_id))))
}

/// Whether the signed local netmap cache is enabled by config + env.
pub fn cache_enabled(cfg: &AgentConfig) -> bool {
    if cfg.overlay_netmap_cache == Some(false) {
        return false;
    }
    tunnel_core::env::flag("OVERLAY_NETMAP_CACHE", true)
}

/// Maximum cache age in milliseconds (config / env, clamped to `1..=90` days,
/// default 14 days).
pub fn max_cache_age_ms(cfg: &AgentConfig) -> u64 {
    let days = tunnel_core::env::node_env("OVERLAY_NETMAP_CACHE_MAX_DAYS")
        .and_then(|s| s.trim().parse::<u32>().ok())
        .or(cfg.overlay_netmap_cache_max_days)
        .unwrap_or(DEFAULT_MAX_CACHE_AGE_DAYS)
        .clamp(1, 90);
    u64::from(days) * 86_400 * 1_000
}

/// Suspend offline cache seeding for `tenant_id` (HTTP 401 `AuthRejected`)
/// without deleting the cache file on disk.
pub fn suspend_cache(tenant_id: &str) {
    let mut reg = registry().lock().unwrap_or_else(|e| e.into_inner());
    if reg.suspended.insert(tenant_id.to_string()) {
        warn!(tenant = %tenant_id, "overlay cache: suspended cold-boot seeding after auth refusal");
    }
}

/// Lift auth suspension for `tenant_id` after successful authentication or live
/// authoritative netmap receipt.
pub fn unsuspend_cache(tenant_id: &str) {
    let mut reg = registry().lock().unwrap_or_else(|e| e.into_inner());
    reg.suspended.remove(tenant_id);
}

/// Whether `tenant_id` is currently auth-suspended from cold-boot cache seeding.
pub fn is_suspended(tenant_id: &str) -> bool {
    let reg = registry().lock().unwrap_or_else(|e| e.into_inner());
    reg.suspended.contains(tenant_id)
}

/// Cancel any pending debounced write and delete the on-disk cache file for
/// `tenant_id` (called on `Goodbye` and terminal `OverlayJoinRefused`).
pub fn delete_cache(config_path: &Path, tenant_id: &str) {
    crate::p2pctl::clear_tenant_directory(tenant_id);
    {
        let mut reg = registry().lock().unwrap_or_else(|e| e.into_inner());
        if let Some(mut st) = reg.writers.remove(tenant_id)
            && let Some(h) = st.pending_timer.take()
        {
            h.abort();
        }
        reg.suspended.remove(tenant_id);
    }
    let Some(path) = cache_path(config_path, tenant_id) else {
        return;
    };
    match std::fs::remove_file(&path) {
        Ok(()) => info!(tenant = %tenant_id, path = %path.display(), "overlay cache: deleted on revocation/goodbye"),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => warn!(tenant = %tenant_id, path = %path.display(), %e, "overlay cache: failed to delete cache file"),
    }
}

/// Load and cryptographically verify `<config_dir>/overlay/netmap-<tenant>.json`.
///
/// Returns `None` if caching is disabled, the tenant is auth-suspended, the
/// file is missing, or any integrity/identity/rollback/age check fails.
pub fn load_verified(
    config_path: &Path,
    cfg: &AgentConfig,
    keypair: &WgKeypair,
) -> Option<NetmapCachePayload> {
    load_verified_at(config_path, cfg, keypair, now_epoch_ms())
}

fn load_verified_at(
    config_path: &Path,
    cfg: &AgentConfig,
    keypair: &WgKeypair,
    now_ms: u64,
) -> Option<NetmapCachePayload> {
    if !cache_enabled(cfg) {
        return None;
    }
    if is_suspended(&cfg.tenant_id) {
        warn!(tenant = %cfg.tenant_id, "overlay cache: skipping cold seed while tenant auth is suspended");
        return None;
    }
    let path = cache_path(config_path, &cfg.tenant_id)?;
    let raw = match std::fs::read_to_string(&path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return None,
        Err(e) => {
            warn!(tenant = %cfg.tenant_id, path = %path.display(), %e, "overlay cache: read failed");
            return None;
        }
    };
    let envelope: SignedNetmapCache = match serde_json::from_str(&raw) {
        Ok(env) => env,
        Err(e) => {
            warn!(tenant = %cfg.tenant_id, path = %path.display(), %e, "overlay cache: invalid envelope JSON");
            return None;
        }
    };
    let pubkey_b64 = keypair.public_base64();
    let id = CacheIdentity {
        tenant_id: &cfg.tenant_id,
        node_id: &cfg.agent_id,
        self_wg_pubkey: &pubkey_b64,
    };
    let secret = keypair.secret.to_bytes();
    let max_age = max_cache_age_ms(cfg);
    match open_and_verify(&secret, &id, &envelope, now_ms, max_age, None) {
        Ok(payload) => {
            // Seed writer metadata from the verified cache so any offline
            // learned-endpoint updates preserve the exact original authoritative
            // timestamp and revision without ever extending them.
            let mut reg = registry().lock().unwrap_or_else(|e| e.into_inner());
            let entry = reg
                .writers
                .entry(cfg.tenant_id.clone())
                .or_insert_with(|| TenantWriteState {
                    last_authoritative_at_ms: payload.last_authoritative_at_ms,
                    last_authoritative_revision: payload.last_authoritative_revision,
                    monotonic_clock_floor_ms: payload.monotonic_clock_floor_ms.max(now_ms),
                    generation: 0,
                    pending_timer: None,
                });
            entry.last_authoritative_at_ms = payload.last_authoritative_at_ms;
            entry.last_authoritative_revision = payload.last_authoritative_revision;
            entry.monotonic_clock_floor_ms = entry
                .monotonic_clock_floor_ms
                .max(payload.monotonic_clock_floor_ms)
                .max(now_ms);
            info!(
                tenant = %cfg.tenant_id,
                peers = payload.peers.len(),
                revision = payload.last_authoritative_revision,
                "overlay cache: verified local netmap cache for cold offline boot"
            );
            Some(payload)
        }
        Err(e) => {
            warn!(tenant = %cfg.tenant_id, path = %path.display(), %e, "overlay cache: verification refused cached netmap");
            None
        }
    }
}

/// Build the [`NetmapSnapshotSink`] wired into [`OverlayRuntime`].
pub fn snapshot_sink(
    config_path: &Path,
    cfg: &AgentConfig,
    keypair: &WgKeypair,
) -> Option<NetmapSnapshotSink> {
    if !cache_enabled(cfg) {
        return None;
    }
    let path = cache_path(config_path, &cfg.tenant_id)?;
    let tenant_id = cfg.tenant_id.clone();
    let node_id = cfg.agent_id.clone();
    let wg_secret = keypair.secret.to_bytes();
    let self_wg_pubkey = keypair.public_base64();
    Some(Arc::new(move |snap: NetmapSnapshot| {
        handle_snapshot(
            &path,
            &tenant_id,
            &node_id,
            &wg_secret,
            &self_wg_pubkey,
            snap,
            now_epoch_ms(),
            WRITE_DEBOUNCE,
        );
    }))
}

#[allow(clippy::too_many_arguments)]
fn handle_snapshot(
    path: &Path,
    tenant_id: &str,
    node_id: &str,
    wg_secret: &[u8; 32],
    self_wg_pubkey: &str,
    snap: NetmapSnapshot,
    now_ms: u64,
    debounce: Duration,
) {
    let (payload, urgent_flush, gen_now) = {
        let mut reg = registry().lock().unwrap_or_else(|e| e.into_inner());
        if snap.authoritative {
            reg.suspended.remove(tenant_id);
        }
        let st = reg
            .writers
            .entry(tenant_id.to_string())
            .or_insert_with(|| TenantWriteState {
                last_authoritative_at_ms: 0,
                last_authoritative_revision: 0,
                monotonic_clock_floor_ms: now_ms,
                generation: 0,
                pending_timer: None,
            });
        if snap.authoritative {
            st.last_authoritative_at_ms = now_ms;
            st.last_authoritative_revision = snap.auth_revision;
        } else if st.last_authoritative_at_ms == 0 {
            // Never persist a non-authoritative learned-endpoint snapshot
            // without an authoritative baseline.
            return;
        }
        st.monotonic_clock_floor_ms = st.monotonic_clock_floor_ms.max(now_ms);
        st.generation = st.generation.wrapping_add(1);
        let gen_now = st.generation;
        if let Some(prev) = st.pending_timer.take() {
            prev.abort();
        }
        let payload = NetmapCachePayload {
            schema_version: CACHE_SCHEMA_VERSION,
            tenant_id: tenant_id.to_string(),
            node_id: node_id.to_string(),
            self_wg_pubkey: self_wg_pubkey.to_string(),
            self_ip: snap.self_ip,
            network: snap.network,
            peers: snap.peers,
            last_authoritative_revision: st.last_authoritative_revision,
            last_authoritative_at_ms: st.last_authoritative_at_ms,
            monotonic_clock_floor_ms: st.monotonic_clock_floor_ms,
            learned_endpoints: snap.learned_endpoints,
        };
        (payload, snap.urgent_flush, gen_now)
    };

    let id = CacheIdentity {
        tenant_id,
        node_id,
        self_wg_pubkey,
    };
    let sealed = match seal(wg_secret, &id, &payload) {
        Ok(s) => s,
        Err(e) => {
            warn!(tenant = %tenant_id, %e, "overlay cache: failed to seal snapshot");
            return;
        }
    };
    let bytes = match serde_json::to_vec(&sealed) {
        Ok(b) => b,
        Err(e) => {
            warn!(tenant = %tenant_id, %e, "overlay cache: failed to serialize envelope");
            return;
        }
    };

    if urgent_flush || debounce.is_zero() || tokio::runtime::Handle::try_current().is_err() {
        if let Err(e) = write_private_atomic(path, &bytes) {
            warn!(tenant = %tenant_id, path = %path.display(), %e, "overlay cache: synchronous flush failed");
        } else {
            debug!(
                tenant = %tenant_id,
                urgent_flush,
                revision = payload.last_authoritative_revision,
                "overlay cache: flushed synchronously"
            );
        }
        return;
    }

    let path_owned = path.to_path_buf();
    let tenant_owned = tenant_id.to_string();
    let timer = tokio::spawn(async move {
        tokio::time::sleep(debounce).await;
        let still_current = {
            let reg = registry().lock().unwrap_or_else(|e| e.into_inner());
            reg.writers
                .get(&tenant_owned)
                .is_some_and(|st| st.generation == gen_now)
        };
        if !still_current {
            return;
        }
        if let Err(e) = write_private_atomic(&path_owned, &bytes) {
            warn!(tenant = %tenant_owned, path = %path_owned.display(), %e, "overlay cache: debounced write failed");
        } else {
            debug!(tenant = %tenant_owned, "overlay cache: debounced snapshot persisted");
        }
    });
    let mut reg = registry().lock().unwrap_or_else(|e| e.into_inner());
    if let Some(st) = reg.writers.get_mut(tenant_id)
        && st.generation == gen_now
    {
        st.pending_timer = Some(timer);
    } else {
        timer.abort();
    }
}

/// Owner-only atomic write: `0o700` directory, sibling `.tmp.<pid>` created
/// `0o600` (`create_new`), `write_all`, `sync_all`, atomic `rename`, directory
/// fsync.
fn write_private_atomic(path: &Path, bytes: &[u8]) -> Result<(), String> {
    use std::io::Write as _;

    let dir = path
        .parent()
        .ok_or_else(|| format!("{} has no parent directory", path.display()))?;
    std::fs::create_dir_all(dir).map_err(|e| format!("creating {}: {e}", dir.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
            .map_err(|e| format!("chmod 0700 {}: {e}", dir.display()))?;
    }
    let tmp = path.with_extension(format!(
        "json.tmp.{}.{}",
        std::process::id(),
        rand::random::<u32>()
    ));
    let _ = std::fs::remove_file(&tmp);
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        opts.mode(0o600);
    }
    let mut file = opts
        .open(&tmp)
        .map_err(|e| format!("opening {}: {e}", tmp.display()))?;
    let write_res = file.write_all(bytes).and_then(|()| file.sync_all());
    drop(file);
    if let Err(e) = write_res {
        let _ = std::fs::remove_file(&tmp);
        return Err(format!("writing {}: {e}", tmp.display()));
    }
    if let Err(e) = std::fs::rename(&tmp, path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(format!("renaming {} -> {}: {e}", tmp.display(), path.display()));
    }
    #[cfg(unix)]
    if let Ok(d) = std::fs::File::open(dir) {
        let _ = d.sync_all();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bson::oid::ObjectId;
    use meshharbor_remote_control::signaling::{NetmapPeer, OverlayNetworkInfo};
    use std::collections::BTreeMap;
    use tunnel_core::overlay::netmap_cache::LearnedPeerEndpoint;

    fn test_cfg(tenant: &str, keypair: &WgKeypair) -> AgentConfig {
        let mut cfg = crate::config::test_fixture();
        cfg.tenant_id = tenant.to_string();
        cfg.agent_id = "507f1f77bcf86cd799439011".to_string();
        cfg.overlay_enabled = true;
        cfg.overlay_wg_secret_key = Some(keypair.secret_base64());
        cfg
    }

    fn sample_net(rev: u64) -> OverlayNetworkInfo {
        OverlayNetworkInfo {
            org_relay_fallback_v1: false,
            org_relay_loss_v1: false,
            path_quality_v1: false,
            cidr: "100.64.0.0/10".into(),
            cidrs: vec!["100.64.0.0/10".into()],
            mtu: 1280,
            magic_domain: Some("offline.mesh.test".into()),
            nameservers: vec![],
            self_name: Some("node-a".into()),
            self_node_id: None,
            self_name_revision: None,
            stun_urls: vec![],
            strict_stun: false,
            central_relay_denied: false,
            relay_probe_targets: vec![],
            backbone_probe_targets: vec![],
            auth_revision: rev,
        }
    }

    fn sample_peer(ip: &str, name: &str) -> NetmapPeer {
        NetmapPeer {
            node_id: ObjectId::new(),
            overlay_ip: ip.into(),
            name: name.into(),
            wg_public_key: WgKeypair::generate().public_base64(),
            endpoints: vec![],
            lan_endpoints: vec!["192.168.50.10:43648".into()],
            srflx_endpoints: vec![],
            srflx_nat: None,
            supports_org_relay: false,
            caps: None,
            udp_dialer_ok: None,
            relay_home: None,
            warm_relay_endpoint: None,
            reachable: true,
            supports_quic: false,
            supports_relay_single: false,
            supports_derp: false,
            supports_forced_derp: false,
            relay_strategy: None,
            prefer_relay_ms: None,
            backbone_only: false,
            supports_overlay_echo: false,
            supports_p2pctl: false,
            supports_derp_floor: false,
            routes: vec![],
            agent_id: None,
            ingress_rules: Some(vec![]),
            ingress_rules_preview: None,
        }
    }

    #[tokio::test]
    async fn fr139_urgent_removal_flushes_synchronously_and_cancels_debounced_stale_write() {
        let dir = tempfile::tempdir().unwrap();
        let cfg_path = dir.path().join("config.toml");
        let kp = WgKeypair::generate();
        let tenant = format!("tenant-urgent-{}", ObjectId::new().to_hex());
        let cfg = test_cfg(&tenant, &kp);
        let path = cache_path(&cfg_path, &tenant).unwrap();

        let p1 = sample_peer("100.64.0.2", "peer-one");
        let p2 = sample_peer("100.64.0.3", "peer-revoked");

        // 1. Schedule a debounced write with 2 peers (simulates pending write).
        handle_snapshot(
            &path,
            &tenant,
            &cfg.agent_id,
            &kp.secret.to_bytes(),
            &kp.public_base64(),
            NetmapSnapshot {
                self_ip: "100.64.0.1".into(),
                network: sample_net(10),
                peers: vec![p1.clone(), p2.clone()],
                auth_revision: 10,
                authoritative: true,
                urgent_flush: false,
                learned_endpoints: BTreeMap::new(),
            },
            1_700_000_000_000,
            Duration::from_millis(80),
        );

        // 2. Immediately revoke `p2` with `urgent_flush = true`.
        handle_snapshot(
            &path,
            &tenant,
            &cfg.agent_id,
            &kp.secret.to_bytes(),
            &kp.public_base64(),
            NetmapSnapshot {
                self_ip: "100.64.0.1".into(),
                network: sample_net(11),
                peers: vec![p1.clone()],
                auth_revision: 11,
                authoritative: true,
                urgent_flush: true,
                learned_endpoints: BTreeMap::new(),
            },
            1_700_000_001_000,
            Duration::from_millis(80),
        );

        // Disk MUST already hold only `p1` immediately (before any debounce wait).
        let loaded = load_verified_at(&cfg_path, &cfg, &kp, 1_700_000_002_000)
            .expect("urgent flush must already be on disk");
        assert_eq!(loaded.peers.len(), 1);
        assert_eq!(loaded.peers[0].node_id, p1.node_id);
        assert_eq!(loaded.last_authoritative_revision, 11);

        // Even after the old debounce window elapses, the revoked peer is NEVER resurrected.
        tokio::time::sleep(Duration::from_millis(120)).await;
        let after = load_verified_at(&cfg_path, &cfg, &kp, 1_700_000_003_000)
            .expect("cache still valid");
        assert_eq!(after.peers.len(), 1);
        assert_eq!(after.peers[0].node_id, p1.node_id);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
        delete_cache(&cfg_path, &tenant);
    }

    #[test]
    fn fr139_non_authoritative_learned_flush_preserves_original_age_and_revision() {
        let dir = tempfile::tempdir().unwrap();
        let cfg_path = dir.path().join("config.toml");
        let kp = WgKeypair::generate();
        let tenant = format!("tenant-learned-{}", ObjectId::new().to_hex());
        let cfg = test_cfg(&tenant, &kp);
        let path = cache_path(&cfg_path, &tenant).unwrap();
        let p1 = sample_peer("100.64.0.2", "peer-one");

        let auth_t = 1_700_000_000_000u64;
        handle_snapshot(
            &path,
            &tenant,
            &cfg.agent_id,
            &kp.secret.to_bytes(),
            &kp.public_base64(),
            NetmapSnapshot {
                self_ip: "100.64.0.1".into(),
                network: sample_net(5),
                peers: vec![p1.clone()],
                auth_revision: 5,
                authoritative: true,
                urgent_flush: true,
                learned_endpoints: BTreeMap::new(),
            },
            auth_t,
            Duration::ZERO,
        );

        // 5 days later, an offline learned-endpoint flush happens (authoritative=false).
        let later_t = auth_t + 5 * 86_400 * 1_000;
        let mut learned = BTreeMap::new();
        learned.insert(
            p1.node_id.to_hex(),
            vec![LearnedPeerEndpoint {
                addr: "192.168.50.10:43649".into(),
                last_verified_at_ms: later_t,
            }],
        );
        handle_snapshot(
            &path,
            &tenant,
            &cfg.agent_id,
            &kp.secret.to_bytes(),
            &kp.public_base64(),
            NetmapSnapshot {
                self_ip: "100.64.0.1".into(),
                network: sample_net(99), // must be ignored because authoritative == false
                peers: vec![p1.clone()],
                auth_revision: 99,
                authoritative: false,
                urgent_flush: true,
                learned_endpoints: learned,
            },
            later_t,
            Duration::ZERO,
        );

        let loaded = load_verified_at(&cfg_path, &cfg, &kp, later_t + 1_000).unwrap();
        assert_eq!(loaded.last_authoritative_at_ms, auth_t);
        assert_eq!(loaded.last_authoritative_revision, 5);
        assert_eq!(loaded.monotonic_clock_floor_ms, later_t);
        assert_eq!(
            loaded.learned_endpoints[&p1.node_id.to_hex()][0].addr,
            "192.168.50.10:43649"
        );
        delete_cache(&cfg_path, &tenant);
    }

    #[test]
    fn fr139_401_suspends_without_deleting_and_goodbye_deletes_cache() {
        let dir = tempfile::tempdir().unwrap();
        let cfg_path = dir.path().join("config.toml");
        let kp = WgKeypair::generate();
        let tenant = format!("tenant-suspend-{}", ObjectId::new().to_hex());
        let cfg = test_cfg(&tenant, &kp);
        let path = cache_path(&cfg_path, &tenant).unwrap();
        let p1 = sample_peer("100.64.0.2", "peer-one");
        let t0 = 1_700_000_000_000u64;

        handle_snapshot(
            &path,
            &tenant,
            &cfg.agent_id,
            &kp.secret.to_bytes(),
            &kp.public_base64(),
            NetmapSnapshot {
                self_ip: "100.64.0.1".into(),
                network: sample_net(3),
                peers: vec![p1],
                auth_revision: 3,
                authoritative: true,
                urgent_flush: true,
                learned_endpoints: BTreeMap::new(),
            },
            t0,
            Duration::ZERO,
        );
        assert!(path.exists());

        // HTTP 401 suspends seeding without deleting file.
        suspend_cache(&tenant);
        assert!(load_verified_at(&cfg_path, &cfg, &kp, t0 + 1_000).is_none());
        assert!(path.exists(), "401 must NOT delete the cache file");

        // Auth recovery re-enables seeding.
        unsuspend_cache(&tenant);
        assert!(load_verified_at(&cfg_path, &cfg, &kp, t0 + 2_000).is_some());

        // Goodbye / terminal refusal deletes the cache file.
        delete_cache(&cfg_path, &tenant);
        assert!(!path.exists());
    }
}
