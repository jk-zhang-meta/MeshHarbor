// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! The TURN credential configuration builders (FR-69 P7a): `Core` holds the
//! region-keyed [`TurnMap`], and both the overlay relay grant (network) and
//! the tunnel socket (network, P7b) mint per-session configs the same way —
//! so the builders are core's, next to the map they fill.

use meshharbor_config::{Settings, TurnSettings};
use meshharbor_remote_control::{
    turn_creds::{TurnConfig, TurnMap},
    turn_url::{VariantCaps, expand_turn_url},
};

/// Build a [`TurnConfig`] from settings. Returns `None` when `shared_secret` is
/// absent (e.g. dev environments using static username/password instead).
/// Shared with the tunnel socket, which mints
/// per-session QUIC-over-TURN creds the same way (Phase 3c).
pub fn build_turn_config(turn: &TurnSettings) -> Option<TurnConfig> {
    let secret = turn.shared_secret.as_ref()?.clone();
    let base = turn.url.as_deref()?;

    // Same-worker TURN affinity (2026-07-14): optional comma-separated
    // per-worker base URLs, each expanded into the same transport variants
    // as the generic hostname. The Hub then pins BOTH sides of a session to
    // one worker (see `turn_creds::issue_for_session`) — the generic
    // hostname is 3 DNS A records, so without this each ICE side resolves
    // independently and relay↔relay sessions straddle two coturn workers.
    // Unset → empty → exactly the old single-hostname behaviour.
    let workers: Vec<Vec<String>> = turn
        .worker_urls
        .as_deref()
        .map(|s| {
            s.split(',')
                .map(str::trim)
                .filter(|w| !w.is_empty())
                .map(|w| expand_turn_url(w, &VariantCaps::default()))
                .collect()
        })
        .unwrap_or_default();

    Some(TurnConfig {
        urls: expand_turn_url(base, &VariantCaps::default()),
        workers,
        shared_secret: secret,
        ttl_secs: turn.ttl_secs.unwrap_or(600),
    })
}

/// Build the region-keyed [`TurnMap`]: the legacy `turn.*` config as the
/// default region plus one [`TurnConfig`] per enabled spec in
/// `ROOMLER__RELAY__REGIONS`. A malformed JSON or a region without any usable
/// shared secret is logged and skipped — never fatal, and with
/// `relay.regions_enabled=false` the map degrades to exactly the legacy
/// behaviour.
pub fn build_turn_map(settings: &Settings) -> TurnMap {
    use meshharbor_remote_control::turn_creds::RelayRegionSpec;

    let default = build_turn_config(&settings.turn);
    let ttl_secs = settings.turn.ttl_secs.unwrap_or(600);
    let mut regions = std::collections::HashMap::new();
    let mut specs: Vec<RelayRegionSpec> = Vec::new();
    if let Some(json) = settings.relay.regions.as_deref() {
        match serde_json::from_str::<Vec<RelayRegionSpec>>(json) {
            Ok(list) => {
                for spec in list {
                    if !spec.enabled {
                        specs.push(spec);
                        continue;
                    }
                    let Some(secret) = spec
                        .shared_secret
                        .clone()
                        .or_else(|| settings.turn.shared_secret.clone())
                    else {
                        tracing::warn!(
                            region = %spec.id,
                            "relay region has no shared secret (own or global turn.shared_secret); skipping"
                        );
                        continue;
                    };
                    regions.insert(
                        spec.id.clone(),
                        TurnConfig {
                            urls: expand_turn_url(&spec.turn_url, &spec.caps),
                            workers: spec
                                .worker_urls
                                .iter()
                                .map(|w| expand_turn_url(w, &spec.caps))
                                .collect(),
                            shared_secret: secret,
                            ttl_secs,
                        },
                    );
                    specs.push(spec);
                }
            }
            Err(e) => {
                tracing::error!(%e, "ROOMLER__RELAY__REGIONS is not valid JSON; ignoring regions");
            }
        }
    }
    if settings.relay.regions_enabled && regions.is_empty() {
        tracing::warn!(
            "relay.regions_enabled=true but no usable regions parsed — all issuance stays on the default region"
        );
    }
    TurnMap {
        default,
        regions,
        specs,
        enabled: settings.relay.regions_enabled,
    }
}
