# FR-137: Zone Backbone Globe and Read-Only Backbone API

> **Status:** in progress — claimed 2026-11-24. Tracking issue: none (GitHub Issues are disabled on
> this repository); this spec and its registry row are the record.

## Goal

Replace the legacy manual "Server topology" click-to-add/toggle/delete editor
(`ui/src/components/admin/ServerTopologySection.vue`) with a live, read-only **Zone Backbone
Globe** backed by the shared Three.js WebGL2 globe module (`ui/src/components/globe/`, FR-136) and
a dedicated read-only endpoint `GET /api/tenant/{tenant_id}/network-zones/backbone`:

- **Single source of truth from existing server state** (zero new MongoDB collections, zero new
  location collection):
  - Configured logical network zones from `OverlayNetwork.zones` (including FR-134 `is_centre`,
    `is_default`, `cross_zone_mode`, `auto_countries`, `gateway_relay_ids`, and live per-zone
    resolved `device_count`).
  - Every active device referenced by at least one zone's `gateway_relay_ids` — **including**
    devices whose `peer_relay_policy.serve == false` (such as a centre-zone host whose central
    reporting role is deliberately kept separate from relay forwarding and port `18443`
    management-entry listening) — enriched with online status, existing GeoIP/location metadata,
    `is_centre`, `serving_relay`, live management-entry listener state (`entry_listening`,
    `entry_port` strictly from live Hub state and only when `serving_relay == true`, so offline or
    non-serving hosts never falsely report listening), and live `entry_device_count` (currently
    connected agents whose `/ws?role=agent` upgrade carried a valid management-entry attestation
    through that gateway).
  - **Centre zone & role separation**: the centre zone is treated as an ordinary logical zone in
    the zone legend/filter bar, while the **Centre** role (reporting authority) stays distinct from
    the **Gateway / Forwarder** (`serving_relay`) and **Management Entry** (`entry_listening`)
    badges in both `ServerTopologySection.vue` and `GlobeDetailPanel.vue`.
  - Live gateway↔gateway connections assembled from recent `stats_mesh` snapshots (180 s window,
    identical pessimistic carrier merge and per-direction `ends` as `GET /api/tenant/{tid}/stats/mesh`,
    translated into gateway `agent_id` space and filtered to pairs where both ends are zone
    gateways).
- **Shared globe refinements (FR-136 T6 follow-ups)**:
  - Pure, unit-tested 2D projected label placement (`layoutProjectedLabels` in `geoLayout.ts`) with
    left/center/right inward edge alignment so zero labels ever clip outside a 390 px phone canvas.
  - Pure screen-space clustering (`clusterProjectedNodes` in `geoLayout.ts`) rendering ≥ 36×36 px
    interactive cluster count pills when co-located devices overlap (`36 px` mobile / `26 px`
    desktop); tapping flies in to fan out the cluster, and tapping when already zoomed (or still
    overlapping) opens a compact cluster device picker (desktop popover / mobile bottom sheet) with
    ≥ 40 px tap-target rows.
  - Gateway management-entry state and multi-zone chips surfaced in `GlobeDetailPanel.vue` and
    desktop hover tooltips.

---

## Explicitly Untouched Legacy Surfaces

- **Legacy `server_links` routes & storage** (`crates/modules/network/src/routes/server_link.rs`,
  `OverlayNetwork.server_links`, `/api/tenant/{tid}/server-link`): left intact in place on the
  server (unused by the updated UI) as a separate later cleanup.
- **Central "Server" role logic** (`business_authority`, used by org-relay `auto` mode and
  business isolation): completely untouched.
- **Route & sidebar preservation**: `/tenant/{tenantId}/network/servers` remains the route and
  sidebar destination (`nav.serverTopology` renamed to `"Zone backbone"` / `"分区骨干"`).

---

## API Contract: `GET /api/tenant/{tenant_id}/network-zones/backbone`

- **AuthZ**: requires `MANAGE_AGENTS` in `tenant_id` (`403 Forbidden` otherwise). Read-only; never
  allocates an `overlay_networks` document for an unconfigured tenant.
- **Response (`ZoneBackboneResponse`)**:
  - `revision: u64` — `OverlayNetwork.zone_revision` (`0` if unconfigured).
  - `zones: BackboneZoneView[]` — `id`, `name`, `is_centre`, `is_default`, `cross_zone_mode`,
    `auto_countries`, `gateway_relay_ids`, `device_count`.
  - `gateways: BackboneGatewayView[]` — `agent_id`, `name`, `online`, `os`, `agent_version`,
    `last_seen_at`, `country_code`, `country`, `region`, `city`, `relay_home`, `public_ip`,
    `zone_ids`, `is_centre`, `serving_relay`, `entry_listening`, `entry_port`, `entry_device_count`.
  - `links: BackboneLinkView[]` — `from_agent_id`, `to_agent_id`, `carrier`, `rtt_ms`, `stalled`,
    `reports`, `cross_zone`, `ends` (`{ node, carrier, relay, rtt_ms, stalled }`, `node` = gateway
    `agent_id` hex).

---

## Phases

| Phase | What | Kill switch | Status |
|---|---|---|---|
| **P1 (Server)** | Hub live `via_management_entry` tracking + `management_entry_device_counts` + `agent_management_entry_port`; `GET /api/tenant/{tid}/network-zones/backbone`; composition baseline & `TestApp` integration tests | Read-only route; legacy `/server-link` untouched | implemented |
| **P2 (Shared Globe)** | Edge-clamped `layoutProjectedLabels`, ≥ 36 px `clusterProjectedNodes` pills + ≥ 40 px cluster device picker, management-entry details in `GlobeDetailPanel` & hover tooltip | Automatic non-WebGL2 `#fallback` | implemented |
| **P3 (Backbone UI)** | Replace `ServerTopologySection.vue` with Zone Backbone Globe + zone legend/filters + responsive Gateways/Links summary tables + `en`/`zh-CN` i18n | Non-WebGL2 fallback + always-present accessible tables | implemented |

---

## Acceptance Criteria

- [x] **AC1 (Live entry device tracking).** `resolve_origin` returns the attesting gateway
  `ObjectId` on valid attestation (both public and private device IPs); `Hub` tracks
  `via_management_entry` per connected agent, isolates counts by tenant, and drops counts on
  disconnect or displacement.
- [x] **AC2 (Read-only backbone endpoint).** `GET /api/tenant/{tid}/network-zones/backbone` gated on
  `MANAGE_AGENTS` returns zones (with `is_centre` & resolved `device_count`), approved gateways
  (with live `entry_listening`, `entry_port`, `entry_device_count`, and offline safety), and live
  gateway↔gateway `stats_mesh` links (180 s window, pessimistic merge, non-gateway & stale links
  excluded).
- [x] **AC3 (390 px label containment & dense cluster UX).** Zero projected labels clip outside
  `[8, 382]` on a `390×844` viewport; dense co-located devices group into ≥ 36 px interactive
  cluster pills that zoom/fan out and open a ≥ 40 px-row device picker (`Esc` closes).
- [x] **AC4 (Zone Backbone UI & i18n).** `ServerTopologySection.vue` renders zones, centre accent,
  gateways, entry state, and gateway↔gateway links on the shared `MeshGlobe`, removes the legacy
  manual link editor, preserves `/network/servers` with updated nav labels, provides non-WebGL2
  fallback + responsive Gateways/Links tables, and maintains 100% `en`/`zh-CN` key parity.
- [x] **AC5 (Audits & headless visual verification).** `fr-registry-audit.sh`,
  `anchor-range-audit.sh`, `name-audit.sh`, `composition_tests`, Rust & Vitest suites, and headless
  Playwright visual checks (0 external CDN requests, 0 console/page errors) all pass.
