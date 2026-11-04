// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
import { defineStore } from 'pinia'
import { ref } from 'vue'
import { api } from '@/api/client'
import { useTenantStore } from '@/stores/tenant'
import { canManageOrgSettings } from '@/utils/permissions'
import { isKeepBusyPattern, type KeepBusyPattern } from '@/composables/keepBusy'
import type { AgentReleaseBrief } from '@/utils/updateStall'

/**
 * The three org-level switches (`exec-settings`, `ssh-settings`,
 * `ephemeral-key-settings`) all sit behind `MANAGE_TENANT`, which
 * `DEFAULT_ADMIN` deliberately does not carry — so for everyone but an
 * owner these GETs are a guaranteed 403.
 *
 * FR-82 — the gate lives in the STORE, not at each call site, which is the
 * rule FR-75 (#1447) paid for on the `network` module's routes: a per-caller
 * predicate leaks the moment one caller reaches for the wrong one, and the
 * `ephemeral-key-settings` fetch had NO caller-side gate at all (the Devices
 * page mounts its card unconditionally). One guard here makes the class
 * unrepresentable.
 *
 * ⚠️ It AWAITS the membership rather than reading the mask: AppLayout's
 * `/member/me` is in flight while this page mounts, so a synchronous read
 * would be a coin-flip between "hidden from the owner" and "fires anyway".
 *
 * ⚠️ This is no longer a session-safety gate — after FR-82 a 403 here would
 * be harmless. It is why the request is not sent at all: a fetch whose
 * refusal is known in advance is a round-trip, a red line in the browser
 * console and a 403 in the server log that make the REAL ones harder to see.
 */
async function mayReadOrgSettings(tenantId: string): Promise<boolean> {
  const tenants = useTenantStore()
  await tenants.ensureMyMembership(tenantId)
  return canManageOrgSettings(tenants.myPermissions, tenants.isOwner)
}

export type AgentOs = 'linux' | 'macos' | 'windows'
export type AgentStatusValue = 'online' | 'offline' | 'unenrolled' | 'quarantined'

/** How consent is obtained before a controller may drive a device. Mirrors the
 *  Rust `ConsentMode` (snake_case). `null` = inherit the system default
 *  (`prompt` — attended). Replaces the legacy `require_consent` bool. */
export type ConsentMode = 'auto' | 'prompt' | 'email' | 'push' | 'prompt_then_email'

/** FR-99 P3 — whether a device locks its screen when the last remote session
 *  ends. Mirrors the Rust `LockOnEnd` (lowercase on the wire). */
export type LockOnEnd = 'never' | 'auto' | 'always'

/** FR-101 P2 — one sensitive session feature, as an org allows it. Mirrors the
 *  Rust `RcFeaturePolicy` (lowercase on the wire). */
export type RcFeaturePolicy = 'on' | 'ask' | 'off'

/** FR-101 P2 — the org's remote-session policy (`GET/PUT …/rc-session-policy`). */
export interface RcSessionPolicy {
  clipboard: RcFeaturePolicy
  files: RcFeaturePolicy
  audio: RcFeaturePolicy
}

export interface AccessPolicy {
  consent_mode: ConsentMode | null
  /** FR-27 — apply `consent_mode` to the device's OWNER too.
   *
   *  `null`/`false` (the default) keeps the historical shortcut: controlling
   *  your own device auto-consents, because unattended access to your own
   *  headless boxes is the common case.
   *
   *  That shortcut is applied server-side BEFORE the policy is read, which is
   *  why the consent picker appeared to do nothing on a fleet where one person
   *  owns every device. Turning this on makes the mode authoritative for the
   *  owner as well. */
  prompt_owner?: boolean | null
  allowed_role_ids: string[]
  allowed_user_ids: string[]
  auto_terminate_idle_minutes: number | null
  /** P6 — multi-user input arbitration: `free` (default — everyone with
   *  INPUT injects, agent-fenced) | `exclusive` (one floor holder,
   *  request/grant). `null`/absent = free. */
  input_mode?: 'free' | 'exclusive' | null
  /** #1882 — may a remote-desktop session to this device ride the WireGuard
   *  mesh (overlay)? `null`/absent/`false` = no, the default: the agent keeps
   *  every overlay address out of the session's ICE, so it takes a LAN,
   *  direct or TURN path. `true` lets ICE pick the overlay pair when it is
   *  the best one (it can be the only working path between two hostile NATs,
   *  but it inherits the mesh's failure modes). */
  rc_overlay?: boolean | null
  /** FR-99 P3b — what this device's sessions ask of it when the last one
   *  ends: `auto` (lock again if it was locked, or nobody was at it, when the
   *  session began) or `always`. The device takes the stricter of this and its
   *  owner's own setting, so an ask can only tighten it. `null`/absent/`never`
   *  asks nothing. */
  lock_on_end?: LockOnEnd | null
}

/** S1a / FR-2 / FR-67 P7 — the bulk update's answer: one row per target. */
export interface BulkUpdateResponse {
  requested: number
  delivered: number
  refused: number
  results: Array<{
    agent_id: string
    delivered: boolean
    refused?: string
    refused_code?: string
  }>
}

/** Codec + HW backend availability advertised by the agent in its
 *  rc:agent.hello payload. AgentsSection renders these as chips so
 *  operators can spot which agents support H.265 / AV1 etc. without
 *  starting a session. Phase 2 codec negotiation uses the union with
 *  the controller browser's capabilities to pick the best codec.
 *  Defaults to empty arrays for agents that haven't reconnected since
 *  the 2A.1 schema landed (server back-fills `Default::default()`). */
export interface AgentCapabilities {
  /** FR-67 P7 — whether this enrollment acts on an update ordered from this
   *  organization: 'self' (it does), 'primary_org' (a secondary enrollment:
   *  only the machine's primary drives its updater), 'off' (auto-update off
   *  on the device). Absent on older agents. See utils/updateRefusal.ts. */
  update_mode?: string
  /** mime-style codec names: 'h264', 'h265', 'av1'. */
  codecs: string[]
  /** Descriptive backend labels: 'openh264-sw', 'mf-h264-hw', 'mf-h265-hw',
   *  'ffmpeg-hevc_nvenc', 'ffmpeg-vp9_qsv', 'ffmpeg-av1_nvenc',
   *  'libvpx-vp9-444-sw'. The rc.190 HW×HW transport auto-rank reads
   *  these to know which codecs the agent HARDWARE-encodes. */
  hw_encoders: string[]
  /** DC video transports beyond the default WebRTC track:
   *  'data-channel-vp9-444', 'data-channel-hevc', 'data-channel-av1'.
   *  Serialized only when non-empty (serde skip_serializing_if), so
   *  it's optional here; the auto-rank falls back to deriving from
   *  `hw_encoders` for older agent rows. */
  transports?: string[]
  /** FR-17 — opt-in `video-bytes` wire extensions the agent understands.
   *  Today the only value is `'chunk-framing'`: every 16 KiB DataChannel
   *  message carries an 8-byte {frame_seq, chunk_idx, chunk_count}
   *  prefix so a receiver can tell a gap from a boundary. Absent on
   *  agents below 0.4.14, which is exactly why the viewer must ASK for
   *  it rather than assume it — an unframed stream parsed as a framed
   *  one is garbage, not a degraded picture. */
  video?: string[]
  has_input_permission: boolean
  /** Host permissions the OS has actually GRANTED (rc.454+):
   *  'screen-capture', 'input'. macOS is the only platform that gates
   *  them, and it never errors when one is missing — capture returns
   *  wallpaper-only frames and injected input is silently dropped.
   *
   *  ⚠️ `undefined` and `[]` mean OPPOSITE things: undefined is a
   *  pre-rc.454 agent that cannot report (say nothing), `[]` is an
   *  agent reporting it holds NEITHER (warn loudly). Never collapse
   *  them with a falsy check.
   *
   *  'no-gui-session' is a THIRD state and appears ALONE: the process
   *  is outside a GUI login session (macOS's root LaunchDaemon), so
   *  capture and input are impossible regardless of grants. It is not
   *  a device with missing permissions — it is not a capture target. */
  permissions?: string[]
  supports_clipboard: boolean
  supports_file_transfer: boolean
  max_simultaneous_sessions: number
  /** File-DC v2 (0.3.0+) per-feature capability list. Recognised
   *  values: 'upload', 'download', 'download-folder', 'browse'.
   *  Empty / unset on older agents — browsers fall back to
   *  `supports_file_transfer` as the upload-only marker. */
  files?: string[]
  /** rc.61 — VP9 chroma format the agent emits on the
   *  `data-channel-vp9-444` transport. Values: `'yuv444'` (default,
   *  VP9 profile 1, sharpest text via ClearType chroma) or
   *  `'yuv420'` (VP9 profile 0, ~30% bandwidth saving with slight
   *  chroma softening on small Windows text). Empty / unset on
   *  pre-rc.61 agents — browsers treat as `'yuv444'`. The vp9-444
   *  worker uses this to pick the right `VideoDecoder` codec
   *  string (`vp09.01.10.08` vs `vp09.00.10.08`); mismatch leaves
   *  the canvas blank. */
  vp9_chroma?: string
  /** P7 — chroma formats the agent's HEVC encoder can emit on the
   *  `data-channel-hevc` transport: `'yuv420'` (Main — every HEVC host)
   *  and `'yuv444'` (Rext — hevc_nvenc only). The browser offers its
   *  "HEVC · crisp text (4:4:4)" picker entry only when this contains
   *  `'yuv444'` AND its own WebCodecs Rext decode probe passes. Empty /
   *  unset on older agents → the entry stays hidden. Mirrors
   *  `AgentCaps.hevc_chroma` in `crates/remote_control/src/models.rs`. */
  hevc_chroma?: string[]
  /** Audio codecs the agent can stream on the opt-in WebRTC audio
   *  track (system / desktop audio). Known value: `'opus'`. Empty /
   *  unset on older agents or agents built without the `audio` Cargo
   *  feature — the browser hides/disables the "receive audio" toggle
   *  when this doesn't contain `'opus'`. Mirrors `AgentCaps.audio` in
   *  `crates/remote_control/src/models.rs`. */
  audio?: string[]
  /** Fleet RPC. Known values: `'exec'` (honours rc:rpc.exec) and
   *  `'originate'` (its LocalAPI can drive `meshharbor exec` at other
   *  devices). Empty / unset on agents that predate the feature — the
   *  console tells the operator to update the agent rather than letting
   *  them send a frame it would silently drop. */
  rpc?: string[]
  /** Remote app selection & launch (FR-56). Known values, matched by
   *  equality: 'list', 'focus', 'launch' — the agent could manage a desktop
   *  when it announced itself (a Linux virtual desktop or a logged-in
   *  X11/Xwayland session, or Windows) and the feature is enabled there;
   *  'status' (AC10) — this build has a Remote Apps backend and answers
   *  rc:apps.list honestly, with the list or with `unavailable: {code,
   *  reason}`. The viewer shows the Apps entry for 'list' OR 'status' and
   *  lets the live reply say what is true now — the hello is a boot-time
   *  snapshot, so 'status' without 'list' can just mean nobody had logged in
   *  yet when the daemon started. Empty / unset on older agents and macOS —
   *  the browser hides the Apps menu. Mirrors `AgentCaps.apps` in
   *  `crates/remote_control/src/models.rs`. */
  apps?: string[]
  /** Clipboard-DC protocol v2. Known values: 'ack' (write-ack replies
   *  gate the deferred Ctrl+V), 'events' (agent pushes host clipboard
   *  changes after `clipboard:subscribe`), 'images' (PNG payloads both
   *  directions), 'html' (v2.1 — CF_HTML + text alt round-trip:
   *  formatted text, tables, web-hosted images survive the paste),
   *  'native' (v2.2 — RTF with EMBEDDED images; needs the viewer's
   *  own local agent bridge to reach its RTF clipboard). Empty /
   *  unset on older agents — the browser falls back to the v1
   *  button-driven text-only flow. Mirrors `AgentCaps.clipboard` in
   *  `crates/remote_control/src/models.rs`. */
  clipboard?: string[]
  /** rc.227 — keyboard-layout integration (Windows hosts). Known
   *  values: 'report' (agent pushes rc:layout snapshots over the
   *  control DC), 'set' (agent accepts rc:layout.set manual switches).
   *  Empty / unset on older agents / non-Windows hosts — the browser
   *  hides the layout chip + picker. Mirrors `AgentCaps.layout`. */
  layout?: string[]
  /** P6 input arbitration, FR-92 and FR-109. Known values, matched by
   *  equality: 'arbiter', 'exclusive', 'ghost-cursor', 'keep-busy' (this
   *  agent can run keep busy here and its owner allows it, so the viewer
   *  offers the Keep busy menu), and 'mouse-rel' (it takes `mouse_rel` and
   *  `mouse_press`, so the viewer offers relative mouse). Mirrors
   *  `AgentCaps.input`. */
  input?: string[]
  /** FR-77 — every cell (codec × chroma format) the host can produce, one
   *  entry per encoder (codec × backend) the start-up probe actually opened.
   *  Absent on agents older than FR-77: `cellsFromCaps()` then derives the
   *  cells from the legacy fields above, which the agent keeps filling
   *  forever. Mirrors `AgentCaps.video_cells`. */
  video_cells?: VideoCell[]
  /** FR-77 — wall-clock ms the start-up capability probe took (child spawn to
   *  parsed result). Absent on older agents or when the probe child died. */
  probe_ms?: number
  /** FR-77 P3 — the cells came from the daemon's probe cache (probe_ms is the cached probe's duration). */
  probe_cached?: boolean
  /** FR-97 P0c — what this host cannot serve, and why: feature →
   *  `{code, reason}`. Known features, matched by equality: 'audio',
   *  'clipboard', 'clipboard-image-events', 'sas'. The lists above still
   *  decide what works; this says why a control does not, and
   *  `not-applicable` hides it. Absent on older agents, which never means
   *  "unavailable". Read it through `utils/hostUnavailable`, never directly.
   *  Mirrors `AgentCaps.unavailable`. */
  unavailable?: Record<string, { code: string; reason: string }>
}

/** FR-77 — one encoder and the chroma formats it opened in. Wire strings:
 *  codec `h264` · `hevc` · `av1` · `vp9`; backend `nvenc` · `qsv` · `amf` ·
 *  `videotoolbox` · `vaapi` · `d3d12` · `vulkan` · `mf` · `openh264` · `libvpx`; chroma `yuv420` ·
 *  `yuv444`. A newer agent may send names this bundle does not know — they are
 *  ignored, never an error. */
export interface VideoCell {
  codec: string
  backend: string
  chroma: string[]
  hw: boolean
}

/** FR-92 P5b — what a device says about its keep busy on each heartbeat. A
 *  CLAIM by the device, shown, never enforced on. `phase` and `reason` are the
 *  agent's own wire words; an unknown one from a newer agent is printed as is. */
export interface KeepBusyBrief {
  on: boolean
  phase: string
  reason?: string
  /** While on: the pattern drawn. */
  pattern?: string
  /** While on: who turned it on. */
  set_by?: string
}

export interface Agent {
  id: string
  tenant_id: string
  owner_user_id: string
  name: string
  /** Admin-set friendly label; display-only (the technical `name` is what
   *  MagicDNS derives from). Absent = show `name`. */
  display_name?: string
  /** Admin-set fleet labels. */
  tags?: string[]
  machine_id: string
  os: AgentOs
  agent_version: string
  /** FR-27 — the `meshharbor-desktop` version installed on the host, reported on
   *  the heartbeat. Absent means one of three things and the UI must not
   *  flatten them: a pre-FR-27 agent, no companion installed, or a probe that
   *  could not read one. The daemon and the companion update by different
   *  mechanisms on every platform, so `agent_version` moving says nothing
   *  about this one. */
  companion_version?: string
  /** FR-92 P5b — keep busy as the device last reported it on a heartbeat.
   *  Absent = the device does not say (no keep busy there, an older agent,
   *  or a supervised Mac's daemon): unknown, never "off". */
  keep_busy?: KeepBusyBrief
  /** FR-51 — enrolled as temporary: the server reaps it after silence, and a
   *  clean stop removes it immediately. Removal is FINAL (hard delete) — a
   *  later enrollment is a NEW device. The grid badges it so nobody is
   *  surprised by the vanishing. Absent on pre-FR-51 bodies = permanent. */
  ephemeral?: boolean
  /** FR-51 P4 — the device's own inactivity deadline override (seconds);
   *  absent = the server default applies. */
  ephemeral_ttl_secs?: number
  status: AgentStatusValue
  /** Phase A-1 three-state truth: `online` = an rc socket is registered
   *  somewhere (Connect will work); `stale` = heartbeat trail fresh but no
   *  pod claims the socket (amber — half-open leg or dead pod); `offline`.
   *  Optional for pre-A-1 API bodies — consumers fall back to `is_online`. */
  presence?: 'online' | 'stale' | 'offline'
  /** Back-compat: `presence === 'online'`. */
  is_online: boolean
  last_seen_at: string
  /** FR-103 — when the agent token the device last connected with expires
   *  (RFC 3339). Absent until the device connects to a server with FR-103,
   *  and on older API bodies: "not reported", never "does not expire". */
  token_expires_at?: string | null
  access_policy: AccessPolicy
  /** Subnet-router CIDRs this agent advertises for the mesh subnet-router
   *  (Phase 2). Managed via the Subnet-routes dialog; the `meshharbor`
   *  mesh longest-prefix-matches a LAN target IP against these to pick the
   *  covering agent. Optional because pre-Phase-2 agents / older API
   *  responses may omit it. */
  routes?: string[]
  /** Subnet CIDRs the agent itself ADVERTISES it can route (from its
   *  `advertise_routes` config, sent on hello). Untrusted suggestions the
   *  admin approves into `routes` via the Subnet-routes dialog. Optional /
   *  empty for pre-feature agents. */
  advertised_routes?: string[]
  /** Optional because pre-2A.1 agents (and tests) may not include it. */
  capabilities?: AgentCapabilities
  /** Fleet RPC gate 3, as actually stored on the device row.
   *
   *  Absent = nobody has configured this device (the server omits a policy
   *  that is byte-for-byte the default), or an API body that predates the
   *  feature. Either way consumers must read it as `mode: 'off'`, never as
   *  permissive. */
  exec_policy?: ExecPolicy
  /** FR-94 — present when an administrator anchored this Windows device, so
   *  its commands run as SYSTEM through its service. Who and when; the
   *  credential never leaves the device. */
  exec_anchor?: { anchored_at: string; anchored_by: string } | null
  /** MeshHarbor SSH gate 3. Same rule as `exec_policy`: absent means OFF.
   *
   *  ⚠️ Absent is also the ONLY correct reading for an unconfigured device:
   *  the server's model default names `account_mode: 'daemon'` (SYSTEM /
   *  root), so if this ever starts arriving for devices nobody configured,
   *  {@link SshPolicyDialog}'s spread would pre-select a root shell. The
   *  dialog's own default is `console_user` for exactly that reason — don't
   *  "helpfully" fill this in. */
  ssh_policy?: SshPolicy
  /** FR-52 gate 2 — approval for control by someone OUTSIDE this org.
   *
   *  Absent = never approved, which is also the correct reading for every
   *  device that predates the feature. Unlike {@link ssh_policy} there is no
   *  hazard in an absent value here: the server's default is `approved:
   *  false`, so a spread of `undefined` yields a closed dialog rather than an
   *  open door. */
  external_access_policy?: ExternalAccessPolicy
  /** Remote config: what an operator asked this device to run, what the device
   *  said it did, and where that leaves things (`docs/remote-config.md`).
   *
   *  Absent = nothing has ever been requested for this device. */
  remote_config?: RemoteConfig
  /** FR-40 — the device's overlay (WireGuard) PUBLIC key as it last joined
   *  with, server-verified. Absent until it has joined on a server that
   *  stamps it. */
  overlay_public_key?: string
  overlay_key_epoch?: number
  /** FR-40 — the standing rotation order and where it stands. Absent = a
   *  rotation was never ordered for this device. */
  key_rotation?: KeyRotation
  /** FR-100 P1a — the public half of the device key this enrollment last said
   *  hello with (a P-256 point, standard base64), and its fingerprint as a
   *  person reads it. Both absent until the device sends a key. A hint for a
   *  browser's first pin, never an authority. */
  peer_auth_key?: string
  peer_auth_fingerprint?: string
  /** Multi-region relay PoPs: the agent's nearest relay region id (derived
   *  server-side from its STUN probe reports), e.g. "us-east". Absent/null =
   *  never probed or all probes timed out — the default region serves it. */
  relay_home?: string | null
}

/** Fleet RPC — whether a device accepts remote commands at all. Mirrors the
 *  Rust `ExecMode`. Default `off` on every device, including every device
 *  that existed before the feature. */
export type ExecMode = 'off' | 'on'

/** Fleet RPC gate 3 — the per-device execution policy.
 *
 *  Deliberately separate from {@link AccessPolicy}: that grants screen-view,
 *  and "may watch your screen" must never be the same checkbox as "may run a
 *  root shell". Commands inherit the daemon's identity — root under
 *  systemd; on Windows the console-session worker's: the signed-in user on an
 *  attended install, SYSTEM in SystemContext mode (FR-94 makes SYSTEM the
 *  default) — so turning `mode` on is
 *  granting root on that device, which the dialog says in those words. */
export interface ExecPolicy {
  mode: ExecMode
  /** May this device ORIGINATE commands against others (`meshharbor exec` from
   *  its CLI)? Default false — without it, one compromised laptop would
   *  inherit its owner's exec rights across the whole fleet. */
  can_originate: boolean
  allowed_user_ids: string[]
  allowed_role_ids: string[]
  /** Only `auto` (unattended) and `prompt` are honoured; the session-shaped
   *  email/push modes collapse to `prompt`. `null` = prompt. */
  consent_mode: ConsentMode | null
  /** Empty = any shell the host supports. */
  shells: string[]
  /** FR-94 P4 — the account a Windows device's SYSTEM service runs a command
   *  as. FR-97 P5a: on Linux and macOS, root (`system`) or the person at the
   *  device's screen, for an agent that says `console-user`. Absent when
   *  saving = keep what the device has (the server never resets it), which is
   *  why the dialog's closed default leaves it out. */
  run_as?: 'system' | 'console_user'
}

/** MeshHarbor SSH — whether a device accepts interactive sessions at all.
 *  Mirrors the Rust `SshMode`. Default `off` everywhere. */
export type SshMode = 'off' | 'on'

/** Which local account a session runs as. Mirrors the Rust
 *  `SshAccountMode`. `daemon` means root under systemd. On Windows it means
 *  the console-session worker — the signed-in user on an attended install,
 *  SYSTEM in SystemContext mode — and `console_user` is refused on an
 *  attended install (it needs SYSTEM's `WTSQueryUserToken`). The SSH dialog
 *  still says "SYSTEM"; correcting it is FR-94's SSH follow-up (§8). On
 *  Linux and macOS `console_user` is the person at the device's screen
 *  (FR-97 P5a), for an agent that says `console-user`. */
export type SshAccountMode = 'daemon' | 'console_user' | 'named'

/** MeshHarbor SSH gate 3 — the per-device session policy.
 *
 *  Deliberately separate from {@link ExecPolicy}, mirroring the server's
 *  separate `SSH_DEVICE` bit: an SSH session is strictly more than a bounded
 *  command — it is interactive, it lasts, and it grows file transfer and port
 *  forwarding as later slices land. "May run one clamped diagnostic" and "may
 *  hold a live session" have to be grantable independently. */
export interface SshPolicy {
  mode: SshMode
  /** May this device ORIGINATE sessions against others? Default false, for
   *  the same reason as {@link ExecPolicy.can_originate}. */
  can_originate: boolean
  allowed_user_ids: string[]
  allowed_role_ids: string[]
  account_mode: SshAccountMode
  /** The account for `account_mode: 'named'`. Ignored otherwise. */
  account: string | null
  /** Only `auto` (unattended) and `prompt` are honoured. `null` = prompt —
   *  an absent directive means ask, the fail-safe the agent also applies. */
  consent_mode: ConsentMode | null
}

/** FR-52 gate 2 — a device's approval for control by someone OUTSIDE the org.
 *
 *  ⚠️ Approving grants nothing on its own. The device must still opt in
 *  locally, the outsider must still prove the device-held password, and the
 *  person at the machine still consents. What this DOES decide is the ceiling
 *  — and an absent `max_permissions` is the NARROW one (`VIEW | INPUT`), never
 *  "unrestricted". */
export interface ExternalAccessPolicy {
  approved: boolean
  /** Pipe-separated names (`"VIEW | INPUT"`), matching the rest of the `rc:*`
   *  surface. `null`/absent = the server's built-in ceiling. */
  max_permissions?: string | null
  /** ISO instant, or absent for an approval that stands until cleared. */
  expires_at?: string | null
}

/** One approved device as the external-access settings view lists it. */
export interface ExternalDevice {
  id: string
  name: string
  status: AgentStatusValue
  /** Display form, `XXXX-XXXX-XXXX`. `null` when no code has been minted —
   *  an approved device with no code is not reachable, which is the most
   *  common "why can they not connect?" answer. */
  connect_code: string | null
  connect_code_rotated_at: string | null
  /** Always the RESOLVED ceiling, never an unset placeholder. */
  max_permissions: string
  expires_at: string | null
  /** Whether the device's agent understands cross-org access at all. An
   *  approved device on an old agent is approved and unreachable. */
  supported: boolean
}

export interface ExternalAccessSettings {
  enabled: boolean
  devices: ExternalDevice[]
}

/** What the device did with a pushed desired-config. Mirrors the Rust
 *  `ConfigOutcome`. Everything except `applied` / `noop` is a refusal, and the
 *  refusals are the ones an operator can act on. */
export type ConfigOutcome = 'applied' | 'noop' | 'not_opted_in' | 'not_primary' | 'failed'

/** Where a device's remote config stands, resolved SERVER-side.
 *
 *  Deliberately one enum rather than several booleans: these are mutually
 *  exclusive, and a client deriving them separately would eventually render
 *  two at once. The comparison behind it (desired revision vs reported
 *  revision vs what the agent is even capable of saying) happens once, on the
 *  server — see `remote_config_view`. */
export type RemoteConfigState =
  /** Confirmed, and everything asked for is in force. */
  | 'applied'
  /** Confirmed, but some keys wait on a daemon restart. NEVER merge this into
   *  `applied`: doing so tells an operator SSH is open while the device still
   *  refuses every session. */
  | 'needs_restart'
  /** The device said no — `report.outcome` says which no. */
  | 'refused'
  /** The device tried and failed; `report.detail` says why. */
  | 'failed'
  /** Waiting on the device to answer about THIS revision (includes "it has
   *  not reconnected yet" — delivery is reconcile-on-connect). */
  | 'pending'
  /** The agent applies pushed config but predates `config-report`, so it will
   *  never say what it did. Distinct from `pending` because waiting is futile
   *  and the fix is to update the device. */
  | 'reports_unsupported'
  /** The agent predates `rc:agent.config` — the push is not even sent. */
  | 'push_unsupported'

/** The device's own account of a push.
 *
 *  ⚠️ A CLAIM BY THE DEVICE, not the server's record. `config_audit` holds who
 *  asked for what and is authoritative; this is what a host says happened
 *  afterwards. */
export interface ConfigReport {
  revision: number
  outcome: ConfigOutcome
  /** Keys now IN FORCE. */
  live: string[]
  /** Keys written to disk, waiting on a restart. */
  needs_restart: string[]
  detail?: string
  reported_at: string
}

/** The keys under management. `undefined` means NOT MANAGED — the device
 *  keeps whatever it has locally — which is a different thing from `false`.
 *
 *  ⚠️ `remote_config_enabled` is deliberately absent and must never be added:
 *  it is the device's opt-in to accepting any of this, and a server able to
 *  set it could opt a device in and then open every other key. */
export interface DesiredConfig {
  revision: number
  exec_enabled?: boolean
  ssh_enabled?: boolean
  ssh_authorized_keys?: string[]
  ssh_account_mode?: string
  ssh_port?: number
  /** FR-77 P3 — the cell denylist (`name:chroma` list or `none`); MANAGE_AGENTS only. */
  encoder_cells_deny?: string
  /** FR-119 P2b — the frame-rate denylist (`name:fps` list, `*` for every
   *  encoder, or `none`); MANAGE_AGENTS only. */
  fps_deny?: string
  updated_by?: string
  updated_at?: string
}

/** Desired config + the device's answer + where that leaves things. */
export interface RemoteConfig {
  desired: DesiredConfig
  report?: ConfigReport
  state: RemoteConfigState
}

/** FR-40 — where a device's overlay-key rotation stands. Resolved ONCE on the
 *  server (`key_rotation_view`) from the order, the device's report and the key
 *  the device has since JOINED with — "the device says it rotated" and "the
 *  device is on the mesh under the new key" are different facts. */
export type KeyRotationState =
  /** Ordered while the device was offline; it rotates on its next connect. */
  | 'queued'
  /** The order reached a live socket; no answer yet. */
  | 'delivered'
  /** The device reported `rotated` and is re-joining (seconds). */
  | 'rotating'
  /** Reported AND joined under the reported key. Done. */
  | 'rotated'
  /** Reported long ago, but the last verified join still shows another key. */
  | 'reported_not_joined'
  /** The device refused — `report.outcome` says which refusal. */
  | 'refused'
  /** Mint or save failed on the device; its identity is unchanged. */
  | 'failed'
  /** Queued for an agent that predates `key-rotate`; it acts once updated. */
  | 'unsupported'

export type KeyRotationOutcome = 'rotated' | 'disabled' | 'rate_limited' | 'unsupported' | 'failed'

/** The device's own account of a rotation order — a claim, like `ConfigReport`.
 *  Keys are PUBLIC halves only. */
export interface KeyRotationReport {
  request_id: string
  outcome: KeyRotationOutcome
  old_public_key?: string
  new_public_key?: string
  key_epoch: number
  detail?: string
  reported_at: string
}

export interface KeyRotation {
  request_id: string
  requested_at: string
  requested_by: string
  delivered_at?: string
  report?: KeyRotationReport
  state: KeyRotationState
}

/** One remote command's result. `exit_code: null` together with a non-null
 *  `error` is how "never ran" (a gate refused, device offline, timed out)
 *  is distinguished from "ran and exited 0". */
export interface ExecResult {
  request_id: string
  agent_id: string
  agent_name: string
  exit_code: number | null
  stdout: string
  stderr: string
  truncated: boolean
  duration_ms: number
  error: string | null
}

/** Why an attempt was refused; `null` on the audit row means it ran. */
export type ExecDenyReason =
  | 'org_disabled'
  | 'no_permission'
  | 'device_disabled'
  | 'caller_not_allowed'
  | 'shell_not_allowed'
  | 'origin_not_allowed'
  | 'unsupported'
  | 'offline'
  | 'consent_denied'
  | 'rate_limited'
  | 'agent_disabled'
  // FR-94 — the org requires SYSTEM and this Windows device cannot take that
  // path; and a device's SYSTEM service asked for a command not pending for it.
  | 'system_required'
  | 'claim_refused'
  // FR-94 P4 — the policy names the signed-in user, which only the device's
  // SYSTEM service can run as, and this command cannot take that path.
  | 'run_as_unavailable'

/** One row of the Fleet-RPC attempt log. Every attempt lands here, allowed
 *  or denied — a refused exec is the interesting one. */
/** FR-92 P7 — what one history row records. Mirrors the Rust
 *  `KeepBusyEventKind`; a word a newer server adds must still render. */
export type KeepBusyEventKind = 'on' | 'off' | 'org_denied' | 'org_allowed' | 'org_default_pattern'
/** `server` = the server's own decision, authoritative; `device` = a claim
 *  the device reported on a heartbeat. The `ssh_audit` / `ssh_activity`
 *  trust split, in one collection. */
export type KeepBusyEventSource = 'server' | 'device'

export interface KeepBusyHistoryEntry {
  id: string
  tenant_id: string
  /** Absent on an org-level row. */
  agent_id?: string
  /** The device's label when the row was written — it outlives the device. */
  agent_name?: string
  at: string
  kind: KeepBusyEventKind | string
  source: KeepBusyEventSource | string
  /** Server rows only: the admin who changed it. */
  actor_user_id?: string
  /** Server rows: the admin's display name. Device rows: who the device
   *  SAID turned it on (`set_by`), a claim. */
  actor_name?: string
  /** `on`: the pattern drawn. `org_default_pattern`: the new default, absent
   *  when cleared to the product default. */
  pattern?: string
  /** `off`: the device's reason code. */
  reason?: string
}

export interface ExecAuditEntry {
  id?: string
  tenant_id: string
  agent_id: string
  user_id: string
  origin_agent_id?: string | null
  request_id: string
  source: string
  shell: string
  command: string
  at: string
  exit_code?: number | null
  duration_ms?: number | null
  denied?: ExecDenyReason | null
  output_sample?: string
  output_sha256?: string
  output_bytes?: number
  truncated?: boolean
  /** FR-94 — where the server sent the command: `system` (a Windows device's
   *  SYSTEM service), `console_user` (the same service, as the signed-in
   *  user) or `worker` (the agent's own process). Absent on a refusal and on
   *  rows from before FR-94. */
  ran_as?: string | null
}

/** Why a meshharbor-SSH request was refused. Mirrors the Rust `SshDenyReason`. */
export type SshDenyReason =
  | 'org_disabled'
  | 'no_permission'
  | 'device_disabled'
  | 'caller_not_allowed'
  | 'origin_not_allowed'
  | 'unsupported'
  | 'offline'
  | 'no_overlay_address'
  | 'rate_limited'
  | 'bad_public_key'
  // FR-83 — reported BY the device in its grant acknowledgement, or its
  // absence within the bound.
  | 'agent_disabled'
  | 'grant_expired_on_arrival'
  | 'grant_refused'
  | 'grant_unconfirmed'
  // FR-105 — a SYSTEM service's claim of a grant not pending for it.
  | 'claim_refused'

/** One SSH grant DECISION.
 *
 *  Not one session: the server hands back an address and a grant and then
 *  steps out of the way — the session rides the overlay directly and the
 *  server never observes it. So there is no duration, exit status or output
 *  here, and a row means "a grant was issued", never "a session happened". */
export interface SshAuditEntry {
  id?: string
  tenant_id: string
  agent_id: string
  user_id: string
  origin_agent_id?: string | null
  grant_id?: string | null
  source: string
  caller: string
  /** Which identity the grant authorised — the field worth reading, since it
   *  is the difference between a shell as the signed-in user and one as
   *  SYSTEM/root. Absent on a refusal. */
  account_mode?: string | null
  session_secs?: number | null
  at: string
  denied?: SshDenyReason | null
  /** The refusal in the words the caller was given, straight from the server
   *  so the UI never has to keep its own copy of the enum's meanings. */
  denied_message?: string | null
  /** FR-105 — where the server sent the grant: `system` (a Windows device's
   *  SYSTEM service, as SYSTEM), `console_user` (the same service, as the
   *  signed-in user) or `worker` (the agent's own process, whose identity
   *  depends on the install). Absent on a refusal and on rows from before
   *  FR-105. Read with `account_mode` through `sshAsChip`. */
  ran_as?: string | null
}

/** What a device REPORTED doing inside an SSH session (P8).
 *
 *  Distinct from {@link SshAuditEntry} on purpose: an audit row is the
 *  server's own decision and is authoritative, while one of these is a claim
 *  by a host that may be compromised or simply have reporting switched off.
 *  Join the two on `grant_id`. */
export type SshActivityKind =
  | 'session_open'
  | 'session_close'
  | 'exec'
  | 'shell'
  | 'sftp'
  | 'forward'

export interface SshActivityEntry {
  id?: string
  agent_id: string
  /** Correlates back to the `ssh_audit` decision that authorised the session.
   *  Absent for a key-list session, which no grant backs. */
  grant_id?: string | null
  /** Principal as the DEVICE saw it — unverified. */
  caller: string
  kind: SshActivityKind
  /** The command for `exec`, `host:port` for `forward`. Redacted and capped
   *  on the device before it ever left the host. */
  detail?: string | null
  exit_code?: number | null
  /** `false` when the DEVICE refused the action — a forward its `forward_acl`
   *  did not permit. Those are the rows worth reading. */
  allowed: boolean
  at: string
}

/** A tenant member as returned by `GET /tenant/{id}/member` — enough to populate
 *  the owner-reassign picker + resolve `owner_user_id` to a name. */
export interface TenantMember {
  user_id: string
  display_name: string
  nickname: string | null
}

export interface EnrollmentToken {
  enrollment_token: string
  expires_in: number
  jti: string
  /** FR-104 — the token may also anchor the Windows device it enrolls, once.
   *  Absent from a server older than FR-104, which reads as "it may not". */
  anchor?: boolean
}

/** FR-51 — one ephemeral enrollment key, as listed (no secret here). */
export interface EnrollmentKeyRow {
  id: string
  jti: string
  label: string
  created_by: string
  max_uses: number
  uses: number
  expires_at: string
  revoked_at?: string
  ephemeral_ttl_secs?: number
  last_used_at?: string
  created_at: string
}

export interface MintEnrollKeyRequest {
  label?: string
  max_uses?: number
  expires_in_secs?: number
  ephemeral_ttl_secs?: number
}

/** The mint response — `key` is the credential itself, shown exactly once. */
export interface MintEnrollKeyResponse {
  key: string
  id: string
  jti: string
  label: string
  max_uses: number
  expires_at: string
  ephemeral_ttl_secs?: number
}

interface AgentListResponse {
  items: Agent[]
  total: number
  page: number
  per_page: number
  total_pages: number
}

/** One agent-side crash report. Wire shape comes from
 *  `crates/remote_control/src/models.rs::AgentCrashPayload` (camelCase)
 *  plus server-attributed `id` + `reportedAt`. Reason values are the
 *  snake_case Rust enum discriminants (`panic` / `watchdog_stall` /
 *  `supervisor_detected`) — the chip-colour map in
 *  AgentCrashesDialog.vue keys off these EXACT strings. */
export interface AgentCrash {
  id: string
  reportedAt: string
  crashedAtUnix: number
  reason: 'panic' | 'watchdog_stall' | 'supervisor_detected'
  summary: string
  logTail: string
  agentVersion: string
  os: string
  hostname: string
  pid: number
}

interface AgentCrashListResponse {
  items: AgentCrash[]
}

/** One uploaded log line. Wire shape from
 *  `crates/db/src/models/agent_log.rs::LogLine` serialised through
 *  `crates/api/src/routes/agent_log.rs`. `level` is the UPPERCASE
 *  Rust enum discriminant (TRACE/DEBUG/INFO/WARN/ERROR); `fields`
 *  is an arbitrary structured-field object (may be empty). */
export interface AgentLogLine {
  ts: string
  level: 'TRACE' | 'DEBUG' | 'INFO' | 'WARN' | 'ERROR'
  target: string
  msg: string
  fields: Record<string, unknown>
}

/** One uploaded log batch. Mirrors `AgentLogBatchView` in
 *  `crates/api/src/routes/agent_log.rs`. `source` is the lowercase
 *  Rust enum (`agent`/`service`/`installer`/`crash`/`updater`/
 *  `browser`); `createdAt` is the server ingest timestamp (RFC3339). */
export interface AgentLogBatch {
  id: string
  source: string
  agentId: string | null
  userId: string | null
  sessionId: string | null
  hostIdHash: string | null
  agentVersion: string | null
  lineCount: number
  createdAt: string
  lines: AgentLogLine[]
}

interface AgentLogsListResponse {
  batches: AgentLogBatch[]
}

/** FR-106 — how long the release list is kept before it is fetched again. */
export const RELEASES_TTL_MS = 30 * 60 * 1000

export const useAgentStore = defineStore('agents', () => {
  const agents = ref<Agent[]>([])
  const total = ref(0)
  const loading = ref(false)
  const error = ref<string | null>(null)

  async function fetchAgents(tenantId: string) {
    loading.value = true
    error.value = null
    try {
      // per_page=100 (the server cap): with no param the server defaulted to
      // 25 and every consumer of this store silently saw a truncated fleet —
      // the devices grid's menus, the dashboard tile, the pickers. Above 100
      // agents the rich-store lookups degrade again; the unified /device
      // endpoint is the paginated path for that scale.
      const resp = await api.get<AgentListResponse>(`/tenant/${tenantId}/agent?per_page=100`)
      agents.value = resp.items
      total.value = resp.total
    } catch (e) {
      error.value = (e as Error).message
      agents.value = []
      total.value = 0
    } finally {
      loading.value = false
    }
  }

  /** FR-106 — the agent releases, newest first, each with its publish time:
   *  `GET /api/agent/latest-release`, the server's cached copy of GitHub's
   *  list (~560 KB, ~90 KB gzipped). Fetched at most once per
   *  {@link RELEASES_TTL_MS}, and kept slim: only what the "not updating" chip
   *  reads. A failed fetch leaves the list empty, and an empty list shows no
   *  chip anywhere — the absence of a signal never invents a problem. */
  const releases = ref<AgentReleaseBrief[]>([])
  let releasesFetchedAt = 0
  async function fetchReleases() {
    if (releases.value.length && Date.now() - releasesFetchedAt < RELEASES_TTL_MS) return
    try {
      const list = await api.get<AgentReleaseBrief[]>('/agent/latest-release')
      releases.value = Array.isArray(list)
        ? list.map((r) => ({
            tag_name: r.tag_name,
            published_at: r.published_at ?? null,
            draft: !!r.draft,
            prerelease: !!r.prerelease,
          }))
        : []
      releasesFetchedAt = Date.now()
    } catch {
      releases.value = []
    }
  }

  /** P4 — patch presence in place from a `device:presence` WS event for the
   *  ACTIVE org. `status` is left alone (it's the Mongo lifecycle field);
   *  `presence`/`is_online` are the reachability truth the list renders.
   *  Unknown agent ids are ignored — the next fetch converges. */
  function applyPresence(updates: Array<{ agent_id: string; presence: 'online' | 'stale' | 'offline' }>) {
    for (const u of updates) {
      const a = agents.value.find((x) => x.id === u.agent_id)
      if (!a) continue
      a.presence = u.presence
      a.is_online = u.presence === 'online'
    }
  }

  /** #1631 — resolve ONE device whether or not the cached page holds it.
   *  `fetchAgents` stops at the server's 100-row page, so a device beyond
   *  it — or a deep link opened before any listing ran — was invisible to
   *  the remote view, and its 5-min status poll then NULLED the device it
   *  was showing. `GET /tenant/{tid}/agent/{id}` is the same
   *  `AgentResponse` shape as a list row (`crates/modules/fleet/src/agent.rs`
   *  `get_agent` / `list_agents` share `to_agent_response`). The row is
   *  upserted into `agents` so `applyPresence` patches it like any other,
   *  and the STORE's row is returned so the caller holds the reactive one.
   *  Throws on any error (transport, 404, not-a-member) — the caller decides
   *  whether to keep the snapshot it already has. */
  async function fetchAgent(tenantId: string, agentId: string): Promise<Agent> {
    const fetched = await api.get<Agent>(`/tenant/${tenantId}/agent/${agentId}`)
    const idx = agents.value.findIndex((a) => a.id === fetched.id)
    if (idx === -1) {
      agents.value.push(fetched)
      return agents.value[agents.value.length - 1]!
    }
    agents.value[idx] = { ...agents.value[idx]!, ...fetched }
    return agents.value[idx]!
  }

  async function issueEnrollmentToken(
    tenantId: string,
    opts: { anchor?: boolean } = {},
  ): Promise<EnrollmentToken> {
    const url = `/tenant/${tenantId}/agent/enroll-token`
    // FR-104 — a body only when asked: the plain token stays the body-less
    // request every server version answers.
    return opts.anchor
      ? api.post<EnrollmentToken>(url, { anchor: true })
      : api.post<EnrollmentToken>(url)
  }

  async function rename(tenantId: string, agentId: string, name: string) {
    await api.put(`/tenant/${tenantId}/agent/${agentId}`, { name })
    const idx = agents.value.findIndex((a) => a.id === agentId)
    if (idx !== -1) agents.value[idx]!.name = name
  }

  /** Name / display_name / tags in one PUT (the device edit dialog). Reads
   *  the ADDITIVE update envelope — `{updated, agent, dns_renamed, dns_name}`
   *  — patching the local row from the returned agent when present (old
   *  servers omit it; the optimistic patch below still applies). Returns the
   *  DNS half so the dialog can tell the operator what the MagicDNS label
   *  became (or that the rename didn't reach the overlay). */
  async function updateDevice(
    tenantId: string,
    agentId: string,
    fields: { name?: string; display_name?: string; tags?: string[] },
  ): Promise<{ dnsRenamed?: boolean; dnsName?: string }> {
    const resp = await api.put<{
      updated?: boolean
      agent?: Agent
      dns_renamed?: boolean | null
      dns_name?: string | null
    }>(`/tenant/${tenantId}/agent/${agentId}`, fields)
    const idx = agents.value.findIndex((a) => a.id === agentId)
    if (idx !== -1) {
      if (resp?.agent) {
        agents.value[idx] = { ...agents.value[idx]!, ...resp.agent }
      } else {
        if (fields.name !== undefined) agents.value[idx]!.name = fields.name
        if (fields.display_name !== undefined)
          agents.value[idx]!.display_name = fields.display_name || undefined
        if (fields.tags !== undefined) agents.value[idx]!.tags = fields.tags
      }
    }
    return {
      dnsRenamed: resp?.dns_renamed ?? undefined,
      dnsName: resp?.dns_name ?? undefined,
    }
  }

  async function updateAccessPolicy(
    tenantId: string,
    agentId: string,
    policy: AccessPolicy,
  ) {
    await api.put(`/tenant/${tenantId}/agent/${agentId}`, { access_policy: policy })
    const idx = agents.value.findIndex((a) => a.id === agentId)
    if (idx !== -1) agents.value[idx]!.access_policy = policy
  }

  /** Replace the agent's advertised subnet-router CIDRs (mesh Phase 2). A
   *  MANAGE_AGENTS admin action. The server validates + canonicalizes each
   *  CIDR (masks host bits, dedups) and rejects invalid input with 400; we
   *  optimistically patch local state with the caller's already-canonicalized
   *  list. */
  async function updateRoutes(tenantId: string, agentId: string, routes: string[]) {
    await api.put(`/tenant/${tenantId}/agent/${agentId}`, { routes })
    const idx = agents.value.findIndex((a) => a.id === agentId)
    if (idx !== -1) agents.value[idx]!.routes = routes
  }

  /** Reassign the device owner (a MANAGE_AGENTS admin action). The owner is who
   *  self-controls without an allowlist entry + who consent routes to. */
  async function updateOwner(tenantId: string, agentId: string, ownerUserId: string) {
    await api.put(`/tenant/${tenantId}/agent/${agentId}`, { owner_user_id: ownerUserId })
    const idx = agents.value.findIndex((a) => a.id === agentId)
    if (idx !== -1) agents.value[idx]!.owner_user_id = ownerUserId
  }

  /** Tenant members — for the owner-reassign picker + resolving an agent's
   *  `owner_user_id` to a display name. Fetched on demand by AgentsSection. */
  const tenantMembers = ref<TenantMember[]>([])
  async function fetchTenantMembers(tenantId: string) {
    try {
      const resp = await api.get<{ items: TenantMember[] }>(`/tenant/${tenantId}/member`)
      tenantMembers.value = resp.items
    } catch {
      tenantMembers.value = []
    }
  }

  /** S1a — push an immediate self-update to one agent (`rc:agent.update`).
   *  Returns whether the message reached a live agent WS; offline agents
   *  pick the release up on their own periodic check. MANAGE_AGENTS. */
  async function triggerUpdate(tenantId: string, agentId: string): Promise<boolean> {
    const resp = await api.post<{ agent_id: string; delivered: boolean }>(
      `/tenant/${tenantId}/agent/${agentId}/update`,
      {},
    )
    return resp.delivered
  }

  /** FR-40 — order a device to retire its overlay (WireGuard) key
   *  (`rc:agent.key_rotate`). The device mints the new key ITSELF and re-joins
   *  the mesh under it; the server never sees a private key. `delivered` = a
   *  live socket took the order; otherwise it is queued for the device's next
   *  connect. Refusals (`rate_limited`, `agent_unsupported`) come back as a
   *  409 whose message names the reason. MANAGE_AGENTS. */
  async function rotateOverlayKey(
    tenantId: string,
    agentId: string,
  ): Promise<{ request_id: string; dispatch: 'pushed' | 'queued'; delivered: boolean }> {
    return api.post<{ request_id: string; dispatch: 'pushed' | 'queued'; delivered: boolean }>(
      `/tenant/${tenantId}/agent/${agentId}/overlay-key/rotate`,
      {},
    )
  }

  /** S1a — push an immediate self-update to every agent in the tenant
   *  (or a selected subset via `agent_ids`). MANAGE_AGENTS. A row the server
   *  did not push carries `refused` (a sentence) and `refused_code`:
   *  `pin_downgrade` (FR-2), `primary_org` or `auto_update_off` (FR-67 P7). */
  async function triggerUpdateAll(tenantId: string): Promise<BulkUpdateResponse> {
    return api.post<BulkUpdateResponse>(`/tenant/${tenantId}/agent/update`, {})
  }

  /** Multi-org — the organizations this device could be added to: every org
   *  where the caller holds MANAGE_AGENTS, minus the current one. `supported`
   *  is false for agents predating `rc:agent.join_org`, `online` false when
   *  there is no socket to push down; the dialog explains rather than
   *  letting the click fail. */
  async function fetchJoinTargets(
    tenantId: string,
    agentId: string,
  ): Promise<{
    items: Array<{
      tenant_id: string
      name: string
      slug: string
      already_enrolled: boolean
    }>
    supported: boolean
    /** The daemon's TUN is already muxed, so a `tun` join reaches the mesh
     *  live. False ⇒ the join still works, but the mesh waits for the next
     *  daemon start (the agent can't re-open an adapter its primary org
     *  already holds). Optional: older servers omit it. */
    mesh_ready?: boolean
    online: boolean
  }> {
    return api.get(`/tenant/${tenantId}/agent/${agentId}/join-targets`)
  }

  /** Multi-org — add this device to another organization. Requires
   *  MANAGE_AGENTS in BOTH; the server mints a short-lived enrollment token
   *  and pushes it down the device's live socket. */
  async function joinOrg(
    tenantId: string,
    agentId: string,
    targetTenantId: string,
    opts: { label?: string; overlayMode?: string } = {},
  ): Promise<{
    label: string
    delivered: boolean
    already_enrolled?: boolean
    /** A `tun` join whose mesh only comes up after a daemon restart. */
    restart_required?: boolean
  }> {
    return api.post(`/tenant/${tenantId}/agent/${agentId}/join-org`, {
      target_tenant_id: targetTenantId,
      ...(opts.label ? { label: opts.label } : {}),
      ...(opts.overlayMode ? { overlay_mode: opts.overlayMode } : {}),
    })
  }

  async function deleteAgent(tenantId: string, agentId: string) {
    await api.delete(`/tenant/${tenantId}/agent/${agentId}`)
    agents.value = agents.value.filter((a) => a.id !== agentId)
    total.value = Math.max(0, total.value - 1)
  }

  /** Fetch the most-recent 50 crash reports for an agent. No store
   *  caching — callers (AgentCrashesDialog) hold the result locally
   *  and refresh on demand via the modal's Refresh button. The
   *  endpoint is tenant-scoped on both sides; a foreign agentId
   *  returns an empty array, not an error. */
  async function fetchCrashes(
    tenantId: string,
    agentId: string,
  ): Promise<AgentCrash[]> {
    const resp = await api.get<AgentCrashListResponse>(
      `/tenant/${tenantId}/agent/${agentId}/crash`,
    )
    return resp.items
  }

  /** Fetch the most-recent uploaded log batches for an agent (rc.58/
   *  rc.59 centralized log backbone). `limit` is the number of
   *  BATCHES, not lines (the server clamps to 1..=500; default 50).
   *  No store caching — the AgentLogsDialog holds the result and
   *  refreshes on demand. Tenant-scoped on both sides; a foreign
   *  agentId yields an empty list, not an error. */
  async function fetchLogs(
    tenantId: string,
    agentId: string,
    limit = 50,
  ): Promise<AgentLogBatch[]> {
    const resp = await api.get<AgentLogsListResponse>(
      `/tenant/${tenantId}/agent/${agentId}/logs?limit=${limit}`,
    )
    return resp.batches
  }

  // ── Fleet RPC ────────────────────────────────────────────────────

  /** Whether the ORG allows remote execution at all (gate 1). `null` until
   *  fetched. Every device refuses while this is false, whatever its own
   *  policy says — the console shows that as the reason rather than letting
   *  an admin hunt through per-device settings. */
  const orgExecEnabled = ref<boolean | null>(null)
  /** FR-94 — whether the org refuses a Windows command a device would run as
   *  the signed-in user rather than as SYSTEM. `null` until fetched, and on a
   *  server from before FR-94, which never names it. */
  const orgExecRequireSystem = ref<boolean | null>(null)

  type OrgExecSettings = { remote_exec_enabled: boolean; exec_require_system?: boolean }

  function applyOrgExecSettings(resp: OrgExecSettings) {
    orgExecEnabled.value = resp.remote_exec_enabled
    orgExecRequireSystem.value =
      typeof resp.exec_require_system === 'boolean' ? resp.exec_require_system : null
  }

  async function fetchOrgExecEnabled(tenantId: string) {
    if (!(await mayReadOrgSettings(tenantId))) {
      orgExecEnabled.value = null
      orgExecRequireSystem.value = null
      return
    }
    try {
      applyOrgExecSettings(await api.get<OrgExecSettings>(`/tenant/${tenantId}/exec-settings`))
    } catch {
      // A 403 here means "not an admin", not "disabled" — leave it unknown
      // rather than claiming the org is off.
      orgExecEnabled.value = null
      orgExecRequireSystem.value = null
    }
  }

  /** Flip gate 1. MANAGE_TENANT server-side. Names only the kill-switch: the
   *  server leaves `exec_require_system` as it is when a PUT omits it. */
  async function setOrgExecEnabled(tenantId: string, enabled: boolean) {
    applyOrgExecSettings(
      await api.put<OrgExecSettings>(`/tenant/${tenantId}/exec-settings`, {
        remote_exec_enabled: enabled,
      }),
    )
  }

  /** FR-94 — flip `exec_require_system`. The PUT must carry the kill-switch
   *  too (the server reads it as required), so this sends the value it holds
   *  and refuses to guess one it does not. */
  async function setOrgExecRequireSystem(tenantId: string, required: boolean) {
    if (orgExecEnabled.value === null) {
      throw new Error('The organization settings are not loaded yet')
    }
    applyOrgExecSettings(
      await api.put<OrgExecSettings>(`/tenant/${tenantId}/exec-settings`, {
        remote_exec_enabled: orgExecEnabled.value,
        exec_require_system: required,
      }),
    )
  }

  /** Replace a device's exec policy (gate 3). MANAGE_AGENTS server-side. */
  async function updateExecPolicy(tenantId: string, agentId: string, policy: ExecPolicy) {
    await api.put(`/tenant/${tenantId}/agent/${agentId}/exec-policy`, policy)
    const idx = agents.value.findIndex((a) => a.id === agentId)
    if (idx !== -1) agents.value[idx]!.exec_policy = policy
  }

  /** FR-94 — revoke a Windows device's SYSTEM service without removing the
   *  device: its commands go to the worker again, or are refused where the
   *  org requires SYSTEM. MANAGE_AGENTS server-side. */
  async function unanchorDevice(tenantId: string, agentId: string) {
    await api.delete(`/tenant/${tenantId}/agent/${agentId}/exec-anchor`)
    const idx = agents.value.findIndex((a) => a.id === agentId)
    if (idx !== -1) agents.value[idx]!.exec_anchor = null
  }

  // ── MeshHarbor SSH ──────────────────────────────────────────────────
  //
  // A separate org switch and a separate per-device policy from exec's, all
  // the way down — allowing bounded diagnostic commands is not the same
  // decision as allowing interactive sessions, so the UI must not let one
  // control read as the other.

  /** Whether the ORG allows SSH at all (gate 1). `null` until fetched, and
   *  left `null` on a 403 — "not an admin" is not "disabled", and claiming
   *  the org is off would send an admin hunting through device settings. */
  const orgSshEnabled = ref<boolean | null>(null)

  async function fetchOrgSshEnabled(tenantId: string) {
    if (!(await mayReadOrgSettings(tenantId))) {
      orgSshEnabled.value = null
      return
    }
    try {
      const resp = await api.get<{ remote_ssh_enabled: boolean }>(
        `/tenant/${tenantId}/ssh-settings`,
      )
      orgSshEnabled.value = resp.remote_ssh_enabled
    } catch {
      orgSshEnabled.value = null
    }
  }

  /** Flip gate 1. MANAGE_TENANT server-side. */
  async function setOrgSshEnabled(tenantId: string, enabled: boolean) {
    const resp = await api.put<{ remote_ssh_enabled: boolean }>(
      `/tenant/${tenantId}/ssh-settings`,
      { remote_ssh_enabled: enabled },
    )
    orgSshEnabled.value = resp.remote_ssh_enabled
  }

  // ── FR-92 — keep busy, the org deny ─────────────────────────────
  //
  // Keep busy is ON by default; an org owner can deny it org-wide (some
  // orgs ban mouse jigglers because they defeat a screen-lock policy). The
  // device enforces it and a deny also stops one already running.

  /** Whether the org DENIES keep busy. `null` until fetched / on a 403 —
   *  same "not an admin ≠ a value" rule as the exec and SSH switches. */
  const orgKeepBusyDenied = ref<boolean | null>(null)
  /** FR-92 P8 — the org's default pattern as STORED: `null` = the product
   *  default (circle). Known whenever `orgKeepBusyDenied` is (one fetch
   *  carries both), so "unknown" is read off that flag, not off this one. */
  const orgKeepBusyDefaultPattern = ref<string | null>(null)

  /** FR-92 P8 — the body the settings route speaks. Absent = leave alone;
   *  `keep_busy_default_pattern: null` = clear to the product default. */
  interface OrgKeepBusySettingsPatch {
    keep_busy_denied?: boolean
    keep_busy_default_pattern?: string | null
  }
  interface OrgKeepBusySettingsResponse {
    keep_busy_denied: boolean
    keep_busy_default_pattern: string | null
  }

  /** The ADMIN card's read: gated like the other org switches, so a
   *  non-owner's card shows "unknown" and sends nothing. (Any member may
   *  read the route since P8 — `fetchKeepBusyDefaultPattern` is the
   *  ungated read a viewer uses.) */
  async function fetchOrgKeepBusyDenied(tenantId: string) {
    if (!(await mayReadOrgSettings(tenantId))) {
      orgKeepBusyDenied.value = null
      return
    }
    try {
      const resp = await api.get<OrgKeepBusySettingsResponse>(
        `/tenant/${tenantId}/keep-busy-settings`,
      )
      orgKeepBusyDenied.value = resp.keep_busy_denied
      orgKeepBusyDefaultPattern.value = resp.keep_busy_default_pattern ?? null
    } catch {
      orgKeepBusyDenied.value = null
    }
  }

  /** Change one or both settings. MANAGE_TENANT server-side; a deny in the
   *  body is pushed to online devices at once and to the rest at their next
   *  connect, and every actual change lands in the history. */
  async function setOrgKeepBusySettings(tenantId: string, patch: OrgKeepBusySettingsPatch) {
    const resp = await api.put<OrgKeepBusySettingsResponse>(
      `/tenant/${tenantId}/keep-busy-settings`,
      patch,
    )
    orgKeepBusyDenied.value = resp.keep_busy_denied
    orgKeepBusyDefaultPattern.value = resp.keep_busy_default_pattern ?? null
  }

  /** Set the deny alone — the pre-P8 body, unchanged. */
  async function setOrgKeepBusyDenied(tenantId: string, denied: boolean) {
    await setOrgKeepBusySettings(tenantId, { keep_busy_denied: denied })
  }

  /** FR-92 P8 — set the org's default pattern; `null` clears it. */
  async function setOrgKeepBusyDefaultPattern(tenantId: string, pattern: string | null) {
    await setOrgKeepBusySettings(tenantId, { keep_busy_default_pattern: pattern })
  }

  /** FR-92 P8 — the org's default pattern for a VIEWER's menu. Deliberately
   *  ungated (the route is readable by any member) and it never throws:
   *  unset, a word this viewer cannot draw, a 403 or a network failure all
   *  mean `circle`, the product default. A person's own remembered choice
   *  for a device wins over it in the menu. */
  async function fetchKeepBusyDefaultPattern(tenantId: string): Promise<KeepBusyPattern> {
    try {
      const resp = await api.get<OrgKeepBusySettingsResponse>(
        `/tenant/${tenantId}/keep-busy-settings`,
      )
      return isKeepBusyPattern(resp.keep_busy_default_pattern)
        ? resp.keep_busy_default_pattern
        : 'circle'
    } catch {
      return 'circle'
    }
  }

  /** FR-92 P7 — one row of the permanent keep-busy history. `source` tells
   *  the server's own decision (`server`: an admin changed a setting) from a
   *  device's CLAIM (`device`: derived from its heartbeats, so an on and an
   *  off inside one ~30 s beat are not seen). */
  async function fetchKeepBusyHistory(
    tenantId: string,
    opts: { agentId?: string; before?: string; limit?: number } = {},
  ): Promise<KeepBusyHistoryEntry[]> {
    const q = new URLSearchParams()
    if (opts.agentId) q.set('agent_id', opts.agentId)
    if (opts.before) q.set('before', opts.before)
    q.set('limit', String(opts.limit ?? 50))
    return api.get<KeepBusyHistoryEntry[]>(
      `/tenant/${tenantId}/keep-busy-history?${q.toString()}`,
    )
  }

  // ── FR-101 P2 — the org's session policy (clipboard, files, audio) ──
  //
  // Each `on` | `ask` | `off`. The hub strips what the policy refuses and
  // names why, and the device enforces it again; this is the admin card's
  // read and write.

  /** `null` until fetched, and for a member who may not manage org
   *  settings — the "not an admin ≠ a value" rule of the switches above. */
  const orgRcSessionPolicy = ref<RcSessionPolicy | null>(null)

  async function fetchOrgRcSessionPolicy(tenantId: string) {
    if (!(await mayReadOrgSettings(tenantId))) {
      orgRcSessionPolicy.value = null
      return
    }
    try {
      orgRcSessionPolicy.value = await api.get<RcSessionPolicy>(
        `/tenant/${tenantId}/rc-session-policy`,
      )
    } catch {
      orgRcSessionPolicy.value = null
    }
  }

  // ── FR-111 P4 — the org's on-screen control presets ───────────────
  //
  // Read by ANY member (`GET …/touch-preset`): every viewer in the org offers
  // them beside the built-ins. The rows go to the overlay as the server sends
  // them, and `orgPresets` (touchControls.ts) turns them into presets.

  /** The org's presets, as the server sent them. */
  const orgTouchPresets = ref<unknown[]>([])

  /** An older server without the route, or any error, is none: the built-ins
   *  are still offered. */
  async function fetchOrgTouchPresets(tenantId: string) {
    try {
      const r = await api.get<{ items?: unknown[] }>(`/tenant/${tenantId}/touch-preset`)
      orgTouchPresets.value = Array.isArray(r?.items) ? r.items : []
    } catch {
      orgTouchPresets.value = []
    }
  }

  /** The refusal code a write answered (`name_taken`, `key_invalid`, …), or a
   *  generic one: the editor says what it means. */
  function touchPresetRefusal(e: unknown): string {
    const data = (e as { data?: { error?: unknown } } | null)?.data
    return typeof data?.error === 'string' ? data.error : 'unavailable'
  }

  /** FR-111 P4b-2 — publish a layout to the org (MANAGE_TENANT server-side):
   *  `serverId` null creates one, else it replaces that one. Resolves to
   *  `null`, or the refusal code; the list is fetched again either way. */
  async function saveOrgTouchPreset(
    tenantId: string,
    body: { name: string; controls: unknown[] },
    serverId: string | null,
  ): Promise<string | null> {
    try {
      if (serverId) await api.put(`/tenant/${tenantId}/touch-preset/${serverId}`, body)
      else await api.post(`/tenant/${tenantId}/touch-preset`, body)
      return null
    } catch (e) {
      return touchPresetRefusal(e)
    } finally {
      await fetchOrgTouchPresets(tenantId)
    }
  }

  /** FR-111 P4b-2 — remove an org layout (MANAGE_TENANT server-side). */
  async function deleteOrgTouchPreset(tenantId: string, serverId: string): Promise<string | null> {
    try {
      await api.delete(`/tenant/${tenantId}/touch-preset/${serverId}`)
      return null
    } catch (e) {
      return touchPresetRefusal(e)
    } finally {
      await fetchOrgTouchPresets(tenantId)
    }
  }

  /** Set one or more features (MANAGE_TENANT server-side). The route leaves
   *  a feature the body does not name alone, and answers with all three. */
  async function setOrgRcSessionPolicy(tenantId: string, patch: Partial<RcSessionPolicy>) {
    orgRcSessionPolicy.value = await api.put<RcSessionPolicy>(
      `/tenant/${tenantId}/rc-session-policy`,
      patch,
    )
  }

  // ── FR-52 — cross-org remote access ──────────────────────────────
  //
  // A THIRD org switch, separate from exec's and SSH's, because those two
  // govern what a MEMBER may do and this one governs whether a stranger may
  // do anything at all. Nothing about letting employees run commands implies
  // letting outsiders onto a screen.

  /** Whether the ORG can be reached from outside at all (gate 1). `null`
   *  until fetched, and left `null` on a 403 — the same "not an admin is not
   *  disabled" rule as the exec and SSH switches. */
  const orgExternalAccessEnabled = ref<boolean | null>(null)
  /** Devices approved under gate 2, with their connect codes. Only ever
   *  populated for a `MANAGE_AGENTS` holder — the ordinary device list
   *  deliberately omits connect codes. */
  const externalDevices = ref<ExternalDevice[]>([])

  async function fetchExternalAccess(tenantId: string) {
    try {
      const resp = await api.get<ExternalAccessSettings>(`/tenant/${tenantId}/external-access`)
      orgExternalAccessEnabled.value = resp.enabled
      externalDevices.value = resp.devices
    } catch {
      orgExternalAccessEnabled.value = null
      externalDevices.value = []
    }
  }

  /** Flip gate 1. MANAGE_TENANT server-side. */
  async function setOrgExternalAccessEnabled(tenantId: string, enabled: boolean) {
    const resp = await api.put<{ enabled: boolean }>(`/tenant/${tenantId}/external-access`, {
      enabled,
    })
    orgExternalAccessEnabled.value = resp.enabled
  }

  /** Replace a device's external-access approval (gate 2).
   *
   *  MANAGE_AGENTS + REMOTE_CONTROL to grant, MANAGE_AGENTS alone to clear.
   *  A rejected save must leave the caller's dialog OPEN — the server refuses
   *  an approval on a device whose agent is too old to say "this controller is
   *  from outside your organization", and silently closing would look like it
   *  worked. */
  async function updateExternalAccessPolicy(
    tenantId: string,
    agentId: string,
    policy: ExternalAccessPolicy,
  ) {
    await api.put(`/tenant/${tenantId}/agent/${agentId}/external-access-policy`, policy)
    const idx = agents.value.findIndex((a) => a.id === agentId)
    if (idx !== -1) agents.value[idx]!.external_access_policy = policy
  }

  /** Mint or rotate a device's connect code. One call for both, because
   *  rotation IS the revocation story for a leaked code. */
  async function rotateConnectCode(tenantId: string, agentId: string): Promise<string> {
    const resp = await api.post<{ connect_code: string; rotated_at: string }>(
      `/tenant/${tenantId}/agent/${agentId}/connect-code`,
      {},
    )
    const dev = externalDevices.value.find((d) => d.id === agentId)
    if (dev) {
      dev.connect_code = resp.connect_code
      dev.connect_code_rotated_at = resp.rotated_at
    }
    return resp.connect_code
  }

  // ── FR-51 — ephemeral enrollment keys ────────────────────────────
  //
  // A reusable credential that mints self-removing devices (CI runners,
  // containers). The org switch is its own grant, separate from exec/SSH,
  // and flipping it off revokes every outstanding key immediately.

  /** Whether the ORG allows ephemeral enrollment keys at all. `null` until
   *  fetched / on a 403 — same "not an admin ≠ disabled" rule as the exec
   *  and SSH switches. */
  const orgEphemeralKeysEnabled = ref<boolean | null>(null)

  async function fetchOrgEphemeralKeysEnabled(tenantId: string) {
    if (!(await mayReadOrgSettings(tenantId))) {
      orgEphemeralKeysEnabled.value = null
      return
    }
    try {
      const resp = await api.get<{ ephemeral_keys_enabled: boolean }>(
        `/tenant/${tenantId}/ephemeral-key-settings`,
      )
      orgEphemeralKeysEnabled.value = resp.ephemeral_keys_enabled
    } catch {
      orgEphemeralKeysEnabled.value = null
    }
  }

  /** Flip the class switch. MANAGE_TENANT server-side; off = an org-wide
   *  revocation of every outstanding key that burns nothing. */
  async function setOrgEphemeralKeysEnabled(tenantId: string, enabled: boolean) {
    const resp = await api.put<{ ephemeral_keys_enabled: boolean }>(
      `/tenant/${tenantId}/ephemeral-key-settings`,
      { ephemeral_keys_enabled: enabled },
    )
    orgEphemeralKeysEnabled.value = resp.ephemeral_keys_enabled
  }

  // ── FR-101 P4b — the org's session limits ──────────────────────────
  //
  // The maximum length of a remote-desktop session, in seconds; the hub ends
  // a session that reaches it. P4b-2: and how long one may sit idle (no input
  // and no change on the screen), which the device ends. `null` = no limit.

  /** `undefined` until fetched, and for a member who may not manage org
   *  settings; `null` = no limit. */
  const orgRcMaxSessionSecs = ref<number | null | undefined>(undefined)
  /** P4b-2 — the idle limit, in seconds; the same states. */
  const orgRcIdleSecs = ref<number | null | undefined>(undefined)

  type RcSessionLimitsResp = { max_secs: number | null; idle_secs?: number | null }
  function applyRcSessionLimits(resp: RcSessionLimitsResp) {
    orgRcMaxSessionSecs.value = resp.max_secs ?? null
    // A server from before P4b-2 does not send the field: no idle limit.
    orgRcIdleSecs.value = resp.idle_secs ?? null
  }

  async function fetchOrgRcSessionLimits(tenantId: string) {
    if (!(await mayReadOrgSettings(tenantId))) {
      orgRcMaxSessionSecs.value = undefined
      orgRcIdleSecs.value = undefined
      return
    }
    try {
      applyRcSessionLimits(
        await api.get<RcSessionLimitsResp>(`/tenant/${tenantId}/rc-session-limits`),
      )
    } catch {
      orgRcMaxSessionSecs.value = undefined
      orgRcIdleSecs.value = undefined
    }
  }

  /** Set the maximum length (`null` clears it). MANAGE_TENANT server-side;
   *  applies to sessions that go live after the change. */
  async function setOrgRcMaxSessionSecs(tenantId: string, maxSecs: number | null) {
    applyRcSessionLimits(
      await api.put<RcSessionLimitsResp>(`/tenant/${tenantId}/rc-session-limits`, {
        max_secs: maxSecs,
      }),
    )
  }

  /** P4b-2 — set the idle limit (`null` clears it). The body names only this
   *  limit, so the maximum length is left as it is. Kept by devices that
   *  advertise `idle-timeout`; applies to sessions requested after it. */
  async function setOrgRcIdleSecs(tenantId: string, idleSecs: number | null) {
    applyRcSessionLimits(
      await api.put<RcSessionLimitsResp>(`/tenant/${tenantId}/rc-session-limits`, {
        idle_secs: idleSecs,
      }),
    )
  }

  /** List the org's keys (secrets are never in the list — mint-once only). */
  async function listEnrollKeys(tenantId: string): Promise<EnrollmentKeyRow[]> {
    const resp = await api.get<{ items: EnrollmentKeyRow[] }>(
      `/tenant/${tenantId}/agent/enroll-key`,
    )
    return resp.items
  }

  /** Mint a key. The returned `key` is shown ONCE and cannot be re-fetched. */
  async function mintEnrollKey(
    tenantId: string,
    req: MintEnrollKeyRequest,
  ): Promise<MintEnrollKeyResponse> {
    return api.post<MintEnrollKeyResponse>(`/tenant/${tenantId}/agent/enroll-key`, req)
  }

  /** Revoke — dead from the next use onward; devices it minted are untouched
   *  (they die by their own TTL). */
  async function revokeEnrollKey(tenantId: string, keyId: string): Promise<void> {
    await api.delete(`/tenant/${tenantId}/agent/enroll-key/${keyId}`)
  }

  /** Replace a device's SSH policy (gate 3). MANAGE_AGENTS server-side.
   *
   *  The server REFUSES a non-auto `consent_mode` for a device whose agent
   *  predates P5d — such an agent accepts the field and ignores it, and a
   *  policy that reads as enforced while doing nothing is worse than no
   *  policy. That refusal surfaces here as a thrown error, deliberately: the
   *  caller must not report "saved". */
  async function updateSshPolicy(tenantId: string, agentId: string, policy: SshPolicy) {
    await api.put(`/tenant/${tenantId}/agent/${agentId}/ssh-policy`, policy)
    const idx = agents.value.findIndex((a) => a.id === agentId)
    if (idx !== -1) agents.value[idx]!.ssh_policy = policy
  }

  /** Record the device config an operator wants (`docs/remote-config.md`).
   *
   *  This writes an INTENT, never a fact. The device reconciles it when it
   *  next connects and is free to refuse — so the response must NOT be read
   *  back as "this device now has exec on". Re-fetch and read
   *  `remote_config.state` for that; until the device answers, the honest
   *  answer is `pending`.
   *
   *  Omitting a key means "leave it alone", so a partial body is normal.
   *
   *  Throws on a 403: enabling exec needs `EXEC_DEVICE` and any SSH key needs
   *  `SSH_DEVICE`, on top of `MANAGE_AGENTS` — you cannot grant a permission
   *  you do not hold. The caller must surface that rather than close. */
  async function updateDesiredConfig(
    tenantId: string,
    agentId: string,
    desired: Omit<DesiredConfig, 'revision'>,
  ): Promise<{ revision: number }> {
    const resp = await api.put<{ revision: number; desired: DesiredConfig }>(
      `/tenant/${tenantId}/agent/${agentId}/desired-config`,
      desired,
    )
    const idx = agents.value.findIndex((a) => a.id === agentId)
    if (idx !== -1) {
      // Optimistic, and deliberately only the DESIRED half: the report is the
      // device's word and we have not heard from it about this revision, so
      // anything else here would be inventing an answer. `pending` is the
      // truth until it speaks.
      agents.value[idx]!.remote_config = {
        desired: resp.desired,
        state: 'pending',
      }
    }
    return { revision: resp.revision }
  }

  /** Run a command on one device.
   *
   *  Resolves even when the command was REFUSED — the server answers 200 with
   *  `error` set, so the caller renders one shape and never has to guess
   *  whether a rejection was a policy decision or a network failure. Only a
   *  malformed request or a missing device throws. */
  async function execOnAgent(
    tenantId: string,
    agentId: string,
    body: { shell?: string; command: string; timeout_ms?: number },
  ): Promise<ExecResult> {
    return await api.post<ExecResult>(`/tenant/${tenantId}/agent/${agentId}/exec`, body)
  }

  /** Run one command across several devices. An empty `agentIds` means every
   *  device in the org whose policy allows it. */
  async function execOnFleet(
    tenantId: string,
    agentIds: string[],
    body: { shell?: string; command: string; timeout_ms?: number },
  ): Promise<ExecResult[]> {
    const resp = await api.post<{ results: ExecResult[] }>(`/tenant/${tenantId}/agent/exec`, {
      agent_ids: agentIds,
      ...body,
    })
    return resp.results
  }

  /** Kill an in-flight command. The device still answers, so the pending
   *  request resolves with an error rather than hanging. */
  async function cancelExec(tenantId: string, agentId: string, requestId: string) {
    await api.post(`/tenant/${tenantId}/agent/${agentId}/exec/${requestId}/cancel`, {})
  }

  /** The attempt log. `agentId` narrows to one device's console history;
   *  `userId` answers "what did this person run?" — where an incident review
   *  starts. VIEW_EXEC_AUDIT server-side. */
  async function fetchExecAudit(
    tenantId: string,
    opts: { agentId?: string; userId?: string; page?: number; perPage?: number } = {},
  ): Promise<{ items: ExecAuditEntry[]; total: number }> {
    const q = new URLSearchParams()
    if (opts.agentId) q.set('agent_id', opts.agentId)
    if (opts.userId) q.set('user_id', opts.userId)
    q.set('page', String(opts.page ?? 1))
    q.set('per_page', String(opts.perPage ?? 50))
    const resp = await api.get<{ items: ExecAuditEntry[]; total: number }>(
      `/tenant/${tenantId}/exec-audit?${q.toString()}`,
    )
    return { items: resp.items, total: resp.total }
  }

  /** Read the SSH grant log. Requires `VIEW_SSH_AUDIT` — a separate bit from
   *  `VIEW_EXEC_AUDIT`, so an admin can hold one view and not the other. */
  async function fetchSshAudit(
    tenantId: string,
    opts: { agentId?: string; userId?: string; page?: number; perPage?: number } = {},
  ): Promise<{ items: SshAuditEntry[]; total: number }> {
    const q = new URLSearchParams()
    if (opts.agentId) q.set('agent_id', opts.agentId)
    if (opts.userId) q.set('user_id', opts.userId)
    q.set('page', String(opts.page ?? 1))
    q.set('per_page', String(opts.perPage ?? 50))
    const resp = await api.get<{ items: SshAuditEntry[]; total: number }>(
      `/tenant/${tenantId}/ssh-audit?${q.toString()}`,
    )
    return { items: resp.items, total: resp.total }
  }

  /** P8 — what devices reported doing inside their sessions.
   *
   *  `grantId` narrows to ONE session, which is how a reader gets from an
   *  audit row ("who was let in") to what followed it. */
  async function fetchSshActivity(
    tenantId: string,
    opts: { agentId?: string; grantId?: string; page?: number; perPage?: number } = {},
  ): Promise<{ items: SshActivityEntry[]; total: number }> {
    const q = new URLSearchParams()
    if (opts.agentId) q.set('agent_id', opts.agentId)
    if (opts.grantId) q.set('grant_id', opts.grantId)
    q.set('page', String(opts.page ?? 1))
    q.set('per_page', String(opts.perPage ?? 50))
    const resp = await api.get<{ items: SshActivityEntry[]; total: number }>(
      `/tenant/${tenantId}/ssh-activity?${q.toString()}`,
    )
    return { items: resp.items, total: resp.total }
  }

  return {
    agents,
    total,
    loading,
    error,
    releases,
    fetchAgents,
    fetchAgent,
    fetchReleases,
    applyPresence,
    issueEnrollmentToken,
    rename,
    updateDevice,
    updateAccessPolicy,
    updateRoutes,
    updateOwner,
    tenantMembers,
    fetchTenantMembers,
    triggerUpdate,
    triggerUpdateAll,
    rotateOverlayKey,
    fetchJoinTargets,
    joinOrg,
    deleteAgent,
    fetchCrashes,
    fetchLogs,
    orgExecEnabled,
    fetchOrgExecEnabled,
    setOrgExecEnabled,
    orgExecRequireSystem,
    setOrgExecRequireSystem,
    updateExecPolicy,
    unanchorDevice,
    orgSshEnabled,
    fetchOrgSshEnabled,
    setOrgSshEnabled,
    orgKeepBusyDenied,
    orgKeepBusyDefaultPattern,
    fetchOrgKeepBusyDenied,
    setOrgKeepBusySettings,
    setOrgKeepBusyDenied,
    setOrgKeepBusyDefaultPattern,
    fetchKeepBusyDefaultPattern,
    fetchKeepBusyHistory,
    orgRcSessionPolicy,
    fetchOrgRcSessionPolicy,
    setOrgRcSessionPolicy,
    orgTouchPresets,
    fetchOrgTouchPresets,
    saveOrgTouchPreset,
    deleteOrgTouchPreset,
    orgExternalAccessEnabled,
    externalDevices,
    fetchExternalAccess,
    setOrgExternalAccessEnabled,
    updateExternalAccessPolicy,
    rotateConnectCode,
    orgEphemeralKeysEnabled,
    fetchOrgEphemeralKeysEnabled,
    setOrgEphemeralKeysEnabled,
    orgRcMaxSessionSecs,
    orgRcIdleSecs,
    fetchOrgRcSessionLimits,
    setOrgRcMaxSessionSecs,
    setOrgRcIdleSecs,
    listEnrollKeys,
    mintEnrollKey,
    revokeEnrollKey,
    updateSshPolicy,
    updateDesiredConfig,
    fetchSshAudit,
    fetchSshActivity,
    execOnAgent,
    execOnFleet,
    cancelExec,
    fetchExecAudit,
  }
})
