// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
/**
 * The tenant permission catalog — a TS mirror of the server's bitfield in
 * `crates/db/src/models/role.rs::permissions`.
 *
 * Keep this file in lockstep with the Rust module: the unit test locks the
 * composite values so drift is caught at `bun run test:unit`, not in prod.
 *
 * ⚠️ JS bitwise operands are coerced to **signed int32**, so this file uses NO
 * bitwise operators on a mask — see `maskHas`/`maskSet`/`maskClear`/`maskUnion`,
 * which are arithmetic and exact to bit 52 (#888).
 */

import i18n from '@/plugins/i18n'

export interface PermissionFlag {
  /** SCREAMING_SNAKE key, identical to the Rust constant name. */
  key: string
  /** The bit VALUE (1 << n), not the shift. */
  bit: number
  label: string
  group: string
  description?: string
}

export const ADMINISTRATOR = 1 << 23

/** Active flags for MeshHarbor 0.5.0, grouped for the role-editor UI. */
export const PERMISSION_FLAGS: PermissionFlag[] = [
  // ── General ──────────────────────────────────────────────────────
  { key: 'MANAGE_ROLES', bit: 1 << 2, label: 'Manage roles', group: 'General' },
  { key: 'MANAGE_TENANT', bit: 1 << 3, label: 'Manage tenant', group: 'General' },
  { key: 'KICK_MEMBERS', bit: 1 << 4, label: 'Kick members', group: 'General' },
  { key: 'BAN_MEMBERS', bit: 1 << 5, label: 'Ban members', group: 'General' },
  { key: 'INVITE_MEMBERS', bit: 1 << 6, label: 'Invite members', group: 'General' },
  {
    key: 'ADMINISTRATOR',
    bit: ADMINISTRATOR,
    label: 'Administrator',
    group: 'General',
    description: 'Bypasses ALL permission checks — grants everything below implicitly.',
  },
  // ── Remote control ───────────────────────────────────────────────
  {
    key: 'MANAGE_AGENTS',
    bit: 1 << 24,
    label: 'Manage devices',
    group: 'Remote control',
    description: 'Enroll, rename, delete, reassign and set policy for remote-control devices.',
  },
  {
    key: 'REMOTE_CONTROL',
    bit: 1 << 25,
    label: 'Remote control',
    group: 'Remote control',
    description: "Start remote-control sessions against devices the user does NOT own (controlling one's own device never needs this).",
  },
  {
    key: 'VIEW_REMOTE_AUDIT',
    bit: 1 << 26,
    label: 'View remote audit log',
    group: 'Remote control',
    description: 'Read the remote-control session audit trail.',
  },
  // ── Fleet access ─────────────────────────────────────────────────
  // Deliberately NOT implied by "Manage devices", and deliberately not part
  // of the admin preset: managing a device's metadata and holding a root
  // shell on it are different powers.
  {
    key: 'EXEC_DEVICE',
    bit: 1 << 27,
    label: 'Run commands on devices',
    group: 'Fleet access',
    description:
      'Run a command on a device via Fleet RPC. Commands execute as root (Linux) or, on Windows, as the daemon\'s worker: the signed-in user on an attended install, SYSTEM in SystemContext mode. Also requires the org switch, the device policy, and the device-local key.',
  },
  {
    key: 'VIEW_EXEC_AUDIT',
    bit: 1 << 28,
    label: 'View command audit log',
    group: 'Fleet access',
    description: 'Read the Fleet-RPC audit trail — who ran what, where.',
  },
  {
    key: 'SSH_DEVICE',
    bit: 1 << 29,
    label: 'SSH to devices',
    group: 'Fleet access',
    description:
      'Open an interactive meshharbor SSH session to a device. Strictly more than a single command: it lasts, and it carries file transfer.',
  },
  {
    key: 'VIEW_SSH_AUDIT',
    bit: 1 << 30,
    label: 'View SSH audit log',
    group: 'Fleet access',
    description: 'Read the meshharbor-SSH audit trail — who was granted, or refused, a session.',
  },
  {
    key: 'RECORD_REMOTE_SCREEN',
    // FR-85 P3 — `2 ** 31`, never `1 << 31`: that is NEGATIVE in JS (int32).
    bit: 2 ** 31,
    label: 'Record remote screens',
    group: 'Fleet access',
    description:
      'Record a device’s screen during a remote-control session. The device must allow it, and the person there sees it. A recording outlives the session, so no role gets this by default.',
  },
]

// A flag's label and description are read in the interface language when they
// are accessed (`mh.permFlag.<KEY>.*`); the literals above are their English
// source. `group` stays the English id, shown through `permissionGroupLabel`.
for (const f of PERMISSION_FLAGS) {
  Object.defineProperty(f, 'label', {
    enumerable: true,
    get: () => i18n.global.t(`mh.permFlag.${f.key}.label`),
  })
  if (f.description !== undefined) {
    Object.defineProperty(f, 'description', {
      enumerable: true,
      get: () => i18n.global.t(`mh.permFlag.${f.key}.description`),
    })
  }
}

/** Group names in display order (insertion order of the flags above). */
export const PERMISSION_GROUPS: string[] = [...new Set(PERMISSION_FLAGS.map((f) => f.group))]

const GROUP_SLUGS: Record<string, string> = {
  General: 'general',
  'Remote control': 'remote',
  'Fleet access': 'fleet',
}
/** A flag's label in the interface language, by its key. */
export function permissionLabel(key: string): string {
  return i18n.global.t(`mh.permFlag.${key}.label`)
}

/** A permission group's name in the interface language. */
export function permissionGroupLabel(group: string): string {
  const slug = GROUP_SLUGS[group]
  return slug ? i18n.global.t(`mh.permGroup.${slug}`) : group
}

function byKeys(keys: string[]): number {
  return keys.reduce((mask, key) => {
    const flag = PERMISSION_FLAGS.find((f) => f.key === key)
    if (!flag) throw new Error(`unknown permission key: ${key}`)
    return maskSet(mask, flag.bit)
  }, 0)
}

/** Baseline member role: no administrative or fleet-control privileges. */
export const DEFAULT_MEMBER = 0

/**
 * Default admin composite. NOT "everything except ADMINISTRATOR":
 * `MANAGE_TENANT`, `EXEC_DEVICE`, `SSH_DEVICE` and `RECORD_REMOTE_SCREEN`
 * are withheld on purpose so that opening a root shell or recording a screen
 * stays an explicit grant. The matching audit views ARE included.
 */
export const DEFAULT_ADMIN = byKeys([
  'MANAGE_ROLES',
  'KICK_MEMBERS',
  'BAN_MEMBERS',
  'INVITE_MEMBERS',
  'MANAGE_AGENTS',
  'REMOTE_CONTROL',
  'VIEW_REMOTE_AUDIT',
  'VIEW_EXEC_AUDIT',
  'VIEW_SSH_AUDIT',
])

/** Union of every defined permission bit in this catalog. */
export const ALL_PERMISSIONS = PERMISSION_FLAGS.reduce((m, f) => maskUnion(m, f.bit), 0)

/**
 * Mask arithmetic that is exact to `Number.MAX_SAFE_INTEGER`, i.e. bits 0–52.
 */
function maskHas(mask: number, bit: number): boolean {
  return Math.floor(mask / bit) % 2 === 1
}

function maskSet(mask: number, bit: number): number {
  return maskHas(mask, bit) ? mask : mask + bit
}

function maskClear(mask: number, bit: number): number {
  return maskHas(mask, bit) ? mask - bit : mask
}

/**
 * Arithmetic `(mask & flag) === flag`: every set bit of `flag` is set in `mask`.
 */
function maskContainsAll(mask: number, flag: number): boolean {
  let m = mask
  let f = flag
  while (f > 0) {
    if (f % 2 === 1 && m % 2 !== 1) return false
    m = Math.floor(m / 2)
    f = Math.floor(f / 2)
  }
  return true
}

/** Arithmetic `a | b`, exact to bit 52. */
function maskUnion(a: number, b: number): number {
  let out = a
  let bit = 1
  let rest = b
  while (rest > 0) {
    if (rest % 2 === 1) out = maskSet(out, bit)
    rest = Math.floor(rest / 2)
    bit *= 2
  }
  return out
}

export { maskHas, maskSet, maskClear, maskUnion }

/**
 * Mirror of the server check: ADMINISTRATOR bypasses everything, else the
 * flag's bits must all be present.
 */
export function hasPermission(mask: number, flag: number): boolean {
  return maskHas(mask, ADMINISTRATOR) || maskContainsAll(mask, flag)
}

/** Labels of the flags present in `mask`, in catalog order. */
export function describePermissions(mask: number): string[] {
  return PERMISSION_FLAGS.filter((f) => maskHas(mask, f.bit)).map((f) => f.label)
}

/**
 * Nav-gating predicate for the fleet surfaces (Devices page + Network
 * group). Deliberately FAIL-OPEN while the membership hasn't loaded yet.
 */
export function canSeeFleetNav(mask: number | null, isOwner: boolean): boolean {
  if (mask === null) return true
  if (isOwner) return true
  return (
    hasPermission(mask, byKeys(['MANAGE_AGENTS'])) ||
    hasPermission(mask, byKeys(['REMOTE_CONTROL']))
  )
}

/**
 * May this caller read the ORG-level switches — `exec-settings`,
 * `ssh-settings`, `ephemeral-key-settings`? Server gate: `MANAGE_TENANT`.
 * FAIL-CLOSED on `mask === null`.
 */
export function canManageOrgSettings(mask: number | null, isOwner: boolean): boolean {
  if (isOwner) return true
  if (mask === null) return false
  return hasPermission(mask, byKeys(['MANAGE_TENANT']))
}

/**
 * Nav gate for the Invites surface (sidebar item + dashboard card).
 * FAIL-CLOSED on `mask === null`. Server gate: `INVITE_MEMBERS`.
 */
export function canManageInvites(mask: number | null, isOwner: boolean): boolean {
  if (isOwner) return true
  if (mask === null) return false
  return hasPermission(mask, byKeys(['INVITE_MEMBERS']))
}

/**
 * Nav gates for the Audit pages. FAIL-CLOSED on `mask === null`.
 */
export function canViewExecAudit(mask: number | null, isOwner: boolean): boolean {
  if (isOwner) return true
  if (mask === null) return false
  return hasPermission(mask, byKeys(['VIEW_EXEC_AUDIT']))
}

export function canViewSshAudit(mask: number | null, isOwner: boolean): boolean {
  if (isOwner) return true
  if (mask === null) return false
  return hasPermission(mask, byKeys(['VIEW_SSH_AUDIT']))
}

/**
 * May this caller ask a device to turn exec / SSH ON?
 * Mirrors `remote_config::decide` server-side. FAIL-CLOSED on `mask === null`.
 */
export function canGrantDeviceExec(mask: number | null, isOwner: boolean): boolean {
  if (isOwner) return true
  if (mask === null) return false
  return hasPermission(mask, byKeys(['MANAGE_AGENTS', 'EXEC_DEVICE']))
}

/** {@link canGrantDeviceExec}'s twin for interactive SSH sessions. */
export function canGrantDeviceSsh(mask: number | null, isOwner: boolean): boolean {
  if (isOwner) return true
  if (mask === null) return false
  return hasPermission(mask, byKeys(['MANAGE_AGENTS', 'SSH_DEVICE']))
}

/**
 * May this caller read tenant network zones and mutate per-device fleet
 * settings such as logical zone assignment?
 * Server gate: `MANAGE_AGENTS` (owner/ADMINISTRATOR bypass included).
 * FAIL-CLOSED on `mask === null`.
 */
export function canManageAgents(mask: number | null, isOwner: boolean): boolean {
  if (isOwner) return true
  if (mask === null) return false
  return hasPermission(mask, byKeys(['MANAGE_AGENTS']))
}

/**
 * May this caller view or configure organization Relay Nodes?
 * Restricted strictly to Administrators (`ADMINISTRATOR` / org owner).
 * FAIL-CLOSED on `mask === null`.
 */
export function canManageRelays(mask: number | null, isOwner: boolean): boolean {
  if (isOwner) return true
  if (mask === null) return false
  return hasPermission(mask, ADMINISTRATOR)
}
