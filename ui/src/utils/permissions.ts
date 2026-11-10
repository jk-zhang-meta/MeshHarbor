// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
/**
 * The tenant permission catalog — a TS mirror of the server's bitfield in
 * `crates/db/src/models/role.rs::permissions`.
 *
 * Keep this file in lockstep with the Rust module: the unit test locks the
 * composite values so drift is caught at `bun run test:unit`, not in prod.
 * Drift is not cosmetic — the role editor writes back the mask it built from
 * THIS catalog, so a bit missing here is a bit silently stripped from any
 * role that gets saved.
 *
 * ⚠️ JS bitwise operands are coerced to **signed int32**, so this file uses NO
 * bitwise operators on a mask — see `maskHas`/`maskSet`/`maskClear`/`maskUnion`,
 * which are arithmetic and exact to bit 52 (#888). A composite must likewise not
 * be built with a shift: `(1 << 31) - 1` is −2147483649 in JS, not 2147483647.
 *
 * The ceiling is therefore bit 52, not bit 30, and it is the JSON number's
 * 2^53 integer limit rather than anything about the wire or the server (`u64`).
 * Adding a bit above 30 needs a catalog entry here and nothing else; adding one
 * above 52 needs BigInt or string masks end to end.
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

/** All 31 defined flags, grouped for the role-editor UI. */
export const PERMISSION_FLAGS: PermissionFlag[] = [
  // ── General ──────────────────────────────────────────────────────
  { key: 'VIEW_CHANNELS', bit: 1 << 0, label: 'View channels', group: 'General' },
  { key: 'MANAGE_CHANNELS', bit: 1 << 1, label: 'Manage channels', group: 'General' },
  { key: 'MANAGE_ROLES', bit: 1 << 2, label: 'Manage roles', group: 'General' },
  { key: 'MANAGE_TENANT', bit: 1 << 3, label: 'Manage tenant', group: 'General' },
  { key: 'INVITE_MEMBERS', bit: 1 << 6, label: 'Invite members', group: 'General' },
  {
    key: 'ADMINISTRATOR',
    bit: ADMINISTRATOR,
    label: 'Administrator',
    group: 'General',
    description: 'Bypasses ALL permission checks — grants everything below implicitly.',
  },
  // ── Messaging ────────────────────────────────────────────────────
  { key: 'SEND_MESSAGES', bit: 1 << 7, label: 'Send messages', group: 'Messaging' },
  { key: 'SEND_THREADS', bit: 1 << 8, label: 'Create threads', group: 'Messaging' },
  { key: 'EMBED_LINKS', bit: 1 << 9, label: 'Embed links', group: 'Messaging' },
  { key: 'ATTACH_FILES', bit: 1 << 10, label: 'Attach files', group: 'Messaging' },
  { key: 'READ_HISTORY', bit: 1 << 11, label: 'Read history', group: 'Messaging' },
  { key: 'MENTION_EVERYONE', bit: 1 << 12, label: 'Mention @everyone', group: 'Messaging' },
  { key: 'MANAGE_MESSAGES', bit: 1 << 13, label: 'Manage messages', group: 'Messaging' },
  { key: 'ADD_REACTIONS', bit: 1 << 14, label: 'Add reactions', group: 'Messaging' },
  // ── Voice & video ────────────────────────────────────────────────
  { key: 'CONNECT_VOICE', bit: 1 << 15, label: 'Connect to voice', group: 'Voice & video' },
  { key: 'SPEAK', bit: 1 << 16, label: 'Speak', group: 'Voice & video' },
  { key: 'STREAM_VIDEO', bit: 1 << 17, label: 'Stream video', group: 'Voice & video' },
  { key: 'MANAGE_MEETINGS', bit: 1 << 21, label: 'Manage meetings', group: 'Voice & video' },
  // ── Moderation ───────────────────────────────────────────────────
  { key: 'KICK_MEMBERS', bit: 1 << 4, label: 'Kick members', group: 'Moderation' },
  { key: 'BAN_MEMBERS', bit: 1 << 5, label: 'Ban members', group: 'Moderation' },
  { key: 'MUTE_MEMBERS', bit: 1 << 18, label: 'Mute members', group: 'Moderation' },
  { key: 'DEAFEN_MEMBERS', bit: 1 << 19, label: 'Deafen members', group: 'Moderation' },
  { key: 'MOVE_MEMBERS', bit: 1 << 20, label: 'Move members', group: 'Moderation' },
  { key: 'MANAGE_DOCUMENTS', bit: 1 << 22, label: 'Manage documents', group: 'Moderation' },
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
  // shell on it are different powers. Both run as SYSTEM/root with nobody
  // at the machine watching, which is why the audit views are separate bits.
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
  {
    key: 'HIVE_RUN',
    // FR-90 — the first flag above bit 31: `2 ** 32`, which a shift cannot
    // even express in JS (`1 << 32` is 1).
    bit: 2 ** 32,
    label: 'Run agent sessions',
    group: 'Fleet access',
    description:
      'Start and drive AI agent sessions on a device. A session runs as the account the device maps you to — never SYSTEM or root — and only where the device allows it. It runs commands on that device, so no role gets this by default.',
  },
]

// A flag's label and description are read in the interface language when they
// are accessed (`mh.permFlag.<KEY>.*`); the literals above are their English
// source. `group` stays the English id, shown through `permissionGroupLabel`.
const FLAG_PARAMS = { everyone: '@everyone' }
for (const f of PERMISSION_FLAGS) {
  Object.defineProperty(f, 'label', {
    enumerable: true,
    get: () => i18n.global.t(`mh.permFlag.${f.key}.label`, FLAG_PARAMS),
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
  Messaging: 'messaging',
  'Voice & video': 'voice',
  Moderation: 'moderation',
  'Remote control': 'remote',
  'Fleet access': 'fleet',
}
/** A flag's label in the interface language, by its key. */
export function permissionLabel(key: string): string {
  return i18n.global.t(`mh.permFlag.${key}.label`, FLAG_PARAMS)
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

/** Server `DEFAULT_MEMBER` composite — the sensible baseline role. */
export const DEFAULT_MEMBER = byKeys([
  'VIEW_CHANNELS',
  'SEND_MESSAGES',
  'SEND_THREADS',
  'EMBED_LINKS',
  'ATTACH_FILES',
  'READ_HISTORY',
  'ADD_REACTIONS',
  'CONNECT_VOICE',
  'SPEAK',
  'STREAM_VIDEO',
])

/**
 * Server `DEFAULT_ADMIN` composite. NOT "everything except ADMINISTRATOR":
 * `EXEC_DEVICE` and `SSH_DEVICE` are withheld on purpose so that opening a
 * root shell on a fleet device stays an explicit grant. The matching audit
 * views ARE included — seeing what the fleet served is a different job from
 * being able to serve it.
 */
export const DEFAULT_ADMIN = maskUnion(
  DEFAULT_MEMBER,
  byKeys([
    'MANAGE_CHANNELS',
    'MANAGE_ROLES',
    'KICK_MEMBERS',
    'BAN_MEMBERS',
    'INVITE_MEMBERS',
    'MENTION_EVERYONE',
    'MANAGE_MESSAGES',
    'MUTE_MEMBERS',
    'DEAFEN_MEMBERS',
    'MOVE_MEMBERS',
    'MANAGE_MEETINGS',
    'MANAGE_DOCUMENTS',
    'MANAGE_AGENTS',
    'REMOTE_CONTROL',
    'VIEW_REMOTE_AUDIT',
    'VIEW_EXEC_AUDIT',
    'VIEW_SSH_AUDIT',
  ]),
)

/**
 * Every defined bit — server `ALL = (1 << 33) - 1` = bits 0–32.
 * Written as `2 ** 33 - 1` because the Rust spelling is not a JS expression
 * at all: a shift coerces to int32, so `1 << 33` is 2 (see the int32 note at
 * the top of this file).
 */
export const ALL_PERMISSIONS = 2 ** 33 - 1

/**
 * Mask arithmetic that is exact to `Number.MAX_SAFE_INTEGER`, i.e. bits 0–52.
 *
 * #888: the ceiling was bit 30 because every mask operation here used a JS
 * bitwise operator, and those coerce both operands to **signed int32** —
 * `1 << 31` is negative and anything above bit 31 is truncated outright. The
 * limit was never the wire and never the server (which is `u64`): a JSON number
 * carries an integer EXACTLY up to 2^53, verified rather than assumed —
 * `2 ** 52` survives `JSON.parse(JSON.stringify(...))` unchanged, while
 * `2 ** 40 & 2 ** 40` does not survive the operator.
 *
 * So the fix is arithmetic, not `BigInt`. That keeps `number` end to end — no
 * string-on-the-wire, no server serialisation change, no client-compat break —
 * and moves the ceiling from **31 flags to 53**, which at the observed rate of a
 * few bits a year is a decade rather than a stopgap.
 *
 * ⚠️ `maskSet`/`maskClear` are add/subtract and are therefore only correct when
 * guarded by `maskHas`. They are written that way on purpose: `|` and `&~` are
 * exactly the operators that silently truncate, and the role editor WRITES BACK
 * the mask it builds, so a truncation here does not throw — it strips
 * permissions from a saved role and looks like a successful save.
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
 *
 * Walks the bits rather than consulting `PERMISSION_FLAGS`, deliberately. A
 * catalog-driven version would silently IGNORE any bit the catalog does not
 * know — and a mask arriving from a newer server is exactly the case where that
 * happens, so the check would quietly answer "yes, you have it" for a
 * permission this build has never heard of.
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
 * group). Deliberately FAIL-OPEN: while the membership hasn't loaded yet
 * (`mask === null` — first paint, endpoint hiccup, older server without
 * /member/me) the nav stays visible; the server still enforces every
 * action, so the worst case of failing open is a visible link to a page
 * whose actions 403. Failing closed would hide navigation behind a
 * network round-trip on every load.
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
 * `ssh-settings`, `ephemeral-key-settings`? Server gate on all three:
 * `MANAGE_TENANT` (owner/ADMINISTRATOR bypass included).
 *
 * ⚠️ `MANAGE_TENANT` is deliberately NOT in `DEFAULT_ADMIN`, so this is
 * false for an org's own admins and true only for its owner. That is the
 * server's policy, not an accident — configuring the organisation is the
 * owner's job — and it is why the Devices page's enrollment-keys card is
 * invisible to almost everyone.
 *
 * FAIL-CLOSED on `mask === null`, and the callers `await
 * ensureMyMembership` so `null` means "the fetch failed", not "too early".
 */
export function canManageOrgSettings(mask: number | null, isOwner: boolean): boolean {
  if (isOwner) return true
  if (mask === null) return false
  return hasPermission(mask, byKeys(['MANAGE_TENANT']))
}

/**
 * Gate for the org Analytics queries (stats PR-4). Unlike
 * `canSeeFleetNav` this is deliberately FAIL-CLOSED on `mask === null`:
 * the stats endpoints answer 404 to a caller without MANAGE_AGENTS, so the
 * UI would draw a page whose every query came back empty.
 * Server gate: `MANAGE_AGENTS` (owner/ADMINISTRATOR bypass included).
 *
 * ⚠️ The reason recorded here used to be "the api client force-logs-out on
 * any 403". It no longer does (FR-82) — a 403 is an answer, not a dead
 * session. These predicates are UX now: don't draw a door that opens onto a
 * refusal, and don't spend a round-trip learning what the mask already says.
 * Keep them; just don't believe they are load-bearing for the session.
 */
export function canQueryAnalytics(mask: number | null, isOwner: boolean): boolean {
  if (isOwner) return true
  if (mask === null) return false
  return hasPermission(mask, byKeys(['MANAGE_AGENTS']))
}

/**
 * Nav gate for the Invites surface (sidebar item + dashboard card).
 * Deliberately FAIL-CLOSED on `mask === null`, like {@link canQueryAnalytics}
 * and unlike {@link canSeeFleetNav}: `list_invites` requires INVITE_MEMBERS,
 * so an ungated entry leads a plain member to an empty page.
 *
 * ⚠️ This helper was originally added because an ungated entry turned that
 * member's click into a LOGOUT. It doesn't any more (FR-82) — see the note
 * on {@link canQueryAnalytics}. Server gate: `INVITE_MEMBERS`
 * (owner/ADMINISTRATOR bypass included).
 */
export function canManageInvites(mask: number | null, isOwner: boolean): boolean {
  if (isOwner) return true
  if (mask === null) return false
  return hasPermission(mask, byKeys(['INVITE_MEMBERS']))
}

/**
 * Nav gates for the Audit pages. FAIL-CLOSED like {@link canQueryAnalytics}
 * and for the same reason: the audit endpoints 403 without their bit, so the
 * page would render nothing but its own error. Two separate helpers because
 * the server deliberately splits the bits — reviewing command history
 * (VIEW_EXEC_AUDIT) and reviewing SSH sessions (VIEW_SSH_AUDIT) are
 * different jobs.
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
 *
 * `MANAGE_AGENTS` alone is NOT enough, and that is the whole point. Enabling
 * exec on a device is *granting a power*, and #600/#605 established the rule:
 * **you cannot grant a permission you do not hold.** An admin without
 * `EXEC_DEVICE` must not be able to open exec on a fleet device for somebody
 * else — that is the same escalation those PRs closed, one indirection away.
 * `EXEC_DEVICE` and `SSH_DEVICE` are deliberately absent from `DEFAULT_ADMIN`,
 * which is what makes this a real constraint rather than a formality.
 *
 * Mirrors `remote_config::decide` server-side. This only avoids offering a
 * control whose save would 403 — the server is where it is enforced.
 *
 * Deliberately FAIL-CLOSED on `mask === null`, like {@link canQueryAnalytics}
 * and unlike {@link canSeeFleetNav}: the failure mode of guessing wrong here
 * is an operator who flips a switch, gets a 403, and cannot tell whether the
 * device refused or they did.
 */
export function canGrantDeviceExec(mask: number | null, isOwner: boolean): boolean {
  if (isOwner) return true
  if (mask === null) return false
  return hasPermission(mask, byKeys(['MANAGE_AGENTS', 'EXEC_DEVICE']))
}

/** {@link canGrantDeviceExec}'s twin. A SEPARATE bit on purpose: an SSH
 *  session is strictly more than a bounded command, so holding one must never
 *  imply the other. */
export function canGrantDeviceSsh(mask: number | null, isOwner: boolean): boolean {
  if (isOwner) return true
  if (mask === null) return false
  return hasPermission(mask, byKeys(['MANAGE_AGENTS', 'SSH_DEVICE']))
}

/**
 * FR-90 P2h-2 — may this caller set the organization's Hive replica policy:
 * designate archive replicas, and add one? Server gate: `ADMINISTRATOR`
 * (`crates/modules/hive/src/policy.rs`, `put_policy`). FAIL-CLOSED on
 * `mask === null`: the page shows its switches only once it knows.
 */
export function canSetHivePolicy(mask: number | null, isOwner: boolean): boolean {
  if (isOwner) return true
  if (mask === null) return false
  return hasPermission(mask, ADMINISTRATOR)
}
