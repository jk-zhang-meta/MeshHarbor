// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
import { describe, expect, it } from 'vitest'
import {
  ADMINISTRATOR,
  ALL_PERMISSIONS,
  maskClear,
  maskHas,
  maskSet,
  maskUnion,
  DEFAULT_ADMIN,
  DEFAULT_MEMBER,
  PERMISSION_FLAGS,
  PERMISSION_GROUPS,
  canGrantDeviceExec,
  canGrantDeviceSsh,
  canManageInvites,
  canViewExecAudit,
  canViewSshAudit,
  canSeeFleetNav,
  describePermissions,
  hasPermission,
} from '@/utils/permissions'

describe('permission catalog', () => {
  it('defines all 14 active flags with unique bits and keys', () => {
    expect(PERMISSION_FLAGS).toHaveLength(14)
    const bits = PERMISSION_FLAGS.map((f) => f.bit)
    expect(new Set(bits).size).toBe(14)
    const keys = PERMISSION_FLAGS.map((f) => f.key)
    expect(new Set(keys).size).toBe(14)
    for (const bit of bits) {
      expect(Number.isInteger(Math.log2(bit))).toBe(true)
      expect(bit).toBeGreaterThan(0)
      expect(bit).toBeLessThanOrEqual(2 ** 52)
    }
  })

  it('OR of every flag equals ALL_PERMISSIONS', () => {
    const all = PERMISSION_FLAGS.reduce((m, f) => maskUnion(m, f.bit), 0)
    expect(all).toBe(ALL_PERMISSIONS)
    expect(ALL_PERMISSIONS).toBeGreaterThan(0)
  })

  it('mirrors the server shift assignments for the load-bearing flags', () => {
    const bit = (key: string) => PERMISSION_FLAGS.find((f) => f.key === key)?.bit
    expect(bit('MANAGE_ROLES')).toBe(1 << 2)
    expect(bit('MANAGE_TENANT')).toBe(1 << 3)
    expect(bit('KICK_MEMBERS')).toBe(1 << 4)
    expect(bit('BAN_MEMBERS')).toBe(1 << 5)
    expect(bit('INVITE_MEMBERS')).toBe(1 << 6)
    expect(ADMINISTRATOR).toBe(1 << 23)
    expect(bit('ADMINISTRATOR')).toBe(1 << 23)
    expect(bit('MANAGE_AGENTS')).toBe(1 << 24)
    expect(bit('REMOTE_CONTROL')).toBe(1 << 25)
    expect(bit('VIEW_REMOTE_AUDIT')).toBe(1 << 26)
    expect(bit('EXEC_DEVICE')).toBe(1 << 27)
    expect(bit('VIEW_EXEC_AUDIT')).toBe(1 << 28)
    expect(bit('SSH_DEVICE')).toBe(1 << 29)
    expect(bit('VIEW_SSH_AUDIT')).toBe(1 << 30)
    expect(bit('RECORD_REMOTE_SCREEN')).toBe(2 ** 31)
  })

  it('withholds the fleet-access grants from the admin preset', () => {
    expect(maskHas(DEFAULT_ADMIN, 1 << 27)).toBe(false) // EXEC_DEVICE
    expect(maskHas(DEFAULT_ADMIN, 1 << 29)).toBe(false) // SSH_DEVICE
    expect(maskHas(DEFAULT_ADMIN, 1 << 28)).toBe(true) // VIEW_EXEC_AUDIT
    expect(maskHas(DEFAULT_ADMIN, 1 << 30)).toBe(true) // VIEW_SSH_AUDIT
    expect(maskHas(DEFAULT_ADMIN, 2 ** 31)).toBe(false) // RECORD_REMOTE_SCREEN
  })

  it('a preset round-trip preserves every bit the preset claims to set', () => {
    for (const preset of [DEFAULT_MEMBER, DEFAULT_ADMIN, ALL_PERMISSIONS]) {
      const covered = PERMISSION_FLAGS.reduce(
        (m, f) => (maskHas(preset, f.bit) ? maskUnion(m, f.bit) : m),
        0,
      )
      expect(covered).toBe(preset)
    }
  })

  it('DEFAULT_MEMBER is 0 and DEFAULT_ADMIN excludes ADMINISTRATOR and MANAGE_TENANT', () => {
    expect(DEFAULT_MEMBER).toBe(0)
    const expected =
      (1 << 2) |
      (1 << 4) |
      (1 << 5) |
      (1 << 6) |
      (1 << 24) |
      (1 << 25) |
      (1 << 26) |
      (1 << 28) |
      (1 << 30)
    expect(DEFAULT_ADMIN).toBe(expected)
    expect(maskHas(DEFAULT_ADMIN, ADMINISTRATOR)).toBe(false)
    expect(maskHas(DEFAULT_ADMIN, 1 << 3)).toBe(false) // MANAGE_TENANT
  })

  it('hasPermission mirrors the server ADMINISTRATOR bypass', () => {
    const remote = 1 << 25
    expect(hasPermission(ADMINISTRATOR, remote)).toBe(true)
    expect(hasPermission(remote, remote)).toBe(true)
    expect(hasPermission(remote, 1 << 2)).toBe(false)
    expect(hasPermission(0, 0)).toBe(true)
  })

  it('describePermissions lists labels in catalog order', () => {
    const labels = describePermissions((1 << 2) | (1 << 25))
    expect(labels).toEqual(['Manage roles', 'Remote control'])
    expect(describePermissions(0)).toEqual([])
  })

  it('groups are stable for the editor layout', () => {
    expect(PERMISSION_GROUPS).toEqual([
      'General',
      'Remote control',
      'Fleet access',
    ])
  })
})

describe('canSeeFleetNav (Devices + Network nav gating)', () => {
  const MANAGE_AGENTS = 1 << 24
  const REMOTE_CONTROL = 1 << 25

  it('fails OPEN while the membership has not loaded (null mask)', () => {
    expect(canSeeFleetNav(null, false)).toBe(true)
  })

  it('shows for either fleet permission alone', () => {
    expect(canSeeFleetNav(MANAGE_AGENTS, false)).toBe(true)
    expect(canSeeFleetNav(REMOTE_CONTROL, false)).toBe(true)
  })

  it('shows for ADMINISTRATOR and for the tenant owner regardless of mask', () => {
    expect(canSeeFleetNav(ADMINISTRATOR, false)).toBe(true)
    expect(canSeeFleetNav(0, true)).toBe(true)
  })

  it('hides for a plain member', () => {
    expect(canSeeFleetNav(DEFAULT_MEMBER, false)).toBe(false)
    expect(canSeeFleetNav(0, false)).toBe(false)
  })

  it('DEFAULT_ADMIN sees fleet nav', () => {
    expect(canSeeFleetNav(DEFAULT_ADMIN, false)).toBe(true)
  })
})

describe('canViewExecAudit / canViewSshAudit (Audit nav gating)', () => {
  const VIEW_EXEC_AUDIT = 1 << 28
  const VIEW_SSH_AUDIT = 1 << 30

  it('fail CLOSED on a null mask', () => {
    expect(canViewExecAudit(null, false)).toBe(false)
    expect(canViewSshAudit(null, false)).toBe(false)
    expect(canViewExecAudit(null, true)).toBe(true)
    expect(canViewSshAudit(null, true)).toBe(true)
  })

  it('the two bits are independent — one never implies the other', () => {
    expect(canViewExecAudit(VIEW_EXEC_AUDIT, false)).toBe(true)
    expect(canViewExecAudit(VIEW_SSH_AUDIT, false)).toBe(false)
    expect(canViewSshAudit(VIEW_SSH_AUDIT, false)).toBe(true)
    expect(canViewSshAudit(VIEW_EXEC_AUDIT, false)).toBe(false)
  })

  it('ADMINISTRATOR and DEFAULT_ADMIN pass both; plain member neither', () => {
    expect(canViewExecAudit(ADMINISTRATOR, false)).toBe(true)
    expect(canViewSshAudit(ADMINISTRATOR, false)).toBe(true)
    expect(canViewExecAudit(DEFAULT_ADMIN, false)).toBe(true)
    expect(canViewSshAudit(DEFAULT_ADMIN, false)).toBe(true)
    expect(canViewExecAudit(DEFAULT_MEMBER, false)).toBe(false)
    expect(canViewSshAudit(DEFAULT_MEMBER, false)).toBe(false)
  })
})

describe('canManageInvites (invites nav gating)', () => {
  const INVITE_MEMBERS = 1 << 6

  it('fails CLOSED while the membership has not loaded (null mask)', () => {
    expect(canManageInvites(null, false)).toBe(false)
  })

  it('owner always allowed, even before the mask loads', () => {
    expect(canManageInvites(null, true)).toBe(true)
    expect(canManageInvites(0, true)).toBe(true)
  })

  it('INVITE_MEMBERS or ADMINISTRATOR allowed — DEFAULT_ADMIN carries it', () => {
    expect(canManageInvites(INVITE_MEMBERS, false)).toBe(true)
    expect(canManageInvites(ADMINISTRATOR, false)).toBe(true)
    expect(canManageInvites(DEFAULT_ADMIN, false)).toBe(true)
  })

  it('plain member denied', () => {
    expect(canManageInvites(DEFAULT_MEMBER, false)).toBe(false)
    expect(canManageInvites(0, false)).toBe(false)
  })
})

describe('canGrantDeviceExec / canGrantDeviceSsh', () => {
  const MANAGE_AGENTS = 1 << 24
  const EXEC_DEVICE = 1 << 27
  const SSH_DEVICE = 1 << 29

  it('MANAGE_AGENTS alone cannot open exec or SSH on a device', () => {
    expect(hasPermission(DEFAULT_ADMIN, MANAGE_AGENTS)).toBe(true)
    expect(canGrantDeviceExec(DEFAULT_ADMIN, false)).toBe(false)
    expect(canGrantDeviceSsh(DEFAULT_ADMIN, false)).toBe(false)
  })

  it('the matching grant bit, on top of MANAGE_AGENTS, is what it takes', () => {
    expect(canGrantDeviceExec(DEFAULT_ADMIN | EXEC_DEVICE, false)).toBe(true)
    expect(canGrantDeviceSsh(DEFAULT_ADMIN | SSH_DEVICE, false)).toBe(true)
    expect(canGrantDeviceExec(EXEC_DEVICE, false)).toBe(false)
    expect(canGrantDeviceSsh(SSH_DEVICE, false)).toBe(false)
  })

  it('the two grants never substitute for each other', () => {
    expect(canGrantDeviceSsh(DEFAULT_ADMIN | EXEC_DEVICE, false)).toBe(false)
    expect(canGrantDeviceExec(DEFAULT_ADMIN | SSH_DEVICE, false)).toBe(false)
  })

  it('ADMINISTRATOR and owner bypass, as everywhere else', () => {
    expect(canGrantDeviceExec(ADMINISTRATOR, false)).toBe(true)
    expect(canGrantDeviceSsh(ADMINISTRATOR, false)).toBe(true)
    expect(canGrantDeviceExec(null, true)).toBe(true)
    expect(canGrantDeviceSsh(0, true)).toBe(true)
  })

  it('fails CLOSED before the mask loads', () => {
    expect(canGrantDeviceExec(null, false)).toBe(false)
    expect(canGrantDeviceSsh(null, false)).toBe(false)
  })
})

describe('#888 — the ceiling is bit 52, not bit 30', () => {
  const HIGH = [2 ** 31, 2 ** 40, 2 ** 52]

  it('the OLD bitwise approach really does break there — the reason this exists', () => {
    for (const bit of HIGH) {
      expect((bit & bit) === bit).toBe(false)
    }
    expect(((1 << 30) & (1 << 30)) === 1 << 30).toBe(true)
  })

  it('maskHas reads high bits the bitwise version could not', () => {
    for (const bit of HIGH) {
      expect(maskHas(bit, bit)).toBe(true)
      expect(maskHas(0, bit)).toBe(false)
      expect(maskHas(bit * 2, bit)).toBe(false)
    }
  })

  it('maskSet / maskClear round-trip a high bit without disturbing the rest', () => {
    for (const bit of HIGH) {
      const base = DEFAULT_ADMIN
      const set = maskSet(base, bit)
      expect(maskHas(set, bit)).toBe(true)
      expect(describePermissions(set)).toEqual(expect.arrayContaining(describePermissions(base)))
      expect(maskClear(set, bit)).toBe(base)
      expect(maskSet(set, bit)).toBe(set)
      expect(maskClear(base, bit)).toBe(base)
    }
  })

  it('hasPermission honours a high-bit flag, and ADMINISTRATOR still bypasses', () => {
    for (const bit of HIGH) {
      expect(hasPermission(bit, bit)).toBe(true)
      expect(hasPermission(0, bit)).toBe(false)
      expect(hasPermission(ADMINISTRATOR, bit)).toBe(true)
    }
  })

  it('a high-bit mask survives the wire — JSON carries it exactly', () => {
    for (const bit of HIGH) {
      const mask = maskSet(DEFAULT_ADMIN, bit)
      const round = JSON.parse(JSON.stringify({ permissions: mask })).permissions
      expect(round).toBe(mask)
      expect(Number.isSafeInteger(round)).toBe(true)
    }
  })

  it('maskUnion composes disjoint and overlapping masks like `|` used to', () => {
    expect(maskUnion(0b0101, 0b0011)).toBe(0b0111)
    expect(maskUnion(DEFAULT_ADMIN, DEFAULT_ADMIN)).toBe(DEFAULT_ADMIN)
    expect(maskHas(maskUnion(DEFAULT_ADMIN, 2 ** 45), 2 ** 45)).toBe(true)
  })
})
