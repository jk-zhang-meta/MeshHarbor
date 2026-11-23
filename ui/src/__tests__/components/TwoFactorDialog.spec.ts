// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//
// FR-129 — switching a device's two-factor on and off from the admin page.
// The device answers every step; the dialog shows the app choice, the QR code
// and the key in fours, the recovery codes once, and forgets every secret
// when it closes.
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'
import { createVuetify } from 'vuetify'
import * as components from 'vuetify/components'
import * as directives from 'vuetify/directives'
import type { Agent } from '@/stores/agents'

const hoisted = vi.hoisted(() => ({
  twoFactorStep: vi.fn(),
  toDataURL: vi.fn(async () => 'data:image/png;base64,UVI='),
}))
vi.mock('@/stores/agents', () => ({
  useAgentStore: () => ({ twoFactorStep: hoisted.twoFactorStep }),
}))
vi.mock('qrcode', () => ({ default: { toDataURL: hoisted.toDataURL } }))

import TwoFactorDialog from '@/components/admin/TwoFactorDialog.vue'

const vuetify = createVuetify({ components, directives })
/** The dialog inline, its content there while it is open. */
const DialogStub = { props: ['modelValue'], template: '<div v-if="modelValue"><slot /></div>' }

const SECRET = 'JBSWY3DPEHPK3PXP'
const URI = `otpauth://totp/MeshHarbor:gpu?secret=${SECRET}&issuer=MeshHarbor&algorithm=SHA1&digits=6&period=30`
const CODES = ['abcd-efgh', 'jkmn-pqrs', 'tuvw-xyz2', '3456-789a', 'bcde-fghj', 'kmnp-qrst', 'uvwx-yz23', '4567-89ab', 'cdef-ghjk', 'mnpq-rstu']

function agent(caps: Record<string, unknown>): Agent {
  return { id: 'a1', name: 'gpu', display_name: 'GPU box', agent_version: '0.4.212', capabilities: caps } as unknown as Agent
}

function render(a: Agent) {
  return mount(TwoFactorDialog, {
    props: { modelValue: true, tenantId: 't1', agent: a },
    global: { plugins: [vuetify], stubs: { VDialog: DialogStub } },
  })
}

const by = (w: ReturnType<typeof render>, id: string) => w.find(`[data-testid="${id}"]`)
const typeCode = (w: ReturnType<typeof render>, v: string) =>
  w.find('[data-testid="tfa-code-input"] input').setValue(v)

let writeText: ReturnType<typeof vi.fn>
beforeEach(() => {
  vi.stubGlobal(
    'ResizeObserver',
    class {
      observe() {}
      unobserve() {}
      disconnect() {}
    },
  )
  writeText = vi.fn(async () => {})
  Object.defineProperty(navigator, 'clipboard', { value: { writeText }, configurable: true })
})

afterEach(() => {
  vi.clearAllMocks()
  vi.unstubAllGlobals()
})

describe('TwoFactorDialog (FR-129)', () => {
  it('turns two-factor on: app choice, QR code and key in fours, a confirming code, the recovery codes once', async () => {
    const w = render(agent({ rpc: ['two-factor'] }))
    expect(by(w, 'tfa-state').text()).toContain('Two-factor is off.')
    await by(w, 'tfa-enable').trigger('click')

    hoisted.twoFactorStep.mockResolvedValueOnce({ enabled: false, secret: SECRET, otpauth_uri: URI, setup_id: 'setup-1' })
    await by(w, 'tfa-app-google').trigger('click')
    await flushPromises()
    expect(hoisted.twoFactorStep).toHaveBeenLastCalledWith('t1', 'a1', { op: 'begin' })
    expect(hoisted.toDataURL).toHaveBeenCalledWith(URI, expect.anything())
    expect(by(w, 'tfa-qr').attributes('src')).toBe('data:image/png;base64,UVI=')
    expect(by(w, 'tfa-key').text()).toBe('JBSW Y3DP EHPK 3PXP')
    expect(by(w, 'tfa-steps').text()).toContain('Scan a QR code')
    expect(by(w, 'tfa-steps').text()).toContain('Enter a setup key')

    // The copy button copies the key whole, not in groups.
    await by(w, 'tfa-copy-key').trigger('click')
    await flushPromises()
    expect(writeText).toHaveBeenCalledWith(SECRET)

    // A wrong code: said, and the same code is not sent a second time.
    hoisted.twoFactorStep.mockResolvedValueOnce({
      enabled: false,
      refused: 'two_factor_invalid',
      message: 'the two-factor code is wrong, expired or already used',
    })
    await typeCode(w, '123456')
    await by(w, 'tfa-confirm').trigger('click')
    await flushPromises()
    expect(hoisted.twoFactorStep).toHaveBeenLastCalledWith('t1', 'a1', {
      op: 'confirm',
      code: '123456',
      setup_id: 'setup-1',
    })
    expect(by(w, 'tfa-error').text()).toContain('wrong, expired or already used')
    await typeCode(w, '123456')
    await by(w, 'tfa-confirm').trigger('click')
    await flushPromises()
    expect(hoisted.twoFactorStep).toHaveBeenCalledTimes(2)
    expect(by(w, 'tfa-error').text()).toContain('already tried')

    hoisted.twoFactorStep.mockResolvedValueOnce({ enabled: true, recovery_codes: CODES })
    await typeCode(w, '654321')
    await by(w, 'tfa-confirm').trigger('click')
    await flushPromises()
    const shown = by(w, 'tfa-recovery-codes').findAll('code').map((c) => c.text())
    expect(shown).toEqual(CODES)
    expect(w.text()).toContain('shown only this once')
    await by(w, 'tfa-copy-codes').trigger('click')
    await flushPromises()
    expect(writeText).toHaveBeenLastCalledWith(CODES.join('\n'))

    // Closed and opened again: nothing secret is left, and it reads as on.
    await by(w, 'tfa-saved').trigger('click')
    expect(w.emitted('update:modelValue')?.at(-1)).toEqual([false])
    await w.setProps({ modelValue: false })
    // What the component still holds once closed, not just what it renders.
    const held = w.vm as unknown as { secret: string; qrDataUrl: string; recoveryCodes: string[]; code: string }
    expect(held.secret).toBe('')
    expect(held.qrDataUrl).toBe('')
    expect(held.recoveryCodes).toEqual([])
    expect(held.code).toBe('')
    await w.setProps({ agent: agent({ rpc: ['two-factor'], two_factor: true }), modelValue: true })
    const html = w.html()
    expect(html).not.toContain(SECRET.slice(0, 8))
    expect(html).not.toContain('JBSW Y3DP')
    expect(html).not.toContain(CODES[0])
    expect(html).not.toContain('data:image/png')
    expect(by(w, 'tfa-state').text()).toContain('Two-factor is on.')
  })

  it('offers to start again when the pending setup is gone', async () => {
    const w = render(agent({ rpc: ['two-factor'] }))
    await by(w, 'tfa-enable').trigger('click')
    hoisted.twoFactorStep.mockResolvedValueOnce({ enabled: false, secret: SECRET, otpauth_uri: URI, setup_id: 'setup-1' })
    await by(w, 'tfa-app-microsoft').trigger('click')
    await flushPromises()
    expect(by(w, 'tfa-steps').text()).toContain('Other account')

    hoisted.twoFactorStep.mockResolvedValueOnce({ enabled: false, refused: 'no_pending' })
    await typeCode(w, '123456')
    await by(w, 'tfa-confirm').trigger('click')
    await flushPromises()
    expect(by(w, 'tfa-error').text()).toContain('Start again')
    hoisted.twoFactorStep.mockResolvedValueOnce({ enabled: false, secret: 'NEWSECRETNEWSECR', otpauth_uri: URI })
    await by(w, 'tfa-restart').trigger('click')
    await flushPromises()
    expect(hoisted.twoFactorStep).toHaveBeenLastCalledWith('t1', 'a1', { op: 'begin' })
    expect(by(w, 'tfa-key').text()).toBe('NEWS ECRE TNEW SECR')
  })

  it('says how long to wait when the device locked', async () => {
    const w = render(agent({ rpc: ['two-factor'], two_factor: true }))
    await by(w, 'tfa-disable').trigger('click')
    hoisted.twoFactorStep.mockResolvedValueOnce({
      enabled: true,
      refused: 'two_factor_locked',
      retry_after_secs: 60,
    })
    await typeCode(w, '111111')
    await by(w, 'tfa-disable-confirm').trigger('click')
    await flushPromises()
    expect(by(w, 'tfa-error').text()).toContain('Try again in 1 min')
  })

  it('turns it off with a recovery code', async () => {
    const w = render(agent({ rpc: ['two-factor'], two_factor: true }))
    expect(by(w, 'tfa-state').text()).toContain('Two-factor is on.')
    await by(w, 'tfa-disable').trigger('click')
    await by(w, 'tfa-code-mode').trigger('click')
    await typeCode(w, 'ABCD-EFGH')
    hoisted.twoFactorStep.mockResolvedValueOnce({ enabled: false })
    await by(w, 'tfa-disable-confirm').trigger('click')
    await flushPromises()
    expect(hoisted.twoFactorStep).toHaveBeenLastCalledWith('t1', 'a1', { op: 'disable', code: 'abcd-efgh' })
    expect(by(w, 'tfa-state').text()).toContain('Two-factor is off.')
    expect(by(w, 'tfa-notice').text()).toContain('now off')
  })

  it('cannot be switched on from a device that does not understand it', () => {
    const w = render(agent({ rpc: ['exec'] }))
    expect(by(w, 'tfa-too-old').text()).toContain('0.4.212')
    expect(by(w, 'tfa-enable').attributes('disabled')).toBeDefined()
  })
})
