// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//
// FR-129 — the remote-desktop viewer's code prompt.
import { describe, expect, it, vi } from 'vitest'
import { nextTick, ref } from 'vue'
import { useTwoFactorPrompt } from '@/composables/useTwoFactorPrompt'

function setup(opts: { on?: boolean; enabled?: boolean } = {}) {
  const rc = { twoFactorCode: ref(''), overrideReason: ref(''), errorCode: ref<string | null>(null) }
  const on = ref(opts.on ?? true)
  const connect = vi.fn()
  const p = useTwoFactorPrompt({ rc, isOn: () => on.value, enabled: opts.enabled ?? true, connect })
  return { rc, on, connect, p }
}

/** The device ends the attempt: the RC composable resets the code on the next
 *  connect, then sets it from the `rc:terminate` reason. */
async function deviceEnds(rc: ReturnType<typeof setup>['rc'], reason: string) {
  rc.errorCode.value = null
  await nextTick()
  rc.errorCode.value = reason
  await nextTick()
}

describe('useTwoFactorPrompt (FR-129)', () => {
  it('asks before connecting to a device with two-factor on, and sends the code once', () => {
    const { rc, connect, p } = setup()
    p.start()
    expect(p.open.value).toBe(true)
    expect(p.note.value).toBeNull()
    expect(connect).not.toHaveBeenCalled()

    p.input.value = '12345'
    expect(p.ready.value).toBe(false)
    p.submit()
    expect(connect).not.toHaveBeenCalled()

    p.input.value = '123456'
    expect(p.ready.value).toBe(true)
    p.submit()
    expect(rc.twoFactorCode.value).toBe('123456')
    expect(p.open.value).toBe(false)
    expect(p.input.value).toBe('')
    expect(connect).toHaveBeenCalledTimes(1)
  })

  it('connects straight away where the device does not ask, or no code can go', () => {
    const off = setup({ on: false })
    off.p.start()
    expect(off.p.open.value).toBe(false)
    expect(off.connect).toHaveBeenCalledTimes(1)

    const external = setup({ enabled: false })
    external.p.start()
    expect(external.p.open.value).toBe(false)
    expect(external.connect).toHaveBeenCalledTimes(1)
  })

  it('asks again after a refusal, saying why, and never sends the same code twice', async () => {
    const { rc, connect, p } = setup()
    p.start()
    p.input.value = '123456'
    p.submit()
    await deviceEnds(rc, 'two_factor_invalid')
    expect(p.open.value).toBe(true)
    expect(p.note.value).toMatch(/wrong, expired or already used/)

    p.input.value = '123 456'
    p.submit()
    expect(connect).toHaveBeenCalledTimes(1)
    expect(p.open.value).toBe(true)
    expect(p.note.value).toMatch(/already tried/)

    p.input.value = '654321'
    p.submit()
    expect(connect).toHaveBeenCalledTimes(2)
    expect(rc.twoFactorCode.value).toBe('654321')
  })

  it('asks when the device wanted a code its report did not announce', async () => {
    const { rc, connect, p } = setup({ on: false })
    p.start()
    expect(connect).toHaveBeenCalledTimes(1)
    await deviceEnds(rc, 'two_factor_required')
    expect(p.open.value).toBe(true)
    expect(p.note.value).toMatch(/asks for a two-factor code/)
  })

  it('does not ask while the device is locked, nor on an external login, nor for other endings', async () => {
    const locked = setup()
    await deviceEnds(locked.rc, 'two_factor_locked')
    expect(locked.p.open.value).toBe(false)

    const external = setup({ enabled: false })
    await deviceEnds(external.rc, 'two_factor_required')
    expect(external.p.open.value).toBe(false)

    const denied = setup()
    await deviceEnds(denied.rc, 'user_denied')
    expect(denied.p.open.value).toBe(false)
  })

  it('backing out drops a break-glass reason waiting for the next request', () => {
    const { rc, connect, p } = setup()
    rc.overrideReason.value = 'locked out of the box'
    p.start()
    p.input.value = '1234'
    p.cancel()
    expect(p.open.value).toBe(false)
    expect(p.input.value).toBe('')
    expect(rc.overrideReason.value).toBe('')
    expect(rc.twoFactorCode.value).toBe('')
    expect(connect).not.toHaveBeenCalled()
  })
})
