// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//
// FR-88 (#1790) §3b — `install-copy` in the app: copying an install or
// enroll COMMAND counts, copying the bare token does not, a failed clipboard
// write does not, and without purestat the copy still works.
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'
import { createVuetify } from 'vuetify'
import * as components from 'vuetify/components'
import * as directives from 'vuetify/directives'
import EnrollmentDialog from '@/components/enroll/EnrollmentDialog.vue'

const vuetify = createVuetify({ components, directives })
type W = Window & { purestat?: unknown }
const purestat = vi.fn()
let writeText: ReturnType<typeof vi.fn>

async function open() {
  const w = mount(EnrollmentDialog, {
    props: { modelValue: true, kind: 'agent', token: 'tok-123', expiresIn: 600, loading: false, error: null },
    // The overlay machinery needs browser APIs jsdom lacks; what is under
    // test is the dialog's content, so the dialog renders it in place.
    global: { plugins: [vuetify], stubs: { VDialog: { template: '<div><slot /></div>' } } },
    attachTo: document.body,
  })
  await flushPromises()
  return w
}

const buttons = (label: string) =>
  [...document.body.querySelectorAll('button')].filter((b) => b.textContent!.trim() === label) as HTMLButtonElement[]

beforeEach(() => {
  vi.stubGlobal(
    'ResizeObserver',
    class {
      observe() {}
      unobserve() {}
      disconnect() {}
    },
  )
  writeText = vi.fn(() => Promise.resolve())
  Object.defineProperty(navigator, 'clipboard', { value: { writeText }, configurable: true })
  purestat.mockReset()
  ;(window as W).purestat = purestat
})

afterEach(() => {
  delete (window as W).purestat
  vi.unstubAllGlobals()
  document.body.innerHTML = ''
})

describe('EnrollmentDialog — install-copy (FR-88)', () => {
  it('fires once when a command is copied', async () => {
    const w = await open()
    const copy = buttons('Copy')
    expect(copy.length).toBeGreaterThan(0)
    copy[0]!.click()
    await flushPromises()
    expect(writeText).toHaveBeenCalledTimes(1)
    expect(writeText.mock.calls[0]![0]).toMatch(/install\.(?:ps1|sh)|enroll --server/)
    expect(purestat.mock.calls).toEqual([['install-copy']])
    w.unmount()
  })

  it('does not fire for the bare token', async () => {
    const w = await open()
    buttons('Copy token')[0]!.click()
    await flushPromises()
    expect(writeText).toHaveBeenCalledWith('tok-123')
    expect(purestat).not.toHaveBeenCalled()
    w.unmount()
  })

  it('does not fire when the clipboard refuses', async () => {
    writeText.mockRejectedValueOnce(new Error('NotAllowedError'))
    const w = await open()
    buttons('Copy')[0]!.click()
    await flushPromises()
    expect(purestat).not.toHaveBeenCalled()
    w.unmount()
  })

  it('still copies without purestat', async () => {
    delete (window as W).purestat
    const w = await open()
    buttons('Copy')[0]!.click()
    await flushPromises()
    expect(writeText).toHaveBeenCalledTimes(1)
    expect(document.body.textContent).toContain('Copied')
    w.unmount()
  })
})

// FR-104 — "Also let administrators run commands as SYSTEM on this device".
describe('EnrollmentDialog — the anchor box (FR-104)', () => {
  async function mountWith(props: Record<string, unknown>) {
    // The Windows tab is the one that carries the box; the default tab
    // follows the visitor's platform, which on a Linux runner is not it.
    vi.spyOn(navigator, 'userAgent', 'get').mockReturnValue(
      'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
    )
    const w = mount(EnrollmentDialog, {
      props: {
        modelValue: true,
        kind: 'agent',
        token: 'tok-123',
        expiresIn: 600,
        loading: false,
        error: null,
        ...props,
      },
      global: { plugins: [vuetify], stubs: { VDialog: { template: '<div><slot /></div>' } } },
      attachTo: document.body,
    })
    await flushPromises()
    return w
  }
  const box = () =>
    document.body.querySelector('[data-test="enroll-anchor"] input') as HTMLInputElement | null
  const anchorCommand = () =>
    [...document.body.querySelectorAll('pre')].find((p) =>
      p.textContent!.includes('meshharbord anchor create'),
    )

  afterEach(() => vi.restoreAllMocks())

  it('asks for a new token when ticked, and shows what the token carries', async () => {
    const w = await mountWith({ anchor: false })
    expect(box()).not.toBeNull()
    expect(box()!.checked).toBe(false)
    expect(anchorCommand()).toBeUndefined()
    box()!.click()
    await flushPromises()
    expect(w.emitted('update:anchor')).toEqual([[true]])
    // The box and the command follow the token the parent hands over.
    expect(anchorCommand()).toBeUndefined()
    // ⚠️ Cast, as KeepBusyMenu.spec.ts's `setDefaultPattern` does: the hosted
    // image type-checks `.vue` through env.d.ts's shim (oven/bun has no
    // `node`), where these REAL props fail the excess-property check, and
    // that failed every hosted build after #2174. Vitest exercises them.
    await w.setProps({ token: 'tok-456', anchor: true } as unknown as Parameters<
      typeof w.setProps
    >[0])
    await flushPromises()
    expect(box()!.checked).toBe(true)
    expect(anchorCommand()!.textContent).toContain('--token tok-456')
    w.unmount()
  })

  it('an anchoring token shows the anchor command with the same token', async () => {
    const w = await mountWith({ anchor: true })
    expect(box()!.checked).toBe(true)
    expect(anchorCommand()!.textContent).toContain('--token tok-123')
    box()!.click()
    await flushPromises()
    expect(w.emitted('update:anchor')).toEqual([[false]])
    w.unmount()
  })

  it('is not offered for a per-user install or a tunnel client', async () => {
    const w = await mountWith({ anchor: false })
    buttons('This user only')[0]!.click()
    await flushPromises()
    expect(box()).toBeNull()
    w.unmount()
    document.body.innerHTML = ''
    const t = await mountWith({ kind: 'tunnel', anchor: false })
    expect(box()).toBeNull()
    t.unmount()
  })
})
