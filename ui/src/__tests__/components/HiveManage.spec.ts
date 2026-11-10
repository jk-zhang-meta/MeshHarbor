// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//
// FR-90 P2j-5 — an ended terminal session made a managed one, from its room.
// Offered to its owner, where sessions are copied, on an adopted session its
// terminal ended, and on nothing else; its folder sent only when it is not
// its terminal's; the answer in the server's words; a refused asking's word
// said; the asking in flight shown, to anyone in the room.
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'
import { createVuetify } from 'vuetify'
import * as components from 'vuetify/components'
import * as directives from 'vuetify/directives'
import { createI18n } from 'vue-i18n'
import en from '@/locales/en.json'
import type { HiveSession } from '@/stores/hive'

const hoisted = vi.hoisted(() => ({
  manage: vi.fn(),
  checkServed: vi.fn(),
  sessions: [] as unknown[],
  copied: {} as Record<string, boolean>,
  user: { id: 'u1' } as { id: string } | null,
  /** The org's devices, as the shell has loaded them (FR-116 AC4). */
  agents: [] as { id: string; name: string; display_name?: string }[],
}))
vi.mock('@/stores/agents', () => ({
  useAgentStore: () => ({
    get agents() {
      return hoisted.agents
    },
    fetchAgents: vi.fn(),
  }),
}))
vi.mock('@/stores/tunnelClients', () => ({
  useTunnelClientStore: () => ({ clients: [], fetchTunnelClients: vi.fn() }),
}))
vi.mock('@/stores/hive', async (importOriginal) => {
  const real = await importOriginal<typeof import('@/stores/hive')>()
  return {
    isBecomingManaged: real.isBecomingManaged,
    mayBecomeManaged: real.mayBecomeManaged,
    useHiveStore: () => ({
      get sessions() {
        return hoisted.sessions
      },
      get copied() {
        return hoisted.copied
      },
      manage: hoisted.manage,
      checkServed: hoisted.checkServed,
    }),
  }
})
vi.mock('@/stores/auth', () => ({
  useAuthStore: () => ({
    get user() {
      return hoisted.user
    },
  }),
}))

import HiveManage from '@/components/hive/HiveManage.vue'

const vuetify = createVuetify({ components, directives })
/** The dialog inline: its activator, then its content while it is open. */
const DialogStub = {
  props: ['modelValue'],
  emits: ['update:modelValue'],
  template:
    '<div><slot name="activator" :props="{ onClick: () => $emit(\'update:modelValue\', true) }" /><div v-if="modelValue"><slot /></div></div>',
}

/** An adopted session its terminal ended. */
const session = (over: Partial<HiveSession> = {}): HiveSession => ({
  id: 's1',
  owner_id: 'u1',
  title: 'Fix the kubelet',
  harness: 'claude-code',
  harness_session: 'h',
  device_id: 'd1',
  device_name: 'laptop',
  folder: '/work/app',
  status: 'ended',
  end_reason: 'exited',
  origin: 'adopted',
  fence: 1,
  created_at: '',
  updated_at: '',
  ...over,
})

function render() {
  const i18n = createI18n({ legacy: false, locale: 'en', messages: { en } })
  return mount(HiveManage, {
    props: { tenantId: 't1', sessionId: 's1' },
    global: { plugins: [vuetify, i18n], stubs: { VDialog: DialogStub } },
  })
}

type W = ReturnType<typeof render>
const by = (w: W, id: string) => w.find(`[data-testid="hive-manage-${id}"]`)
/** An element's text, or '' where it is not shown. */
const textOf = (w: W, id: string) => (by(w, id).exists() ? by(w, id).text() : '')
async function open(w: W) {
  await by(w, 'open').trigger('click')
  await flushPromises()
}

beforeEach(() => {
  vi.stubGlobal(
    'ResizeObserver',
    class {
      observe() {}
      unobserve() {}
      disconnect() {}
    },
  )
  hoisted.sessions = [session()]
  hoisted.copied = { t1: true }
  hoisted.user = { id: 'u1' }
  hoisted.agents = []
  hoisted.checkServed.mockResolvedValue(true)
})

afterEach(() => {
  vi.clearAllMocks()
  vi.unstubAllGlobals()
})

describe('HiveManage (FR-90 P2j-5)', () => {
  it('is offered to its owner, where sessions are copied, on an adopted session its terminal ended', async () => {
    const w = render()
    await flushPromises()
    expect(hoisted.checkServed, 'whether sessions are copied there').toHaveBeenCalledWith('t1')
    expect(by(w, 'open').exists(), 'offered').toBe(true)
    w.unmount()

    const not = async (why: string, set: () => void) => {
      hoisted.sessions = [session()]
      hoisted.copied = { t1: true }
      hoisted.user = { id: 'u1' }
      set()
      const n = render()
      await flushPromises()
      expect(by(n, 'open').exists(), why).toBe(false)
      n.unmount()
    }
    await not('nowhere sessions are not copied', () => (hoisted.copied = {}))
    await not('to anyone but its owner', () => (hoisted.user = { id: 'u2' }))
    await not('signed out', () => (hoisted.user = null))
    await not('a started session', () => (hoisted.sessions = [session({ origin: 'started' })]))
    await not('one whose terminal still runs', () => (hoisted.sessions = [session({ status: 'running' })]))
    await not('one stopped from MeshHarbor', () => (hoisted.sessions = [session({ end_reason: 'stopped' })]))
    await not('one ended any other way', () => (hoisted.sessions = [session({ end_reason: 'lost' })]))
  })

  it("asks for it on its device, its folder sent only when it is not its terminal's", async () => {
    const w = render()
    await flushPromises()
    await open(w)
    expect(textOf(w, 'explain'), 'on the device that adopted it').toContain('managed session on laptop')
    expect((by(w, 'folder').find('input').element as HTMLInputElement).value, "its terminal's folder").toBe(
      '/work/app',
    )
    hoisted.manage.mockResolvedValue({
      outcome: 'accepted',
      session: session({ origin: undefined, status: 'running', accepted_at: 'now' }),
    })
    await by(w, 'submit').trigger('click')
    await flushPromises()
    expect(hoisted.manage.mock.calls[0], "no folder sent for its terminal's").toEqual(['t1', 's1', undefined])
    expect(textOf(w, 'outcome'), 'said').toContain('It is a managed session now, on laptop.')
    expect(by(w, 'submit').attributes('disabled'), 'asked once').toBeDefined()
    w.unmount()

    const other = render()
    await flushPromises()
    await open(other)
    await by(other, 'folder').find('input').setValue('  /work/app-2 ')
    hoisted.manage.mockResolvedValue({ outcome: 'pending' })
    await by(other, 'submit').trigger('click')
    await flushPromises()
    expect(hoisted.manage.mock.calls[1], 'another folder, sent').toEqual(['t1', 's1', '/work/app-2'])
    expect(textOf(other, 'outcome'), 'not answered yet').toContain('Its device has not answered yet')
  })

  it("says a refusal in the server's words, and may be asked again", async () => {
    hoisted.manage.mockResolvedValue({
      outcome: 'refused',
      reason: 'device_unsupported',
      message: "the device's agent does not make terminal sessions managed — update it",
      session: session(),
    })
    const w = render()
    await flushPromises()
    await open(w)
    await by(w, 'submit').trigger('click')
    await flushPromises()
    expect(textOf(w, 'outcome'), "the server's words").toContain('does not make terminal sessions managed — update it')
    expect(by(w, 'submit').attributes('disabled'), 'may be asked again').toBeUndefined()

    hoisted.manage.mockResolvedValue({ outcome: 'refused', reason: 'rate_limited' })
    await by(w, 'submit').trigger('click')
    await flushPromises()
    expect(textOf(w, 'outcome'), 'its word, with no message').toContain('Not made managed: rate_limited')
  })

  it("says the word its device refused the last asking with", async () => {
    hoisted.sessions = [session({ from_terminal: { at: '2026-10-16T10:00:00Z', refused: 'folder_taken' } })]
    const w = render()
    await flushPromises()
    await open(w)
    expect(textOf(w, 'last-refused'), 'the refused asking').toContain('Its device refused the last asking: folder_taken')
  })

  it('shows the asking in flight to anyone in the room, and offers nothing meanwhile', async () => {
    hoisted.user = { id: 'u2' }
    hoisted.sessions = [
      session({ origin: undefined, status: 'starting', end_reason: undefined, from_terminal: { at: 'now' } }),
    ]
    const w = render()
    await flushPromises()
    expect(textOf(w, 'in-progress'), 'in flight').toContain('Being made a managed session')
    expect(by(w, 'open').exists(), 'nothing to ask').toBe(false)

    // Its device took it: accepted, still starting.
    hoisted.sessions = [
      session({ origin: undefined, status: 'starting', accepted_at: 'now', end_reason: undefined, from_terminal: { at: 'now' } }),
    ]
    const accepted = render()
    await flushPromises()
    expect(by(accepted, 'in-progress').exists(), 'accepted: no longer in flight').toBe(false)
  })
})

describe('HiveManage — the device by its display name (FR-116 AC4)', () => {
  it('names the device as the Devices page does, and keeps the session’s name only for a device not listed', async () => {
    hoisted.agents = [{ id: 'd1', name: 'laptop', display_name: 'Reception PC' }]
    const w = render()
    await flushPromises()
    await open(w)
    expect(textOf(w, 'explain'), 'the listed device, by its display name').toContain('managed session on Reception PC')
    hoisted.manage.mockResolvedValue({
      outcome: 'accepted',
      session: session({ origin: undefined, status: 'running', accepted_at: 'now' }),
    })
    await by(w, 'submit').trigger('click')
    await flushPromises()
    expect(textOf(w, 'outcome'), 'said with the display name').toContain('It is a managed session now, on Reception PC.')
    w.unmount()

    // A device this org no longer lists: the machine name the session kept.
    hoisted.agents = [{ id: 'other', name: 'elsewhere', display_name: 'Elsewhere' }]
    const gone = render()
    await flushPromises()
    await open(gone)
    expect(textOf(gone, 'explain'), 'the kept name').toContain('managed session on laptop')
  })
})
