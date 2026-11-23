// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//
// FR-90 P2i-3 — the search box on Agent sessions. Shown only where the
// organization's copies can be searched, asked again at every visit; a query
// is asked once typing pauses (Enter at once); a hit's marks are drawn as
// <mark> from text, so a snippet that looks like HTML stays text; a hit names
// its session by the title the list holds, else says it is one you can read;
// a click opens its room; a refusal is said in words, a word this build does
// not know as itself.
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'
import type { Ref, ShallowRef } from 'vue'
import { createVuetify } from 'vuetify'
import * as components from 'vuetify/components'
import * as directives from 'vuetify/directives'
import { createI18n } from 'vue-i18n'
import en from '@/locales/en.json'

/** The search's state, set by hand: made in the mock's factory, which runs
 *  before anything at the top level of this file does. */
interface SearchState {
  status: Ref<string>
  reason: Ref<string | null>
  detail: Ref<string | null>
  named: Ref<number | null>
  searched: Ref<number | null>
  hits: ShallowRef<Array<{ session: string; seq: number; snippet: string }>>
  answered: Ref<string | null>
  searching: Ref<boolean>
  error: Ref<string | null>
}

const hoisted = vi.hoisted(() => ({
  fetchSessions: vi.fn(),
  fetchSession: vi.fn(),
  checkSearchable: vi.fn(),
  purge: vi.fn(),
  fetchPurge: vi.fn(),
  stop: vi.fn(),
  fetchAgent: vi.fn(),
  fetchAgents: vi.fn(),
  push: vi.fn(),
  run: vi.fn(),
  close: vi.fn(),
  hive: {
    sessions: [] as Array<{
      id: string
      owner_id?: string
      title: string
      room_id?: string
      status: string
      device_id?: string
      device_name?: string
      folder?: string
    }>,
    loading: false,
    searchable: {} as Record<string, boolean>,
    copied: {} as Record<string, boolean>,
    total: 0,
  },
  /** FR-120 P2 — the sessions a test calls live (empty: none, as before). */
  liveIds: new Set<string>(),
  agents: [] as Array<{ id: string; name: string; display_name?: string }>,
  user: { id: 'u1' } as { id: string } | null,
  state: null as SearchState | null,
}))

vi.mock('@/stores/hive', () => ({
  isAdopted: () => false,
  isLive: (s: { id: string }) => hoisted.liveIds.has(s.id),
  useHiveStore: () => ({
    get sessions() {
      return hoisted.hive.sessions
    },
    get total() {
      return hoisted.hive.total
    },
    get loading() {
      return hoisted.hive.loading
    },
    get searchable() {
      return hoisted.hive.searchable
    },
    get copied() {
      return hoisted.hive.copied
    },
    fetchSessions: hoisted.fetchSessions,
    fetchSession: hoisted.fetchSession,
    checkSearchable: hoisted.checkSearchable,
    purge: hoisted.purge,
    fetchPurge: hoisted.fetchPurge,
    stop: hoisted.stop,
  }),
}))
vi.mock('@/stores/devices', () => ({
  useDeviceStore: () => ({ items: [], loading: false, fetchDevices: vi.fn() }),
}))
vi.mock('@/stores/agents', () => ({
  useAgentStore: () => ({
    get agents() {
      return hoisted.agents
    },
    fetchAgent: hoisted.fetchAgent,
    fetchAgents: hoisted.fetchAgents,
  }),
}))
// `useNodeLabel` (FR-116 AC4) reads tunnel clients too; the real store would
// pull in the router plugin, which this file's vue-router mock does not carry.
vi.mock('@/stores/tunnelClients', () => ({
  useTunnelClientStore: () => ({ clients: [], fetchTunnelClients: vi.fn() }),
}))
vi.mock('vue-router', () => ({
  useRoute: () => ({ params: { tenantId: 't1' } }),
  useRouter: () => ({ push: hoisted.push }),
}))
vi.mock('@/stores/ws', () => ({ useWsStore: () => ({}) }))
vi.mock('@/stores/auth', () => ({
  useAuthStore: () => ({
    get user() {
      return hoisted.user
    },
  }),
}))

// The search itself is `useHiveSearch`'s (its own spec); here its state is
// set by hand. `snippetParts` and the limit stay the real ones.
vi.mock('@/composables/useHiveSearch', async (importOriginal) => {
  const real = await importOriginal<typeof import('@/composables/useHiveSearch')>()
  const { ref, shallowRef } = await import('vue')
  hoisted.state = {
    status: ref('idle'),
    reason: ref(null),
    detail: ref(null),
    named: ref(null),
    searched: ref(null),
    hits: shallowRef([]),
    answered: ref(null),
    searching: ref(false),
    error: ref(null),
  }
  return {
    ...real,
    useHiveSearch: () => ({ ...hoisted.state!, run: hoisted.run, close: hoisted.close }),
  }
})

import HiveSessionsView from '@/views/hive/HiveSessionsView.vue'

const state = (): SearchState => hoisted.state!

const vuetify = createVuetify({ components, directives })

/** A dialog inline, its content there while it is open: jsdom has no
 *  `visualViewport` for Vuetify's overlay. */
const DialogStub = { props: ['modelValue'], template: '<div v-if="modelValue"><slot /></div>' }

async function render() {
  const i18n = createI18n({ legacy: false, locale: 'en', messages: { en } })
  const w = mount(HiveSessionsView, { global: { plugins: [vuetify, i18n], stubs: { VDialog: DialogStub } } })
  await flushPromises()
  return w
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
  // FR-120 P2 — a row's menu measures itself against the viewport; jsdom has none.
  vi.stubGlobal('visualViewport', {
    width: 360,
    height: 780,
    offsetLeft: 0,
    offsetTop: 0,
    pageLeft: 0,
    pageTop: 0,
    scale: 1,
    addEventListener() {},
    removeEventListener() {},
  })
  hoisted.hive.sessions = [{ id: 's-mine', owner_id: 'u1', title: 'Fix the kubelet', room_id: 'r-mine', status: 'ended' }]
  hoisted.agents = []
  hoisted.user = { id: 'u1' }
  hoisted.hive.searchable = { t1: true }
  hoisted.hive.copied = {}
  hoisted.hive.total = 0
  hoisted.liveIds.clear()
  hoisted.checkSearchable.mockResolvedValue(true)
  state().status.value = 'idle'
  state().reason.value = null
  state().detail.value = null
  state().searched.value = null
  state().hits.value = []
  state().answered.value = null
  state().searching.value = false
  state().error.value = null
})

afterEach(() => {
  vi.clearAllMocks()
  vi.unstubAllGlobals()
  vi.useRealTimers()
})

async function type(w: Awaited<ReturnType<typeof render>>, text: string): Promise<void> {
  await w.find('[data-testid="hive-search"] input').setValue(text)
}

describe('HiveSessionsView — the search box (FR-90 P2i-3)', () => {
  it('asks at every visit whether the copies can be searched, and shows the box only then', async () => {
    hoisted.hive.searchable = {}
    let w = await render()
    expect(hoisted.checkSearchable, 'asked at every visit').toHaveBeenCalledWith('t1')
    expect(w.find('[data-testid="hive-search"]').exists(), 'no box while it cannot be searched').toBe(false)
    w.unmount()

    hoisted.hive.searchable = { t1: false }
    w = await render()
    expect(w.find('[data-testid="hive-search"]').exists()).toBe(false)
    w.unmount()

    hoisted.hive.searchable = { t1: true }
    w = await render()
    expect(w.find('[data-testid="hive-search"]').exists()).toBe(true)
    // The list is still there until something is typed.
    expect(w.find('[data-testid="hive-session-s-mine"]').exists()).toBe(true)
    w.unmount()
  })

  it('asks once typing pauses, Enter at once, and clearing asks for nothing', async () => {
    vi.useFakeTimers()
    const w = await render()
    await type(w, 'kub')
    await type(w, 'kubelet')
    expect(hoisted.run, 'nothing asked while typing').not.toHaveBeenCalled()
    await vi.advanceTimersByTimeAsync(300)
    expect(hoisted.run).toHaveBeenCalledTimes(1)
    expect(hoisted.run).toHaveBeenLastCalledWith('t1', 'kubelet')
    // The results take the list's place while a query stands.
    expect(w.find('[data-testid="hive-search-results"]').exists()).toBe(true)
    expect(w.find('[data-testid="hive-session-s-mine"]').exists()).toBe(false)

    await type(w, 'etcd')
    await w.find('[data-testid="hive-search"] input').trigger('keydown', { key: 'Enter' })
    expect(hoisted.run).toHaveBeenLastCalledWith('t1', 'etcd')
    const asked = hoisted.run.mock.calls.length
    await vi.advanceTimersByTimeAsync(300)
    expect(hoisted.run.mock.calls.length, 'the pause asks nothing more').toBe(asked)

    await type(w, '')
    expect(hoisted.run).toHaveBeenLastCalledWith('t1', '')
    expect(w.find('[data-testid="hive-search-results"]').exists()).toBe(false)
    expect(w.find('[data-testid="hive-session-s-mine"]').exists()).toBe(true)
    w.unmount()
  })

  it("draws the device's marks as <mark> from text: a snippet that looks like HTML stays text", async () => {
    const w = await render()
    await type(w, 'kubelet')
    state().hits.value = [
      { session: 's-mine', seq: 4, snippet: '…the [kubelet] said <img src=x onerror="alert(1)"> [twice]' },
      { session: 's-theirs', seq: 9, snippet: '[kubelet] ok' },
    ]
    state().answered.value = 'kubelet'
    state().searched.value = 12
    await flushPromises()

    const first = w.find('[data-testid="hive-hit-0"]')
    expect(first.find('img').exists(), 'never parsed as HTML').toBe(false)
    expect(first.text()).toContain('<img src=x onerror="alert(1)">')
    expect(first.findAll('mark').map((m) => m.text())).toEqual(['kubelet', 'twice'])
    // A session of yours by its title; one read through a room as such.
    expect(first.text(), 'your session by its title').toContain('Fix the kubelet')
    expect(w.find('[data-testid="hive-hit-1"]').text()).toContain('A session you can read')
    expect(w.find('[data-testid="hive-search-scope"]').text()).toContain('Sessions searched: 12')
    expect(w.find('[data-testid="hive-search-none"]').exists()).toBe(false)
    w.unmount()
  })

  it('says nothing was found only for the query asked', async () => {
    const w = await render()
    await type(w, 'nothing')
    state().answered.value = 'noth'
    await flushPromises()
    expect(w.find('[data-testid="hive-search-none"]').exists(), 'not for another query').toBe(false)
    state().answered.value = 'nothing'
    await flushPromises()
    expect(w.find('[data-testid="hive-search-none"]').text()).toContain('Nothing found')
    w.unmount()
  })

  it("opens a hit's room: a session of yours from the list, another read first", async () => {
    const w = await render()
    await type(w, 'kubelet')
    state().hits.value = [
      { session: 's-mine', seq: 4, snippet: '[kubelet]' },
      { session: 's-theirs', seq: 9, snippet: '[kubelet]' },
    ]
    await flushPromises()

    await w.find('[data-testid="hive-hit-0"]').trigger('click')
    await flushPromises()
    expect(hoisted.fetchSession).not.toHaveBeenCalled()
    expect(hoisted.push).toHaveBeenLastCalledWith('/tenant/t1/room/r-mine')

    hoisted.fetchSession.mockResolvedValue({ id: 's-theirs', title: 'Theirs', room_id: 'r-theirs', status: 'idle' })
    await w.find('[data-testid="hive-hit-1"]').trigger('click')
    await flushPromises()
    expect(hoisted.fetchSession, "another's session is read first").toHaveBeenCalledWith('t1', 's-theirs')
    expect(hoisted.push).toHaveBeenLastCalledWith('/tenant/t1/room/r-theirs')

    // One no longer readable says so, and goes nowhere.
    hoisted.push.mockClear()
    hoisted.fetchSession.mockRejectedValue(new Error('not found'))
    await w.find('[data-testid="hive-hit-1"]').trigger('click')
    await flushPromises()
    expect(hoisted.push).not.toHaveBeenCalled()
    expect(w.find('[data-testid="hive-search-results"]').text()).toContain('Could not open that session: not found')
    w.unmount()
  })

  it('says a refusal in words, a word it does not know as itself, with its detail', async () => {
    const w = await render()
    await type(w, 'kubelet')
    state().status.value = 'refused'
    state().reason.value = 'no_archive_replica'
    await flushPromises()
    expect(w.find('[data-testid="hive-search-refused"]').text()).toContain(
      'No archive replica that searches is online right now.',
    )

    state().reason.value = 'hive_disabled'
    state().detail.value = 'this device serves a search only as an archive replica (hive_archive)'
    await flushPromises()
    expect(w.find('[data-testid="hive-search-refused"]').text()).toContain(
      'does not serve searches. (this device serves a search only as an archive replica (hive_archive))',
    )

    state().reason.value = 'a_newer_word'
    state().detail.value = null
    await flushPromises()
    expect(w.find('[data-testid="hive-search-refused"]').text(), 'a word it does not know, as itself').toContain(
      'The search was refused: a_newer_word',
    )

    // A failed search, in the device's words.
    state().status.value = 'open'
    state().error.value = 'this device could not search its copies'
    await flushPromises()
    expect(w.find('[data-testid="hive-search-refused"]').exists()).toBe(false)
    expect(w.find('[data-testid="hive-search-error"]').text()).toContain('this device could not search its copies')
    w.unmount()
  })
})

// FR-90 P2j-3 — a session deleted for good, from the list: the room goes with
// it, so the way to it is here, and only where sessions are copied at all.
describe('HiveSessionsView — delete for good (FR-90 P2j-3)', () => {
  it('offers it only where sessions are copied, and asks for that session', async () => {
    let w = await render()
    expect(w.find('[data-testid="hive-purge-open-s-mine"]').exists(), 'not where nothing is copied').toBe(false)
    w.unmount()

    hoisted.hive.copied = { t1: true }
    // Someone else's, read from its room: the list holds it too.
    hoisted.hive.sessions = [
      ...hoisted.hive.sessions,
      { id: 's-theirs', owner_id: 'u2', title: 'Theirs', room_id: 'r-theirs', status: 'idle' },
    ]
    w = await render()
    expect(w.find('[data-testid="hive-purge-open-s-theirs"]').exists(), "not on someone else's session").toBe(false)
    await w.find('[data-testid="hive-purge-open-s-mine"]').trigger('click')
    await flushPromises()
    expect(w.find('[data-testid="hive-purge-explain"]').exists(), 'the dialog, for the session asked').toBe(true)
    expect(w.find('[data-testid="hive-purge-explain"]').text()).toContain('"Fix the kubelet"')
    expect(hoisted.push, 'the row is not opened').not.toHaveBeenCalled()
    w.unmount()
  })
})

describe('HiveSessionsView — each session names its device as the Devices page does (FR-116 AC4)', () => {
  it('shows the display name of a listed device, the kept machine name of one not listed, and the id last', async () => {
    hoisted.agents = [{ id: 'd-listed', name: 'front-desk-pc', display_name: 'Reception PC' }]
    hoisted.hive.sessions = [
      { id: 's-a', owner_id: 'u1', title: 'A', status: 'ended', device_id: 'd-listed', device_name: 'front-desk-pc', folder: '/w/a' },
      { id: 's-b', owner_id: 'u1', title: 'B', status: 'ended', device_id: 'd-gone', device_name: 'old-laptop', folder: '/w/b' },
      { id: 's-c', owner_id: 'u1', title: 'C', status: 'ended', device_id: 'd-bare', folder: '/w/c' },
    ]
    const w = await render()
    const sub = (id: string) => w.find(`[data-testid="hive-session-${id}"] .v-list-item-subtitle`).text()
    expect(sub('s-a'), 'listed: its display name, never the kept machine name').toContain('Reception PC · /w/a')
    expect(sub('s-a')).not.toContain('front-desk-pc')
    expect(sub('s-b'), 'not listed: the machine name the session kept').toContain('old-laptop · /w/b')
    expect(sub('s-c'), 'no name at all: the id').toContain('d-bare · /w/c')
    w.unmount()
  })

  it('loads the devices it names rows by when nobody has yet', async () => {
    const w = await render()
    expect(hoisted.fetchAgents, 'the agents, for the labels').toHaveBeenCalledWith('t1')
    w.unmount()
  })
})

// FR-120 P2 — on a phone a row keeps its title, device and folder: the state
// and "adopted" are words in its subtitle, and its actions are one tap away in
// a menu. Chips and buttons beside it had left the text 0–40 px at 360 px.
describe('HiveSessionsView on a phone (FR-120 P2)', () => {
  /** Vuetify reads the window's width when the plugin is made. The menu's
   *  list is teleported to the body, so a test that opens it attaches. */
  let mounted: ReturnType<typeof mount> | null = null
  async function renderAt(width: number, attach = false) {
    window.innerWidth = width
    const sized = createVuetify({ components, directives })
    const i18n = createI18n({ legacy: false, locale: 'en', messages: { en } })
    const w = mount(HiveSessionsView, {
      global: { plugins: [sized, i18n], stubs: { VDialog: DialogStub } },
      ...(attach ? { attachTo: document.body } : {}),
    })
    mounted = w
    await flushPromises()
    return w
  }

  afterEach(() => {
    mounted?.unmount()
    mounted = null
    window.innerWidth = 1024
  })

  const live = { id: 's-live', owner_id: 'u1', title: 'Fix the kubelet', room_id: 'r-live', status: 'running', device_id: 'd1', device_name: 'build-01', folder: '/srv/app' }

  it('says the state in the row and moves its actions into a menu', async () => {
    hoisted.hive.sessions = [live]
    hoisted.liveIds.add('s-live')
    const w = await renderAt(360)
    expect(w.find('[data-testid="hive-row-state"]').text()).toContain('Running')
    expect(w.find('[data-testid="hive-row-menu-s-live"]').exists()).toBe(true)
    // Nothing beside the row on a phone: no chip, no Stop button until the menu opens.
    const row = w.find('[data-testid="hive-session-s-live"]')
    expect(row.findAll('.v-chip')).toHaveLength(0)
    expect(row.text()).not.toContain('Stop')
  })

  it('stops a live session from its row menu, one tap after opening it', async () => {
    hoisted.hive.sessions = [live]
    hoisted.liveIds.add('s-live')
    hoisted.stop.mockResolvedValue(undefined)
    const w = await renderAt(360, true)
    await w.find('[data-testid="hive-row-menu-s-live"]').trigger('click')
    await flushPromises()
    const items = [...document.body.querySelectorAll('.v-overlay__content .v-list-item')] as HTMLElement[]
    const stop = items.find((i) => i.textContent?.trim() === 'Stop')
    expect(stop).toBeTruthy()
    stop!.click()
    await flushPromises()
    expect(hoisted.stop).toHaveBeenCalledWith('t1', 's-live')
    // The tap was the menu's, not the row's: nothing navigated.
    expect(hoisted.push).not.toHaveBeenCalled()
  })

  it('offers no menu on a row with nothing to do', async () => {
    hoisted.hive.sessions = [{ ...live, id: 's-ended', status: 'ended' }]
    const w = await renderAt(360)
    expect(w.find('[data-testid="hive-row-menu-s-ended"]').exists()).toBe(false)
  })

  it('keeps the row as it was from 600 px', async () => {
    hoisted.hive.sessions = [live]
    hoisted.liveIds.add('s-live')
    const w = await renderAt(1024)
    const row = w.find('[data-testid="hive-session-s-live"]')
    expect(w.find('[data-testid="hive-row-state"]').exists()).toBe(false)
    expect(row.find('.v-chip').text()).toContain('Running')
    expect(row.text()).toContain('Stop')
  })
})

// FR-120 P2 — the list is paged, 50 a page; the view asked only for page 1.
describe('HiveSessionsView — the pager (FR-120 P2)', () => {
  it('shows no pager for one page', async () => {
    hoisted.hive.total = 50
    const w = await render()
    expect(w.find('[data-testid="hive-sessions-pager"]').exists()).toBe(false)
  })

  it('pages through every session, asking the server for the page chosen', async () => {
    hoisted.hive.total = 120
    const w = await render()
    const pager = w.find('[data-testid="hive-sessions-pager"]')
    expect(pager.exists()).toBe(true)
    await pager.find('button[aria-label="Go to page 2"]').trigger('click')
    await flushPromises()
    expect(hoisted.fetchSessions).toHaveBeenLastCalledWith('t1', 2, 50)
  })
})
