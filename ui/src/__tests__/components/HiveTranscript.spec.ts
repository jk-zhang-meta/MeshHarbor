// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//
// FR-90 P1a — an approval in a session's transcript: a driver sees Allow and
// Deny while the device says it is open; anyone else sees that it waits;
// once it is over, how it ended. What the model asked to run is text, never
// markup — the model writes it.
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'
import { ref, shallowRef } from 'vue'
import { createVuetify } from 'vuetify'
import * as components from 'vuetify/components'
import * as directives from 'vuetify/directives'
import { createI18n } from 'vue-i18n'
import en from '@/locales/en.json'

const hoisted = vi.hoisted(() => ({
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  viewer: null as any,
}))
vi.mock('@/composables/useHiveViewer', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@/composables/useHiveViewer')>()),
  useHiveViewer: () => hoisted.viewer,
}))

import HiveTranscript from '@/components/hive/HiveTranscript.vue'

const vuetify = createVuetify({ components, directives })

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function makeViewer(events: any[], pending: string[], mayAnswer: boolean) {
  return {
    status: ref('open'),
    reason: ref(null),
    events: shallowRef(events.map((event, i) => ({ seq: i + 1, ts: i, fence: 1, event }))),
    runState: ref(pending.length ? 'awaiting_approval' : 'running'),
    mayPrompt: ref(mayAnswer),
    mayAnswer: ref(mayAnswer),
    drivingRefused: ref<string | null>(null),
    copy: ref(false),
    pendingApprovals: ref(pending),
    live: ref(true),
    hasEarlier: ref(false),
    open: vi.fn(),
    close: vi.fn(),
    prompt: vi.fn(() => Promise.resolve({ ok: true })),
    answer: vi.fn(() => Promise.resolve({ ok: true })),
    loadEarlier: vi.fn(),
    trimEarlier: vi.fn(),
  }
}

const asked = (id: string, input: unknown = { command: 'whoami' }) => ({
  kind: 'approval_requested',
  id,
  tool_name: 'Bash',
  tool_use_id: 'toolu_1',
  input,
})

async function render(extra: Record<string, unknown> = {}) {
  const i18n = createI18n({ legacy: false, locale: 'en', messages: { en } })
  const w = mount(HiveTranscript, {
    props: { sessionId: 's1', ...extra },
    global: { plugins: [vuetify, i18n] },
  })
  await flushPromises()
  return w
}

const button = (w: Awaited<ReturnType<typeof render>>, id: string) => w.find(`[data-testid="${id}"]`)

beforeEach(() => {
  // The composer's auto-grow textarea measures itself; jsdom has no observer.
  vi.stubGlobal(
    'ResizeObserver',
    class {
      observe() {}
      unobserve() {}
      disconnect() {}
    },
  )
})

afterEach(() => {
  hoisted.viewer = null
  vi.unstubAllGlobals()
})

describe('HiveTranscript — approvals (FR-90 P1a)', () => {
  it('lets a driver allow an open approval', async () => {
    hoisted.viewer = makeViewer([asked('a1')], ['a1'], true)
    const w = await render()
    const card = w.find('[data-approval="a1"]')
    expect(card.text()).toContain('Bash needs approval to run')
    // P1f — the command the driver is asked about, as a command line.
    expect(card.find('[data-testid="hive-command"]').text()).toBe('$ whoami')
    await button(w, 'hive-approve').trigger('click')
    await flushPromises()
    expect(hoisted.viewer.answer).toHaveBeenCalledWith('a1', 'allow', undefined)
  })

  it('sends a driver’s reason with a denial', async () => {
    hoisted.viewer = makeViewer([asked('a1')], ['a1'], true)
    const w = await render()
    await w.find('[data-testid="hive-deny-note"] input').setValue('  not on this box ')
    await button(w, 'hive-deny').trigger('click')
    await flushPromises()
    expect(hoisted.viewer.answer).toHaveBeenCalledWith('a1', 'deny', 'not on this box')
  })

  it('shows anyone else that it waits, with nothing to press', async () => {
    hoisted.viewer = makeViewer([asked('a1')], ['a1'], false)
    const w = await render()
    expect(button(w, 'hive-approve').exists()).toBe(false)
    expect(button(w, 'hive-deny').exists()).toBe(false)
    expect(w.find('[data-approval="a1"]').text()).toContain("Waiting for one of the session's drivers to answer.")
  })

  it('takes the device’s word over the transcript: not open means no buttons', async () => {
    hoisted.viewer = makeViewer(
      [
        asked('a1'),
        { kind: 'approval_resolved', id: 'a1', outcome: 'allowed', by: 'Dev' },
        asked('a2'),
        { kind: 'approval_resolved', id: 'a2', outcome: 'denied', by: 'Dev', message: 'not now' },
        asked('a3'),
        { kind: 'approval_resolved', id: 'a3', outcome: 'expired' },
        asked('a4'),
      ],
      [],
      true,
    )
    const w = await render()
    expect(button(w, 'hive-approve').exists()).toBe(false)
    const ends = w.findAll('[data-testid="hive-approval-end"]').map((e) => e.text())
    expect(ends).toEqual([
      '✅ Allowed by Dev',
      '⛔ Denied by Dev: not now',
      '⌛ Nobody answered in time, so it did not run.',
    ])
    // Open nowhere and ended nowhere: the session ended under it.
    expect(w.find('[data-approval="a4"]').text()).toContain('Not answered.')
  })

  it('renders what the model asked to run as text, never as markup', async () => {
    hoisted.viewer = makeViewer([asked('a1', { command: '<img src=x onerror="alert(1)">' })], ['a1'], true)
    const w = await render()
    const card = w.find('[data-approval="a1"]')
    expect(card.find('img').exists()).toBe(false)
    expect(card.text()).toContain('<img src=x onerror=')
  })
})

describe('HiveTranscript — tool calls (FR-90 P1f)', () => {
  const edit = { file_path: '/w/notes.txt', old_string: 'beta', new_string: 'BETA' }

  it('draws a call that waited for an approval by its approval card, its result after the answer', async () => {
    hoisted.viewer = makeViewer(
      [
        { kind: 'tool_use', id: 't1', name: 'Edit', input: edit },
        { kind: 'approval_requested', id: 'a1', tool_name: 'Edit', tool_use_id: 't1', input: edit },
        { kind: 'approval_resolved', id: 'a1', outcome: 'allowed', by: 'Olga' },
        { kind: 'tool_result', tool_use_id: 't1', ok: true, output: 'The file /w/notes.txt has been updated.' },
      ],
      [],
      true,
    )
    const w = await render()
    // One card for the call: the approval's, with the edit as a diff.
    expect(w.findAll('[data-testid="hive-tool"]')).toHaveLength(0)
    const rows = w.findAll('[data-approval="a1"] .hive-diff-row')
    expect(rows.map((r) => r.attributes('data-kind'))).toEqual(['del', 'add'])
    // In the order it happened: the card, the answer, then what the edit said.
    const kinds = w.findAll('.hive-event').map((e) => e.attributes('data-kind'))
    expect(kinds).toEqual(['approval_requested', 'approval_resolved', 'tool_result'])
    expect(w.find('[data-testid="hive-tool-line"]').text()).toBe('The file /w/notes.txt has been updated.')
  })

  it('draws any other call with its result under it, once', async () => {
    hoisted.viewer = makeViewer(
      [
        { kind: 'tool_use', id: 't2', name: 'Bash', input: { command: 'echo hi' } },
        { kind: 'tool_result', tool_use_id: 't2', ok: true, output: 'hi\n' },
        { kind: 'tool_result', tool_use_id: 'before-the-window', ok: true, output: 'from earlier\n' },
      ],
      [],
      true,
    )
    const w = await render()
    const card = w.find('[data-testid="hive-tool"]')
    expect(card.find('[data-testid="hive-command"]').text()).toBe('$ echo hi')
    expect(card.find('[data-testid="hive-ansi"]').text()).toBe('hi')
    // Only the result whose call is not loaded stands alone.
    const alone = w.findAll('.hive-event[data-kind="tool_result"]')
    expect(alone).toHaveLength(1)
    expect(alone[0].text()).toContain('from earlier')
  })
})

describe('HiveTranscript — checkpoints (FR-90 P2b)', () => {
  const file = (path: string, changed: boolean) => ({
    path,
    growth: 'whole',
    mode: 0o600,
    len: 3,
    hash: 'a'.repeat(64),
    ...(changed ? { chunks: [{ offset: 0, len: 3, hash: 'a'.repeat(64) }] } : {}),
  })

  it('says what a checkpoint kept, never as an event this version cannot show', async () => {
    hoisted.viewer = makeViewer(
      [
        {
          kind: 'checkpoint',
          n: 2,
          turn: 4,
          files: [file('CLAUDE.md', false), file('projects/hive-x/x.jsonl', true), file('projects/hive-x/memory/MEMORY.md', false)],
          workspace: { repo: 'own', tree: 'b'.repeat(40), commit: 'c'.repeat(40), pack: [{ offset: 0, len: 9, hash: 'd'.repeat(64) }] },
        },
        {
          kind: 'checkpoint',
          n: 3,
          turn: 5,
          files: [file('CLAUDE.md', false)],
          workspace: { repo: 'own', tree: 'b'.repeat(40), commit: 'c'.repeat(40) },
        },
        {
          kind: 'checkpoint',
          n: 4,
          turn: 6,
          files: [],
          skipped: [{ path: 'the workspace', why: 'git was not found' }],
        },
      ],
      [],
      true,
    )
    const w = await render()
    const lines = w.findAll('.hive-checkpoint').map((l) => l.text())
    expect(lines).toEqual([
      "💾 Checkpoint 2: 1 of 3 of the agent's files changed; the folder committed",
      "💾 Checkpoint 3: 0 of 1 of the agent's files changed; the folder unchanged",
      "💾 Checkpoint 4: 0 of 0 of the agent's files changed; the folder not kept (git was not found)",
    ])
    expect(w.text()).not.toContain('cannot show')
  })
})

describe('HiveTranscript — a long session (FR-90 P1f-2)', () => {
  const note = (n: number) => ({ kind: 'note', text: `n${n}` })

  it('keeps a bounded page while it follows the newest, never while someone reads further up', async () => {
    hoisted.viewer = makeViewer([note(1), note(2)], [], true)
    const i18n = createI18n({ legacy: false, locale: 'en', messages: { en } })
    const w = mount(HiveTranscript, { props: { sessionId: 's1', keep: 5 }, global: { plugins: [vuetify, i18n] } })
    await flushPromises()
    const live = (n: number) => {
      hoisted.viewer.events.value = Array.from({ length: n }, (_, i) => ({ seq: i + 1, ts: i, fence: 1, event: note(i + 1) }))
    }
    live(3)
    await flushPromises()
    expect(hoisted.viewer.trimEarlier).toHaveBeenLastCalledWith(5)

    // Scrolled up, reading: the page is left alone.
    hoisted.viewer.trimEarlier.mockClear()
    const list = w.find('.overflow-y-auto').element as HTMLElement
    Object.defineProperty(list, 'scrollHeight', { configurable: true, value: 2000 })
    Object.defineProperty(list, 'clientHeight', { configurable: true, value: 400 })
    list.scrollTop = 0
    await w.find('.overflow-y-auto').trigger('scroll')
    live(4)
    await flushPromises()
    expect(hoisted.viewer.trimEarlier).not.toHaveBeenCalled()
  })
})

describe('HiveTranscript — who drives (FR-90 P1c)', () => {
  it('tells a reader they read and talk, and gives them no composer', async () => {
    hoisted.viewer = makeViewer([], [], false)
    const w = await render()
    expect(w.find('[data-testid="hive-ask"]').exists()).toBe(false)
    expect(w.find('[data-testid="hive-read-only"]').text()).toContain('Only its drivers can prompt the agent.')
  })

  it('says an adopted session (P1j) runs in a terminal and is read-only, with no composer', async () => {
    hoisted.viewer = makeViewer([], [], false)
    const w = await render({ adopted: true })
    expect(w.find('[data-testid="hive-ask"]').exists()).toBe(false)
    expect(w.find('[data-testid="hive-read-only"]').text()).toBe(
      'This session runs in a terminal on its device, so it is read-only here: nobody prompts it from MeshHarbor.',
    )
  })

  it('names the terminal as who typed an adopted session’s prompt; elsewhere an unknown author is someone', async () => {
    const prompt = { kind: 'user_message', text: 'tidy the build' }
    hoisted.viewer = makeViewer([prompt], [], false)
    const adopted = await render({ adopted: true })
    expect(adopted.find('.hive-event[data-kind="user_message"] .text-caption').text()).toBe('In the terminal')
    hoisted.viewer = makeViewer([prompt], [], false)
    const started = await render()
    expect(started.find('.hive-event[data-kind="user_message"] .text-caption').text()).toBe('Someone')
  })

  it("says in the device's words why a driver the server named cannot act there", async () => {
    hoisted.viewer = makeViewer([], [], false)
    hoisted.viewer.drivingRefused.value = "this device's hive_accounts maps you to no account"
    const w = await render()
    expect(w.find('[data-testid="hive-ask"]').exists()).toBe(false)
    expect(w.find('[data-testid="hive-read-only"]').text()).toBe(
      "You drive this session, but its device does not let you act there: this device's hive_accounts maps you to no account",
    )
  })

  it('says on its chip that it reads a copy (P2k-6), never that it is live from the device', async () => {
    hoisted.viewer = makeViewer([], [], false)
    const live = await render()
    expect(live.find('[data-testid="hive-viewer-status"]').text()).toBe('Live from the device')
    hoisted.viewer = makeViewer([], [], false)
    hoisted.viewer.copy.value = true
    const copy = await render()
    expect(copy.find('[data-testid="hive-viewer-status"]').text()).toBe('Reading a copy')
    hoisted.viewer = makeViewer([], [], false)
    hoisted.viewer.copy.value = true
    hoisted.viewer.status.value = 'connecting'
    const dialing = await render()
    expect(
      dialing.find('[data-testid="hive-viewer-status"]').text(),
      'a copy not yet open is still being connected to',
    ).toBe('Connecting…')
  })

  it('says a copy (P2d-5) is read-only because the device that runs the session cannot serve it, with no composer', async () => {
    hoisted.viewer = makeViewer([], [], false)
    hoisted.viewer.copy.value = true
    const w = await render()
    expect(w.find('[data-testid="hive-ask"]').exists()).toBe(false)
    expect(w.find('[data-testid="hive-read-only"]').text()).toBe(
      'You are reading a copy another device holds, because the device that runs this session cannot serve it now. It is read-only: only that device takes prompts.',
    )
  })
})
