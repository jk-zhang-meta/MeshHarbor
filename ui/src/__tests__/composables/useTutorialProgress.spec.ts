// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
import { describe, it, expect, beforeEach, vi } from 'vitest'
import { api } from '@/api/client'
import {
  hasSeenTour,
  markTourSeen,
  readTourProgress,
  writeTourProgress,
  seedTutorialFromServer,
  pushTutorialState,
  shouldAutoOpenTour,
  tourProgressKey,
  tourSeenKey,
  useTutorialProgress,
} from '@/composables/useTutorialProgress'
import {
  TUTORIAL_CHAPTERS,
  chapterById,
  richSegments,
} from '@/views/tutorial/tutorialChapters'

vi.mock('@/api/client', () => ({ api: { put: vi.fn(() => Promise.resolve({})) } }))

const USER = 'u-123'

beforeEach(() => {
  localStorage.clear()
  vi.restoreAllMocks()
})

describe('tutorial seen flag', () => {
  it('is per user and sticks once marked', () => {
    expect(hasSeenTour(USER)).toBe(false)
    markTourSeen(USER)
    expect(hasSeenTour(USER)).toBe(true)
    // A different account on the same machine starts fresh.
    expect(hasSeenTour('someone-else')).toBe(false)
    expect(localStorage.getItem(tourSeenKey(USER))).toBeTruthy()
  })

  it('reads as SEEN when storage throws — never ambush a user we cannot remember', () => {
    vi.spyOn(Storage.prototype, 'getItem').mockImplementation(() => {
      throw new Error('policy: storage disabled')
    })
    expect(hasSeenTour(USER)).toBe(true)
  })

  it('marking is non-fatal when storage throws', () => {
    vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => {
      throw new Error('quota')
    })
    expect(() => markTourSeen(USER)).not.toThrow()
  })
})

describe('shouldAutoOpenTour', () => {
  it('fires exactly once for a never-seen user in an empty org', () => {
    expect(shouldAutoOpenTour({ userId: USER, devices: 0, rooms: 0 })).toBe(true)
    expect(shouldAutoOpenTour({ userId: USER, devices: 0, rooms: 1 })).toBe(true)
    markTourSeen(USER)
    expect(shouldAutoOpenTour({ userId: USER, devices: 0, rooms: 0 })).toBe(false)
  })

  it('never fires for an org that has been set up', () => {
    expect(shouldAutoOpenTour({ userId: USER, devices: 3, rooms: 0 })).toBe(false)
    expect(shouldAutoOpenTour({ userId: USER, devices: 0, rooms: 2 })).toBe(false)
  })

  it('does not navigate on missing evidence (counts not loaded, or no user)', () => {
    expect(shouldAutoOpenTour({ userId: USER, devices: null, rooms: 0 })).toBe(false)
    expect(shouldAutoOpenTour({ userId: USER, devices: 0, rooms: null })).toBe(false)
    expect(shouldAutoOpenTour({ userId: undefined, devices: 0, rooms: 0 })).toBe(false)
  })
})

describe('chapter progress', () => {
  it('toggles, dedupes and persists per user', () => {
    const p = useTutorialProgress(() => USER)
    expect(p.doneCount.value).toBe(0)

    p.toggle('devices')
    p.toggle('devices') // idempotent add path must not duplicate
    p.toggle('devices', true)
    expect(p.done.value).toEqual(['devices'])
    expect(readTourProgress(USER)).toEqual(['devices'])

    p.toggle('rooms')
    expect(p.doneCount.value).toBe(2)

    p.toggle('devices', false)
    expect(p.done.value).toEqual(['rooms'])

    p.reset()
    expect(p.doneCount.value).toBe(0)
    expect(readTourProgress(USER)).toEqual([])
  })

  it('survives corrupt storage', () => {
    localStorage.setItem(tourProgressKey(USER), '{not json')
    expect(readTourProgress(USER)).toEqual([])
    localStorage.setItem(tourProgressKey(USER), '{"nope":1}')
    expect(readTourProgress(USER)).toEqual([])
    // Non-string entries are dropped rather than rendered as [object Object].
    writeTourProgress(USER, ['devices'])
    localStorage.setItem(tourProgressKey(USER), JSON.stringify(['devices', 7, null]))
    expect(readTourProgress(USER)).toEqual(['devices'])
  })
})

describe('tutorial chapters (FR-12 content contract)', () => {
  const ROUTE_NAMES = new Set([
    'tenant-dashboard',
    'devices',
    'rooms',
    'explore',
    'files',
    'invites',
    'analytics',
    'network-acl',
    'network-dns',
    'network-subnet-routes',
    'admin-settings',
    'admin-members',
    'admin-roles',
    'audit-exec',
    'audit-ssh',
    'audit-ssh-activity',
    'tutorial',
  ])

  it('covers every capability the operator asked for', () => {
    const ids = TUTORIAL_CHAPTERS.map((c) => c.id)
    expect(ids).toEqual([
      'get-started',
      'devices',
      'remote-desktop',
      'network',
      'tunnels',
      'acl',
      'rooms',
      'calls',
    ])
    expect(new Set(ids).size).toBe(ids.length)
  })

  it('every chapter is renderable: title, lead, at least one step and a detail table', () => {
    for (const c of TUTORIAL_CHAPTERS) {
      expect(c.title.length).toBeGreaterThan(0)
      expect(c.lead.length).toBeGreaterThan(40)
      expect(c.steps.length).toBeGreaterThan(0)
      expect(c.detail.length).toBeGreaterThan(0)
      expect(c.icon.startsWith('mdi-')).toBe(true)
    }
  })

  it('every deep link names a route that actually exists', () => {
    // The bug this catches: a chapter promising a walk-through step that
    // dead-ends because the route was renamed underneath it.
    for (const c of TUTORIAL_CHAPTERS) {
      for (const s of c.steps) {
        if (!s.to) continue
        expect(ROUTE_NAMES.has(s.to.name), `${c.id}: unknown route "${s.to.name}"`).toBe(true)
      }
    }
  })

  it('every step offers something actionable — a link, a command, or plain instruction text', () => {
    for (const c of TUTORIAL_CHAPTERS) {
      for (const s of c.steps) {
        expect(s.text.length, `${c.id}: empty step text`).toBeGreaterThan(10)
      }
    }
  })

  it('chapterById resolves the URL hash and shrugs off an unknown one', () => {
    expect(chapterById('devices')?.title).toBe('Devices')
    expect(chapterById('nope')).toBeUndefined()
  })

  it('opens with the landing page’s own promise — headline, sub and three badges', () => {
    // The visual pass (#799): someone arriving from meshharbor.itachi.fans must meet
    // the same three promises, in the same words, once they are inside.
    const start = chapterById('get-started')!
    expect(start.tagline?.headline).toBe('Every device you own,')
    expect(start.tagline?.accent).toBe('one secure network')
    expect(start.tagline?.sub).toContain('WireGuard-style mesh')
    expect(start.badges).toHaveLength(3)
    const titles = start.badges!.map((b) => b.title)
    expect(titles[0]).toMatch(/remote desktop/i)
    expect(titles[1]).toMatch(/mesh network/i)
    expect(titles[2]).toMatch(/video conferencing/i)
    // The landing capability strip carries over verbatim.
    expect(start.chips).toContain('Remote desktop')
    expect(start.chips).toContain('Chat & video included')
  })

  it('every badge and highlight is fully populated (icon, colour, title, text)', () => {
    for (const c of TUTORIAL_CHAPTERS) {
      for (const b of [...(c.badges ?? []), ...(c.highlights ?? [])]) {
        expect(b.icon.startsWith('mdi-'), `${c.id}: bad icon ${b.icon}`).toBe(true)
        expect(b.color).toMatch(/^#[0-9a-f]{6}$/i)
        expect(b.title.length).toBeGreaterThan(3)
        expect(b.text.length).toBeGreaterThan(20)
      }
    }
  })

  it('every chapter carries artwork, and step graphics come with alt text', () => {
    for (const c of TUTORIAL_CHAPTERS) {
      expect(c.hero, `${c.id}: no hero`).toBeTruthy()
      expect(c.heroAlt!.length, `${c.id}: hero needs alt text`).toBeGreaterThan(10)
      for (const s of c.steps) {
        if (!s.graphic) continue
        expect(s.graphicAlt!.length, `${c.id}: step graphic needs alt text`).toBeGreaterThan(10)
      }
    }
    // The visual pass promised diagrams beyond the four heroes.
    const withGraphics = TUTORIAL_CHAPTERS.filter((c) => c.steps.some((s) => s.graphic))
    expect(withGraphics.length).toBeGreaterThanOrEqual(6)
  })

  // P3 exists because eight chapters shared four images: the ACL chapter showed
  // the same picture as the network one, calls the same as rooms. A reader who
  // sees a familiar illustration reasonably concludes they are back where they
  // started. Sharing regresses SILENTLY -- the page still renders -- so the only
  // thing that keeps it fixed is an assertion that no two chapters point at one
  // asset.
  it('no two chapters share a hero image', () => {
    const heroes = TUTORIAL_CHAPTERS.map((c) => c.hero)
    expect(new Set(heroes).size, `heroes reused: ${heroes.join(', ')}`).toBe(
      TUTORIAL_CHAPTERS.length,
    )
  })

  // Read the assets themselves rather than the imported URLs: what matters is
  // what ships. An animated illustration that ignores prefers-reduced-motion is
  // an accessibility defect nobody on this team would notice, because the
  // motion is pleasant on the machines we develop on.
  it('every tutorial illustration is titled, and animated ones are describable and stoppable', () => {
    const svgs = import.meta.glob('../../assets/tutorial/*.svg', {
      eager: true,
      query: '?raw',
      import: 'default',
    }) as Record<string, string>

    const names = Object.keys(svgs)
    expect(names.length, 'no tutorial SVGs found -- the glob path is wrong').toBeGreaterThan(10)

    for (const [path, src] of Object.entries(svgs)) {
      expect(src, `${path}: no <title> for screen readers`).toContain('<title')
      if (!src.includes('animation:')) continue
      expect(src, `${path}: animated but has no <desc>`).toContain('<desc')
      expect(src, `${path}: animated with no prefers-reduced-motion guard`).toContain(
        'prefers-reduced-motion',
      )
    }
  })
})

describe('richSegments (bold without v-html)', () => {
  it('splits **bold** runs out of prose, preserving order and spacing', () => {
    expect(richSegments('one **two** three')).toEqual([
      { text: 'one ', bold: false },
      { text: 'two', bold: true },
      { text: ' three', bold: false },
    ])
  })

  it('handles plain text, leading/trailing emphasis and multiple runs', () => {
    expect(richSegments('plain')).toEqual([{ text: 'plain', bold: false }])
    expect(richSegments('**lead** rest')).toEqual([
      { text: 'lead', bold: true },
      { text: ' rest', bold: false },
    ])
    expect(richSegments('a **b** c **d**').filter((s) => s.bold).map((s) => s.text)).toEqual([
      'b',
      'd',
    ])
  })

  it('never emits empty segments (they would render as stray nodes)', () => {
    for (const c of TUTORIAL_CHAPTERS) {
      for (const text of [c.lead, ...c.steps.map((s) => s.text)]) {
        for (const seg of richSegments(text)) {
          expect(seg.text.length, `${c.id}: empty segment in "${text}"`).toBeGreaterThan(0)
        }
        // Round-trip: rendering the segments must reproduce the prose
        // minus its markers — a dropped word would be invisible in review.
        expect(richSegments(text).map((s) => s.text).join('')).toBe(text.replace(/\*\*/g, ''))
      }
    }
  })
})

describe('server-side mirror (FR-12 P3)', () => {
  it('unions the server list into local progress instead of replacing it', () => {
    writeTourProgress(USER, ['devices', 'tunnels'])
    seedTutorialFromServer(USER, { done: ['acl', 'devices'] })
    // A tick made on THIS device while the PUT was failing must survive the
    // first sync from another device -- that is why the seed is a union.
    expect(readTourProgress(USER).sort()).toEqual(['acl', 'devices', 'tunnels'])
  })

  it('an absent or empty server state changes nothing', () => {
    writeTourProgress(USER, ['rooms'])
    seedTutorialFromServer(USER, undefined)
    seedTutorialFromServer(USER, {})
    seedTutorialFromServer(USER, { done: [] })
    expect(readTourProgress(USER)).toEqual(['rooms'])
    expect(hasSeenTour(USER)).toBe(false)
  })

  it('seen_at sets the local flag, and its absence never clears one', () => {
    seedTutorialFromServer(USER, { seen_at: '2026-09-01T10:00:00Z' })
    expect(hasSeenTour(USER)).toBe(true)
    // "no opinion" is not "never seen": a server that has not heard about
    // this user yet must not re-arm an ambush the browser already knows about.
    seedTutorialFromServer(USER, { done: ['acl'] })
    expect(hasSeenTour(USER)).toBe(true)
  })

  it('a failing push is swallowed -- the tutorial never breaks the shell', async () => {
    vi.mocked(api.put).mockRejectedValueOnce(new Error('offline'))
    expect(() => pushTutorialState({ done: ['acl'] })).not.toThrow()
    await Promise.resolve()
    expect(api.put).toHaveBeenCalledWith('/user/tutorial', { done: ['acl'] })
  })

  it('ticking a chapter writes through to the account', () => {
    vi.mocked(api.put).mockClear()
    const { toggle } = useTutorialProgress(() => USER)
    toggle('devices', true)
    expect(api.put).toHaveBeenCalledWith('/user/tutorial', { done: ['devices'] })
    toggle('devices', false)
    // Un-ticking must send the SHORTER list: if the write unioned server-side
    // there would be no way to express it at all.
    expect(api.put).toHaveBeenLastCalledWith('/user/tutorial', { done: [] })
  })
})
