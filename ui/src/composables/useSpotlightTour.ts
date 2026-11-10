// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//
// FR-12 P2 — spotlight micro-tours on the LIVE pages.
//
// The Tutorial explains the product; a tour points at the actual control on
// the actual page, which is the step people miss. Dependency-free on purpose:
// a tour library is a lot of bundle for an overlay, a box and two buttons.
//
// The state is module-scoped rather than per-caller, because the mount point
// (one <SpotlightTour> in the layout) and the starter (the Tutorial, or a
// `?tour=` query) are different components.
import { computed, ref } from 'vue'

export interface TourStep {
  /** Value of the target's `data-tour` attribute. */
  anchor: string
  title: string
  body: string
}

export interface TourDef {
  id: string
  /** Named route the tour runs on — the entry point navigates there first. */
  routeName: string
  steps: TourStep[]
}

/** ⚠️ Anchors are `data-tour` attributes, never CSS shapes.
 *
 * A tour that selects `.v-btn:nth-child(2)` breaks the first time someone adds
 * a button, and breaks SILENTLY — it highlights the wrong thing rather than
 * failing. This session spent hours on exactly that class of locator in the
 * e2e suite; the fix there and here is the same: name the thing you mean.
 */
export const TOURS: Record<string, TourDef> = {
  enroll: {
    id: 'enroll',
    routeName: 'devices',
    steps: [
      {
        anchor: 'enroll-button',
        title: 'Add your first machine here',
        body: 'Enroll mints a single-use token and gives you a one-line install command. A device joins the mesh and becomes remote-controllable; a tunnel client is CLI-only.',
      },
      {
        anchor: 'device-search',
        title: 'Find a machine fast',
        body: 'Searches name, tag, IP and MagicDNS name together — useful once a fleet outgrows one screen.',
      },
      {
        anchor: 'device-grid',
        title: 'Everything about a device lives here',
        body: 'Online state, overlay address, version and last-seen. The row menu is where you connect, run a command, or change per-device policy.',
      },
    ],
  },
  viewer: {
    id: 'viewer',
    routeName: 'agent-remote',
    steps: [
      {
        anchor: 'viewer-connect',
        title: 'Start a remote session',
        body: 'Connect negotiates a direct peer-to-peer path where it can, and falls back to a relay only if it must. Pixels and keystrokes never pass through the server in the clear.',
      },
      {
        anchor: 'viewer-settings',
        title: 'Quality and metrics live here',
        body: 'Codec and resolution under Video, sharpening under Display, and Metrics chooses which quality pills the toolbar shows during a session.',
      },
    ],
  },
}

const activeId = ref<string | null>(null)
const stepIndex = ref(0)

const SEEN_KEY = 'meshharbor-tour-seen'

function readSeen(): string[] {
  try {
    const raw = JSON.parse(localStorage.getItem(SEEN_KEY) || '[]')
    return Array.isArray(raw) ? raw.filter((x) => typeof x === 'string') : []
  } catch {
    // Corrupt or unavailable storage must not stop a tour from running — the
    // worst case is offering it twice.
    return []
  }
}

function markSeen(id: string) {
  try {
    const seen = readSeen()
    if (!seen.includes(id)) localStorage.setItem(SEEN_KEY, JSON.stringify([...seen, id]))
  } catch { /* not worth failing a tour over */ }
}

export function useSpotlightTour() {
  const tour = computed(() => (activeId.value ? TOURS[activeId.value] ?? null : null))
  const step = computed(() => tour.value?.steps[stepIndex.value] ?? null)
  const total = computed(() => tour.value?.steps.length ?? 0)
  const isLast = computed(() => total.value > 0 && stepIndex.value >= total.value - 1)

  function start(id: string) {
    if (!TOURS[id]) return false
    activeId.value = id
    stepIndex.value = 0
    return true
  }

  /** End the tour. `completed` distinguishes "read it" from "dismissed it";
   *  both mark it seen, because re-offering something you skipped is nagging. */
  function end(completed: boolean) {
    if (activeId.value) markSeen(activeId.value)
    void completed
    activeId.value = null
    stepIndex.value = 0
  }

  function next() {
    if (!tour.value) return
    if (isLast.value) end(true)
    else stepIndex.value += 1
  }

  /** Skip a step whose anchor never rendered, rather than stranding the user
   *  on an overlay pointing at nothing. If it was the last one, the tour ends. */
  function skipMissingStep() {
    if (!tour.value) return
    if (isLast.value) end(true)
    else stepIndex.value += 1
  }

  return {
    tour,
    step,
    stepIndex: computed(() => stepIndex.value),
    total,
    isLast,
    active: computed(() => activeId.value !== null),
    start,
    next,
    end,
    skipMissingStep,
    hasSeen: (id: string) => readSeen().includes(id),
  }
}
