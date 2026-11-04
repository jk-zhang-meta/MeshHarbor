// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
import { ref, computed, watch, onScopeDispose, type Ref } from 'vue'

export type LayoutMode = 'auto' | 'tiled' | 'spotlight' | 'sidebar'
export type SelfViewMode = 'in-grid-cropped' | 'in-grid-uncropped' | 'floating-uncropped'

export interface LayoutParticipant {
  streamKey: string
  /** FR-30 — the peer SAID their camera is off. Not derivable from the track. */
  videoPaused: boolean
  userId: string
  displayName: string
  stream: MediaStream | null
  isMuted: boolean
  isLocal: boolean
  isScreenShare: boolean
  isPinned: boolean
  audioLevel: number
}

export interface LayoutPreferences {
  mode: LayoutMode
  tiledMaxTiles: number
  selfViewMode: SelfViewMode
  hideNonVideo: boolean
  pinnedStreamKeys: string[]
}

export interface ResolvedLayout {
  effectiveMode: 'tiled' | 'spotlight' | 'sidebar'
  primary: LayoutParticipant[]
  secondary: LayoutParticipant[]
  selfViewFloating: boolean
}

const STORAGE_KEY = 'meshharbor:layout-prefs'
const MAX_PINS = 6

function loadPrefs(): LayoutPreferences {
  try {
    const stored = localStorage.getItem(STORAGE_KEY)
    if (stored) {
      const parsed = JSON.parse(stored)
      return {
        mode: parsed.mode || 'auto',
        tiledMaxTiles: parsed.tiledMaxTiles ?? 16,
        selfViewMode: parsed.selfViewMode || 'in-grid-cropped',
        hideNonVideo: parsed.hideNonVideo ?? false,
        pinnedStreamKeys: parsed.pinnedStreamKeys || [],
      }
    }
  } catch {}
  return {
    mode: 'auto',
    tiledMaxTiles: 16,
    selfViewMode: 'in-grid-cropped',
    hideNonVideo: false,
    pinnedStreamKeys: [],
  }
}

function savePrefs(prefs: LayoutPreferences) {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(prefs))
  } catch {}
}

interface RemoteStream {
  userId: string
  connectionId: string
  stream: MediaStream
  kind: string
  source: string
}

/**
 * FR-25 — which layout a mode actually resolves to. Pure so the rules can be
 * read (and tested) without a call: Auto used to be an inline chain inside a
 * computed, which is exactly where the "layout controls don't work" reports
 * came from — nobody could point at the rule that fired.
 *
 * Order is deliberate: a screen share is the reason everyone is looking, an
 * explicit pin is the operator overriding us, a 1:1 wants one big tile, and
 * everything else is a grid.
 *
 * FR-116 — `narrow` (below 960 px): a share goes to spotlight, not sidebar.
 * The sidebar's 280 px strip left the shared screen ~72 px wide on a phone;
 * spotlight's filmstrip scrolls and the share gets the width.
 */
export function resolveEffectiveMode(
  mode: LayoutMode,
  ctx: { hasScreenShare: boolean; pinnedCount: number; participantCount: number; narrow?: boolean },
): 'tiled' | 'spotlight' | 'sidebar' {
  if (mode !== 'auto') return mode
  if (ctx.hasScreenShare) return ctx.narrow ? 'spotlight' : 'sidebar'
  if (ctx.pinnedCount > 0) return 'spotlight'
  if (ctx.participantCount <= 2) return 'spotlight'
  return 'tiled'
}

/**
 * FR-25 — pick the big tile for sidebar/spotlight when nothing is pinned.
 * NEVER the local tile while a remote exists: "Sidebar" used to take
 * `sorted[0]`, which is alphabetical, so an operator whose name sorted first
 * got a full-screen view of themselves.
 */
export function pickPrimaryFallback(
  sorted: LayoutParticipant[],
  activeSpeakerKey: string | null,
): LayoutParticipant[] {
  const speaker = activeSpeakerKey
    ? sorted.find((p) => p.streamKey === activeSpeakerKey && !p.isLocal)
    : undefined
  if (speaker) return [speaker]
  const firstRemote = sorted.find((p) => !p.isLocal)
  if (firstRemote) return [firstRemote]
  // Alone in the call — showing yourself is all there is.
  return sorted.slice(0, 1)
}

export function useConferenceLayout(
  localStream: Ref<MediaStream | null>,
  remoteStreams: Map<string, RemoteStream>,
  isMuted: Ref<boolean>,
  audioLevels: Ref<Map<string, number>>,
  activeSpeakerKey: Ref<string | null>,
  getDisplayName: (userId: string) => string,
  localDisplayName: Ref<string>,
  // FR-30 — what each peer SAYS about their own camera/mic, keyed by
  // streamKey. Optional so the composable stays usable (and testable) without
  // a live call store. ⚠️ An options object rather than more positional
  // arguments: P1 shipped `remoteVideoPaused` here and audio would have made
  // it nine in a row, at which point a call site gets one wrong silently.
  remotePaused?: {
    video?: Map<string, boolean>
    audio?: Map<string, boolean>
    /** FR-116 — the viewport is narrow (below 960 px): Auto spotlights a
     *  screen share instead of the sidebar layout. Rides this options object
     *  for the reason above. */
    narrow?: Ref<boolean>
  },
) {
  const prefs = ref<LayoutPreferences>(loadPrefs())

  // Persist on change
  watch(prefs, (v) => savePrefs(v), { deep: true })

  // FR-25 — native MediaStream/track state is INVISIBLE to Vue reactivity
  // (VideoTile learned this the hard way and keeps its own ref). Reading it
  // straight from a computed meant "hide participants without video" was
  // decided once and never revisited: a camera switched on after the filter
  // ran left its owner hidden until something unrelated invalidated the
  // computed. This counter is the dependency that makes it converge.
  const videoStateVersion = ref(0)
  const watchedStreams = new Map<MediaStream, () => void>()

  function watchStream(stream: MediaStream) {
    if (watchedStreams.has(stream)) return
    const bump = () => {
      videoStateVersion.value++
    }
    const tracks = stream.getVideoTracks()
    stream.addEventListener('addtrack', bump)
    stream.addEventListener('removetrack', bump)
    for (const t of tracks) {
      t.addEventListener('ended', bump)
      t.addEventListener('mute', bump)
      t.addEventListener('unmute', bump)
    }
    watchedStreams.set(stream, () => {
      stream.removeEventListener('addtrack', bump)
      stream.removeEventListener('removetrack', bump)
      for (const t of tracks) {
        t.removeEventListener('ended', bump)
        t.removeEventListener('mute', bump)
        t.removeEventListener('unmute', bump)
      }
    })
    // A track added later needs its own listeners; the addtrack bump
    // re-enters this via the participants computed.
    stream.addEventListener('addtrack', () => {
      const teardown = watchedStreams.get(stream)
      if (teardown) {
        teardown()
        watchedStreams.delete(stream)
      }
      watchStream(stream)
    })
  }

  function unwatchAll() {
    for (const teardown of watchedStreams.values()) teardown()
    watchedStreams.clear()
  }
  onScopeDispose(unwatchAll)

  function hasLiveVideoTrack(stream: MediaStream | null): boolean {
    // Touch the counter so every caller inside a computed re-runs on a
    // track transition. Cheap, and the only honest way to depend on it.
    void videoStateVersion.value
    if (!stream) return false
    return stream.getVideoTracks().some((t) => t.enabled && t.readyState === 'live')
  }

  const participants = computed<LayoutParticipant[]>(() => {
    const list: LayoutParticipant[] = []

    // Local participant
    if (localStream.value) {
      watchStream(localStream.value)
      list.push({
        streamKey: 'local',
        userId: 'local',
        displayName: localDisplayName.value,
        stream: localStream.value,
        isMuted: isMuted.value,
        isLocal: true,
        isScreenShare: false,
        isPinned: prefs.value.pinnedStreamKeys.includes('local'),
        // Your own camera state is already visible to you locally; the signal
        // is about what OTHERS cannot otherwise see.
        videoPaused: false,
        audioLevel: 0,
      })
    }

    // Remote participants
    for (const [streamKey, remote] of remoteStreams) {
      watchStream(remote.stream)
      const isScreen = streamKey.endsWith(':screen') || remote.source === 'screen'
      const name = isScreen
        ? getDisplayName(remote.userId) + ' (Screen)'
        : getDisplayName(remote.userId)
      list.push({
        streamKey,
        userId: remote.userId,
        displayName: name,
        stream: remote.stream,
        // FR-30 P3 — was hardcoded `false`, so a remote could never show as
        // muted. Same signal as the camera, different map.
        isMuted: remotePaused?.audio?.get(streamKey) === true,
        isLocal: false,
        isScreenShare: isScreen,
        isPinned: prefs.value.pinnedStreamKeys.includes(streamKey),
        videoPaused: remotePaused?.video?.get(streamKey) === true,
        audioLevel: audioLevels.value.get(streamKey) ?? 0,
      })
    }

    return list
  })

  const hasScreenShare = computed(() =>
    participants.value.some((p) => p.isScreenShare),
  )

  const pinnedParticipants = computed(() =>
    participants.value.filter((p) => p.isPinned),
  )

  function filterHidden(list: LayoutParticipant[]): LayoutParticipant[] {
    if (!prefs.value.hideNonVideo) return list
    return list.filter(
      // FR-30 — a paused sender's track is still `live` and unmuted here, so
      // the peer's own signal is the only thing that can answer this.
      (p) => p.isPinned || p.isLocal || (!p.videoPaused && hasLiveVideoTrack(p.stream)),
    )
  }

  function sortParticipants(list: LayoutParticipant[]): LayoutParticipant[] {
    return [...list].sort((a, b) => {
      // Pinned first
      if (a.isPinned !== b.isPinned) return a.isPinned ? -1 : 1
      // Active speaker next
      const aActive = a.streamKey === activeSpeakerKey.value
      const bActive = b.streamKey === activeSpeakerKey.value
      if (aActive !== bActive) return aActive ? -1 : 1
      // Alphabetical
      return a.displayName.localeCompare(b.displayName)
    })
  }

  const layout = computed<ResolvedLayout>(() => {
    const mode = prefs.value.mode
    const all = filterHidden(participants.value)
    const sorted = sortParticipants(all)
    const selfFloating = prefs.value.selfViewMode === 'floating-uncropped'

    const effectiveMode = resolveEffectiveMode(mode, {
      hasScreenShare: hasScreenShare.value,
      pinnedCount: pinnedParticipants.value.length,
      participantCount: sorted.length,
      narrow: remotePaused?.narrow?.value === true,
    })

    // Split into primary/secondary based on effective mode
    let primary: LayoutParticipant[] = []
    let secondary: LayoutParticipant[] = []

    if (effectiveMode === 'tiled') {
      // In tiled mode, everyone in primary (up to max tiles)
      const gridParticipants = selfFloating
        ? sorted.filter((p) => !p.isLocal)
        : sorted
      primary = gridParticipants.slice(0, prefs.value.tiledMaxTiles)
      secondary = [] // no filmstrip in tiled
    } else if (effectiveMode === 'spotlight') {
      // Pinned wins; otherwise the speaker, then the first remote — never
      // yourself while someone else is on the call (FR-25).
      const pinned = sorted.filter((p) => p.isPinned)
      primary = pinned.length > 0 ? pinned : pickPrimaryFallback(sorted, activeSpeakerKey.value)
      const primaryKeys = new Set(primary.map((p) => p.streamKey))
      secondary = sorted.filter((p) => !primaryKeys.has(p.streamKey))
      if (selfFloating) {
        secondary = secondary.filter((p) => !p.isLocal)
      }
    } else {
      // sidebar: screen share or pinned in primary, rest in the sidebar.
      // With neither, fall back the same way spotlight does — `sorted[0]`
      // is alphabetical, which used to hand the big tile to whoever sorted
      // first, usually yourself (FR-25).
      const screenShares = sorted.filter((p) => p.isScreenShare)
      if (screenShares.length > 0) {
        primary = screenShares
      } else {
        const pinned = sorted.filter((p) => p.isPinned)
        primary =
          pinned.length > 0 ? pinned : pickPrimaryFallback(sorted, activeSpeakerKey.value)
      }
      const primaryKeys = new Set(primary.map((p) => p.streamKey))
      secondary = sorted.filter((p) => !primaryKeys.has(p.streamKey))
      if (selfFloating) {
        secondary = secondary.filter((p) => !p.isLocal)
      }
    }

    return {
      effectiveMode,
      primary,
      secondary,
      selfViewFloating: selfFloating,
    }
  })

  // Self-view participant for floating overlay
  const selfParticipant = computed(() =>
    participants.value.find((p) => p.isLocal) ?? null,
  )

  function togglePin(streamKey: string): boolean {
    const idx = prefs.value.pinnedStreamKeys.indexOf(streamKey)
    if (idx >= 0) {
      prefs.value.pinnedStreamKeys.splice(idx, 1)
      return true
    }
    if (prefs.value.pinnedStreamKeys.length >= MAX_PINS) {
      return false
    }
    prefs.value.pinnedStreamKeys.push(streamKey)
    return true
  }

  function setMode(mode: LayoutMode) {
    prefs.value.mode = mode
  }

  // FR-25 — double-click spotlights a tile. The mode we came from is
  // remembered (in memory, not storage: it describes THIS call) so the
  // second double-click really undoes the first instead of stranding the
  // operator in spotlight.
  let modeBeforeSpotlight: LayoutMode | null = null

  /** Returns true if the tile is now spotlit, false if it was released. */
  function toggleSpotlight(streamKey: string): boolean {
    const isOnlyPin =
      prefs.value.pinnedStreamKeys.length === 1 &&
      prefs.value.pinnedStreamKeys[0] === streamKey
    if (isOnlyPin && prefs.value.mode === 'spotlight') {
      prefs.value.pinnedStreamKeys = []
      prefs.value.mode = modeBeforeSpotlight ?? 'auto'
      modeBeforeSpotlight = null
      return false
    }
    if (prefs.value.mode !== 'spotlight') modeBeforeSpotlight = prefs.value.mode
    // Sole pin: spotlighting a second tile replaces the first rather than
    // silently doing nothing at the MAX_PINS ceiling.
    prefs.value.pinnedStreamKeys = [streamKey]
    prefs.value.mode = 'spotlight'
    return true
  }

  function setMaxTiles(n: number) {
    prefs.value.tiledMaxTiles = Math.max(4, Math.min(49, n))
  }

  function setSelfViewMode(mode: SelfViewMode) {
    prefs.value.selfViewMode = mode
  }

  function setHideNonVideo(v: boolean) {
    prefs.value.hideNonVideo = v
  }

  return {
    prefs,
    participants,
    layout,
    selfParticipant,
    togglePin,
    toggleSpotlight,
    setMode,
    setMaxTiles,
    setSelfViewMode,
    setHideNonVideo,
  }
}
