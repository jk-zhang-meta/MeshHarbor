// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
/**
 * FR-88 (#1790) P3 — the videos the site and the app embed. ONE list for both, like
 * `landing.ts`: the docs generator (a `:::video <id>` container, the static homepage)
 * and the SPA (the tutorial). An id that is not here fails the docs build.
 *
 * ⚠️ Only a PUBLIC video belongs here. The player of a private or scheduled one
 * shows "Video unavailable", on a page that is otherwise ours.
 *
 * Nothing is fetched from YouTube before a click: the poster is our own copy of
 * the video's thumbnail (`ui/src/assets/tutorial/`, which both builds publish),
 * and the player is `youtube-nocookie.com`, loaded only when someone presses
 * play. The pages stay as tracker-free as they are without a video.
 */

export interface SiteVideo {
  /** The YouTube video id. */
  id: string
  title: string
  /** One or two plain sentences: the structured data's description. */
  description: string
  /** When it went public, ISO 8601 with a zone. */
  uploadDate: string
  /** ISO 8601 duration, as YouTube reports it. */
  duration: string
  /** The poster's file name in `ui/src/assets/tutorial/` (1280x720). */
  poster: string
}

export const VIDEOS: readonly SiteVideo[] = [
  {
    id: 'C1YdfmhbAKM',
    title: 'Self-hosted TeamViewer alternative: MeshHarbor on Windows, Mac and Linux',
    description:
      'Install the MeshHarbor agent on Windows, macOS and Linux, connect from a browser tab, and go through ' +
      'consent and unattended access, the Windows lock screen, hardware encoding and sharp text, files ' +
      'and the clipboard, and the private network the same agent builds.',
    uploadDate: '2026-10-15T18:00:00Z',
    duration: 'PT9M3S',
    poster: 'video-C1YdfmhbAKM.jpg',
  },
]

/** The video the homepage and the tutorial's first chapter show. ⚠️ The SPA
 *  imports its poster by file name (`tutorialChapters.ts`, `LandingView.vue`),
 *  so a new featured video changes those imports too. */
export const FEATURED_VIDEO_ID = 'C1YdfmhbAKM'

export function videoById(id: string): SiteVideo | undefined {
  return VIDEOS.find((v) => v.id === id)
}

/** The player, loaded on the click: no cookie until then, autoplay because
 *  the click was the request to play, and related videos from this channel only. */
export function embedUrl(id: string): string {
  return `https://www.youtube-nocookie.com/embed/${encodeURIComponent(id)}?autoplay=1&rel=0`
}

/** Where the facade's link goes when scripts are off. */
export function watchUrl(id: string): string {
  return `https://www.youtube.com/watch?v=${encodeURIComponent(id)}`
}

function parts(duration: string): { h: number; m: number; s: number } {
  const p = /^PT(?:(\d+)H)?(?:(\d+)M)?(?:(\d+)S)?$/.exec(duration)
  if (!p) throw new Error(`videos: "${duration}" is not an ISO 8601 duration`)
  return { h: Number(p[1] ?? 0), m: Number(p[2] ?? 0), s: Number(p[3] ?? 0) }
}

/** `PT9M3S` → `9:03`, for the badge on the poster. */
export function clockOf(duration: string): string {
  const { h, m, s } = parts(duration)
  const ss = String(s).padStart(2, '0')
  return h ? `${h}:${String(m).padStart(2, '0')}:${ss}` : `${m}:${ss}`
}

/** Rounded minutes, for "a 9-minute video". */
export function minutesOf(duration: string): number {
  const { h, m, s } = parts(duration)
  return h * 60 + m + (s >= 30 ? 1 : 0)
}
