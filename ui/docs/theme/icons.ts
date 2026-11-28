// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
/**
 * FR-60 (#1165) — inline SVG icons.
 *
 * The app uses the MDI webfont (`@mdi/font`, ~1.2 MB of woff2 + CSS). A
 * static docs page must not pay that to draw a dozen glyphs, and an icon
 * font is also a render-blocking request on the critical path — the exact
 * cost this generator exists to avoid. These are hand-authored 24x24
 * stroke icons inlined into the HTML: zero requests, zero bytes over the
 * wire beyond the markup, and they inherit `currentColor` so a section
 * accent recolours them for free.
 *
 * ⚠️ The OS glyphs are deliberately generic marks (window panes, the
 * command loop, a terminal prompt) rather than vendor logos. They read
 * correctly at 16-20 px, and no vendor trademark is redistributed in this
 * AGPL tree to draw a tab label that already says the OS name in words.
 */

type IconBody = string

/** Stroke icons: 24x24, 1.75 stroke, round caps/joins. */
const STROKE: Record<string, IconBody> = {
  flag: '<path d="M4 21V4.5m0 0c3.5-2 6.5 2 10 0v9c-3.5 2-6.5-2-10 0"/>',
  monitor:
    '<rect x="2.5" y="4" width="19" height="12.5" rx="1.8"/><path d="M8.5 20.5h7M12 16.5v4"/>',
  network:
    '<circle cx="12" cy="4.6" r="2.4"/><circle cx="4.6" cy="18" r="2.4"/><circle cx="19.4" cy="18" r="2.4"/><path d="M10.4 6.7 6.2 15.9m5.4-9.2 4.2 9.2M7 18h10"/>',
  video:
    '<rect x="2.5" y="6" width="13" height="12" rx="2"/><path d="m15.5 10.8 6-3.3v9l-6-3.3z"/>',
  chip:
    '<rect x="7" y="7" width="10" height="10" rx="1.5"/><path d="M9.5 3v4M14.5 3v4M9.5 17v4M14.5 17v4M3 9.5h4M3 14.5h4M17 9.5h4M17 14.5h4"/>',
  file:
    '<path d="M13.5 3H7a1.5 1.5 0 0 0-1.5 1.5v15A1.5 1.5 0 0 0 7 21h10a1.5 1.5 0 0 0 1.5-1.5V8z"/><path d="M13.5 3v5h5M9 13h6M9 16.5h4"/>',
  blueprint:
    '<rect x="3" y="3" width="18" height="18" rx="2"/><path d="M3 9h18M9 9v12M13 13h4M13 17h4"/>',
  shield: '<path d="M12 2.8 4.5 6v6.2c0 4.6 3.1 7.9 7.5 9 4.4-1.1 7.5-4.4 7.5-9V6z"/><path d="m9.2 12 2 2 3.6-3.8"/>',
  wrench:
    '<path d="M15.4 3.6a5.2 5.2 0 0 0-6.6 6.4L3.3 15.5a2 2 0 0 0 0 2.8l2.4 2.4a2 2 0 0 0 2.8 0L14 15.2a5.2 5.2 0 0 0 6.4-6.6l-3 3-2.8-.8-.8-2.8z"/>',
  book: '<path d="M4 4.5A1.5 1.5 0 0 1 5.5 3H19v15H5.5A1.5 1.5 0 0 0 4 19.5z"/><path d="M4 19.5A1.5 1.5 0 0 1 5.5 21H19"/>',
  help: '<circle cx="12" cy="12" r="9"/><path d="M9.6 9.4a2.5 2.5 0 1 1 3.3 2.4c-.6.2-.9.8-.9 1.4v.5"/><path d="M12 17h.01"/>',
  compare:
    '<path d="M12 3v18M6.5 6.5 3 13h7zM17.5 6.5 14 13h7z"/><path d="M3 13a3.5 3.5 0 0 0 7 0M14 13a3.5 3.5 0 0 0 7 0"/>',
  search: '<circle cx="10.5" cy="10.5" r="6.5"/><path d="m15.5 15.5 4.5 4.5"/>',
  chevronRight: '<path d="m9 5 7 7-7 7"/>',
  chevronDown: '<path d="m5 9 7 7 7-7"/>',
  arrowLeft: '<path d="M20 12H4m0 0 6-6m-6 6 6 6"/>',
  arrowRight: '<path d="M4 12h16m0 0-6-6m6 6-6 6"/>',
  copy: '<rect x="8.5" y="8.5" width="12" height="12" rx="2"/><path d="M15.5 5.5v-1a1 1 0 0 0-1-1h-10a1 1 0 0 0-1 1v10a1 1 0 0 0 1 1h1"/>',
  check: '<path d="m4.5 12.5 5 5 10-11"/>',
  link: '<path d="M10 13.5a4 4 0 0 0 5.7 0l3-3a4 4 0 0 0-5.7-5.7l-1.5 1.5"/><path d="M14 10.5a4 4 0 0 0-5.7 0l-3 3a4 4 0 0 0 5.7 5.7l1.5-1.5"/>',
  info: '<circle cx="12" cy="12" r="9"/><path d="M12 11v5.5M12 7.8h.01"/>',
  tip: '<path d="M9 18h6M10 21h4"/><path d="M12 3a6 6 0 0 0-3.6 10.8c.6.5 1 1.2 1.1 2h5c.1-.8.5-1.5 1.1-2A6 6 0 0 0 12 3z"/>',
  warning: '<path d="M10.3 3.9 2.5 17.4A2 2 0 0 0 4.2 20.4h15.6a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z"/><path d="M12 9.5V14M12 17.2h.01"/>',
  danger: '<path d="M8.2 3h7.6L21 8.2v7.6L15.8 21H8.2L3 15.8V8.2z"/><path d="M12 8v5M12 16.2h.01"/>',
  external: '<path d="M14 4h6v6"/><path d="m20 4-8.5 8.5"/><path d="M18 14.5V19a1.5 1.5 0 0 1-1.5 1.5h-11A1.5 1.5 0 0 1 4 19V8a1.5 1.5 0 0 1 1.5-1.5H10"/>',
  menu: '<path d="M4 7h16M4 12h16M4 17h16"/>',
  close: '<path d="m6 6 12 12M18 6 6 18"/>',
  download: '<path d="M12 3.5v11m0 0 4.2-4.2M12 14.5 7.8 10.3"/><path d="M4 17v2.5A1.5 1.5 0 0 0 5.5 21h13a1.5 1.5 0 0 0 1.5-1.5V17"/>',
  terminal: '<rect x="2.5" y="4" width="19" height="16" rx="2"/><path d="m7 10 2.6 2.4L7 14.8M12.5 15.2H17"/>',
  windows: '<path d="M3.5 6.2 10.6 5v6.3H3.5zM12.4 4.7 20.5 3.5v7.8h-8.1zM3.5 12.7h7.1V19L3.5 17.8zM12.4 12.7h8.1v7.8l-8.1-1.2z"/>',
  command:
    '<path d="M9 6a2.5 2.5 0 1 0-2.5 2.5H9zm0 0v12m0-12h6M9 18a2.5 2.5 0 1 1-2.5-2.5H9zm6-12a2.5 2.5 0 1 1 2.5 2.5H15zm0 0v12m0 0a2.5 2.5 0 1 0 2.5-2.5H15zM9 18h6"/>',
}

/** Filled icons need their own render mode — a stroke-only `<svg>` draws
 *  them as outlines and they stop reading as the same family. */
const FILLED: Record<string, IconBody> = {
  windows: STROKE.windows!,
}

export type IconName = keyof typeof STROKE

export function icon(name: string, opts: { size?: number; cls?: string } = {}): string {
  const body = STROKE[name]
  if (!body) {
    // A typo in an icon name must not ship as an invisible gap.
    throw new Error(`unknown icon "${name}" — add it to ui/docs/theme/icons.ts`)
  }
  const size = opts.size ?? 24
  const filled = name in FILLED
  const cls = opts.cls ? ` class="${opts.cls}"` : ''
  return (
    `<svg${cls} width="${size}" height="${size}" viewBox="0 0 24 24" aria-hidden="true" focusable="false" ` +
    `fill="${filled ? 'currentColor' : 'none'}" stroke="${filled ? 'none' : 'currentColor'}" ` +
    `stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round">${body}</svg>`
  )
}

export function hasIcon(name: string): boolean {
  return name in STROKE
}

/** OS tab glyphs, keyed by the same slugs `enrollCommands.ts` uses. */
export const OS_ICON: Record<string, string> = {
  windows: 'windows',
  macos: 'command',
  linux: 'terminal',
}

export const OS_LABEL: Record<string, string> = {
  windows: 'Windows',
  macos: 'macOS',
  linux: 'Linux',
}
