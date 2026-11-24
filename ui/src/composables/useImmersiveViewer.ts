// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
/**
 * FR-131 P1, a port of roomler-ai's FR-125 P1 — immersive landscape on
 * phones. While a session runs on a touch page held sideways and under
 * {@link IMMERSIVE_MAX_HEIGHT} px tall, the app bar and the viewer's toolbar
 * step aside and the stage takes the whole page; a pull-tab brings the toolbar back as an overlay,
 * so the stage never resizes (a resize re-sends `rc:resolution`).
 *
 * Measured on production before it (2026-10-26): the bars left the remote
 * desktop 146–254 px on a phone held sideways, and every built-in touch preset
 * ran off the top. The viewer decides; the app shell only reads
 * {@link immersiveViewer} to hide its bar. The helpers are pure, so a spec
 * drives them at every size.
 */
import { readonly, ref } from 'vue'

/** A phone held sideways leaves at most ~430 px of page; a tablet held
 *  sideways leaves 600 px or more, and keeps its bars. */
export const IMMERSIVE_MAX_HEIGHT = 500

/** How long the revealed toolbar stays without a touch inside it (D2). */
export const IMMERSIVE_CHROME_HIDE_MS = 4000

/** Per browser, like the viewer's other preferences. Absent = on (D1). */
export const IMMERSIVE_STORAGE_KEY = 'meshharbor-rc-immersive.v1'

/** A touch page held sideways and short enough to be a phone. A desktop has a
 *  fine pointer, a phone held upright is taller than wide, and a tablet held
 *  sideways is taller than {@link IMMERSIVE_MAX_HEIGHT}. */
export function isPhoneSideways(coarse: boolean, width: number, height: number): boolean {
  return coarse && width > height && height < IMMERSIVE_MAX_HEIGHT
}

/** The setting, the mode's kill switch (FR-125 §3.4): on unless this browser
 *  turned it off. Blocked site data reads as on. */
export function readImmersiveSetting(
  storage: Pick<Storage, 'getItem'> | undefined = globalThis.localStorage,
): boolean {
  try {
    return storage?.getItem(IMMERSIVE_STORAGE_KEY) !== 'off'
  } catch {
    return true
  }
}

export function writeImmersiveSetting(
  on: boolean,
  storage: Pick<Storage, 'setItem' | 'removeItem'> | undefined = globalThis.localStorage,
): void {
  try {
    if (on) storage?.removeItem(IMMERSIVE_STORAGE_KEY)
    else storage?.setItem(IMMERSIVE_STORAGE_KEY, 'off')
  } catch {
    /* blocked site data: this tab only */
  }
}

/** FR-125 P3 — the one-time "Full screen" chip, where the browser can put the
 *  stage into element fullscreen (Android's Chrome; never iPhone Safari): it
 *  also hides the browser's own bar, 356 → 412 px on a Pixel 7. Used or
 *  closed once, it is gone for this browser. */
export const FULLSCREEN_CHIP_STORAGE_KEY = 'meshharbor-rc-fullscreen-chip.v1'

export function readFullscreenChipDismissed(
  storage: Pick<Storage, 'getItem'> | undefined = globalThis.localStorage,
): boolean {
  try {
    return storage?.getItem(FULLSCREEN_CHIP_STORAGE_KEY) === 'dismissed'
  } catch {
    return false
  }
}

export function dismissFullscreenChip(
  storage: Pick<Storage, 'setItem'> | undefined = globalThis.localStorage,
): void {
  try {
    storage?.setItem(FULLSCREEN_CHIP_STORAGE_KEY, 'dismissed')
  } catch {
    /* blocked site data: this tab only */
  }
}

const immersive = ref(false)

/** True while the viewer is immersive: the app shell hides its bar. Only the
 *  viewer writes it ({@link setImmersiveViewer}), and clears it when it
 *  unmounts, so no other page ever starts without the bar. */
export const immersiveViewer = readonly(immersive)

export function setImmersiveViewer(on: boolean): void {
  immersive.value = on
}
