// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//
// FR-126 P2 — what one browser sends of the meeting whiteboard, and what it must not echo.
//
// Excalidraw bumps an element's `version` on every edit, so "changed" is "newer than the
// newest copy this browser has sent OR received". Recording received versions is what stops an
// applied remote edit from bouncing back to the server on the next `onChange`. Concurrent edits
// of one element at the same version are settled by the server and by Excalidraw's
// `reconcileElements`, with one rule on both sides (higher version, then lower versionNonce).

export interface BoardElement {
  id: string
  version: number
  versionNonce: number
  type?: string
  isDeleted?: boolean
}

export class BoardSync {
  private known = new Map<string, number>()

  /** The elements edited here since the last call; each is remembered as sent. */
  outgoing(elements: readonly BoardElement[]): BoardElement[] {
    const out: BoardElement[] = []
    for (const e of elements) {
      // Images are not carried: their pixels are separate files (the server refuses them too).
      if (e.type === 'image') continue
      const seen = this.known.get(e.id)
      if (seen === undefined || e.version > seen) {
        out.push(e)
        this.known.set(e.id, e.version)
      }
    }
    return out
  }

  /** Elements that arrived from the meeting and were applied here: never send them back. */
  received(elements: readonly BoardElement[]): void {
    for (const e of elements) {
      const seen = this.known.get(e.id)
      if (seen === undefined || e.version > seen) this.known.set(e.id, e.version)
    }
  }
}

/** Shapes on the board (tombstones excluded). */
export function liveCount(elements: readonly BoardElement[]): number {
  let n = 0
  for (const e of elements) if (!e.isDeleted) n++
  return n
}
