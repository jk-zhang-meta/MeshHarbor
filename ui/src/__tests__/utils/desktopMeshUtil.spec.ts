// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
// @vitest-environment node
//
// FR-84 D5c — the desktop companion's mesh graph reads edges by the SAME rules
// as the web one: agents/meshharbor-desktop/src/front/mesh-util.js is generated
// from ui/src/utils/mesh.ts and checked in (the companion has no bundler).
// This fails when the checked-in copy is not what mesh.ts builds to today.
//
// `node` environment on purpose: esbuild's JS API refuses to run under jsdom
// (its TextEncoder/Uint8Array realm check fails there).
import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { buildDesktopMeshUtil, TARGET } from '../../../scripts/build-desktop-mesh-util.mjs'
import { qualifiedCarrier, edgeSides, participatingCarriers } from '@/utils/mesh'

interface MeshUtil {
  qualifiedCarrier: typeof qualifiedCarrier
  edgeSides: typeof edgeSides
  participatingCarriers: typeof participatingCarriers
}

/** Run the classic-script text the way a <script src> would, and hand back
 *  the global it defines. */
function load(text: string): MeshUtil {
  return new Function(`${text}\nreturn MeshHarborMesh;`)() as MeshUtil
}

describe('desktop mesh-util.js', () => {
  it('is the current build of ui/src/utils/mesh.ts', async () => {
    const fresh = await buildDesktopMeshUtil()
    // core.autocrlf may hand the checked-in file back with CRLF endings.
    const checkedIn = readFileSync(TARGET, 'utf8').replace(/\r\n/g, '\n')
    expect(
      checkedIn,
      'agents/meshharbor-desktop/src/front/mesh-util.js is stale — run: cd ui && bun scripts/build-desktop-mesh-util.mjs',
    ).toBe(fresh)
  })

  it('defines window.MeshHarborMesh with helpers that answer like mesh.ts', () => {
    const util = load(readFileSync(TARGET, 'utf8'))
    const ends = [
      { node: 'a', carrier: 'direct', rtt_ms: 4 },
      { node: 'b', carrier: 'relay', relay: 'turn/udp', rtt_ms: 52 },
    ]
    expect(util.qualifiedCarrier('relay', 'turn/udp')).toBe(qualifiedCarrier('relay', 'turn/udp'))
    expect(util.qualifiedCarrier('direct', 'turn/udp')).toBe('direct')
    expect(util.edgeSides(ends, 'a', 'b')).toEqual(edgeSides(ends, 'a', 'b'))
    expect(util.edgeSides(undefined, 'a', 'b')).toEqual(edgeSides(undefined, 'a', 'b'))
    expect(util.participatingCarriers('relay', ends).sort()).toEqual(
      participatingCarriers('relay', ends).sort(),
    )
  })
})
