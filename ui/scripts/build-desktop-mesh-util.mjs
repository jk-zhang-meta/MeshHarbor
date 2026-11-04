// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//
// FR-84 D5c — generate the desktop companion's copy of the mesh helpers.
//
// `ui/src/utils/mesh.ts` is the ONE source of the rules the mesh graph reads
// an edge by (qualifiedCarrier / edgeSides / participatingCarriers). The
// desktop companion (agents/meshharbor-desktop/src/front) is plain JavaScript
// that Tauri serves as-is — no bundler, `<script src>` tags, CSP
// `script-src 'self'` — so it cannot import TypeScript. This bundles mesh.ts
// into a classic-script IIFE that defines `window.RoomlerMesh`, and writes it
// CHECKED IN to agents/meshharbor-desktop/src/front/mesh-util.js.
//
// ui/src/__tests__/utils/desktopMeshUtil.spec.ts rebuilds it in memory and
// fails when the checked-in copy is stale, so a change to mesh.ts that forgets
// to regenerate cannot reach master with the two graphs disagreeing.
//
//   cd ui && bun scripts/build-desktop-mesh-util.mjs     (node works too)
//
// esbuild ships with vite, so this adds no dependency.

import { build } from 'esbuild'
import { writeFileSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'

const here = dirname(fileURLToPath(import.meta.url))

/** The single source of the helpers. */
export const SOURCE = resolve(here, '../src/utils/mesh.ts')
/** The checked-in, generated desktop copy. */
export const TARGET = resolve(here, '../../agents/meshharbor-desktop/src/front/mesh-util.js')

// The target lives under agents/, which the licence split classes as MPL-2.0
// client code (scripts/licence-classes.sh); the SPDX check reads the first
// three lines, so the header must name MPL-2.0 there.
const HEADER = `// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
// GENERATED from ui/src/utils/mesh.ts by ui/scripts/build-desktop-mesh-util.mjs — do not edit.
// Regenerate: cd ui && bun scripts/build-desktop-mesh-util.mjs
// ui/src/__tests__/utils/desktopMeshUtil.spec.ts fails while this copy is stale.
`

/** Bundle mesh.ts into the classic-script text the desktop loads. */
export async function buildDesktopMeshUtil() {
  const out = await build({
    entryPoints: [SOURCE],
    // esbuild names the source in a comment, relative to this directory —
    // pinned to ui/ so the output does not depend on where it was run from.
    absWorkingDir: resolve(here, '..'),
    bundle: true,
    write: false,
    format: 'iife',
    globalName: 'RoomlerMesh',
    platform: 'browser',
    // WebView2 (Chromium) and WebKitGTK 2.4x both run ES2019 natively.
    target: ['es2019'],
    legalComments: 'none',
    charset: 'utf8',
    logLevel: 'silent',
  })
  return HEADER + out.outputFiles[0].text
}

const invokedDirectly =
  process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href
if (invokedDirectly) {
  const text = await buildDesktopMeshUtil()
  writeFileSync(TARGET, text)
  console.log(`wrote ${TARGET} (${text.length} bytes)`)
}
