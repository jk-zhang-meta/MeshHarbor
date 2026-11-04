// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
/**
 * FR-69 P9 — the SPA's module registry (spec D11).
 *
 * One web app serves every server profile. What decides whether a pillar's
 * navigation and routes exist is answered in two places, and BOTH must say
 * yes:
 *
 * 1. **Build time** — `VITE_MODULES` (a comma list) prunes the registry when
 *    an operator builds a bundle for one profile. Unset ⇒ every module is
 *    built in, which is the published bundle and the kill switch.
 * 2. **Run time** — `GET /api/capabilities` says which modules THIS server
 *    mounts (`stores/capabilities.ts`). A `mesh` server never grows a chat
 *    tab because the bundle happened to carry one.
 *
 * Routes carry `meta.module`; the router guard and the layout's navigation
 * read the same predicate (`useCapabilitiesStore().has`), so a pillar that
 * is absent is absent everywhere at once — no dead link, no blank page.
 */

/**
 * The server modules, in the graph's order (`meshharbor_core::graph::MODULES`).
 * `hive` (FR-90, agent sessions) is the one a server switches OFF by default,
 * so `/api/capabilities` names it only where an operator turned it on.
 */
export const ALL_MODULES = ['saas', 'chat', 'conference', 'fleet', 'remote', 'network', 'hive'] as const

export type ModuleId = (typeof ALL_MODULES)[number]

/**
 * The modules a server mounts only when an operator switches them ON — the
 * SPA's mirror of `ModulesSettings::DEFAULT_OFF`. These fail CLOSED while
 * `/api/capabilities` is unknown, where every other module fails open: for a
 * switch that is usually off, "unknown" most likely means "absent", and
 * failing open would show every user on every server a link to a feature
 * their server does not run.
 */
export const DEFAULT_OFF: readonly ModuleId[] = ['hive']

export function isModuleId(value: string): value is ModuleId {
  return (ALL_MODULES as readonly string[]).includes(value)
}

/**
 * Parse a `VITE_MODULES` value into the set of modules a bundle carries.
 * Unset or blank ⇒ all of them. Unknown names are IGNORED, never an error:
 * a newer server may name a module this bundle has never heard of, and an
 * additive list is only additive if old readers skip what they don't know
 * (the same rule the agent capability verbs follow).
 */
export function parseBuiltModules(raw: string | undefined | null): readonly ModuleId[] {
  const trimmed = (raw ?? '').trim()
  if (trimmed === '') return ALL_MODULES
  const wanted = trimmed
    .split(',')
    .map((s) => s.trim())
    .filter((s) => s.length > 0)
  const kept = ALL_MODULES.filter((m) => wanted.includes(m))
  // A list that names nothing we know is a misconfiguration, not a request
  // for an empty product — keep everything and let the console say why.
  if (kept.length === 0) {
    console.warn(`[modules] VITE_MODULES="${trimmed}" names no known module — building all of them`)
    return ALL_MODULES
  }
  return kept
}

/** The modules THIS bundle was built with (see `parseBuiltModules`). */
export const BUILT_MODULES: readonly ModuleId[] = parseBuiltModules(
  (import.meta.env?.VITE_MODULES as string | undefined) ?? undefined,
)

/**
 * The module → dependency edges the server's graph declares
 * (`conference → chat`, `remote → fleet`, `network → fleet`, `hive → fleet`,
 * `hive → chat`). A server never
 * mounts a module without its dependency, so the UI does not need to reason
 * about it — this exists so a build-time prune cannot produce a bundle whose
 * routes assume a parent the prune removed.
 */
export const MODULE_DEPS: Readonly<Record<ModuleId, readonly ModuleId[]>> = {
  saas: [],
  chat: [],
  conference: ['chat'],
  fleet: [],
  remote: ['fleet'],
  network: ['fleet'],
  hive: ['chat', 'fleet'],
}

/** Close a module set over `MODULE_DEPS`. */
export function withDependencies(modules: readonly ModuleId[]): ModuleId[] {
  const out = new Set<ModuleId>()
  const visit = (m: ModuleId) => {
    if (out.has(m)) return
    out.add(m)
    for (const d of MODULE_DEPS[m]) visit(d)
  }
  for (const m of modules) visit(m)
  return ALL_MODULES.filter((m) => out.has(m))
}
