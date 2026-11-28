// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
import type { RouteLocationNormalizedLoaded } from 'vue-router'

/**
 * #1631 — the `:key` for the component a `<router-view>` renders
 * (`components/layout/KeyedRouterView.vue`).
 *
 * `undefined` for every route without `meta.remountOn`. Vue treats a missing
 * key as "the same element", which is Vue Router's default reuse across a
 * param change — and what the views that rewrite `route.query` in place via
 * `router.replace` (the devices grid's kind filter, the ACL tabs) depend on.
 * Keying on `fullPath` would remount those on every filter flip. A route that
 * names a param remounts when THAT param changes and only then:
 * `agent-remote:A` → `agent-remote:B` is a new view; `agent-remote:A` with a
 * different query is not.
 */
export function routeViewKey(route: RouteLocationNormalizedLoaded): string | undefined {
  const param = route.meta.remountOn
  if (!param) return undefined
  return `${String(route.name)}:${String(route.params[param] ?? '')}`
}
