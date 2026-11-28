// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
import { defineStore } from 'pinia'
import { computed, ref } from 'vue'
import { api } from '@/api/client'
import { BUILT_MODULES, DEFAULT_OFF, isModuleId, type ModuleId } from '@/modules/registry'

/** `GET /api/capabilities` (FR-69 D10) — unauthenticated, one request per page load. */
export interface ServerCapabilities {
  version: string
  /** What THIS server mounts — the profile it was built as, minus `[modules]` switches. */
  modules: string[]
  /** What the build linked (P8); absent on a pre-P8 server. */
  compiled?: string[]
  /** Switched off by config; a subset of `compiled`. */
  switched_off?: string[]
  /** FR-102 P9b — server-wide switches a client must read before offering
   *  something (`session_feedback`: the post-session rating). Absent on an
   *  older server. */
  features?: Record<string, unknown>
}

/**
 * FR-69 P9 — which pillars this server has, as the SPA's single gate for
 * navigation and routes.
 *
 * Deliberately FAIL-OPEN while unknown: before the request lands (first
 * paint), or if it fails (an older server, a proxy hiccup), every module the
 * bundle carries is treated as present. The server enforces every action
 * anyway, so the worst case of failing open is a link whose page 404s — while
 * failing closed would blank the whole product behind one round-trip. The
 * same rule `canSeeFleetNav` follows for permissions.
 */
export const useCapabilitiesStore = defineStore('capabilities', () => {
  /** `null` until the server has answered (or refused to). */
  const modules = ref<ModuleId[] | null>(null)
  const compiled = ref<ModuleId[] | null>(null)
  const switchedOff = ref<ModuleId[]>([])
  const version = ref<string | null>(null)
  const loaded = ref(false)
  const failed = ref(false)
  /** FR-102 P9b — the server's feature switches, only the booleans it sent. */
  const features = ref<Record<string, boolean>>({})

  let inflight: Promise<void> | null = null

  function apply(caps: ServerCapabilities): void {
    modules.value = (caps.modules ?? []).filter(isModuleId)
    compiled.value = caps.compiled ? caps.compiled.filter(isModuleId) : null
    switchedOff.value = (caps.switched_off ?? []).filter(isModuleId)
    version.value = caps.version ?? null
    const f: Record<string, boolean> = {}
    for (const [k, v] of Object.entries(caps.features ?? {})) if (typeof v === 'boolean') f[k] = v
    features.value = f
    loaded.value = true
    failed.value = false
  }

  /**
   * FR-102 P9b — is a server feature on? The opposite rule to `has`: a
   * feature fails **CLOSED** — before the answer, after a failed request, on
   * an older server that sends no `features`, and for a name it never sent,
   * the answer is `false`. A feature is something the client OFFERS (the
   * rating prompt), and offering what the server refuses is the worse
   * mistake.
   */
  function feature(name: string): boolean {
    return features.value[name] === true
  }

  /** Fetch once; concurrent callers share the request. Never throws. */
  function load(): Promise<void> {
    if (loaded.value) return Promise.resolve()
    if (inflight) return inflight
    inflight = api
      .get<ServerCapabilities>('/capabilities')
      .then(apply)
      .catch((e: unknown) => {
        // Fail OPEN, loudly: the product stays reachable and the console
        // says why the gate is not gating.
        failed.value = true
        loaded.value = true
        console.warn('[modules] /api/capabilities unavailable — showing every built-in module', e)
      })
      .finally(() => {
        inflight = null
      })
    return inflight
  }

  /** The request that is (or was) in flight — the router guard awaits it. */
  function ready(): Promise<void> {
    return loaded.value ? Promise.resolve() : load()
  }

  /**
   * Is a module usable from this bundle against this server? Both gates:
   * the bundle must carry it (`VITE_MODULES`) AND the server must mount it —
   * or the server has not answered yet, in which case the bundle's word
   * stands (fail-open). Any DEFAULT-OFF module is the exception:
   * it is present only once the server has said so.
   */
  function has(module: ModuleId): boolean {
    if (!BUILT_MODULES.includes(module)) return false
    if (modules.value === null) return !DEFAULT_OFF.includes(module)
    return modules.value.includes(module)
  }

  /** For the UI's own diagnostics (settings page, console): what is missing and why. */
  const summary = computed(() => ({
    built: [...BUILT_MODULES],
    mounted: modules.value,
    compiled: compiled.value,
    switchedOff: [...switchedOff.value],
    version: version.value,
    failed: failed.value,
    features: { ...features.value },
  }))

  /** Test seam / logout reset. */
  function reset(): void {
    modules.value = null
    compiled.value = null
    switchedOff.value = []
    version.value = null
    features.value = {}
    loaded.value = false
    failed.value = false
    inflight = null
  }

  return {
    modules,
    compiled,
    switchedOff,
    version,
    features,
    loaded,
    failed,
    summary,
    load,
    ready,
    has,
    feature,
    apply,
    reset,
  }
})
