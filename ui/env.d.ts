// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
/// <reference types="vite/client" />

interface ImportMetaEnv {
  /** Build-time outer path (Vite resolves it into built-in BASE_URL). */
  readonly VITE_BASE_PATH?: string
  /** FR-69 P9 — comma list of server modules this bundle is built for
   *  (`chat,conference,fleet,remote,network,saas`); unset = all of them.
   *  See `src/modules/registry.ts`. */
  readonly VITE_MODULES?: string
}

declare module '*.vue' {
  import type { DefineComponent } from 'vue'
  const component: DefineComponent<object, object, unknown>
  export default component
}
