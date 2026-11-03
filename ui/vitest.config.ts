// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
import { defineConfig } from 'vitest/config'
import vue from '@vitejs/plugin-vue'
import { resolve } from 'path'

export default defineConfig({
  plugins: [vue()],
  resolve: {
    alias: {
      '@': resolve(__dirname, 'src'),
      // Vuetify components ship side-effect CSS imports. In the test
      // env we don't render styles, so alias every .css import to an
      // empty stub rather than round-tripping them through Node's ESM
      // loader (which fails with "Unknown file extension '.css'" on
      // CI). Local bun is lenient about this, which masked the issue.
    },
  },
  test: {
    environment: 'jsdom',
    globals: true,
    setupFiles: ['src/__tests__/setup-i18n.ts'],
    // `docs/**` is FR-60's static documentation generator. Its specs live
    // next to it rather than under src/, because it is a build-time tool
    // and not part of the SPA bundle.
    include: ['src/**/*.spec.ts', 'src/**/*.test.ts', 'docs/**/*.spec.ts'],
    // Vuetify inlining pushes the first `await import('../vuetify')`
    // past the 5-s default on cold caches (CI runners + fresh local
    // clones). Bump once; the rest of the suite is unaffected.
    testTimeout: 30000,
    hookTimeout: 30000,
    server: {
      deps: {
        // Force vuetify through Vite's transform pipeline so its CSS
        // side-imports are picked up by our `css.include` below rather
        // than hitting Node's loader as an external ESM import.
        inline: [/vuetify/],
      },
    },
    coverage: {
      provider: 'v8',
      reporter: ['text', 'lcov'],
      include: ['src/**/*.{ts,vue}'],
      exclude: ['src/**/*.spec.ts', 'src/**/*.test.ts', 'src/**/*.d.ts'],
    },
  },
  // Swallow CSS imports in node_modules so jsdom-based tests don't
  // trip on vuetify's per-component .css side-effect imports.
  css: {
    modules: {},
  },
})
