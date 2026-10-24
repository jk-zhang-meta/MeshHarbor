// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
import { deploymentPath, normalizeBasePath } from './src/utils/deploymentPath'
import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'
import vuetify from 'vite-plugin-vuetify'
import { resolve } from 'path'

const apiTarget = process.env.VITE_API_URL || 'http://localhost:5001'

const basePath = normalizeBasePath(process.env.VITE_BASE_PATH || '/')
const stripBase = (path: string): string => basePath === '/' ? path : `/${path.slice(basePath.length)}`

export default defineConfig({
  base: basePath,
  plugins: [
    vue(),
    vuetify({ autoImport: true }),
  ],
  resolve: {
    alias: {
      '@': resolve(__dirname, 'src'),
    },
    // FR-25 — THE fix for the duplicate-prosemirror crash. Chunking was not.
    //
    // The install tree carries nested copies: root `prosemirror-model` is
    // 1.25.11 while prosemirror-{commands,markdown,schema-list,state,tables}
    // each vendor their own 1.25.4 — and -transform and -view are duplicated
    // the same way. Every requirer's range (`^1.0.0`, `^1.25.0`, `^1.25.4`)
    // accepts the root version, so this is installer duplication, not a real
    // conflict: an editor built by one instance rejects a node built by
    // another with
    //   "Can not convert <mention, ' '> to a Fragment
    //    (looks like multiple versions of prosemirror-model were loaded)"
    // which is what picking a mention did, in room chat and in-call chat.
    //
    // ⚠️ Deduping at the RESOLVER is what makes it single-instance. Grouping
    // the family into one chunk (below) only moved the copies; it did not
    // remove them — the first fix attempt shipped and the crash survived it.
    // Verify by TOTAL, never per chunk:
    //   grep -c "multiple versions of prosemirror-model" dist/assets/*.js
    // summed over every file must be exactly 1 (the string occurs once per
    // copy of the library). `ui/e2e/mention.spec.ts` asserts the behaviour.
    //
    // Regenerate the list with:
    //   ls -d ui/node_modules/prosemirror-* | xargs -n1 basename
    dedupe: [
      'prosemirror-changeset',
      'prosemirror-collab',
      'prosemirror-commands',
      'prosemirror-dropcursor',
      'prosemirror-gapcursor',
      'prosemirror-history',
      'prosemirror-inputrules',
      'prosemirror-keymap',
      'prosemirror-markdown',
      'prosemirror-menu',
      'prosemirror-model',
      'prosemirror-schema-basic',
      'prosemirror-schema-list',
      'prosemirror-state',
      'prosemirror-tables',
      'prosemirror-trailing-node',
      'prosemirror-transform',
      'prosemirror-view',
    ],
  },
  build: {
    rollupOptions: {
      output: {
        // FR-25 — function form, NOT the object form it replaced.
        //
        // The object form listed only `@tiptap/starter-kit` + `@tiptap/vue-3`,
        // so the other seven tiptap packages (extension-mention, suggestion,
        // tiptap-markdown, …) were chunked wherever they were imported from —
        // the message-editor chunk. Both chunks then carried their OWN copy of
        // `prosemirror-model`, and a node built by one instance is rejected by
        // the other: picking a mention threw
        //   "Can not convert <mention, ' '> to a Fragment
        //    (looks like multiple versions of prosemirror-model were loaded)"
        // in EVERY editor (room chat and the in-call chat alike).
        //
        // Grouping the family keeps the editor in one cacheable chunk. ⚠️ It
        // does NOT make prosemirror single-instance — that is `resolve.dedupe`
        // above. This comment used to claim the fix, and the claim was wrong:
        // "in exactly ONE chunk" was satisfied while five copies sat inside
        // that chunk and the crash continued in production.
        manualChunks(id: string) {
          if (!id.includes('node_modules')) return
          if (/[\\/]node_modules[\\/](@tiptap[\\/]|prosemirror-|tiptap-markdown|y-prosemirror)/.test(id)) {
            return 'tiptap'
          }
          if (/[\\/]node_modules[\\/]vuetify[\\/]/.test(id)) return 'vuetify'
          if (/[\\/]node_modules[\\/]mediasoup-client[\\/]/.test(id)) return 'mediasoup'
          if (/[\\/]node_modules[\\/]d3-(array|scale|shape|time|time-format)[\\/]/.test(id)) {
            return 'charts'
          }
        },
      },
    },
  },
  server: {
    port: 5000,
    proxy: {
      [deploymentPath('/api', basePath)]: {
        rewrite: stripBase,
        target: apiTarget,
        changeOrigin: true,
      },
      [deploymentPath('/ws', basePath)]: {
        rewrite: stripBase,
        target: apiTarget,
        changeOrigin: true,
        ws: true,
        rewriteWsOrigin: true,
      },
    },
  },
})
