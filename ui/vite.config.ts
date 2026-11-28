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
  },
  build: {
    rollupOptions: {
      output: {
        // FR-136 — emit `.mjs` assets as `.js`. Production nginx maps only `js` to
        // `application/javascript`, so a `.mjs` file (the MapLibre worker, loaded as a
        // module worker) is served as `application/octet-stream`, and the browser's
        // strict module MIME check refuses it: the globe never draws.
        assetFileNames: (info) =>
          (info.names?.[0] ?? info.name ?? '').endsWith('.mjs')
            ? 'assets/[name]-[hash].js'
            : 'assets/[name]-[hash][extname]',
        manualChunks(id: string) {
          if (!id.includes('node_modules')) return
          if (/[\\/]node_modules[\\/]vuetify[\\/]/.test(id)) return 'vuetify'
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
