import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { describe, expect, it } from 'vitest'

const REPO_ROOT = resolve(__dirname, '../../..')
const DOCKERFILE = readFileSync(resolve(REPO_ROOT, 'Dockerfile'), 'utf8')
const NGINX_POD = readFileSync(resolve(REPO_ROOT, 'files/nginx-pod.conf'), 'utf8')

describe('subpath deployment contract (PersonalWeb /meshharbor/)', () => {
  it('wires VITE_BASE_PATH into the ui-builder stage and strips root-only /home on subpath images', () => {
    expect(DOCKERFILE).toMatch(/FROM oven\/bun:1 AS ui-builder[\s\S]*?ARG VITE_BASE_PATH=\/[\s\S]*?ENV VITE_BASE_PATH=\$\{VITE_BASE_PATH\}[\s\S]*?RUN bun run build/)
    expect(DOCKERFILE).toMatch(/FROM debian:trixie-slim AS runtime[\s\S]*?ARG VITE_BASE_PATH=\/[\s\S]*?if \[ "\$VITE_BASE_PATH" != "\/" \]; then rm -rf \/var\/www\/meshharbor\/home; fi/)
  })

  it('falls back location = / to /index.html when /home/index.html is absent on subpath images', () => {
    const rootLoc = NGINX_POD.match(/location = \/ \{([^}]*)\}/)
    expect(rootLoc).not.toBeNull()
    expect(rootLoc![1]).toContain('try_files $root_doc /index.html =404;')
    expect(rootLoc![1]).not.toContain('add_header')
  })

  it('preserves upstream X-Forwarded-Proto and upgrades shared-SSH WebSockets', () => {
    expect(NGINX_POD).toMatch(/map \$http_x_forwarded_proto \$forwarded_proto \{[\s\S]*?default \$http_x_forwarded_proto;/)
    expect(NGINX_POD).not.toContain('proxy_set_header X-Forwarded-Proto $scheme;')
    expect(NGINX_POD).toContain('location ~ "^/api/device-shares/[0-9A-Fa-f]{24}/ssh/ws$"')
  })
})
