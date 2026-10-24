// SPDX-License-Identifier: AGPL-3.0-only
import { describe, expect, it } from 'vitest'
import { deploymentPath, deploymentWebSocketUrl, normalizeBasePath, stripDeploymentBase } from '@/utils/deploymentPath'

describe('deployment path isolation', () => {
  it('preserves root deployment URLs by default', () => {
    expect(normalizeBasePath()).toBe('/')
    expect(deploymentPath('/api/auth/me')).toBe('/api/auth/me')
    expect(deploymentPath('/docs/')).toBe('/docs/')
    expect(deploymentWebSocketUrl('https://example.test', null)).toBe('wss://example.test/ws')
  })
  it('isolates API, assets, redirects and downloads under the selected base', () => {
    expect(normalizeBasePath('/meshharbor')).toBe('/meshharbor/')
    for (const path of ['/api/auth/me', '/api/tenant/abc/file/def/download', '/docs/', '/sw.js', '/tenant/abc?tab=files#recent']) {
      expect(deploymentPath(path, '/meshharbor/')).toBe(`/meshharbor${path}`)
    }
  })
  it('builds same-origin WebSockets with encoded affinity', () => {
    expect(deploymentWebSocketUrl('https://www.itachi.fans', 'abc', '/meshharbor/')).toBe('wss://www.itachi.fans/meshharbor/ws?tid=abc')
    expect(deploymentWebSocketUrl('http://localhost:5000', null, '/meshharbor/')).toBe('ws://localhost:5000/meshharbor/ws')
  })
  it('extracts route paths only from the correct deployment', () => {
    expect(stripDeploymentBase('/meshharbor/tenant/abc', '/meshharbor/')).toBe('/tenant/abc')
    expect(stripDeploymentBase('/meshharbor', '/meshharbor/')).toBe('/')
    expect(stripDeploymentBase('/tenant/abc', '/meshharbor/')).toBeNull()
    expect(stripDeploymentBase('/meshharbor-other/tenant/abc', '/meshharbor/')).toBeNull()
    expect(stripDeploymentBase('/tenant/abc')).toBe('/tenant/abc')
  })
  it('rejects external, ambiguous and traversal paths', () => {
    for (const base of ['https://evil.test/', '//evil.test/', '/../', '/meshharbor?x/']) {
      expect(() => normalizeBasePath(base)).toThrow()
    }
    for (const path of ['https://evil.test/', '//evil.test/', '/\\evil.test/', '/../api', '/%2e%2e/api']) {
      expect(() => deploymentPath(path, '/meshharbor/')).toThrow()
    }
  })
})
