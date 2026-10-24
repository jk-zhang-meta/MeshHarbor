// SPDX-License-Identifier: AGPL-3.0-only
/** Pure path rules shared by Vite configuration and the browser. */
export function normalizeBasePath(value = '/'): string {
  const path = value.endsWith('/') ? value : `${value}/`
  if (!/^\/(?:[A-Za-z0-9_-]+\/)*$/.test(path)) {
    throw new Error('VITE_BASE_PATH must be a root-relative directory path, such as /meshharbor/')
  }
  return path
}

export function deploymentPath(path: string, base = '/'): string {
  const prefix = normalizeBasePath(base)
  if (!path.startsWith('/') || path.startsWith('//') || path.includes('\\')) {
    throw new Error('Application paths must be root-relative, not external URLs')
  }
  const pathname = path.split(/[?#]/, 1)[0] || '/'
  const decoded = decodeURIComponent(pathname)
  if (decoded.includes('\\') || decoded.split('/').some((segment) => segment === '.' || segment === '..')) {
    throw new Error('Application paths cannot escape their deployment')
  }
  return `${prefix.slice(0, -1)}${path}`
}

export function stripDeploymentBase(pathname: string, base = '/'): string | null {
  const prefix = normalizeBasePath(base)
  if (prefix === '/') return pathname
  if (pathname === prefix.slice(0, -1)) return '/'
  return pathname.startsWith(prefix) ? `/${pathname.slice(prefix.length)}` : null
}

export function deploymentWebSocketUrl(origin: string, tenantId: string | null, base = '/'): string {
  const url = new URL(deploymentPath('/ws', base), origin)
  url.protocol = url.protocol === 'https:' ? 'wss:' : 'ws:'
  if (tenantId) url.searchParams.set('tid', tenantId)
  return url.toString()
}
