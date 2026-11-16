// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
import { appPath } from '@/utils/deployment'

let oauthRedirecting = false
let decided = false

export function extractDeviceCodeFromPath(fullPath: string | null | undefined): string | null {
  if (!fullPath) return null
  try {
    const u = new URL(fullPath, 'https://meshharbor.local')
    if (!u.pathname.endsWith('/device-login')) return null
    const raw = (u.searchParams.get('code') ?? '').replace(/[\s-]/g, '').toUpperCase()
    return /^[BCDFGHJKLMNPQRSTVWXZ]{10}$/.test(raw) ? `${raw.slice(0, 5)}-${raw.slice(5)}` : null
  } catch {
    return null
  }
}

export function currentPendingDeviceCode(currentFullPath?: string): string | null {
  const direct = extractDeviceCodeFromPath(
    currentFullPath ?? (typeof window !== 'undefined' ? window.location.pathname + window.location.search : ''),
  )
  if (direct) return direct
  try {
    return extractDeviceCodeFromPath(sessionStorage.getItem('pending_redirect'))
  } catch {
    return null
  }
}

function sendPresence(code: string, state: 'open' | 'oauth' | 'closed', beacon = false): void {
  const url = appPath('/api/native/device-login/presence')
  const payload = JSON.stringify({ user_code: code, state })
  if (beacon && typeof navigator !== 'undefined' && typeof navigator.sendBeacon === 'function') {
    navigator.sendBeacon(url, new Blob([payload], { type: 'application/json' }))
    return
  }
  if (typeof fetch === 'function') {
    void fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: payload,
      keepalive: true,
    }).catch(() => {})
  }
}

export function markDeviceLoginOAuthRedirect(): void {
  oauthRedirecting = true
  const code = currentPendingDeviceCode()
  if (code) sendPresence(code, 'oauth', true)
}

export function markDeviceLoginDecided(): void {
  decided = true
}

export function onDeviceLoginRouteChanged(fullPath: string): void {
  oauthRedirecting = false
  const code = currentPendingDeviceCode(fullPath)
  if (code && !decided) {
    sendPresence(code, 'open', false)
  }
}

export function onDeviceLoginPageHide(fullPath?: string): void {
  if (oauthRedirecting || decided) return
  const code = currentPendingDeviceCode(fullPath)
  if (code) {
    sendPresence(code, 'closed', true)
  }
}
