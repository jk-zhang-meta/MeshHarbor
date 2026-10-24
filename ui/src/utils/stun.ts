// SPDX-License-Identifier: AGPL-3.0-only
// Public discovery only, never a relay or an iceTransportPolicy override.
// Match remote_control::turn_creds::default_stun_servers for API-unavailable
// browser fallback. Return fresh containers so a caller cannot poison defaults.
export function defaultStunServers(): { urls: string[] }[] {
  return [{ urls: ['stun:stun.cloudflare.com:3478', 'stun:stun.l.google.com:19302'] }]
}
