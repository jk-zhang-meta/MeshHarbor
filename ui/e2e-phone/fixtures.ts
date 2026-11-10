// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//
// FR-116 D6 — the phone smoke's synthetic organization: every `/api` call the
// signed-in routes make, answered from here. No backend, no database.
//
// Synthetic on purpose: no real machine names, and nothing key-shaped (no
// WireGuard keys, fingerprints or tokens) — the scanners read test files too.
import type { BrowserContext, Route } from '@playwright/test'

export const TID = 'aaaaaaaaaaaaaaaaaaaaaaaa'
export const UID = 'bbbbbbbbbbbbbbbbbbbbbbbb'
const OTHER = 'bbbbbbbbbbbbbbbbbbbbbbb2'
export const ROOM = 'e00000000000000000000002'
export const AGENT = 'c00000000000000000000002'

const DAY = 864e5
const ago = (ms: number) => new Date(Date.now() - ms).toISOString()
const daysAgo = (d: number) => ago(d * DAY)
const nowS = () => Math.floor(Date.now() / 1000)
const agentId = (n: number) => 'c00000000000000000000' + String(n).padStart(3, '0')

const user = {
  id: UID,
  email: 'alex@example.test',
  username: 'alex',
  display_name: 'Alex Admin',
  is_platform_admin: true,
  tutorial: { seen: true, done: ['welcome'] },
}
const tenants = [
  { id: TID, name: 'Acme Labs', slug: 'acme-labs', plan: 'business', owner_id: UID },
  { id: 'aaaaaaaaaaaaaaaaaaaaaaa2', name: 'Side Project', slug: 'side' },
]

const caps = (o: Record<string, unknown> = {}) => ({
  codecs: ['h264'],
  hw_encoders: [],
  has_input_permission: true,
  supports_clipboard: true,
  supports_file_transfer: true,
  max_simultaneous_sessions: 4,
  rpc: ['exec'],
  update_mode: 'self',
  ...o,
})
const policy = (o: Record<string, unknown> = {}) => ({
  consent_mode: 'prompt',
  prompt_owner: false,
  allowed_role_ids: [],
  allowed_user_ids: [],
  auto_terminate_idle_minutes: null,
  input_mode: 'free',
  rc_overlay: false,
  lock_on_end: null,
  ...o,
})
type A = Record<string, unknown> & { id: string; name: string; display_name?: string; os: string; is_online: boolean; last_seen_at: string }
const agents: A[] = [
  { id: agentId(1), tenant_id: TID, owner_user_id: UID, name: 'studio-mac-mini', display_name: 'Design Studio Mac', tags: ['design', 'studio'], machine_id: 'machine-01', os: 'macos', agent_version: '0.4.146', status: 'online', presence: 'online', is_online: true, last_seen_at: ago(30e3), access_policy: policy({ consent_mode: 'auto' }), capabilities: caps({ codecs: ['h264', 'h265'] }) },
  { id: agentId(2), tenant_id: TID, owner_user_id: UID, name: 'build-01', display_name: 'Build Server', tags: ['ci', 'linux', 'x86', 'rack-2'], machine_id: 'machine-02', os: 'linux', agent_version: '0.4.146', status: 'online', presence: 'online', is_online: true, last_seen_at: ago(12e3), access_policy: policy({ input_mode: 'exclusive', auto_terminate_idle_minutes: 30, lock_on_end: 'always', rc_overlay: true }), capabilities: caps({ codecs: ['h264', 'h265', 'av1'] }) },
  { id: agentId(3), tenant_id: TID, owner_user_id: OTHER, name: 'front-desk-pc', display_name: 'Reception PC (front desk, ground floor)', tags: ['front-desk'], machine_id: 'machine-03', os: 'windows', agent_version: '0.4.146', status: 'online', presence: 'stale', is_online: false, last_seen_at: ago(80e3), access_policy: policy({ consent_mode: 'prompt_then_email' }), capabilities: caps() },
  { id: agentId(4), tenant_id: TID, owner_user_id: UID, name: 'lab-pi-arm64', tags: [], machine_id: 'machine-04', os: 'linux', agent_version: '0.4.140', ephemeral: true, status: 'offline', presence: 'offline', is_online: false, last_seen_at: daysAgo(2), access_policy: policy(), capabilities: caps(), remote_config: { state: 'pending' } },
  { id: agentId(5), tenant_id: TID, owner_user_id: OTHER, name: 'finance-laptop', display_name: 'Finance Laptop — CFO office, 3rd floor', tags: ['finance', 'laptop'], machine_id: 'machine-05', os: 'windows', agent_version: '0.4.138', status: 'online', presence: 'online', is_online: true, last_seen_at: ago(5e3), token_expires_at: new Date(Date.now() + 12 * DAY).toISOString(), access_policy: policy({ consent_mode: 'email' }), capabilities: caps() },
]
const tunnelClients = [
  { id: agentId(101), tenant_id: TID, owner_user_id: UID, name: 'my-laptop', display_name: 'My laptop', tags: ['dev'], machine_id: 'machine-11', os: 'linux', client_version: '0.4.146', status: 'online', last_seen_at: ago(60e3) },
]
const overlayNodes = agents.map((a, i) => ({
  id: 'd0000000000000000000' + String(i).padStart(4, '0'),
  name: a.name,
  overlay_ip: `100.65.4.${i + 2}`,
  kind: 'agent',
  advertised_routes: i === 1 ? ['10.66.24.0/24'] : [],
  approved_routes: [],
  is_exit_node: false,
  can_be_exit_node: i === 1,
  online: a.is_online,
  will_rejoin: true,
  last_seen_at: a.last_seen_at,
  agent_id: a.id,
  os: a.os,
}))
function deviceRows() {
  const rows = agents.map((a, i) => ({
    kind: 'agent', id: a.id, owner_user_id: a.owner_user_id, name: a.name, display_name: a.display_name, tags: a.tags,
    machine_id: a.machine_id, os: a.os, version: a.agent_version, status: a.status, presence: a.presence,
    is_online: a.is_online, last_seen_at: a.last_seen_at, created_at: daysAgo(90),
    overlay_ip: overlayNodes[i].overlay_ip, overlay_node_id: overlayNodes[i].id,
    magic_dns_name: a.name, magic_dns_fqdn: `${a.name}.acme.example`,
  }))
  const trows = tunnelClients.map((c) => ({
    kind: 'tunnel_client', id: c.id, owner_user_id: c.owner_user_id, name: c.name, display_name: c.display_name, tags: c.tags,
    machine_id: c.machine_id, os: c.os, version: c.client_version, status: c.status, presence: 'online', is_online: true,
    last_seen_at: c.last_seen_at, created_at: daysAgo(30),
  }))
  return [...rows, ...trows]
}
function page<T>(items: T[]) {
  return { items, total: items.length, page: 1, per_page: 25, total_pages: 1 }
}

const members = [
  { id: 'f00000000000000000000001', user_id: UID, display_name: 'Alex Admin', nickname: null, email: 'alex@example.test', role_ids: ['r00000000000000000000002'], joined_at: daysAgo(400) },
  { id: 'f00000000000000000000002', user_id: OTHER, display_name: 'Sam Support', nickname: 'sam', email: 'sam.support@example.test', role_ids: ['r00000000000000000000001'], joined_at: daysAgo(90) },
  { id: 'f00000000000000000000003', user_id: 'bbbbbbbbbbbbbbbbbbbbbbb3', display_name: 'Maximiliane Oberhuber-Kowalczyk', nickname: 'max', email: 'maximiliane.oberhuber-kowalczyk@subsidiary.example.test', role_ids: ['r00000000000000000000001'], joined_at: daysAgo(3) },
]
const roles = [
  { id: 'r00000000000000000000002', tenant_id: TID, name: 'Administrator', description: 'Everything, including roles and devices', permissions: 1 << 23, position: 0, is_managed: true, is_default: false, color: 0xdc2626 },
  { id: 'r00000000000000000000001', tenant_id: TID, name: 'Remote Operator', description: 'Remote-controls the support fleet', permissions: 1 | (1 << 7) | (1 << 11), position: 10, is_managed: false, is_default: false, color: 0x7c3aed },
]
const invites = [
  { id: 'i00000000000000000000001', code: 'INVITE01', tenant_id: TID, inviter_id: UID, target_email: 'new.hire.with.a.long.address@subsidiary.example.test', max_uses: 1, use_count: 0, status: 'active', assign_role_ids: [], created_at: daysAgo(1) },
  { id: 'i00000000000000000000002', code: 'INVITE02', tenant_id: TID, inviter_id: UID, max_uses: null, use_count: 14, status: 'active', assign_role_ids: [], created_at: daysAgo(30) },
]
const files = [
  { id: 'd00000000000000000000001', tenant_id: TID, filename: 'quarterly-infrastructure-review-2026-Q3-final-v7 (1).pdf', content_type: 'application/pdf', size: 4812331, uploaded_by: UID, created_at: daysAgo(2), room_id: ROOM, room_name: 'ops-war-room' },
  { id: 'd00000000000000000000002', tenant_id: TID, filename: 'carrier-ladder.png', content_type: 'image/png', size: 182204, uploaded_by: OTHER, created_at: daysAgo(5) },
]
const rooms = [
  { id: 'e00000000000000000000001', tenant_id: TID, name: 'general', member_count: 4, is_member: true, parent_id: null },
  { id: ROOM, tenant_id: TID, name: 'ops-war-room', member_count: 3, is_member: true, parent_id: null },
]
const roomFull = {
  id: ROOM, tenant_id: TID, name: 'ops-war-room', path: 'ops-war-room', is_open: true, visibility: 'public',
  is_archived: false, is_read_only: false, is_default: false, has_media: true, member_count: 3, is_member: true,
  conference_status: 'idle', participant_count: 0,
}
const message = (i: number, mine: boolean, content: string) => ({
  id: 'm0000000000000000000000' + i, room_id: ROOM, author_id: mine ? UID : OTHER,
  author_name: mine ? 'Alex Admin' : 'Sam Support', content, is_thread_root: false, is_pinned: false,
  is_edited: false, reaction_summary: [], attachments: [], created_at: ago((10 - i) * 6e5), updated_at: ago(0),
})
const messages = {
  items: [
    message(1, false, 'The build server is back on the mesh — direct carrier again.'),
    message(2, true, 'Logs: https://example.test/a/very/long/path/that/never/breaks/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'),
    message(3, false, 'Pinned the runbook for tonight.'),
  ].reverse(),
  total: 3,
}
const overlayAcl = {
  items: [
    {
      id: 'f0000000000000000000a001', tenant_id: TID, name: 'Ops reach the build LAN', enabled: true,
      sources: [{ kind: 'role_id', id: 'r00000000000000000000001' }], via: [{ kind: 'all_nodes' }],
      destinations: [{ cidr: '10.66.24.0/24', port_range: { low: 1, high: 65535 }, proto: 'any' }],
      created_at: daysAgo(9), updated_at: daysAgo(9),
    },
  ],
  total: 1, page: 1, per_page: 50, mode: 'warn',
}
const execAudit = {
  items: Array.from({ length: 3 }, (_, i) => ({
    tenant_id: TID, agent_id: AGENT, user_id: UID, request_id: 'req' + i, source: 'console', shell: 'sh',
    command: i === 0 ? "journalctl -u meshharbord --since '1 hour ago' --no-pager | grep -E 'overlay|derp|carrier' | tail -n 200" : 'uptime',
    at: ago(i * 3.6e6), exit_code: 0, duration_ms: 120 + i, denied: null,
  })),
  total: 3,
}
const series = (keys: string[]) =>
  Array.from({ length: 28 }, (_, i) =>
    Object.fromEntries([['t', nowS() - (27 - i) * 6 * 3600], ...keys.map((k, j) => [k, 5 + ((i + j) % 7)])]),
  )

function json(route: Route, body: unknown, status = 200) {
  return route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) })
}

/** Every `/api` call the signed-in routes make. Anything else answers 404 and
 *  is collected in `unmocked`, so a page that grows a new call shows up in the
 *  smoke's annotations instead of passing silently on an error state. */
export async function installMocks(context: BrowserContext, unmocked: Set<string>) {
  await context.addInitScript(([uid, tid]) => {
    localStorage.setItem('meshharbor-signed-in', '1')
    localStorage.setItem('meshharbor-tour-seen:' + uid, '1')
    localStorage.setItem('meshharbor-current-tenant', tid)
  }, [UID, TID])
  // A test browser must never load the analytics script: it would record
  // fake visits (standing rule).
  await context.route('**/purestat.ai/**', (r) => r.abort())
  await context.routeWebSocket(/\/ws/, () => {})
  await context.route(
    (url) => url.pathname.startsWith('/api/'),
    async (route) => {
      const req = route.request()
      const u = new URL(req.url())
      const p = u.pathname.replace(/^\/api/, '')
      const T = `/tenant/${TID}`
      if (req.method() !== 'GET') return json(route, {})
      const table: Record<string, unknown> = {
        '/auth/me': user,
        '/capabilities': { modules: ['chat', 'conference', 'fleet', 'remote', 'network', 'saas'], compiled: ['chat', 'conference', 'fleet', 'remote', 'network', 'saas'], version: 'smoke' },
        '/tenant': tenants,
        [`${T}/member/me`]: { permissions: -1, is_owner: true },
        [`${T}/agent`]: { items: agents, total: agents.length, page: 1, per_page: 100, total_pages: 1 },
        [`${T}/device`]: page(deviceRows()),
        [`${T}/overlay-node`]: { items: overlayNodes, total: overlayNodes.length },
        [`${T}/tunnel-client`]: { items: tunnelClients, total: tunnelClients.length },
        [`${T}/member`]: page(members),
        [`${T}/role`]: roles,
        [`${T}/invite`]: page(invites),
        [`${T}/file`]: page(files),
        [`${T}/room`]: rooms,
        [`${T}/room/${ROOM}`]: roomFull,
        [`${T}/room/${ROOM}/message`]: messages,
        [`${T}/room/${ROOM}/member`]: { items: members.map((m) => ({ ...m, id: m.user_id })), total: members.length },
        [`${T}/overlay-acl`]: overlayAcl,
        [`${T}/tunnel-policy`]: { items: [], total: 0, page: 1, per_page: 50, total_pages: 1 },
        [`${T}/exec-audit`]: execAudit,
        [`${T}/ssh-audit`]: { items: [], total: 0 },
        [`${T}/agent/enroll-key`]: { items: [] },
        [`${T}/exec-settings`]: { remote_exec_enabled: true, exec_require_system: false },
        [`${T}/ssh-settings`]: { remote_ssh_enabled: false },
        [`${T}/external-access`]: { enabled: false, devices: [] },
        [`${T}/keep-busy-settings`]: { keep_busy_denied: false, keep_busy_default_pattern: 'circle' },
        [`${T}/keep-busy-history`]: [],
        [`${T}/rc-session-policy`]: { clipboard: 'on', files: 'ask', audio: 'off' },
        [`${T}/ephemeral-key-settings`]: { ephemeral_keys_enabled: false },
        [`${T}/rc-session-limits`]: { max_secs: 3600, idle_secs: null },
        [`${T}/stats/machines`]: { enabled: true, range: '7d', series: series(['online']), agents: [], uptime: [] },
        [`${T}/stats/calls`]: { enabled: true, range: '7d', series: series(['calls', 'minutes']), totals: { calls: 12, minutes: 340, participant_minutes: 800 } },
        [`${T}/stats/tunnels`]: { enabled: true, range: '7d', series: series(['flows']) },
        [`${T}/stats/usage`]: { enabled: true, range: '7d', watchers_complete: true, users: [] },
        '/agent/latest-release': [{ tag_name: 'agent-v0.4.146', published_at: daysAgo(3) }],
        '/notification': { items: [] },
        '/notification/unread-count': { count: 0 },
        '/user/unread-summary': { tenants: [] },
      }
      if (p in table) return json(route, table[p])
      if (/\/room\/[0-9a-f]{24}\/message\/unread-count$/.test(p)) return json(route, { count: 0 })
      const one = p.match(/^\/tenant\/[0-9a-f]{24}\/agent\/([0-9a-f]{24})$/)
      if (one) {
        const a = agents.find((x) => x.id === one[1])
        return a ? json(route, a) : json(route, { error: 'not found' }, 404)
      }
      unmocked.add(`GET ${p}`)
      return json(route, { error: 'not mocked' }, 404)
    },
  )
}
