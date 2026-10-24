/** Only an explicitly selected disposable/synthetic agent may be exercised.
 * Run with CI=1 and task-owned Playwright output/report paths. No desktop input,
 * native picker, existing browser attachment, enrollment or fixture provisioning.
 */
import { expect, test, type BrowserContext, type Page } from '@playwright/test'

export const BASE_URL = (process.env.E2E_BASE_URL || 'http://localhost:5000').replace(/\/+$/, '')
export const API_URL = (
  process.env.E2E_API_URL || (process.env.E2E_BASE_URL ? BASE_URL : 'http://localhost:5001')
).replace(/\/+$/, '')
export const TENANT_ID = process.env.E2E_AGENT_E2E_TENANT_ID || ''
export const AGENT_ID = process.env.E2E_AGENT_E2E_AGENT_ID || ''
export const REMOTE_DIR = process.env.E2E_AGENT_E2E_REMOTE_DIR || ''
export const fixtureConfigured = Boolean(TENANT_ID && AGENT_ID)

/** Best-effort attachment only: never serializes SDP, addresses, credentials,
 * stats IDs, error messages, or the raw browser configuration/report. */
async function attachRtcDiagnostic(page: Page, outcome: 'passed' | 'failed') {
  let timer: ReturnType<typeof setTimeout> | undefined
  let diagnostic: unknown = { available: false, reason: 'diagnostic-unavailable' }
  try {
    diagnostic = await Promise.race([
      page.evaluate(async () => {
        const pc = (window as unknown as { __roomler_remote_pc?: RTCPeerConnection }).__roomler_remote_pc
        if (!pc) return { available: false, reason: 'peer-connection-absent' }
        const choice = (value: unknown, allowed: string[]) => typeof value === 'string' && allowed.includes(value) ? value : 'unknown'
        const counter = (value: unknown) => typeof value === 'number' && Number.isFinite(value) && value >= 0 ? Math.min(value, Number.MAX_SAFE_INTEGER) : 0
        const safeUrl = (value: unknown) => {
          if (typeof value !== 'string' || value.length > 2048) return '<invalid-ice-url>'
          const m = /^(stun|stuns|turn|turns):([^/?#]+)(?:\?([^#]*))?$/i.exec(value)
          if (!m) return '<invalid-ice-url>'
          // Remove userinfo; emit only DNS names or an IP-redacted placeholder.
          const authority = m[2]!.slice(m[2]!.lastIndexOf('@') + 1)
          const ipv6 = /^\[[^\]]+\](?::([0-9]{1,5}))?$/.exec(authority)
          const hostPort = /^([a-z0-9.-]+)(?::([0-9]{1,5}))?$/i.exec(authority)
          if (!ipv6 && !hostPort) return '<invalid-ice-url>'
          const host = ipv6 ? '<ip-redacted>' : /^(?:[0-9.]+|0x[0-9a-f]+)$/i.test(hostPort![1]!) ? '<ip-redacted>' : hostPort![1]!.toLowerCase()
          const port = ipv6 ? ipv6[1] : hostPort![2]
          if (port && (+port < 1 || +port > 65535)) return '<invalid-ice-url>'
          const transport = new URLSearchParams(m[3] ?? '').get('transport')
          return `${m[1]!.toLowerCase()}:${host}${port ? ':' + port : ''}${transport === 'udp' || transport === 'tcp' ? '?transport=' + transport : ''}`
        }
        const config = pc.getConfiguration()
        const urls = (config.iceServers ?? []).flatMap((server) => typeof server.urls === 'string' ? [server.urls] : server.urls).slice(0, 32).map(safeUrl)
        const report = await pc.getStats()
        const candidates = new Map<string, { type: string; protocol: string }>()
        const localCounts: Record<string, number> = {}, remoteCounts: Record<string, number> = {}, pairCounts: Record<string, number> = {}
        const selected = new Set<string>()
        report.forEach((entry: Record<string, unknown>) => {
          if (entry.type === 'transport' && typeof entry.selectedCandidatePairId === 'string') selected.add(entry.selectedCandidatePairId)
          if (entry.type !== 'local-candidate' && entry.type !== 'remote-candidate') return
          const type = choice(entry.candidateType, ['host', 'srflx', 'prflx', 'relay'])
          const protocol = choice(entry.protocol, ['udp', 'tcp'])
          if (typeof entry.id === 'string') candidates.set(entry.id, { type, protocol })
          const counts = entry.type === 'local-candidate' ? localCounts : remoteCounts
          const key = `${type}/${protocol}`; counts[key] = (counts[key] ?? 0) + 1
        })
        const pairs: { selected: boolean; nominated: boolean; state: string; localType: string; remoteType: string; localProtocol: string; remoteProtocol: string; bytesSent: number; bytesReceived: number }[] = []
        report.forEach((entry: Record<string, unknown>) => {
          if (entry.type !== 'candidate-pair') return
          const state = choice(entry.state, ['frozen', 'waiting', 'in-progress', 'failed', 'succeeded'])
          pairCounts[state] = (pairCounts[state] ?? 0) + 1
          const isSelected = entry.selected === true || typeof entry.id === 'string' && selected.has(entry.id)
          if ((!isSelected && entry.nominated !== true) || pairs.length >= 16) return
          const local = candidates.get(String(entry.localCandidateId)), remote = candidates.get(String(entry.remoteCandidateId))
          pairs.push({ selected: isSelected, nominated: entry.nominated === true, state,
            localType: local?.type ?? 'unknown', remoteType: remote?.type ?? 'unknown',
            localProtocol: local?.protocol ?? 'unknown', remoteProtocol: remote?.protocol ?? 'unknown',
            bytesSent: counter(entry.bytesSent), bytesReceived: counter(entry.bytesReceived) })
        })
        return { available: true,
          connectionState: choice(pc.connectionState, ['new', 'connecting', 'connected', 'disconnected', 'failed', 'closed']),
          iceConnectionState: choice(pc.iceConnectionState, ['new', 'checking', 'connected', 'completed', 'disconnected', 'failed', 'closed']),
          iceGatheringState: choice(pc.iceGatheringState, ['new', 'gathering', 'complete']),
          signalingState: choice(pc.signalingState, ['stable', 'have-local-offer', 'have-remote-offer', 'have-local-pranswer', 'have-remote-pranswer', 'closed']),
          localDescriptionType: pc.localDescription ? choice(pc.localDescription.type, ['offer', 'answer', 'pranswer', 'rollback']) : null,
          remoteDescriptionType: pc.remoteDescription ? choice(pc.remoteDescription.type, ['offer', 'answer', 'pranswer', 'rollback']) : null,
          iceTransportPolicy: choice(config.iceTransportPolicy, ['all', 'relay']), iceServerUrls: urls,
          localCandidateCounts: localCounts, remoteCandidateCounts: remoteCounts, candidatePairCounts: pairCounts, selectedOrNominatedPairs: pairs }
      }),
      new Promise<never>((_, reject) => { timer = setTimeout(() => reject(new Error('rtc-diagnostic-budget')), 2000) }),
    ])
  } catch { /* Fixed unavailable result; exceptions can contain private URLs. */ }
  finally { if (timer !== undefined) clearTimeout(timer) }
  try {
    await test.info().attach('rtc-connection-diagnostic', {
      body: Buffer.from(JSON.stringify({ waitForConnected: outcome, diagnostic }, null, 2)), contentType: 'application/json',
    })
  } catch { /* Diagnostic failure must neither mask the original error nor fail a passed connection. */ }
}

export async function connectFixture(page: Page, context: BrowserContext) {
  expect(TENANT_ID, 'exact fixture tenant ID required').toMatch(/^[a-f\d]{24}$/i)
  expect(AGENT_ID, 'exact synthetic fixture agent ID required').toMatch(/^[a-f\d]{24}$/i)
  await context.route('https://purestat.ai/**', (route) => route.abort())
  const login = await context.request.post(`${API_URL}/api/auth/login`, {
    data: {
      email: process.env.E2E_AGENT_E2E_ADMIN_EMAIL || 'agent-e2e-admin@roomler.local',
      password: process.env.E2E_AGENT_E2E_ADMIN_PASSWORD || 'agent-e2e-bootstrap-pw-2026',
    },
    timeout: 15_000,
  })
  // Never dump auth response bodies or tokens into traces/assertion messages.
  expect(login.status(), 'fixture operator login status').toBe(200)
  await expect.poll(async () => {
    const response = await context.request.get(
      `${API_URL}/api/tenant/${TENANT_ID}/agent/${AGENT_ID}`, { timeout: 10_000 },
    )
    expect(response.status(), 'exact fixture agent lookup status').toBe(200)
    const agent = await response.json() as { id: string; is_online: boolean }
    expect(agent.id, 'server returned a different fixture').toBe(AGENT_ID)
    return agent.is_online === true
  }, { timeout: 30_000, message: 'selected synthetic fixture never became online' }).toBe(true)
  await context.addInitScript(() => localStorage.setItem('roomler-signed-in', '1'))
  await page.goto(`${BASE_URL}/tenant/${TENANT_ID}/agent/${AGENT_ID}/remote`)
  const connect = page.getByRole('button', { name: /^connect$/i }).first()
  await expect(connect).toBeVisible({ timeout: 30_000 })
  await connect.click()
  try {
    await expect(page.locator('text=/^connected$/i').first()).toBeVisible({ timeout: 60_000 })
  } catch (error) {
    await attachRtcDiagnostic(page, 'failed')
    throw error // Preserve the exact original assertion; no skip or weakened oracle.
  }
  await attachRtcDiagnostic(page, 'passed')
}
