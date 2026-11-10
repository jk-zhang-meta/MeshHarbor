// Lists what the demo account can film, from the saved session (`record-demo.sh --login`): each
// org's id and role-relevant facts, and its devices by display name. Prints no cookie or token.
import { request } from '@playwright/test'
import { existsSync } from 'node:fs'
import { join } from 'node:path'
import { homedir } from 'node:os'

const base = process.env.E2E_BASE_URL || 'https://meshharbor.itachi.fans'
const state = process.env.E2E_STORAGE_STATE || join(homedir(), '.meshharbor-demo-state.json')
if (!existsSync(state)) {
  console.error(`no saved session at ${state}: run record-demo.sh --login first`)
  process.exit(1)
}
const ctx = await request.newContext({ baseURL: base, storageState: state })
const me = await ctx.get('/api/auth/me')
console.log(`signed in: ${me.ok() ? 'yes' : `NO (${me.status()})`}`)
const orgs = await (await ctx.get('/api/tenant')).json().catch(() => [])
for (const o of Array.isArray(orgs) ? orgs : []) {
  const r = await ctx.get(`/api/tenant/${o.id}/agent?per_page=100`)
  const b = r.ok() ? await r.json() : {}
  const list: Array<Record<string, unknown>> = b.items ?? (Array.isArray(b) ? b : [])
  console.log(`org ${o.id} (${list.length} devices, agent list ${r.status()})`)
  for (const a of list) {
    const rec = (a.caps as Record<string, unknown> | undefined)?.record
    console.log(`  ${a.is_online ? 'online ' : 'offline'}  ${String(a.os ?? '').padEnd(8)} ${String(a.display_name ?? a.name).padEnd(22)} record=${JSON.stringify(rec ?? null)}`)
  }
}
await ctx.dispose()
