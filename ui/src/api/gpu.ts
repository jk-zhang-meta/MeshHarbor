// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
import { api } from '@/api/client'

export type GpuState =
  | 'free'
  | 'busy'
  | 'held_idle'
  | 'unattributed'
  | 'unknown'

export type GpuFreshness = 'fresh' | 'stale' | 'offline'

export type GpuHostStatus =
  | 'ok'
  | 'no_gpu'
  | 'driver_missing'
  | 'driver_reboot_pending'
  | 'limited'
  | 'off_local'
  | 'sampler_stalled'
  | 'driver_hung'
  | 'unavailable'
  | 'unknown'

export type GpuProcsState = 'ok' | 'partial' | 'off' | 'unsupported' | 'unknown'

export type GpuHostSource = 'org' | 'invited' | 'shared'

export type GpuRange = '1h' | '24h' | '7d' | '30d'

export type GpuBotKind = 'feishu' | 'dingtalk' | 'wecom' | 'webhook'

export type GpuRuntimeKind =
  | 'nvidia'
  | 'ascend'
  | 'amd'
  | 'tpu'
  | 'intel'
  | 'apple'
  | 'pci'

export interface GpuFaultReason {
  scope: string
  severity: 'critical' | 'warning' | string
  code: string
  device_uuid?: string | null
  device_idx?: number | null
  summary: string
}

export interface GpuInventoryCard {
  uuid: string
  idx: number
  name?: string | null
  vendor?: string | null
  mem_total_mb?: number | null
  pci_bus?: string | null
  unified?: boolean
}

export interface GpuInventory {
  backend?: string | null
  driver_version?: string | null
  gpus: GpuInventoryCard[]
  status?: GpuHostStatus
  status_detail?: string | null
}

export interface GpuShareSummary {
  gpu_total: number
  gpu_free: number
  status: GpuHostStatus
}

export interface GpuProc {
  pid: number
  user?: string | null
  name?: string | null
  mem_mb?: number | null
  sm_pct?: number | null
  cpu_pct?: number | null
  started_at?: number | null
  container?: string | null
  kind?: string | null
}

export interface GpuHostLoad {
  cpu_pct?: number | null
  load1?: number | null
  load5?: number | null
  load15?: number | null
  cpu_count?: number | null
  mem_used_mb?: number | null
  mem_total_mb?: number | null
  swap_used_mb?: number | null
  swap_total_mb?: number | null
  disk_root_used_gb?: number | null
  disk_root_total_gb?: number | null
  net_rx_bps?: number | null
  net_tx_bps?: number | null
}

export const APP_LEVEL_XIDS: readonly number[] = [13, 31, 43, 45]

const FAULT_HOST_STATUSES = new Set<string>([
  'driver_missing',
  'driver_reboot_pending',
  'driver_hung',
  'sampler_stalled',
  'unavailable',
])

const XID_DESCRIPTIONS: Record<number, string> = {
  13: 'Graphics engine exception',
  31: 'GPU memory page fault',
  32: 'Corrupted command stream',
  43: 'GPU stopped processing',
  45: 'Preemptive cleanup after prior fault',
  48: 'Double-bit ECC error (DBE)',
  62: 'Internal micro-controller halt',
  63: 'ECC row remapping event',
  64: 'ECC row remapper failure',
  74: 'NVLink error',
  79: 'GPU fell off the bus',
  92: 'High single-bit ECC rate',
  94: 'Contained ECC error',
  95: 'Uncontained ECC error (reset required)',
  119: 'GSP RPC timeout',
  120: 'GSP error',
}

const SAFE_CUDA_ID_RE = /^[A-Za-z0-9._:-]{1,128}$/

export function isSafeCudaUuid(uuid: string): boolean {
  return SAFE_CUDA_ID_RE.test(uuid)
}

export function shellQuoteSingle(val: string): string {
  return `'${val.replace(/'/g, "'\\''")}'`
}

export function decodeNvidiaXid(code: number): string | null {
  return XID_DESCRIPTIONS[code] ?? null
}

export function cardRuntimeKind(
  host: Pick<GpuHostView, 'backend'> | null | undefined,
  g: Pick<GpuCardView, 'backend' | 'uuid' | 'name'>,
): GpuRuntimeKind {
  const b = (g.backend || host?.backend || '').toLowerCase()
  const uuid = g.uuid || ''
  const name = (g.name || '').toLowerCase()
  if (b === 'ascend' || uuid.startsWith('ASCEND-') || name.includes('ascend')) return 'ascend'
  if (b === 'tpu' || uuid.startsWith('TPU-') || name.includes('tpu')) return 'tpu'
  if (b === 'pci' || uuid.startsWith('PCI-')) return 'pci'
  if (b === 'amd' || b === 'rocm') return 'amd'
  if (b === 'intel') return 'intel'
  if (b === 'apple') return 'apple'
  return 'nvidia'
}

export function isExportableRuntime(rt: GpuRuntimeKind): boolean {
  return rt === 'nvidia' || rt === 'ascend' || rt === 'amd'
}

export function cardFaultReasons(g: GpuCardView): GpuFaultReason[] {
  if (g.fault_reasons && g.fault_reasons.length > 0) {
    return g.fault_reasons
  }
  const reasons: GpuFaultReason[] = []
  if (g.lost) {
    reasons.push({
      scope: 'card',
      severity: 'critical',
      code: 'lost',
      device_uuid: g.uuid,
      device_idx: g.idx,
      summary: 'Accelerator fell off the bus (lost)',
    })
  }
  if (g.xid_errors && g.xid_errors.length > 0) {
    const anyHw = g.xid_errors.some((c) => !APP_LEVEL_XIDS.includes(c))
    const formatted = g.xid_errors
      .map((c) => {
        const desc = decodeNvidiaXid(c)
        return desc ? `Xid ${c} (${desc})` : `Xid ${c}`
      })
      .join(', ')
    reasons.push({
      scope: 'card',
      severity: anyHw ? 'critical' : 'warning',
      code: anyHw ? 'xid' : 'xid_app',
      device_uuid: g.uuid,
      device_idx: g.idx,
      summary: formatted,
    })
  }
  if (g.ecc_uncorrected != null && g.ecc_uncorrected > 0) {
    reasons.push({
      scope: 'card',
      severity: 'critical',
      code: 'ecc_uncorrected',
      device_uuid: g.uuid,
      device_idx: g.idx,
      summary: `Uncorrected ECC errors: ${g.ecc_uncorrected}`,
    })
  }
  if (g.remap_failure) {
    reasons.push({
      scope: 'card',
      severity: 'critical',
      code: 'remap_failure',
      device_uuid: g.uuid,
      device_idx: g.idx,
      summary: 'Memory row remapping failed (hardware RMA required)',
    })
  } else if (g.remap_pending) {
    reasons.push({
      scope: 'card',
      severity: 'critical',
      code: 'remap_pending',
      device_uuid: g.uuid,
      device_idx: g.idx,
      summary: 'Memory row remapping pending (GPU reset required)',
    })
  } else if (g.remapped_rows != null && g.remapped_rows > 0) {
    reasons.push({
      scope: 'card',
      severity: 'warning',
      code: 'remapped_rows',
      device_uuid: g.uuid,
      device_idx: g.idx,
      summary: `Remapped memory rows: ${g.remapped_rows}`,
    })
  }
  if (g.vendor_health && g.vendor_health.trim() && g.vendor_health.trim().toLowerCase() !== 'ok') {
    const low = g.vendor_health.toLowerCase()
    const crit = /crit|fatal|error|alarm|fail|general/.test(low)
    reasons.push({
      scope: 'card',
      severity: crit ? 'critical' : 'warning',
      code: 'vendor_health',
      device_uuid: g.uuid,
      device_idx: g.idx,
      summary: `Vendor health: ${g.vendor_health}`,
    })
  }
  if (g.throttle && g.throttle.length > 0) {
    const seen = new Set<string>()
    for (const raw of g.throttle) {
      const low = raw.toLowerCase()
      if ((low === 'thermal' || low === 'sw_thermal') && !seen.has('thermal')) {
        seen.add('thermal')
        reasons.push({
          scope: 'card',
          severity: 'warning',
          code: 'thermal_throttle',
          device_uuid: g.uuid,
          device_idx: g.idx,
          summary: g.temp_c != null ? `Thermal throttling (${g.temp_c}°C)` : 'Thermal throttling',
        })
      } else if (low === 'hw_slowdown' && !seen.has('hw_slowdown')) {
        seen.add('hw_slowdown')
        reasons.push({
          scope: 'card',
          severity: 'warning',
          code: 'hw_slowdown',
          device_uuid: g.uuid,
          device_idx: g.idx,
          summary: 'Hardware slowdown throttling',
        })
      } else if (low === 'power_brake' && !seen.has('power_brake')) {
        seen.add('power_brake')
        reasons.push({
          scope: 'card',
          severity: 'warning',
          code: 'power_brake',
          device_uuid: g.uuid,
          device_idx: g.idx,
          summary: 'External power-brake throttling',
        })
      }
    }
  }
  return reasons
}

export function cardHasFault(g: GpuCardView): boolean {
  if (g.fault_severity != null) {
    return g.fault_severity === 'critical'
  }
  return cardFaultReasons(g).some((r) => r.severity === 'critical')
}

export function cardHasWarning(g: GpuCardView): boolean {
  if (g.fault_severity != null) {
    return g.fault_severity === 'warning'
  }
  const reasons = cardFaultReasons(g)
  return !reasons.some((r) => r.severity === 'critical') && reasons.some((r) => r.severity === 'warning')
}

export function hostHasFault(h: GpuHostView): boolean {
  if (!h.is_online || h.freshness === 'offline') return false
  if (h.host_fault_severity === 'critical' || h.host_fault_severity === 'warning') return true
  if ((h.fault_count ?? 0) > 0) return true
  if (FAULT_HOST_STATUSES.has(h.status)) return true
  return h.gpus.some((g) => cardHasFault(g))
}

export function hostHasWarning(h: GpuHostView): boolean {
  if (!h.is_online || h.freshness === 'offline') return false
  if (h.host_fault_severity === 'warning' || h.lagging || h.freshness === 'stale') return true
  return h.gpus.some((g) => cardHasWarning(g))
}

export function isCardEligibleFree(
  h: GpuHostView,
  g: GpuCardView,
  nowMs?: number,
): boolean {
  if (!h.is_online || h.freshness !== 'fresh' || h.lagging) return false
  if (nowMs != null && h.received_at_ms && h.received_at_ms > 0) {
    // Match server freshness bound (90 s) so prolonged polling outages never
    // leave expired cached cards selectable for allocation/export.
    if (nowMs - h.received_at_ms >= 90_000) return false
  }
  if (h.host_fault_severity === 'critical') return false
  if (h.status !== 'ok' && h.status !== 'limited') return false
  if (g.state !== 'free' || g.stale || g.presence_only) return false
  if (cardHasFault(g)) return false
  return true
}

export function cardExportCmd(h: GpuHostView, g: GpuCardView): string | null {
  if (!isSafeCudaUuid(g.uuid)) return null
  const rt = cardRuntimeKind(h, g)
  if (!isExportableRuntime(rt)) return null
  if (rt === 'ascend') {
    return `export ASCEND_RT_VISIBLE_DEVICES=${shellQuoteSingle(String(g.vendor_index ?? g.idx))}`
  }
  if (rt === 'amd') {
    return `export ROCR_VISIBLE_DEVICES=${shellQuoteSingle(String(g.vendor_index ?? g.idx))}`
  }
  return `export CUDA_DEVICE_ORDER=PCI_BUS_ID CUDA_VISIBLE_DEVICES=${shellQuoteSingle(g.uuid)}`
}

export interface GpuCardView {
  uuid: string
  idx: number
  name?: string | null
  state: GpuState
  mem_used_mb?: number | null
  mem_total_mb?: number | null
  util_pct?: number | null
  temp_c?: number | null
  power_w?: number | null
  power_limit_w?: number | null
  fan_pct?: number | null
  sm_clock_mhz?: number | null
  throttle?: string[] | null
  ecc_uncorrected?: number | null
  remapped_rows?: number | null
  xid_errors?: number[] | null
  mig?: boolean
  lost?: boolean
  vendor_health?: string | null
  backend?: string | null
  vendor_index?: number | null
  remap_pending?: boolean
  remap_failure?: boolean
  presence_only?: boolean
  stale?: boolean
  fault_severity?: 'critical' | 'warning' | string | null
  fault_reasons?: GpuFaultReason[]
  unified?: boolean
  pci_bus?: string | null
  idle_since?: number | null
  procs_state: GpuProcsState
  procs?: GpuProc[] | null
}

export interface GpuHostView {
  agent_id: string
  name: string
  display_name?: string | null
  os: string
  source: GpuHostSource
  read_only?: boolean
  is_online: boolean
  freshness: GpuFreshness
  status: GpuHostStatus
  status_detail?: string | null
  host_fault_severity?: 'critical' | 'warning' | string | null
  fault_reasons?: GpuFaultReason[]
  fault_count?: number
  backend?: string | null
  driver_version?: string | null
  seq?: number
  received_at_ms?: number | null
  age_ms?: number | null
  lagging?: boolean
  interval_ms: number
  free_count: number
  busy_count: number
  held_idle_count: number
  total_count: number
  host?: GpuHostLoad | null
  gpus: GpuCardView[]
  inventory?: GpuInventory | null
}

export interface GpuFleetSummary {
  hosts_total: number
  hosts_online: number
  gpus_total: number
  gpus_free: number
  gpus_busy: number
  gpus_held_idle: number
  gpus_fault: number
  gpus_warning?: number
  gpus_unknown?: number
  gpus_offline?: number
  fault_hosts?: number
  fault_cards?: number
}

export interface GpuFleetResponse {
  hosts: GpuHostView[]
  summary: GpuFleetSummary
  server_time_ms: number
  live_interval_ms?: number
}

export interface GpuHistoryPoint {
  ts_ms: number
  samples: number
  util_avg?: number | null
  util_max?: number | null
  mem_used_avg_mb?: number | null
  mem_used_max_mb?: number | null
  mem_total_mb?: number | null
  temp_max_c?: number | null
  power_avg_w?: number | null
  free_ratio: number
  held_idle_ratio: number
}

export interface GpuHistoryResponse {
  agent_id: string
  uuid?: string | null
  range: GpuRange
  points: GpuHistoryPoint[]
}

export interface GpuUserRow {
  user: string
  held_gpu_hours: number
  busy_gpu_hours: number
  live_gpus: number
  live_mem_mb: number
  hosts: string[]
}

export interface GpuUsersResponse {
  range: GpuRange
  users: GpuUserRow[]
}

export interface GpuAlertRule {
  enabled: boolean
  free_gpus_min?: number | null
  free_min_mem_gb?: number | null
  held_idle_alert: boolean
  fault_alert: boolean
  machine_alert: boolean
  lang?: string | null
}

export interface GpuAlertChannel {
  id: string
  kind: GpuBotKind
  label: string
  webhook_masked: string
  has_secret: boolean
  enabled: boolean
  include_users: boolean
  lang: string
  last_error?: string | null
  last_sent_at?: string | null
  created_at?: string
}

export interface CreateGpuChannelReq {
  kind: GpuBotKind
  label: string
  webhook_url: string
  secret?: string
  include_users?: boolean
  lang?: string
  enabled?: boolean
}

export interface PatchGpuChannelReq {
  label?: string
  webhook_url?: string
  secret?: string
  enabled?: boolean
  include_users?: boolean
  lang?: string
}

export interface TestGpuChannelResp {
  ok: boolean
  error?: string | null
}

export function setAgentGpuServer(
  tenantId: string,
  agentId: string,
  gpuServer: boolean,
): Promise<{ agent_id: string; gpu_server: boolean }> {
  return api.put(`/tenant/${tenantId}/agent/${agentId}/gpu-server`, { gpu_server: gpuServer })
}

export function fetchGpuFleet(
  tenantId: string,
  opts: { live?: boolean; hosts?: string[] } = {},
): Promise<GpuFleetResponse> {
  const params = new URLSearchParams()
  if (opts.live) params.set('live', '1')
  if (opts.hosts?.length) params.set('hosts', opts.hosts.join(','))
  const qs = params.toString()
  return api.get(`/tenant/${tenantId}/gpu/fleet${qs ? `?${qs}` : ''}`)
}

export function fetchGpuHost(
  tenantId: string,
  agentId: string,
  live = true,
): Promise<GpuHostView> {
  return api.get(`/tenant/${tenantId}/gpu/fleet/${agentId}${live ? '?live=1' : ''}`)
}

export function fetchGpuHistory(
  tenantId: string,
  agentId: string,
  range: GpuRange,
  uuid?: string,
): Promise<GpuHistoryResponse> {
  const params = new URLSearchParams({ agent_id: agentId, range })
  if (uuid) params.set('uuid', uuid)
  return api.get(`/tenant/${tenantId}/gpu/history?${params.toString()}`)
}

export function fetchGpuUsers(
  tenantId: string,
  range: GpuRange,
): Promise<GpuUsersResponse> {
  return api.get(`/tenant/${tenantId}/gpu/users?range=${encodeURIComponent(range)}`)
}

export function fetchGpuAlertRules(tenantId: string): Promise<GpuAlertRule> {
  return api.get(`/tenant/${tenantId}/gpu/alert-rules`)
}

export function saveGpuAlertRules(
  tenantId: string,
  rule: GpuAlertRule,
): Promise<GpuAlertRule> {
  return api.put(`/tenant/${tenantId}/gpu/alert-rules`, rule)
}

export async function listGpuChannels(tenantId: string): Promise<GpuAlertChannel[]> {
  const r = await api.get<{ items: GpuAlertChannel[] }>(`/tenant/${tenantId}/gpu/channels`)
  return r.items ?? []
}

export function createGpuChannel(
  tenantId: string,
  body: CreateGpuChannelReq,
): Promise<GpuAlertChannel> {
  return api.post(`/tenant/${tenantId}/gpu/channels`, body)
}

export function patchGpuChannel(
  tenantId: string,
  channelId: string,
  body: PatchGpuChannelReq,
): Promise<GpuAlertChannel> {
  return api.patch(`/tenant/${tenantId}/gpu/channels/${channelId}`, body)
}

export function deleteGpuChannel(tenantId: string, channelId: string): Promise<void> {
  return api.delete(`/tenant/${tenantId}/gpu/channels/${channelId}`)
}

export function testGpuChannel(
  tenantId: string,
  channelId: string,
): Promise<TestGpuChannelResp> {
  return api.post(`/tenant/${tenantId}/gpu/channels/${channelId}/test`, {})
}
