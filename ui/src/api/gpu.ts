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

export type GpuRange = '24h' | '7d' | '30d'

export type GpuBotKind = 'feishu' | 'dingtalk' | 'wecom' | 'webhook'

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

const SAFE_CUDA_ID_RE = /^[A-Za-z0-9._:-]{1,128}$/

export function isSafeCudaUuid(uuid: string): boolean {
  return SAFE_CUDA_ID_RE.test(uuid)
}

export function shellQuoteSingle(val: string): string {
  return `'${val.replace(/'/g, "'\\''")}'`
}

export function cardHasFault(g: GpuCardView): boolean {
  return Boolean(
    g.lost ||
      (g.ecc_uncorrected != null && g.ecc_uncorrected > 0) ||
      (g.xid_errors && g.xid_errors.length > 0),
  )
}

export function hostHasFault(h: GpuHostView): boolean {
  const badStatus = h.status !== 'ok' && h.status !== 'no_gpu' && h.status !== 'limited'
  return badStatus || h.gpus.some((g) => cardHasFault(g))
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
  backend?: string | null
  driver_version?: string | null
  received_at_ms?: number | null
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
}

export interface GpuFleetResponse {
  hosts: GpuHostView[]
  summary: GpuFleetSummary
  server_time_ms: number
}

export interface GpuHistoryPoint {
  ts_ms: number
  samples: number
  util_avg?: number | null
  util_max: number
  mem_used_avg_mb?: number | null
  mem_used_max_mb: number
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
