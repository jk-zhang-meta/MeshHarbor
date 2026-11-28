// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
import { api } from '@/api/client'

export interface MonitoringCapabilities {
  can_see_remote: boolean
  can_see_ssh: boolean
  can_disconnect_remote: boolean
  can_disconnect_ssh: boolean
  can_watch_takeover: boolean
}

export type AttributionKind =
  | 'account'
  | 'member_invite'
  | 'device_invite'
  | 'device_share'
  | 'external'
  | 'key_list'

export interface PartyAttribution {
  device_id?: string
  device_name?: string
  device_os?: string
  account_user_id?: string
  account_name?: string
  account_username?: string
  attribution_kind: AttributionKind
  invite_or_share_label?: string
  inviter_or_owner_name?: string
  invite_or_share_id?: string
}

export interface LiveSessionStatsView {
  bytes_sent: number
  bytes_recv: number
  avg_rtt_ms: number
  peak_fps: number
  input_events: number
}

export interface LiveMonitoringItem {
  kind: 'remote' | 'ssh'
  id: string
  agent_id: string
  phase: string
  started_at: string
  started_at_ms: number
  duration_secs: number
  initiator: PartyAttribution
  target: PartyAttribution
  source: string
  account_mode?: string
  ran_as?: string
  shared_session_id?: string
  resume_allowed?: boolean
  admin_watching?: boolean
  admin_watcher_count?: number
  admin_taken_over?: boolean
  stats?: LiveSessionStatsView
  activity_count?: number
  can_disconnect: boolean
  can_watch_takeover: boolean
}

export interface LiveMonitoringResponse {
  server_time_ms: number
  counts: {
    total: number
    remote: number
    ssh: number
  }
  capabilities: MonitoringCapabilities
  items: LiveMonitoringItem[]
}

export interface HistoryMonitoringItem {
  kind: 'remote' | 'ssh'
  id: string
  agent_id: string
  status: 'live' | 'completed' | 'denied'
  started_at: string
  started_at_ms: number
  ended_at?: string
  duration_secs?: number
  initiator: PartyAttribution
  target: PartyAttribution
  source: string
  carrier?: string
  account_mode?: string
  ran_as?: string
  end_reason?: string
  denied_reason?: string
  grant_id?: string
  stats?: LiveSessionStatsView
  activity_count?: number
}

export interface HistoryMonitoringResponse {
  items: HistoryMonitoringItem[]
  total: number
  page: number
  per_page: number
  total_pages: number
  summary: {
    total_remote: number
    total_ssh: number
    denied_ssh: number
  }
  capabilities: MonitoringCapabilities
}

export interface SshGrantActivityItem {
  id: string
  kind: string
  detail?: string
  exit_code?: number
  allowed: boolean
  caller: string
  at: string
}

export interface SshGrantActivitiesResponse {
  grant_id: string
  items: SshGrantActivityItem[]
}

export interface LiveMonitoringParams {
  kind?: 'all' | 'remote' | 'ssh'
  q?: string
}

export interface HistoryMonitoringParams {
  kind?: 'all' | 'remote' | 'ssh'
  q?: string
  date_from?: string
  date_to?: string
  min_duration_secs?: number
  max_duration_secs?: number
  status?: 'all' | 'completed' | 'live' | 'denied'
  page?: number
  per_page?: number
}

export interface DisconnectPayload {
  kind: 'remote' | 'ssh'
  id: string
  agent_id?: string
  shared_session_id?: string
  reason?: string
}

export async function fetchLiveMonitoring(
  tenantId: string,
  params: LiveMonitoringParams = {},
): Promise<LiveMonitoringResponse> {
  const sp = new URLSearchParams()
  if (params.kind && params.kind !== 'all') sp.set('kind', params.kind)
  if (params.q?.trim()) sp.set('q', params.q.trim())
  const qs = sp.toString()
  return api.get<LiveMonitoringResponse>(
    `/tenant/${tenantId}/monitoring/live${qs ? `?${qs}` : ''}`,
  )
}

export async function fetchMonitoringHistory(
  tenantId: string,
  params: HistoryMonitoringParams = {},
): Promise<HistoryMonitoringResponse> {
  const sp = new URLSearchParams()
  if (params.kind && params.kind !== 'all') sp.set('kind', params.kind)
  if (params.q?.trim()) sp.set('q', params.q.trim())
  if (params.date_from) sp.set('date_from', params.date_from)
  if (params.date_to) sp.set('date_to', params.date_to)
  if (params.min_duration_secs !== undefined && Number.isFinite(params.min_duration_secs)) {
    sp.set('min_duration_secs', String(Math.max(0, Math.floor(params.min_duration_secs))))
  }
  if (params.max_duration_secs !== undefined && Number.isFinite(params.max_duration_secs)) {
    sp.set('max_duration_secs', String(Math.max(0, Math.floor(params.max_duration_secs))))
  }
  if (params.status && params.status !== 'all') sp.set('status', params.status)
  if (params.page) sp.set('page', String(params.page))
  if (params.per_page) sp.set('per_page', String(params.per_page))
  const qs = sp.toString()
  return api.get<HistoryMonitoringResponse>(
    `/tenant/${tenantId}/monitoring/history${qs ? `?${qs}` : ''}`,
  )
}

export async function fetchSshGrantActivities(
  tenantId: string,
  grantId: string,
): Promise<SshGrantActivitiesResponse> {
  return api.get<SshGrantActivitiesResponse>(
    `/tenant/${tenantId}/monitoring/ssh-grant/${encodeURIComponent(grantId)}/activities`,
  )
}

export async function disconnectLiveSession(
  tenantId: string,
  payload: DisconnectPayload,
): Promise<{ disconnected: boolean; kind: string; id: string; delivered_local: boolean }> {
  return api.post(`/tenant/${tenantId}/monitoring/disconnect`, payload)
}

export async function setMonitorTakeover(
  tenantId: string,
  sessionId: string,
  active: boolean,
): Promise<{ ok: boolean; session_id: string; agent_id: string; active: boolean }> {
  return api.post(`/tenant/${tenantId}/monitoring/takeover`, {
    session_id: sessionId,
    active,
  })
}

export function formatMonitoringDuration(secs: number | undefined | null): string {
  if (secs === undefined || secs === null || !Number.isFinite(secs)) return '—'
  const s = Math.max(0, Math.floor(secs))
  const d = Math.floor(s / 86400)
  const h = Math.floor((s % 86400) / 3600)
  const m = Math.floor((s % 3600) / 60)
  const rem = s % 60
  if (d > 0) return `${d}d ${h}h ${m}m`
  if (h > 0) return `${h}h ${m}m ${rem}s`
  if (m > 0) return `${m}m ${rem}s`
  return `${rem}s`
}

export function formatMonitoringBytes(bytes: number | undefined | null): string {
  if (!bytes || !Number.isFinite(bytes) || bytes <= 0) return '0 B'
  const units = ['B', 'KB', 'MB', 'GB', 'TB']
  let val = bytes
  let idx = 0
  while (val >= 1024 && idx < units.length - 1) {
    val /= 1024
    idx++
  }
  return `${val >= 100 || idx === 0 ? Math.round(val) : val.toFixed(1)} ${units[idx]}`
}
