// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
import { defineStore } from 'pinia'
import { computed, ref } from 'vue'
import {
  cardFaultReasons,
  cardHasFault,
  cardHasWarning,
  cardRuntimeKind,
  createGpuChannel,
  deleteGpuChannel,
  fetchGpuAlertRules,
  fetchGpuFleet,
  fetchGpuHistory,
  fetchGpuHost,
  fetchGpuUsers,
  listGpuChannels,
  patchGpuChannel,
  saveGpuAlertRules,
  testGpuChannel,
  type CreateGpuChannelReq,
  type GpuAlertChannel,
  type GpuAlertRule,
  type GpuFleetResponse,
  type GpuHistoryPoint,
  type GpuHostView,
  type GpuRange,
  type GpuState,
  type GpuUserRow,
  type PatchGpuChannelReq,
  type TestGpuChannelResp,
} from '@/api/gpu'

const DEFAULT_LIVE_POLL_MS = 2000
const STANDING_POLL_MS = 15000
const BACKOFF_MS = [10000, 30000, 60000]
const DELTA_TTL_MS = 4000
const MAX_RECENT_CHANGES = 12

export interface GpuCardDelta {
  utilDelta: number
  memDeltaMb: number
  stateChanged: boolean
  at: number
}

export interface GpuLiveChange {
  id: number
  at: number
  kind: 'host_online' | 'host_offline' | 'host_status' | 'card_state' | 'fault_detected' | 'fault_cleared'
  severity: 'info' | 'success' | 'warning' | 'error'
  host: string
  slot?: string
  from?: GpuState | string
  to?: GpuState | string
  detail?: string
}

interface PrevHostSnap {
  seq: number
  received_at_ms: number
  is_online: boolean
  status: string
  gpus: Map<
    string,
    {
      state: GpuState
      util_pct: number | null
      mem_used_mb: number | null
      fault_severity: string | null
    }
  >
}

export const useGpuStore = defineStore('gpu', () => {
  const fleet = ref<GpuFleetResponse | null>(null)
  const loading = ref(false)
  const error = ref<string | null>(null)
  const disabled = ref(false)
  const lastPollOkAt = ref<number>(0)
  const consecutiveFailures = ref<number>(0)
  const nextRetryAt = ref<number>(0)

  const selectedHost = ref<GpuHostView | null>(null)
  const hostHistory = ref<GpuHistoryPoint[]>([])
  const historyLoading = ref(false)
  const historyError = ref<string | null>(null)

  const users = ref<GpuUserRow[]>([])
  const usersRange = ref<GpuRange>('24h')
  const usersLoading = ref(false)

  const alertRule = ref<GpuAlertRule>({
    enabled: false,
    free_gpus_min: null,
    free_min_mem_gb: null,
    held_idle_alert: true,
    fault_alert: true,
    machine_alert: true,
    lang: null,
  })
  const channels = ref<GpuAlertChannel[]>([])
  const alertsLoading = ref(false)

  const liveActive = ref(false)
  const cardDeltas = ref<Record<string, GpuCardDelta>>({})
  const recentChanges = ref<GpuLiveChange[]>([])

  let pollTimer: ReturnType<typeof setTimeout> | null = null
  let activeTenantId: string | null = null
  let visHandler: (() => void) | null = null
  let pollSeq = 0
  let hostDetailSeq = 0
  let historySeq = 0
  let usersSeq = 0
  let changeIdSeq = 0
  let prevHosts = new Map<string, PrevHostSnap>()

  const hosts = computed(() => fleet.value?.hosts ?? [])
  const liveIntervalMs = computed(() => fleet.value?.live_interval_ms ?? DEFAULT_LIVE_POLL_MS)
  const summary = computed(
    () =>
      fleet.value?.summary ?? {
        hosts_total: 0,
        hosts_online: 0,
        gpus_total: 0,
        gpus_free: 0,
        gpus_busy: 0,
        gpus_held_idle: 0,
        gpus_fault: 0,
        gpus_warning: 0,
        gpus_unknown: 0,
        gpus_offline: 0,
        fault_hosts: 0,
        fault_cards: 0,
      },
  )

  function resetTenantState() {
    pollSeq += 1
    hostDetailSeq += 1
    historySeq += 1
    usersSeq += 1
    fleet.value = null
    error.value = null
    disabled.value = false
    lastPollOkAt.value = 0
    consecutiveFailures.value = 0
    nextRetryAt.value = 0
    selectedHost.value = null
    hostHistory.value = []
    historyError.value = null
    users.value = []
    channels.value = []
    cardDeltas.value = {}
    recentChanges.value = []
    prevHosts = new Map()
  }

  function pushChange(entry: Omit<GpuLiveChange, 'id' | 'at'>) {
    const next: GpuLiveChange = {
      ...entry,
      id: ++changeIdSeq,
      at: Date.now(),
    }
    recentChanges.value = [next, ...recentChanges.value].slice(0, MAX_RECENT_CHANGES)
  }

  function clearRecentChanges() {
    recentChanges.value = []
  }

  function trackChanges(resp: GpuFleetResponse) {
    const now = Date.now()
    const nextDeltas: Record<string, GpuCardDelta> = {}
    for (const [k, d] of Object.entries(cardDeltas.value)) {
      if (now - d.at <= DELTA_TTL_MS) nextDeltas[k] = d
    }

    const nextSnaps = new Map<string, PrevHostSnap>()
    for (const h of resp.hosts) {
      const prev = prevHosts.get(h.agent_id)
      const hName = h.display_name?.trim() || h.name
      const nowOnline = h.is_online && h.freshness !== 'offline'

      const curGpus = new Map<
        string,
        { state: GpuState; util_pct: number | null; mem_used_mb: number | null; fault_severity: string | null }
      >()
      for (const g of h.gpus) {
        const sev = g.fault_severity ?? (cardHasFault(g) ? 'critical' : cardHasWarning(g) ? 'warning' : null)
        curGpus.set(g.uuid, {
          state: g.state,
          util_pct: g.util_pct ?? null,
          mem_used_mb: g.mem_used_mb ?? null,
          fault_severity: sev,
        })
      }
      nextSnaps.set(h.agent_id, {
        seq: h.seq ?? 0,
        received_at_ms: h.received_at_ms ?? 0,
        is_online: nowOnline,
        status: h.status,
        gpus: curGpus,
      })

      if (!prev) continue

      if (prev.is_online !== nowOnline) {
        pushChange({
          kind: nowOnline ? 'host_online' : 'host_offline',
          severity: nowOnline ? 'success' : 'warning',
          host: hName,
        })
      } else if (prev.status !== h.status) {
        pushChange({
          kind: 'host_status',
          severity: h.host_fault_severity === 'critical' ? 'error' : h.status === 'ok' ? 'success' : 'warning',
          host: hName,
          to: h.status,
          detail: h.status_detail ?? undefined,
        })
      }

      const advanced =
        (h.seq != null && h.seq > 0 && h.seq !== prev.seq) ||
        (h.received_at_ms != null && h.received_at_ms > 0 && h.received_at_ms !== prev.received_at_ms)
      if (!advanced) continue

      for (const g of h.gpus) {
        const pg = prev.gpus.get(g.uuid)
        if (!pg) continue
        const utilDelta =
          g.util_pct != null && pg.util_pct != null ? g.util_pct - pg.util_pct : 0
        const memDeltaMb =
          g.mem_used_mb != null && pg.mem_used_mb != null ? g.mem_used_mb - pg.mem_used_mb : 0
        const curSev = g.fault_severity ?? (cardHasFault(g) ? 'critical' : cardHasWarning(g) ? 'warning' : null)
        const stateChanged = pg.state !== g.state || pg.fault_severity !== curSev
        if (Math.abs(utilDelta) >= 2 || Math.abs(memDeltaMb) >= 128 || stateChanged) {
          nextDeltas[`${h.agent_id}:${g.uuid}`] = {
            utilDelta: Math.abs(utilDelta) >= 2 ? utilDelta : 0,
            memDeltaMb: Math.abs(memDeltaMb) >= 128 ? memDeltaMb : 0,
            stateChanged,
            at: now,
          }
        }
        const rt = cardRuntimeKind(h, g)
        const slot = rt === 'ascend' ? `NPU${g.vendor_index ?? g.idx}` : rt === 'tpu' ? `TPU${g.idx}` : `#${g.idx}`
        if (pg.fault_severity !== 'critical' && curSev === 'critical') {
          const reason = cardFaultReasons(g)[0]?.summary ?? 'Fault'
          pushChange({
            kind: 'fault_detected',
            severity: 'error',
            host: hName,
            slot,
            detail: reason,
          })
        } else if (pg.fault_severity === 'critical' && curSev !== 'critical') {
          pushChange({
            kind: 'fault_cleared',
            severity: 'success',
            host: hName,
            slot,
          })
        } else if (pg.state !== g.state) {
          pushChange({
            kind: 'card_state',
            severity: g.state === 'free' ? 'success' : g.state === 'held_idle' ? 'warning' : 'info',
            host: hName,
            slot,
            from: pg.state,
            to: g.state,
          })
        }
      }
    }

    prevHosts = nextSnaps
    cardDeltas.value = nextDeltas
  }

  async function refreshFleet(tenantId: string, live = true): Promise<void> {
    const seq = ++pollSeq
    if (!fleet.value) loading.value = true
    try {
      const resp = await fetchGpuFleet(tenantId, { live })
      if (seq !== pollSeq) return
      trackChanges(resp)
      fleet.value = resp
      disabled.value = false
      error.value = null
      consecutiveFailures.value = 0
      nextRetryAt.value = 0
      lastPollOkAt.value = Date.now()
      // Keep open drawer cleanly synchronized without carrying stale removed fields.
      if (selectedHost.value) {
        const updated = resp.hosts.find((h) => h.agent_id === selectedHost.value!.agent_id)
        if (updated) {
          selectedHost.value = {
            ...updated,
            inventory: updated.inventory ?? selectedHost.value.inventory,
          }
        } else {
          selectedHost.value = null
        }
      }
    } catch (e) {
      if (seq !== pollSeq) return
      const status = (e as { status?: number }).status
      if (status === 404) {
        disabled.value = true
        error.value = null
      } else {
        consecutiveFailures.value += 1
        error.value = (e as Error).message
      }
    } finally {
      if (seq === pollSeq) loading.value = false
    }
  }

  function clearTimer() {
    if (pollTimer !== null) {
      clearTimeout(pollTimer)
      pollTimer = null
    }
  }

  function scheduleNextPoll() {
    clearTimer()
    if (!liveActive.value || !activeTenantId || disabled.value) return
    if (typeof document !== 'undefined' && document.visibilityState === 'hidden') return
    const tid = activeTenantId
    let delay: number
    if (consecutiveFailures.value > 0) {
      delay = BACKOFF_MS[Math.min(consecutiveFailures.value - 1, BACKOFF_MS.length - 1)]
      nextRetryAt.value = Date.now() + delay
    } else if (fleet.value?.live_interval_ms === 0) {
      delay = STANDING_POLL_MS
      nextRetryAt.value = 0
    } else {
      delay = Math.max(1000, fleet.value?.live_interval_ms ?? DEFAULT_LIVE_POLL_MS)
      nextRetryAt.value = 0
    }
    pollTimer = setTimeout(async () => {
      if (!liveActive.value || activeTenantId !== tid) return
      if (typeof document !== 'undefined' && document.visibilityState === 'hidden') return
      await refreshFleet(tid, fleet.value?.live_interval_ms !== 0)
      scheduleNextPoll()
    }, delay)
  }

  function startLivePolling(tenantId: string) {
    const switchingTenant = activeTenantId !== null && activeTenantId !== tenantId
    stopLivePolling()
    if (switchingTenant) resetTenantState()
    activeTenantId = tenantId
    liveActive.value = true
    if (typeof document !== 'undefined') {
      visHandler = () => {
        if (document.visibilityState === 'visible' && liveActive.value && activeTenantId) {
          void refreshFleet(activeTenantId, true).then(() => scheduleNextPoll())
        } else {
          clearTimer()
        }
      }
      document.addEventListener('visibilitychange', visHandler)
    }
    void refreshFleet(tenantId, true).then(() => scheduleNextPoll())
  }

  function stopLivePolling() {
    liveActive.value = false
    activeTenantId = null
    clearTimer()
    if (visHandler && typeof document !== 'undefined') {
      document.removeEventListener('visibilitychange', visHandler)
      visHandler = null
    }
  }

  async function openHostDetail(tenantId: string, agentId: string, range: GpuRange = '24h', uuid?: string) {
    const seq = ++hostDetailSeq
    try {
      const host = await fetchGpuHost(tenantId, agentId, true)
      if (seq !== hostDetailSeq) return
      selectedHost.value = host
    } catch {
      if (seq !== hostDetailSeq) return
      selectedHost.value = hosts.value.find((h) => h.agent_id === agentId) ?? null
    }
    if (seq !== hostDetailSeq) return
    await loadHostHistory(tenantId, agentId, range, uuid)
  }

  async function loadHostHistory(tenantId: string, agentId: string, range: GpuRange, uuid?: string) {
    const seq = ++historySeq
    historyLoading.value = true
    historyError.value = null
    try {
      const r = await fetchGpuHistory(tenantId, agentId, range, uuid)
      if (seq !== historySeq) return
      hostHistory.value = r.points ?? []
    } catch (e) {
      if (seq !== historySeq) return
      hostHistory.value = []
      historyError.value = (e as Error).message
    } finally {
      if (seq === historySeq) historyLoading.value = false
    }
  }

  async function loadUsers(tenantId: string, range: GpuRange = usersRange.value) {
    const seq = ++usersSeq
    usersRange.value = range
    usersLoading.value = true
    try {
      const r = await fetchGpuUsers(tenantId, range)
      if (seq !== usersSeq) return
      users.value = r.users ?? []
    } finally {
      if (seq === usersSeq) usersLoading.value = false
    }
  }

  async function loadAlertSettings(tenantId: string) {
    alertsLoading.value = true
    try {
      const [rule, chs] = await Promise.all([
        fetchGpuAlertRules(tenantId),
        listGpuChannels(tenantId),
      ])
      alertRule.value = rule
      channels.value = chs
    } finally {
      alertsLoading.value = false
    }
  }

  async function updateAlertRule(tenantId: string, rule: GpuAlertRule) {
    alertRule.value = await saveGpuAlertRules(tenantId, rule)
  }

  async function addChannel(tenantId: string, body: CreateGpuChannelReq) {
    const ch = await createGpuChannel(tenantId, body)
    channels.value = [ch, ...channels.value]
    return ch
  }

  async function updateChannel(tenantId: string, channelId: string, body: PatchGpuChannelReq) {
    const updated = await patchGpuChannel(tenantId, channelId, body)
    const idx = channels.value.findIndex((c) => c.id === channelId)
    if (idx !== -1) channels.value[idx] = updated
    return updated
  }

  async function removeChannel(tenantId: string, channelId: string) {
    await deleteGpuChannel(tenantId, channelId)
    channels.value = channels.value.filter((c) => c.id !== channelId)
  }

  async function sendTestChannel(tenantId: string, channelId: string): Promise<TestGpuChannelResp> {
    const res = await testGpuChannel(tenantId, channelId)
    channels.value = await listGpuChannels(tenantId)
    return res
  }

  return {
    fleet,
    hosts,
    summary,
    liveIntervalMs,
    loading,
    error,
    disabled,
    lastPollOkAt,
    consecutiveFailures,
    nextRetryAt,
    selectedHost,
    hostHistory,
    historyLoading,
    historyError,
    users,
    usersRange,
    usersLoading,
    alertRule,
    channels,
    alertsLoading,
    liveActive,
    cardDeltas,
    recentChanges,
    clearRecentChanges,
    refreshFleet,
    startLivePolling,
    stopLivePolling,
    openHostDetail,
    loadHostHistory,
    loadUsers,
    loadAlertSettings,
    updateAlertRule,
    addChannel,
    updateChannel,
    removeChannel,
    sendTestChannel,
  }
})
