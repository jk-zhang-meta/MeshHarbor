// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
import { defineStore } from 'pinia'
import { computed, ref } from 'vue'
import {
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
  type GpuUserRow,
  type PatchGpuChannelReq,
  type TestGpuChannelResp,
} from '@/api/gpu'

const LIVE_POLL_MS = 2000

export const useGpuStore = defineStore('gpu', () => {
  const fleet = ref<GpuFleetResponse | null>(null)
  const loading = ref(false)
  const error = ref<string | null>(null)
  const disabled = ref(false)

  const selectedHost = ref<GpuHostView | null>(null)
  const hostHistory = ref<GpuHistoryPoint[]>([])
  const historyLoading = ref(false)

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
  let pollTimer: ReturnType<typeof setTimeout> | null = null
  let activeTenantId: string | null = null
  let visHandler: (() => void) | null = null
  let pollSeq = 0

  const hosts = computed(() => fleet.value?.hosts ?? [])
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
      },
  )

  async function refreshFleet(tenantId: string, live = true): Promise<void> {
    const seq = ++pollSeq
    if (!fleet.value) loading.value = true
    error.value = null
    try {
      const resp = await fetchGpuFleet(tenantId, { live })
      if (seq !== pollSeq) return
      fleet.value = resp
      disabled.value = false
      // Keep open drawer synchronized with live updates.
      if (selectedHost.value) {
        const updated = resp.hosts.find((h) => h.agent_id === selectedHost.value!.agent_id)
        if (updated) selectedHost.value = { ...selectedHost.value, ...updated }
      }
    } catch (e) {
      if (seq !== pollSeq) return
      const status = (e as { status?: number }).status
      if (status === 404 || status === 503) {
        disabled.value = true
      } else {
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
    if (!liveActive.value || !activeTenantId) return
    if (typeof document !== 'undefined' && document.visibilityState === 'hidden') return
    const tid = activeTenantId
    pollTimer = setTimeout(async () => {
      if (!liveActive.value || activeTenantId !== tid) return
      if (typeof document !== 'undefined' && document.visibilityState === 'hidden') return
      await refreshFleet(tid, true)
      scheduleNextPoll()
    }, LIVE_POLL_MS)
  }

  function startLivePolling(tenantId: string) {
    stopLivePolling()
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
    try {
      selectedHost.value = await fetchGpuHost(tenantId, agentId, true)
    } catch {
      selectedHost.value = hosts.value.find((h) => h.agent_id === agentId) ?? null
    }
    await loadHostHistory(tenantId, agentId, range, uuid)
  }

  async function loadHostHistory(tenantId: string, agentId: string, range: GpuRange, uuid?: string) {
    historyLoading.value = true
    try {
      const r = await fetchGpuHistory(tenantId, agentId, range, uuid)
      hostHistory.value = r.points ?? []
    } catch {
      hostHistory.value = []
    } finally {
      historyLoading.value = false
    }
  }

  async function loadUsers(tenantId: string, range: GpuRange = usersRange.value) {
    usersRange.value = range
    usersLoading.value = true
    try {
      const r = await fetchGpuUsers(tenantId, range)
      users.value = r.users ?? []
    } finally {
      usersLoading.value = false
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
    loading,
    error,
    disabled,
    selectedHost,
    hostHistory,
    historyLoading,
    users,
    usersRange,
    usersLoading,
    alertRule,
    channels,
    alertsLoading,
    liveActive,
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
