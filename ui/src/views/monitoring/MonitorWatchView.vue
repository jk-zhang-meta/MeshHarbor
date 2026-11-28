<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 G ROX EOOD -->
<template>
  <div
    ref="wrapperRef"
    class="mw-shell"
    :class="{ 'mw-shell--toolbar-hidden': toolbarCollapsed }"
  >
    <!-- Floating / collapsible top bar -->
    <header class="mw-toolbar">
      <div class="mw-toolbar__left">
        <v-chip
          :color="rc.adminTakeoverActive.value ? 'warning' : 'teal'"
          size="small"
          variant="flat"
          :prepend-icon="rc.adminTakeoverActive.value ? 'mdi-shield-account' : 'mdi-eye-outline'"
        >
          {{
            rc.adminTakeoverActive.value
              ? t('mh.monitoring.watch.takingOverBadge')
              : t('mh.monitoring.watch.watchingBadge')
          }}
        </v-chip>

        <div class="mw-meta">
          <span class="mw-meta__device">{{ targetDeviceLabel }}</span>
          <span v-if="controllerLabel" class="mw-meta__sub">
            {{ t('mh.monitoring.watch.controllerLabel', { name: controllerLabel }) }}
          </span>
        </div>

        <v-chip
          size="x-small"
          variant="tonal"
          :color="phaseColor"
        >
          {{ phaseLabel }}
        </v-chip>
      </div>

      <div class="mw-toolbar__right">
        <!-- Scale mode quick toggle -->
        <v-btn-toggle
          v-model="rc.scaleMode.value"
          density="compact"
          variant="outlined"
          color="primary"
          mandatory
          class="mw-scale-toggle"
        >
          <v-btn value="fit" size="x-small" :title="t('mh.monitoring.watch.scaleFit')">
            {{ t('mh.monitoring.watch.scaleFitShort') }}
          </v-btn>
          <v-btn value="fill" size="x-small" :title="t('mh.monitoring.watch.scaleFill')">
            {{ t('mh.monitoring.watch.scaleFillShort') }}
          </v-btn>
          <v-btn value="original" size="x-small" :title="t('mh.monitoring.watch.scaleOriginal')">
            1:1
          </v-btn>
        </v-btn-toggle>

        <!-- Browser fullscreen -->
        <v-btn
          :icon="isFullscreen ? 'mdi-fullscreen-exit' : 'mdi-fullscreen'"
          size="small"
          variant="text"
          color="white"
          :title="t('mh.monitoring.watch.fullscreen')"
          @click="toggleFullscreen"
        />

        <!-- Silent Takeover / Release toggle -->
        <v-btn
          v-if="!rc.adminTakeoverActive.value"
          color="warning"
          variant="flat"
          size="small"
          prepend-icon="mdi-hand-back-left"
          :disabled="rc.phase.value !== 'connected' || takeoverBusy"
          :loading="takeoverBusy"
          data-testid="mw-takeover-btn"
          @click="toggleTakeover(true)"
        >
          {{ t('mh.monitoring.watch.takeOver') }}
        </v-btn>
        <v-btn
          v-else
          color="success"
          variant="flat"
          size="small"
          prepend-icon="mdi-hand-back-left-off"
          :disabled="takeoverBusy"
          :loading="takeoverBusy"
          data-testid="mw-release-btn"
          @click="toggleTakeover(false)"
        >
          {{ t('mh.monitoring.watch.releaseControl') }}
        </v-btn>

        <!-- Ctrl+Alt+Del (only while taken over) -->
        <v-btn
          v-if="rc.adminTakeoverActive.value"
          size="small"
          variant="tonal"
          color="white"
          :disabled="rc.phase.value !== 'connected'"
          @click="rc.sendCtrlAltDel()"
        >
          Ctrl+Alt+Del
        </v-btn>

        <!-- Actively disconnect the original session -->
        <v-btn
          v-if="targetSessionId"
          size="small"
          variant="tonal"
          color="error"
          prepend-icon="mdi-lan-disconnect"
          :loading="disconnectingTarget"
          @click="confirmDisconnect = true"
        >
          {{ t('mh.monitoring.watch.disconnectTarget') }}
        </v-btn>

        <!-- Collapse toolbar to pull-tab -->
        <v-btn
          icon="mdi-chevron-up"
          size="small"
          variant="text"
          color="white"
          :title="t('mh.monitoring.watch.hideToolbar')"
          @click="toolbarCollapsed = true"
        />

        <!-- Close watch -->
        <v-btn
          size="small"
          variant="outlined"
          color="white"
          prepend-icon="mdi-close"
          @click="closeWatch"
        >
          {{ t('mh.monitoring.watch.close') }}
        </v-btn>
      </div>
    </header>

    <!-- Pull-tab to restore toolbar -->
    <button
      v-if="toolbarCollapsed"
      type="button"
      class="mw-pull-tab"
      :aria-label="t('mh.monitoring.watch.showToolbar')"
      @click="toolbarCollapsed = false"
    >
      <v-icon size="16">mdi-chevron-down</v-icon>
      <span>{{ rc.adminTakeoverActive.value ? t('mh.monitoring.watch.takingOverBadge') : t('mh.monitoring.watch.watchingBadge') }}</span>
    </button>

    <!-- Takeover subtle frame border cue when actively controlling -->
    <div
      ref="stageRef"
      tabindex="0"
      class="mw-stage"
      :class="{
        'mw-stage--takeover': rc.adminTakeoverActive.value,
        'mw-stage--scroll': rc.scaleMode.value === 'original',
        'mw-stage--fill': rc.scaleMode.value === 'fill',
      }"
    >
      <video
        v-show="!rc.webcodecsActive.value"
        ref="videoRef"
        autoplay
        playsinline
        muted
        class="mw-media"
        :style="mediaStyle"
      />
      <canvas
        v-show="rc.webcodecsActive.value"
        ref="canvasRef"
        class="mw-media"
        :style="mediaStyle"
      />

      <!-- Connecting / Ended / Error overlay -->
      <div v-if="overlayMessage" class="mw-overlay">
        <v-card max-width="460" class="pa-5 text-center" color="surface">
          <v-progress-circular
            v-if="isConnecting"
            indeterminate
            color="primary"
            size="36"
            class="mb-3"
          />
          <v-icon
            v-else
            :icon="endedNaturally ? 'mdi-check-circle-outline' : 'mdi-alert-circle-outline'"
            :color="endedNaturally ? 'info' : 'error'"
            size="40"
            class="mb-3"
          />
          <div class="text-subtitle-1 font-weight-medium mb-2">{{ overlayTitle }}</div>
          <div class="text-body-2 text-medium-emphasis mb-4">{{ overlayMessage }}</div>
          <div class="d-flex justify-center ga-2">
            <v-btn
              v-if="!isConnecting && !endedNaturally"
              color="primary"
              variant="flat"
              @click="reconnect"
            >
              {{ t('common.retry') }}
            </v-btn>
            <v-btn variant="outlined" @click="closeWatch">
              {{ t('mh.monitoring.watch.backToMonitoring') }}
            </v-btn>
          </div>
        </v-card>
      </div>
    </div>

    <!-- Confirm disconnect original session dialog -->
    <v-dialog v-model="confirmDisconnect" max-width="420">
      <v-card>
        <v-card-title>{{ t('mh.monitoring.disconnectConfirmTitle') }}</v-card-title>
        <v-card-text>
          {{ t('mh.monitoring.watch.disconnectTargetConfirm', { device: targetDeviceLabel }) }}
        </v-card-text>
        <v-card-actions>
          <v-spacer />
          <v-btn variant="text" @click="confirmDisconnect = false">{{ t('common.cancel') }}</v-btn>
          <v-btn color="error" variant="flat" :loading="disconnectingTarget" @click="disconnectTargetSession">
            {{ t('mh.monitoring.disconnectAction') }}
          </v-btn>
        </v-card-actions>
      </v-card>
    </v-dialog>
  </div>
</template>

<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useI18n } from 'vue-i18n'
import { useAuthStore } from '@/stores/auth'
import { useAgentStore } from '@/stores/agents'
import { useRemoteControl } from '@/composables/useRemoteControl'
import { disconnectLiveSession, setMonitorTakeover } from '@/api/monitoring'
import { useSnackbar } from '@/composables/useSnackbar'

const { t } = useI18n()
const route = useRoute()
const router = useRouter()
const auth = useAuthStore()
const agentStore = useAgentStore()
const { showSuccess, showError } = useSnackbar()

const tenantId = computed(() => String(route.params.tenantId || ''))
const agentId = computed(() => String(route.params.agentId || ''))
const targetSessionId = computed(() =>
  typeof route.query.sessionId === 'string' ? route.query.sessionId : '',
)
const queryDeviceName = computed(() =>
  typeof route.query.deviceName === 'string' ? route.query.deviceName : '',
)
const controllerLabel = computed(() =>
  typeof route.query.controller === 'string' ? route.query.controller : '',
)

const agentRef = computed(
  () => agentStore.agents.find((a) => a.id === agentId.value) ?? null,
)
const targetDeviceLabel = computed(
  () =>
    queryDeviceName.value ||
    agentRef.value?.display_name ||
    agentRef.value?.name ||
    agentId.value.slice(0, 8),
)

const rc = useRemoteControl(agentRef, {
  userId: () => auth.user?.id ?? null,
  silentMonitor: true,
})

const wrapperRef = ref<HTMLElement | null>(null)
const stageRef = ref<HTMLElement | null>(null)
const videoRef = ref<HTMLVideoElement | null>(null)
const canvasRef = ref<HTMLCanvasElement | null>(null)

const toolbarCollapsed = ref(false)
const isFullscreen = ref(false)
const takeoverBusy = ref(false)
const confirmDisconnect = ref(false)
const disconnectingTarget = ref(false)
let detachInput: (() => void) | null = null

const mediaStyle = computed(() => {
  if (rc.scaleMode.value === 'fill') {
    return { width: '100%', height: '100%', objectFit: 'fill' as const }
  }
  if (rc.scaleMode.value === 'original') {
    const r = rc.resolution.value
    if (r?.width && r?.height) {
      return { width: `${r.width}px`, height: `${r.height}px`, objectFit: 'none' as const }
    }
    return { width: 'auto', height: 'auto', objectFit: 'none' as const }
  }
  return { width: '100%', height: '100%', objectFit: 'contain' as const }
})

const isConnecting = computed(() =>
  ['requesting', 'awaiting_consent', 'negotiating'].includes(rc.phase.value),
)
const endedNaturally = computed(
  () => rc.errorCode.value === 'target_session_ended' || rc.phase.value === 'closed',
)
const phaseColor = computed(() => {
  if (rc.phase.value === 'connected') return 'success'
  if (isConnecting.value) return 'info'
  if (rc.phase.value === 'error') return 'error'
  return 'default'
})
const phaseLabel = computed(() => {
  switch (rc.phase.value) {
    case 'connected':
      return t('mh.monitoring.watch.phaseConnected')
    case 'requesting':
    case 'awaiting_consent':
    case 'negotiating':
      return t('mh.monitoring.watch.phaseConnecting')
    case 'closed':
      return t('mh.monitoring.watch.phaseClosed')
    case 'error':
      return t('mh.monitoring.watch.phaseError')
    default:
      return rc.phase.value
  }
})

const overlayTitle = computed(() => {
  if (isConnecting.value) return t('mh.monitoring.watch.connectingTitle')
  if (rc.errorCode.value === 'target_session_ended') {
    return t('mh.monitoring.watch.targetEndedTitle')
  }
  if (rc.phase.value === 'closed') return t('mh.monitoring.watch.closedTitle')
  return t('mh.monitoring.watch.errorTitle')
})

const overlayMessage = computed(() => {
  if (rc.phase.value === 'connected') return ''
  if (isConnecting.value) return t('mh.monitoring.watch.connectingDesc')
  if (rc.errorCode.value === 'target_session_ended') {
    return t('mh.monitoring.watch.targetEndedDesc')
  }
  if (rc.error.value) return rc.error.value
  if (rc.phase.value === 'closed') return t('mh.monitoring.watch.closedDesc')
  return ''
})

watch(
  canvasRef,
  (el) => {
    rc.webcodecsCanvasEl.value = el
  },
  { flush: 'post' },
)

watch(
  [rc.remoteStream, videoRef],
  ([stream, el]) => {
    if (!el) return
    el.srcObject = stream
    if (stream) void el.play().catch(() => {})
  },
  { flush: 'post' },
)

watch(
  [rc.phase, stageRef],
  ([phase, el]) => {
    detachInput?.()
    detachInput = null
    if (phase === 'connected' && el) {
      detachInput = rc.attachInput(el)
    }
  },
  { flush: 'post' },
)

async function toggleTakeover(active: boolean) {
  if (rc.phase.value !== 'connected') return
  takeoverBusy.value = true
  try {
    const sent = rc.setAdminTakeover(active)
    if (!sent) {
      showError(t('mh.monitoring.watch.takeoverChannelNotReady'))
      return
    }
    if (rc.sessionId.value && tenantId.value) {
      await setMonitorTakeover(tenantId.value, rc.sessionId.value, active).catch(() => {})
    }
    if (active) {
      stageRef.value?.focus()
      showSuccess(t('mh.monitoring.watch.takeoverEnabledToast'))
    } else {
      showSuccess(t('mh.monitoring.watch.takeoverReleasedToast'))
    }
  } finally {
    takeoverBusy.value = false
  }
}

async function disconnectTargetSession() {
  if (!targetSessionId.value || !tenantId.value) return
  disconnectingTarget.value = true
  try {
    await disconnectLiveSession(tenantId.value, {
      kind: 'remote',
      id: targetSessionId.value,
      agent_id: agentId.value,
      reason: 'admin_disconnect',
    })
    confirmDisconnect.value = false
    showSuccess(t('mh.monitoring.disconnectSuccess'))
  } catch (e) {
    showError(e instanceof Error ? e.message : t('mh.monitoring.disconnectFailed'))
  } finally {
    disconnectingTarget.value = false
  }
}

function toggleFullscreen() {
  const el = wrapperRef.value
  if (!el) return
  if (document.fullscreenElement) {
    void document.exitFullscreen().catch(() => {})
  } else {
    void el.requestFullscreen().catch(() => {})
  }
}

function onFullscreenChange() {
  isFullscreen.value = Boolean(document.fullscreenElement)
}

function reconnect() {
  if (!agentId.value) return
  void rc.connect(agentId.value, 'VIEW,INPUT')
}

async function cleanupTakeoverAndDisconnect() {
  if (rc.adminTakeoverActive.value) {
    rc.setAdminTakeover(false)
    if (rc.sessionId.value && tenantId.value) {
      await setMonitorTakeover(tenantId.value, rc.sessionId.value, false).catch(() => {})
    }
  }
  detachInput?.()
  detachInput = null
  rc.disconnect()
}

async function closeWatch() {
  await cleanupTakeoverAndDisconnect()
  if (window.opener && !window.opener.closed) {
    window.close()
    return
  }
  if (tenantId.value) {
    void router.push({ name: 'monitoring-live', params: { tenantId: tenantId.value } })
  } else {
    void router.push('/')
  }
}

function onBeforeUnload() {
  if (rc.adminTakeoverActive.value) {
    rc.setAdminTakeover(false)
  }
}

onMounted(async () => {
  document.addEventListener('fullscreenchange', onFullscreenChange)
  window.addEventListener('beforeunload', onBeforeUnload)
  if (tenantId.value && !agentRef.value) {
    await agentStore.fetchAgents(tenantId.value).catch(() => {})
  }
  if (agentId.value) {
    void rc.connect(agentId.value, 'VIEW,INPUT')
  }
})

onBeforeUnmount(() => {
  document.removeEventListener('fullscreenchange', onFullscreenChange)
  window.removeEventListener('beforeunload', onBeforeUnload)
  void cleanupTakeoverAndDisconnect()
})
</script>

<style scoped>
.mw-shell {
  position: relative;
  display: flex;
  flex-direction: column;
  width: 100vw;
  height: 100vh;
  height: 100dvh;
  background: #0b0e14;
  color: #f4f7fb;
  overflow: hidden;
}

.mw-toolbar {
  flex: 0 0 auto;
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  padding: 6px 12px;
  background: rgba(15, 21, 32, 0.94);
  border-bottom: 1px solid rgba(255, 255, 255, 0.08);
  z-index: 15;
  flex-wrap: wrap;
}

.mw-shell--toolbar-hidden .mw-toolbar {
  display: none;
}

.mw-toolbar__left,
.mw-toolbar__right {
  display: flex;
  align-items: center;
  gap: 8px;
  flex-wrap: wrap;
}

.mw-meta {
  display: flex;
  align-items: baseline;
  gap: 8px;
}

.mw-meta__device {
  font-weight: 600;
  font-size: 13px;
}

.mw-meta__sub {
  font-size: 12px;
  color: rgba(244, 247, 251, 0.68);
}

.mw-pull-tab {
  position: absolute;
  top: 0;
  left: 50%;
  transform: translateX(-50%);
  z-index: 20;
  display: inline-flex;
  align-items: center;
  gap: 4px;
  padding: 3px 12px;
  font-size: 11px;
  font-weight: 600;
  color: #f4f7fb;
  background: rgba(15, 21, 32, 0.85);
  border: 1px solid rgba(255, 255, 255, 0.14);
  border-top: none;
  border-radius: 0 0 8px 8px;
  cursor: pointer;
}

.mw-stage {
  position: relative;
  flex: 1 1 0;
  min-height: 0;
  display: flex;
  align-items: center;
  justify-content: center;
  background: #06080c;
  outline: none;
  overflow: hidden;
}

.mw-stage--scroll {
  overflow: auto;
  align-items: flex-start;
  justify-content: flex-start;
}

.mw-stage--takeover {
  box-shadow: inset 0 0 0 3px rgba(245, 158, 11, 0.85);
}

.mw-media {
  display: block;
  user-select: none;
}

.mw-overlay {
  position: absolute;
  inset: 0;
  display: flex;
  align-items: center;
  justify-content: center;
  background: rgba(6, 8, 12, 0.72);
  z-index: 10;
  padding: 16px;
}
</style>
