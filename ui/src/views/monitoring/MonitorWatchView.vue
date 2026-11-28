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
          :color="rc.adminTakeoverActive.value ? 'warning' : rc.adminTakeoverOtherHolder.value ? 'deep-orange' : 'teal'"
          size="small"
          variant="flat"
          :prepend-icon="rc.adminTakeoverActive.value ? 'mdi-shield-account' : 'mdi-eye-outline'"
        >
          {{
            rc.adminTakeoverActive.value
              ? t('mh.monitoring.watch.takingOverBadge')
              : rc.adminTakeoverOtherHolder.value
                ? t('mh.monitoring.watch.otherAdminTakeoverBadge')
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
        <!-- Scale mode quick toggle (exact values matching useRemoteControl coordinate mapping) -->
        <v-btn-toggle
          v-model="rc.scaleMode.value"
          density="compact"
          variant="outlined"
          color="primary"
          mandatory
          class="mw-scale-toggle"
        >
          <v-btn value="adaptive" size="x-small" :title="t('mh.monitoring.watch.scaleFit')">
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

        <!-- Server-authorized Silent Takeover / Release toggle -->
        <v-btn
          v-if="!rc.adminTakeoverActive.value"
          color="warning"
          variant="flat"
          size="small"
          prepend-icon="mdi-hand-back-left"
          :disabled="rc.phase.value !== 'connected' || takeoverBusy || rc.adminTakeoverOtherHolder.value"
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

        <!-- Ctrl+Alt+Del (only while THIS admin holds agent-acknowledged takeover) -->
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

    <!-- Multi-transport video stage (WebRTC RTP + WebCodecs + VP9-444 DC + HEVC DC) -->
    <div
      ref="stageRef"
      tabindex="0"
      class="mw-stage"
      :class="{
        'mw-stage--takeover': rc.adminTakeoverActive.value,
        'mw-stage--scroll': rc.scaleMode.value === 'original',
        'mw-stage--fill': rc.scaleMode.value === 'fill',
      }"
      :style="stageCursorStyle"
    >
      <video
        v-show="!isCanvasRenderer"
        ref="videoRef"
        autoplay
        playsinline
        muted
        class="mw-media remote-video rc-video-canvas"
        :style="mediaStyle"
      />
      <canvas
        v-if="rc.webcodecsActive.value"
        :key="`wc-${canvasGen}`"
        :ref="bindWebcodecsCanvas"
        class="mw-media remote-video rc-video-canvas"
        :style="mediaStyle"
      />
      <canvas
        v-if="rc.vp9_444Active.value"
        :key="`vp9-${canvasGen}`"
        :ref="bindVp9Canvas"
        class="mw-media remote-video rc-video-canvas"
        :style="mediaStyle"
      />
      <canvas
        v-if="rc.hevcActive.value"
        :key="`hevc-${canvasGen}`"
        :ref="bindHevcCanvas"
        class="mw-media remote-video rc-video-canvas"
        :style="mediaStyle"
      />

      <!-- Connecting / Ended / Error / Device-2FA overlay -->
      <div v-if="overlayMessage" class="mw-overlay">
        <v-card max-width="460" class="pa-5 text-center" color="surface">
          <v-progress-circular
            v-if="isConnecting || loadingDevice"
            indeterminate
            color="primary"
            size="36"
            class="mb-3"
          />
          <v-icon
            v-else-if="needsTwoFactorCode"
            icon="mdi-shield-key-outline"
            color="warning"
            size="40"
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
          <v-form
            v-if="needsTwoFactorCode"
            class="mb-3 text-left"
            @submit.prevent="submitTwoFactorAndReconnect"
          >
            <v-text-field
              v-model="twoFactorInput"
              :label="t('mh.tfa.code.label')"
              variant="outlined"
              density="compact"
              autocomplete="one-time-code"
              autofocus
              hide-details="auto"
              class="mb-3"
            />
            <div class="d-flex justify-center ga-2">
              <v-btn
                type="submit"
                color="primary"
                variant="flat"
                :disabled="!twoFactorReady"
              >
                {{ t('mh.tfa.prompt.connect') }}
              </v-btn>
              <v-btn variant="outlined" @click="closeWatch">
                {{ t('mh.monitoring.watch.backToMonitoring') }}
              </v-btn>
            </div>
          </v-form>
          <div v-else class="d-flex justify-center ga-2">
            <v-btn
              v-if="!isConnecting && !loadingDevice && !endedNaturally"
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
import { computed, onBeforeUnmount, onMounted, ref, watch, type ComponentPublicInstance } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useI18n } from 'vue-i18n'
import { api } from '@/api/client'
import { useAuthStore } from '@/stores/auth'
import { useWsStore } from '@/stores/ws'
import type { Agent } from '@/stores/agents'
import { useRemoteControl, localPointerCursorCss } from '@/composables/useRemoteControl'
import { disconnectLiveSession, setMonitorTakeover } from '@/api/monitoring'
import { useSnackbar } from '@/composables/useSnackbar'
import { asksForCode, asTwoFactorRefusal, codeForWire, twoFactorRefusalText } from '@/utils/twoFactor'

const { t } = useI18n()
const route = useRoute()
const router = useRouter()
const auth = useAuthStore()
const wsStore = useWsStore()
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

// Exact target device row fetched directly by ID so signed peer verification
// (`peer_auth_key`) is NEVER skipped on fleets with >100 devices.
const targetAgent = ref<Agent | null>(null)
const loadingDevice = ref(false)
const deviceLoadError = ref('')

const targetDeviceLabel = computed(
  () =>
    queryDeviceName.value ||
    targetAgent.value?.display_name ||
    targetAgent.value?.name ||
    agentId.value.slice(0, 8),
)

const rc = useRemoteControl(targetAgent, {
  userId: () => auth.user?.id ?? null,
  silentMonitor: true,
  monitorTargetSessionId: () => targetSessionId.value || null,
})

const wrapperRef = ref<HTMLElement | null>(null)
const stageRef = ref<HTMLElement | null>(null)
const videoRef = ref<HTMLVideoElement | null>(null)

// Fresh canvas key per connect/reconnect so a transferred OffscreenCanvas is
// never reused after teardown or target change.
const canvasGen = ref(1)
const toolbarCollapsed = ref(false)
const isFullscreen = ref(false)
const takeoverBusy = ref(false)
const confirmDisconnect = ref(false)
const disconnectingTarget = ref(false)
const twoFactorInput = ref('')
let detachInput: (() => void) | null = null
let bootGen = 0

const twoFactorRefusal = computed(() => asTwoFactorRefusal(rc.errorCode.value))
const needsTwoFactorCode = computed(
  () => !loadingDevice.value && !isConnecting.value && asksForCode(twoFactorRefusal.value),
)
const twoFactorReady = computed(() => Boolean(codeForWire(twoFactorInput.value)))

const isCanvasRenderer = computed(
  () => rc.webcodecsActive.value || rc.vp9_444Active.value || rc.hevcActive.value,
)

function bindWebcodecsCanvas(el: Element | ComponentPublicInstance | null) {
  rc.webcodecsCanvasEl.value = (el as HTMLCanvasElement | null) ?? null
}
function bindVp9Canvas(el: Element | ComponentPublicInstance | null) {
  rc.vp9_444CanvasEl.value = (el as HTMLCanvasElement | null) ?? null
}
function bindHevcCanvas(el: Element | ComponentPublicInstance | null) {
  rc.hevcCanvasEl.value = (el as HTMLCanvasElement | null) ?? null
}

// Separate-cursor CSS mapping when admin is actively controlling.
const cursorUrlCache = new Map<number, string | null>()
function cursorBitmapUrl(id: number): string | null {
  if (cursorUrlCache.has(id)) return cursorUrlCache.get(id) ?? null
  const shape = rc.cursor.value.shapes.get(id)
  if (!shape?.bitmap) return null
  try {
    const c = document.createElement('canvas')
    c.width = shape.bitmap.width
    c.height = shape.bitmap.height
    const ctx = c.getContext('2d')
    if (!ctx) return null
    ctx.drawImage(shape.bitmap, 0, 0)
    const url = c.toDataURL('image/png')
    cursorUrlCache.set(id, url)
    return url
  } catch {
    return null
  }
}

const stageCursorStyle = computed(() => {
  if (!rc.adminTakeoverActive.value) return {}
  return { cursor: localPointerCursorCss(rc.cursor.value, cursorBitmapUrl) }
})

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
  () =>
    rc.errorCode.value === 'target_session_ended' ||
    (!deviceLoadError.value && !needsTwoFactorCode.value && rc.phase.value === 'closed'),
)
const phaseColor = computed(() => {
  if (rc.phase.value === 'connected') return 'success'
  if (isConnecting.value || loadingDevice.value) return 'info'
  if (needsTwoFactorCode.value) return 'warning'
  if (rc.phase.value === 'error' || deviceLoadError.value) return 'error'
  return 'default'
})
const phaseLabel = computed(() => {
  if (loadingDevice.value) return t('mh.monitoring.watch.phaseConnecting')
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
  if (loadingDevice.value || isConnecting.value) return t('mh.monitoring.watch.connectingTitle')
  if (needsTwoFactorCode.value) return t('mh.tfa.prompt.title')
  if (deviceLoadError.value) return t('mh.monitoring.watch.errorTitle')
  if (rc.errorCode.value === 'target_session_ended') {
    return t('mh.monitoring.watch.targetEndedTitle')
  }
  if (rc.phase.value === 'closed') return t('mh.monitoring.watch.closedTitle')
  return t('mh.monitoring.watch.errorTitle')
})

const overlayMessage = computed(() => {
  if (rc.phase.value === 'connected') return ''
  if (loadingDevice.value || isConnecting.value) return t('mh.monitoring.watch.connectingDesc')
  if (needsTwoFactorCode.value) return twoFactorRefusalText(twoFactorRefusal.value)
  if (deviceLoadError.value) return deviceLoadError.value
  if (rc.errorCode.value === 'target_session_ended') {
    return t('mh.monitoring.watch.targetEndedDesc')
  }
  if (rc.error.value) return rc.error.value
  if (rc.phase.value === 'closed') return t('mh.monitoring.watch.closedDesc')
  return ''
})

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

// Announce takeover / release ONLY after the agent confirms ownership via
// authoritative `rc:control.state` (never prematurely on HTTP enqueue).
watch(rc.adminTakeoverActive, (active, prev) => {
  if (active && !prev) {
    stageRef.value?.focus()
    showSuccess(t('mh.monitoring.watch.takeoverEnabledToast'))
  } else if (!active && prev && rc.phase.value === 'connected') {
    showSuccess(t('mh.monitoring.watch.takeoverReleasedToast'))
  }
})

async function toggleTakeover(active: boolean) {
  if (rc.phase.value !== 'connected' || !rc.sessionId.value || !tenantId.value) return
  takeoverBusy.value = true
  try {
    // Authoritative server RBAC check + ServerMsg::AdminTakeover push to agent.
    // Input + toast only fire once the agent confirms ownership in `rc:control.state`.
    await setMonitorTakeover(tenantId.value, rc.sessionId.value, active)
  } catch (e) {
    showError(e instanceof Error ? e.message : t('mh.monitoring.watch.takeoverFailed'))
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

function submitTwoFactorAndReconnect() {
  const wire = codeForWire(twoFactorInput.value)
  if (!wire || !agentId.value) return
  twoFactorInput.value = ''
  canvasGen.value += 1
  rc.twoFactorCode.value = wire
  void rc.connect(agentId.value, 'VIEW,INPUT')
}

async function bootTarget() {
  const gen = ++bootGen
  await cleanupTakeoverAndDisconnect(gen)
  if (gen !== bootGen) return

  targetAgent.value = null
  deviceLoadError.value = ''
  twoFactorInput.value = ''
  cursorUrlCache.clear()
  canvasGen.value += 1

  if (!tenantId.value || !agentId.value) {
    deviceLoadError.value = t('mh.monitoring.watch.errorTitle')
    return
  }

  wsStore.setTenantAffinity(tenantId.value)
  loadingDevice.value = true
  try {
    const dev = await api.get<Agent>(`/tenant/${tenantId.value}/agent/${agentId.value}`)
    if (gen !== bootGen) return
    targetAgent.value = dev
  } catch (e) {
    if (gen !== bootGen) return
    deviceLoadError.value = e instanceof Error ? e.message : t('mh.monitoring.watch.errorTitle')
    return
  } finally {
    if (gen === bootGen) loadingDevice.value = false
  }

  // Default to adaptive scale so coordinate mapping matches letterboxing accurately.
  if (rc.scaleMode.value !== 'fill' && rc.scaleMode.value !== 'original') {
    rc.scaleMode.value = 'adaptive'
  }
  void rc.connect(agentId.value, 'VIEW,INPUT')
}

function reconnect() {
  void bootTarget()
}

async function cleanupTakeoverAndDisconnect(expectedGen?: number) {
  const activeSid = rc.adminTakeoverActive.value ? rc.sessionId.value : null
  const activeTid = tenantId.value
  if (activeSid && activeTid) {
    await setMonitorTakeover(activeTid, activeSid, false).catch(() => {})
  }
  if (expectedGen !== undefined && expectedGen !== bootGen) return
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

watch([tenantId, agentId, targetSessionId], () => {
  void bootTarget()
})

onMounted(() => {
  document.addEventListener('fullscreenchange', onFullscreenChange)
  void bootTarget()
})

onBeforeUnmount(() => {
  bootGen += 1
  document.removeEventListener('fullscreenchange', onFullscreenChange)
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
