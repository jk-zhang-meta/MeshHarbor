<template>
  <div
    v-if="visible"
    class="rc-rdp-fallback-card"
    data-test="rdp-fallback-card"
    role="region"
    aria-label="改用 RDP"
  >
    <div class="rc-rdp-fallback-title">改用 RDP</div>
    <p class="rc-rdp-fallback-reason" data-test="rdp-fallback-reason">
      {{ displayReason }}
    </p>
    <div class="rc-rdp-fallback-warning" data-test="rdp-screen-lock-warning" role="alert">
      {{ RDP_SCREEN_LOCK_WARNING }}
    </div>

    <div class="rc-rdp-fallback-actions">
      <button
        v-if="hasBridge"
        type="button"
        class="rc-rdp-btn rc-rdp-btn-primary"
        data-test="rdp-fallback-connect-btn"
        :disabled="busy"
        @click="onClickConnectRdp"
      >
        用 RDP 连接
      </button>
      <button
        type="button"
        class="rc-rdp-btn rc-rdp-btn-secondary"
        data-test="rdp-fallback-retry-btn"
        :disabled="busy"
        @click="emit('retry-rc')"
      >
        重试远控
      </button>
    </div>

    <div
      v-if="!hasBridge"
      class="rc-rdp-no-bridge"
      data-test="rdp-fallback-no-bridge"
    >
      <div class="rc-rdp-no-bridge-title">在桌面应用中打开</div>
      <p class="rc-rdp-no-bridge-desc">
        当前浏览器环境无桌面应用桥接。请在 MeshHarbor 桌面应用中打开以直接拉起系统 RDP 客户端，或在终端运行以下命令：
      </p>
      <div class="rc-rdp-cmd-row">
        <code class="rc-rdp-cmd-code" data-test="rdp-fallback-cli-cmd">{{ cliCommand }}</code>
        <button
          type="button"
          class="rc-rdp-btn rc-rdp-btn-copy"
          data-test="rdp-fallback-copy-btn"
          @click="onCopyCliCommand"
        >
          {{ copied ? '已复制' : '复制命令' }}
        </button>
      </div>
    </div>

    <div class="rc-rdp-auto-row">
      <label class="rc-rdp-auto-label">
        <input
          type="checkbox"
          data-test="rdp-auto-toggle"
          :checked="autoFallbackEnabled"
          @change="onToggleAutoFallback"
        />
        <span>自动改用 RDP（仅针对此设备）</span>
      </label>
    </div>

    <div
      v-if="confirmingAutoFallback"
      class="rc-rdp-auto-confirm"
      data-test="rdp-auto-confirm-prompt"
      role="alertdialog"
      aria-label="确认开启自动改用 RDP"
    >
      <p class="rc-rdp-auto-confirm-text">
        注意：{{ RDP_SCREEN_LOCK_WARNING }}。确认要为此设备开启“自动改用 RDP”吗？
      </p>
      <div class="rc-rdp-auto-confirm-actions">
        <button
          type="button"
          class="rc-rdp-btn rc-rdp-btn-primary"
          data-test="rdp-auto-confirm-accept"
          @click="onConfirmAutoFallback"
        >
          确认开启
        </button>
        <button
          type="button"
          class="rc-rdp-btn rc-rdp-btn-secondary"
          data-test="rdp-auto-confirm-cancel"
          @click="onCancelAutoFallback"
        >
          取消
        </button>
      </div>
    </div>

    <p v-if="bridgeError" class="rc-rdp-bridge-error" data-test="rdp-fallback-bridge-error">
      {{ bridgeError }}
    </p>
  </div>
</template>

<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import {
  RDP_SCREEN_LOCK_WARNING,
  formatMhRdpCommand,
  getDeviceAutoRdpFallback,
  hasDesktopRdpBridge,
  invokeDesktopOpenRdp,
  setDeviceAutoRdpFallback,
  shouldShowRdpFallbackCard,
} from '@/utils/rdpFallback'

const props = withDefaults(
  defineProps<{
    phase: string
    errorCode?: string | null
    errorMessage?: string | null
    mediaUnavailableReason?: string | null
    mediaUnavailableHint?: string | null
    rdpAvailable?: boolean | null
    rdpPort?: number | null
    rdpCertSha256?: string | null
    deviceId: string
    deviceName?: string | null
    org?: string | null
  }>(),
  {
    errorCode: null,
    errorMessage: null,
    mediaUnavailableReason: null,
    mediaUnavailableHint: null,
    rdpAvailable: false,
    rdpPort: null,
    rdpCertSha256: null,
    deviceName: null,
    org: null,
  },
)

const emit = defineEmits<{
  (e: 'retry-rc'): void
  (e: 'switch-to-rdp', payload: { auto: boolean }): void
}>()

const busy = ref(false)
const copied = ref(false)
const bridgeError = ref<string | null>(null)
const confirmingAutoFallback = ref(false)
const autoFallbackEnabled = ref(getDeviceAutoRdpFallback(props.deviceId))
const autoTriggeredForCurrentFailure = ref(false)

const visible = computed(() =>
  shouldShowRdpFallbackCard({
    phase: props.phase,
    errorCode: props.errorCode,
    mediaUnavailableReason: props.mediaUnavailableReason,
    rdpAvailable: props.rdpAvailable,
  }),
)

const hasBridge = computed(() => hasDesktopRdpBridge())

const displayReason = computed(() => {
  if (props.mediaUnavailableHint?.trim()) {
    return props.mediaUnavailableHint.trim()
  }
  if (props.errorMessage?.trim()) {
    return props.errorMessage.trim()
  }
  if (props.mediaUnavailableReason?.trim()) {
    return `远控画面不可用（${props.mediaUnavailableReason.trim()}）`
  }
  if (props.errorCode?.trim()) {
    return `远控连接失败（${props.errorCode.trim()}）`
  }
  return '远控连接失败'
})

const cliCommand = computed(() =>
  formatMhRdpCommand(props.deviceName?.trim() || props.deviceId),
)

watch(
  () => props.deviceId,
  (id) => {
    autoFallbackEnabled.value = getDeviceAutoRdpFallback(id)
    confirmingAutoFallback.value = false
    autoTriggeredForCurrentFailure.value = false
  },
)

watch(
  visible,
  async (isVisible) => {
    if (!isVisible) {
      autoTriggeredForCurrentFailure.value = false
      bridgeError.value = null
      return
    }
    if (
      autoFallbackEnabled.value &&
      hasBridge.value &&
      !autoTriggeredForCurrentFailure.value
    ) {
      autoTriggeredForCurrentFailure.value = true
      await triggerOpenRdp(true)
    }
  },
  { immediate: true },
)

async function triggerOpenRdp(auto: boolean) {
  bridgeError.value = null
  busy.value = true
  try {
    await invokeDesktopOpenRdp({
      target: props.deviceId,
      org: props.org,
      port: props.rdpPort ?? 3389,
      certSha256: props.rdpCertSha256,
    })
    emit('switch-to-rdp', { auto })
  } catch (err) {
    bridgeError.value = err instanceof Error ? err.message : String(err)
  } finally {
    busy.value = false
  }
}

async function onClickConnectRdp() {
  await triggerOpenRdp(false)
}

function onToggleAutoFallback(ev: Event) {
  const input = ev.target as HTMLInputElement
  if (input.checked) {
    // Revert checkbox until the user explicitly confirms the screen-lock warning.
    input.checked = false
    confirmingAutoFallback.value = true
  } else {
    confirmingAutoFallback.value = false
    autoFallbackEnabled.value = setDeviceAutoRdpFallback(props.deviceId, false, false)
  }
}

function onConfirmAutoFallback() {
  confirmingAutoFallback.value = false
  autoFallbackEnabled.value = setDeviceAutoRdpFallback(props.deviceId, true, true)
}

function onCancelAutoFallback() {
  confirmingAutoFallback.value = false
  autoFallbackEnabled.value = getDeviceAutoRdpFallback(props.deviceId)
}

async function onCopyCliCommand() {
  try {
    if (typeof navigator !== 'undefined' && navigator.clipboard?.writeText) {
      await navigator.clipboard.writeText(cliCommand.value)
    }
    copied.value = true
  } catch {
    copied.value = false
  }
}
</script>

<style scoped>
.rc-rdp-fallback-card {
  margin-top: 16px;
  padding: 16px;
  max-width: 460px;
  border-radius: 10px;
  border: 1px solid rgba(255, 255, 255, 0.16);
  background: rgba(18, 22, 31, 0.92);
  color: #f3f4f6;
  text-align: left;
}

.rc-rdp-fallback-title {
  font-size: 15px;
  font-weight: 600;
  margin-bottom: 6px;
}

.rc-rdp-fallback-reason {
  font-size: 13px;
  color: #d1d5db;
  margin: 0 0 10px;
}

.rc-rdp-fallback-warning {
  padding: 8px 10px;
  border-radius: 6px;
  background: rgba(245, 158, 11, 0.16);
  border: 1px solid rgba(245, 158, 11, 0.45);
  color: #fde68a;
  font-size: 13px;
  font-weight: 500;
  margin-bottom: 12px;
}

.rc-rdp-fallback-actions {
  display: flex;
  gap: 8px;
  flex-wrap: wrap;
  margin-bottom: 12px;
}

.rc-rdp-btn {
  padding: 6px 14px;
  border-radius: 6px;
  font-size: 13px;
  font-weight: 500;
  cursor: pointer;
  border: 1px solid transparent;
}

.rc-rdp-btn-primary {
  background: #2563eb;
  color: #fff;
}

.rc-rdp-btn-secondary {
  background: rgba(255, 255, 255, 0.08);
  border-color: rgba(255, 255, 255, 0.2);
  color: #e5e7eb;
}

.rc-rdp-no-bridge {
  margin-top: 8px;
  padding: 10px;
  border-radius: 6px;
  background: rgba(255, 255, 255, 0.05);
  border: 1px solid rgba(255, 255, 255, 0.12);
}

.rc-rdp-no-bridge-title {
  font-size: 13px;
  font-weight: 600;
  margin-bottom: 4px;
}

.rc-rdp-no-bridge-desc {
  font-size: 12px;
  color: #9ca3af;
  margin: 0 0 8px;
}

.rc-rdp-cmd-row {
  display: flex;
  align-items: center;
  gap: 8px;
}

.rc-rdp-cmd-code {
  flex: 1;
  padding: 5px 8px;
  border-radius: 4px;
  background: rgba(0, 0, 0, 0.45);
  font-family: monospace;
  font-size: 12px;
  color: #93c5fd;
}

.rc-rdp-auto-row {
  margin-top: 10px;
  font-size: 12.5px;
  color: #d1d5db;
}

.rc-rdp-auto-label {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  cursor: pointer;
}

.rc-rdp-auto-confirm {
  margin-top: 10px;
  padding: 10px;
  border-radius: 6px;
  background: rgba(245, 158, 11, 0.12);
  border: 1px solid rgba(245, 158, 11, 0.4);
}

.rc-rdp-auto-confirm-text {
  font-size: 12.5px;
  color: #fde68a;
  margin: 0 0 8px;
}

.rc-rdp-auto-confirm-actions {
  display: flex;
  gap: 8px;
}

.rc-rdp-bridge-error {
  margin: 8px 0 0;
  font-size: 12px;
  color: #fca5a5;
}
</style>
