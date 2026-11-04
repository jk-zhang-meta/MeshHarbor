<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 G ROX EOOD -->
<template>
  <v-dialog v-model="open" max-width="1100" scrollable :fullscreen="fullscreen">
    <v-card>
      <v-card-title class="d-flex align-center">
        <v-icon icon="mdi-console" color="primary" class="mr-2" />
        <!-- The span shrinks with an ellipsis (min-width: 0), so the title's own
             buttons stay on screen: a title never wraps, and a long device name
             used to push Close or Refresh past the edge on a phone. -->
        <span class="text-truncate" style="min-width: 0">{{ t('mh.console.title', { name: agentName }) }}</span>
        <v-spacer />
        <v-btn icon="mdi-close" size="small" variant="text" @click="close" :aria-label="t('mh.console.close')" />
      </v-card-title>

      <!-- Say plainly what running a command here means. Under systemd the
           daemon is root. On Windows a command runs as the console-session
           worker: the signed-in user on an attended install (their elevated
           token if they are an admin), SYSTEM in SystemContext mode — FR-94
           makes SYSTEM the default. An operator should learn that from the
           UI, not from an incident. -->
      <!-- In the card text, not a v-card-subtitle: a subtitle never wraps and
           dims its content, which turned this warning into one clipped grey
           line ("Commands run with the Roomler d…") at every width. -->
      <v-card-text :style="fullscreen ? undefined : 'max-height: 70vh'">
        <v-alert
          type="warning"
          variant="tonal"
          density="compact"
          class="mb-3"
          icon="mdi-shield-alert-outline"
        >
          <i18n-t keypath="mh.console.warn" tag="span" scope="global">
            <template #root><strong>root</strong></template>
            <template #user><strong>{{ t('mh.settings.exec.signedInUser') }}</strong></template>
            <template #system><strong>SYSTEM</strong></template>
          </i18n-t>
        </v-alert>

        <!-- Explain a closed gate BEFORE the operator types a command and
             watches it get refused. Each gate names its own owner, because
             "ask your org owner" and "turn it on for this device" are
             different next steps. -->
        <v-alert
          v-if="blockedReason"
          type="info"
          variant="tonal"
          density="compact"
          class="mb-3"
        >
          {{ blockedReason }}
        </v-alert>

        <div class="d-flex align-center flex-wrap ga-2 mb-3">
          <v-select
            v-model="shell"
            :items="shellOptions"
            :label="t('mh.console.shell')"
            density="compact"
            variant="outlined"
            hide-details
            style="max-width: 180px"
          />
          <v-text-field
            v-model.number="timeoutSecs"
            :label="t('mh.console.timeout')"
            type="number"
            density="compact"
            variant="outlined"
            hide-details
            style="max-width: 130px"
            :min="1"
            :max="300"
          />
          <v-spacer />
          <v-btn
            v-if="running"
            color="warning"
            variant="tonal"
            prepend-icon="mdi-stop"
            @click="cancel"
          >
            Cancel
          </v-btn>
        </div>

        <v-textarea
          v-model="command"
          :label="t('mh.console.command')"
          rows="3"
          auto-grow
          density="compact"
          variant="outlined"
          hide-details
          class="mb-2 font-mono"
          :disabled="running"
          @keydown.ctrl.enter.prevent="run"
        />
        <div class="d-flex align-center mb-4">
          <span class="text-caption text-medium-emphasis">{{ t('mh.console.hint') }}</span>
          <v-spacer />
          <v-btn
            color="primary"
            prepend-icon="mdi-play"
            :loading="running"
            :disabled="!command.trim()"
            @click="run"
          >
            {{ t('mh.console.run') }}
          </v-btn>
        </div>

        <v-alert v-if="error" type="error" variant="tonal" density="compact" class="mb-3">
          {{ error }}
        </v-alert>

        <div v-for="(entry, i) in history" :key="entry.request_id || i" class="mb-4">
          <div class="d-flex align-center flex-wrap ga-2 mb-1">
            <v-chip size="small" :color="statusColor(entry)" variant="flat">
              {{ statusLabel(entry) }}
            </v-chip>
            <code class="text-caption">{{ entry.shell || t('mh.console.default') }}</code>
            <span class="text-caption text-medium-emphasis">{{ entry.duration_ms }} ms</span>
            <v-chip v-if="entry.truncated" size="x-small" color="warning" variant="tonal">
              {{ t('mh.console.truncated') }}
            </v-chip>
            <v-spacer />
            <v-btn
              icon="mdi-content-copy"
              size="x-small"
              variant="text"
              :aria-label="t('mh.console.copy')"
              @click="copyOutput(entry)"
            />
          </div>
          <pre class="console-cmd">{{ entry.command }}</pre>
          <pre v-if="entry.error" class="console-err">{{ entry.error }}</pre>
          <pre v-if="entry.stdout" class="console-out">{{ entry.stdout }}</pre>
          <pre v-if="entry.stderr" class="console-err">{{ entry.stderr }}</pre>
        </div>

        <div v-if="!history.length && !running" class="text-medium-emphasis text-caption">
          {{ t('mh.console.empty') }}
        </div>
      </v-card-text>
    </v-card>
  </v-dialog>
</template>

<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { useAgentStore, type Agent, type ExecResult } from '@/stores/agents'
import { useResponsiveDialog } from '@/composables/useResponsiveDialog'
import { deviceLabel } from '@/composables/useHideDeviceName'
import { useI18n } from 'vue-i18n'

const { t } = useI18n()

const props = defineProps<{
  modelValue: boolean
  tenantId: string
  agent: Agent
}>()

const emit = defineEmits<{
  (e: 'update:modelValue', v: boolean): void
}>()

const open = computed({
  get: () => props.modelValue,
  set: (v) => emit('update:modelValue', v),
})

const agentStore = useAgentStore()
// The name a person knows the device by (FR-116), as the Devices page shows it.
const agentName = computed(() => deviceLabel(props.agent))
const { fullscreen } = useResponsiveDialog()

const command = ref('')
const shell = ref('')
const timeoutSecs = ref(30)
const running = ref(false)
const error = ref<string | null>(null)
/** Newest first, so the latest result is where the eye already is. */
const history = ref<Array<ExecResult & { command: string; shell: string }>>([])
/** The in-flight request, so Cancel has something to address. */
const inFlight = ref<string | null>(null)

/** Windows and Unix hosts offer different shells; showing `bash` for a
 *  Windows box would only produce an "unsupported shell" round trip. */
const shellOptions = computed(() =>
  props.agent?.os === 'windows'
    ? [
        { title: t('mh.console.hostDefaultPs'), value: '' },
        { title: 'powershell', value: 'powershell' },
        { title: 'pwsh', value: 'pwsh' },
        { title: 'cmd', value: 'cmd' },
      ]
    : [
        { title: t('mh.console.hostDefaultBash'), value: '' },
        { title: 'bash', value: 'bash' },
        { title: 'sh', value: 'sh' },
      ],
)

/** Which gate is shut, in the order the server evaluates them, phrased as
 *  the action the reader can actually take. `null` = nothing known to be
 *  blocking. */
const blockedReason = computed<string | null>(() => {
  if (agentStore.orgExecEnabled === false) {
    return t('mh.console.orgOff')
  }
  if ((props.agent?.exec_policy?.mode ?? 'off') !== 'on') {
    return t('mh.console.deviceOff')
  }
  if (props.agent && !props.agent.is_online && props.agent.presence !== 'online') {
    return t('mh.console.offline')
  }
  if (!(props.agent?.capabilities?.rpc ?? []).includes('exec')) {
    return t('mh.console.tooOld', { version: props.agent?.agent_version ?? '?' })
  }
  return null
})

function statusLabel(e: ExecResult): string {
  if (e.error) return t('mh.audit.refused')
  return t('mh.audit.exit', { code: e.exit_code ?? '?' })
}

function statusColor(e: ExecResult): string {
  if (e.error) return 'error'
  return e.exit_code === 0 ? 'success' : 'warning'
}

async function run() {
  const cmd = command.value.trim()
  if (!cmd || running.value) return
  running.value = true
  error.value = null
  const usedShell = shell.value
  try {
    const res = await agentStore.execOnAgent(props.tenantId, props.agent.id, {
      shell: usedShell,
      command: cmd,
      timeout_ms: Math.max(1, Math.min(300, timeoutSecs.value || 30)) * 1000,
    })
    inFlight.value = res.request_id
    history.value.unshift({ ...res, command: cmd, shell: usedShell })
  } catch (e) {
    // Only transport / validation failures land here — a policy refusal
    // comes back as a normal result carrying `error`.
    error.value = (e as Error).message
  } finally {
    running.value = false
    inFlight.value = null
  }
}

async function cancel() {
  if (!inFlight.value) return
  try {
    await agentStore.cancelExec(props.tenantId, props.agent.id, inFlight.value)
  } catch (e) {
    error.value = (e as Error).message
  }
}

async function copyOutput(e: ExecResult & { command: string }) {
  const text = [e.command, e.stdout, e.stderr, e.error].filter(Boolean).join('\n')
  try {
    await navigator.clipboard.writeText(text)
  } catch {
    // Clipboard permission denied — not worth an error banner over.
  }
}

function close() {
  open.value = false
}

watch(
  () => props.modelValue,
  (v) => {
    if (!v) return
    error.value = null
    if (agentStore.orgExecEnabled === null) {
      void agentStore.fetchOrgExecEnabled(props.tenantId)
    }
  },
)
</script>

<style scoped>
.console-cmd,
.console-out,
.console-err {
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  font-size: 0.8rem;
  white-space: pre-wrap;
  word-break: break-word;
  padding: 0.5rem 0.75rem;
  border-radius: 4px;
  margin: 0 0 2px;
  /* Scroll long output inside its own box — the dialog itself must never
     scroll sideways. */
  overflow-x: auto;
}
.console-cmd {
  background: rgba(var(--v-theme-primary), 0.08);
}
.console-out {
  background: rgba(var(--v-theme-on-surface), 0.04);
}
.console-err {
  background: rgba(var(--v-theme-error), 0.08);
}
.font-mono :deep(textarea) {
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
}
</style>
