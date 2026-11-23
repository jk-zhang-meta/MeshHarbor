<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 G ROX EOOD -->
<template>
  <!-- FR-129 — switch a device's two-factor on or off. The DEVICE does every
       step: it makes the secret, checks the confirming code, and checks the
       code that switches it off. This dialog only shows what it answers, and
       forgets the secret, the QR code and the recovery codes when it closes.
       The recovery-codes step cannot be dismissed by a stray click: they are
       shown once. -->
  <v-dialog
    v-model="open"
    max-width="700"
    scrollable
    :fullscreen="fullscreen"
    :persistent="step === 'codes'"
  >
    <v-card>
      <v-card-title class="d-flex align-center">
        <v-icon icon="mdi-two-factor-authentication" color="primary" class="mr-2" />
        <span class="text-truncate" style="min-width: 0">{{ t('mh.tfa.title', { name }) }}</span>
        <v-spacer />
        <v-btn
          v-if="step !== 'codes'"
          icon="mdi-close"
          size="small"
          variant="text"
          :aria-label="t('mh.common.close')"
          @click="close"
        />
      </v-card-title>

      <v-card-text>
        <!-- The state, and what it means. -->
        <template v-if="step === 'state'">
          <v-alert
            :type="enabled ? 'success' : 'info'"
            :icon="enabled ? 'mdi-shield-check-outline' : 'mdi-shield-off-outline'"
            variant="tonal"
            density="compact"
            class="mb-3"
            data-testid="tfa-state"
          >
            <strong>{{ enabled ? t('mh.tfa.on') : t('mh.tfa.off') }}</strong>
            {{ enabled ? t('mh.tfa.onBody') : t('mh.tfa.offBody') }}
          </v-alert>
          <p class="text-body-2 text-medium-emphasis mb-3">{{ t('mh.tfa.how') }}</p>
          <v-alert
            v-if="!supported && !enabled"
            type="warning"
            variant="tonal"
            density="compact"
            data-testid="tfa-too-old"
          >
            {{ t('mh.tfa.tooOld', { version }) }}
          </v-alert>
        </template>

        <!-- Step 1: which app. The same QR code either way; the steps differ. -->
        <template v-else-if="step === 'app'">
          <div class="text-subtitle-1 mb-1">{{ t('mh.tfa.chooseApp') }}</div>
          <div class="text-body-2 text-medium-emphasis mb-3">{{ t('mh.tfa.chooseAppHint') }}</div>
          <v-row dense>
            <v-col v-for="a in APPS" :key="a.id" cols="12" sm="6">
              <v-card
                variant="outlined"
                class="pa-4 text-center h-100"
                :disabled="busy"
                :data-testid="`tfa-app-${a.id}`"
                @click="chooseApp(a.id)"
              >
                <v-icon :icon="a.icon" size="40" class="mb-2" />
                <div class="text-subtitle-1">{{ t(`mh.tfa.app.${a.id}`) }}</div>
              </v-card>
            </v-col>
          </v-row>
          <v-progress-linear v-if="busy" indeterminate class="mt-3" />
        </template>

        <!-- Step 2: scan (or type the key), then prove it with a code. -->
        <template v-else-if="step === 'scan'">
          <div class="text-subtitle-1 mb-3">{{ t('mh.tfa.scanTitle', { app: appName }) }}</div>
          <div class="d-flex flex-wrap ga-4 mb-2">
            <div class="tfa-qr">
              <img
                v-if="qrDataUrl"
                :src="qrDataUrl"
                :alt="t('mh.tfa.qrAlt')"
                width="200"
                height="200"
                data-testid="tfa-qr"
              />
              <v-progress-circular v-else-if="!qrFailed" indeterminate color="grey" />
              <v-icon v-else icon="mdi-qrcode-remove" size="48" color="grey" />
            </div>
            <div class="flex-grow-1 tfa-scan-side">
              <div class="text-caption text-medium-emphasis">{{ t('mh.tfa.key') }}</div>
              <div class="d-flex align-center flex-wrap ga-2 mb-3">
                <code class="tfa-key" data-testid="tfa-key">{{ groupedKey }}</code>
                <v-btn
                  size="small"
                  variant="tonal"
                  prepend-icon="mdi-content-copy"
                  data-testid="tfa-copy-key"
                  @click="copyKey"
                >
                  {{ keyCopied ? t('mh.tfa.copied') : t('mh.tfa.copyKey') }}
                </v-btn>
              </div>
              <ol class="text-body-2 pl-5 mb-1" data-testid="tfa-steps">
                <li v-for="(s, i) in appSteps" :key="i" class="mb-1">{{ s }}</li>
              </ol>
              <v-btn variant="text" size="small" class="px-1" @click="app = otherApp">
                {{ t('mh.tfa.otherApp', { app: t(`mh.tfa.app.${otherApp}`) }) }}
              </v-btn>
            </div>
          </div>
          <v-alert v-if="qrFailed" type="info" variant="tonal" density="compact" class="mb-3">
            {{ t('mh.tfa.qrFailed') }}
          </v-alert>
          <TwoFactorCodeInput
            ref="codeInput"
            v-model="code"
            :allow-recovery="false"
            autofocus
            :disabled="busy || pendingGone"
            @submit="confirm"
          />
        </template>

        <!-- Step 3: the recovery codes, once. -->
        <template v-else-if="step === 'codes'">
          <v-alert
            type="warning"
            variant="tonal"
            density="compact"
            class="mb-3"
            icon="mdi-alert-outline"
          >
            <strong>{{ t('mh.tfa.codesTitle') }}</strong>
            {{ t('mh.tfa.codesWarn') }}
          </v-alert>
          <div class="tfa-codes mb-3" data-testid="tfa-recovery-codes">
            <code v-for="c in recoveryCodes" :key="c">{{ c }}</code>
          </div>
          <div class="d-flex flex-wrap ga-2">
            <v-btn variant="tonal" prepend-icon="mdi-content-copy" data-testid="tfa-copy-codes" @click="copyCodes">
              {{ codesCopied ? t('mh.tfa.copied') : t('mh.tfa.copyAll') }}
            </v-btn>
            <v-btn variant="tonal" prepend-icon="mdi-download" @click="downloadCodes">
              {{ t('mh.tfa.download') }}
            </v-btn>
          </div>
        </template>

        <!-- Switching off takes a code, checked by the device: a stolen admin
             session cannot do it. -->
        <template v-else>
          <p class="text-body-2 mb-3">{{ t('mh.tfa.disableBody') }}</p>
          <TwoFactorCodeInput
            ref="codeInput"
            v-model="code"
            autofocus
            :disabled="busy"
            @submit="disable"
          />
        </template>

        <v-alert
          v-if="notice"
          type="success"
          variant="tonal"
          density="compact"
          class="mt-3"
          data-testid="tfa-notice"
        >
          {{ notice }}
        </v-alert>
        <v-alert
          v-if="error"
          type="error"
          variant="tonal"
          density="compact"
          class="mt-3"
          data-testid="tfa-error"
        >
          {{ error }}
        </v-alert>
      </v-card-text>

      <v-card-actions class="flex-wrap">
        <template v-if="step === 'state'">
          <v-spacer />
          <v-btn variant="text" @click="close">{{ t('mh.common.close') }}</v-btn>
          <v-btn
            v-if="enabled"
            color="error"
            variant="tonal"
            prepend-icon="mdi-shield-off-outline"
            data-testid="tfa-disable"
            @click="toStep('disable')"
          >
            {{ t('mh.tfa.disable') }}
          </v-btn>
          <v-btn
            v-else
            color="primary"
            variant="flat"
            prepend-icon="mdi-shield-lock-outline"
            :disabled="!supported"
            data-testid="tfa-enable"
            @click="toStep('app')"
          >
            {{ t('mh.tfa.enable') }}
          </v-btn>
        </template>
        <template v-else-if="step === 'app'">
          <v-btn variant="text" :disabled="busy" @click="toStep('state')">{{ t('mh.tfa.back') }}</v-btn>
          <v-spacer />
        </template>
        <template v-else-if="step === 'scan'">
          <v-btn variant="text" :disabled="busy" @click="toStep('state')">{{ t('common.cancel') }}</v-btn>
          <v-spacer />
          <v-btn
            v-if="pendingGone"
            variant="tonal"
            prepend-icon="mdi-restart"
            :loading="busy"
            data-testid="tfa-restart"
            @click="begin"
          >
            {{ t('mh.tfa.restart') }}
          </v-btn>
          <v-btn
            v-else
            color="primary"
            variant="flat"
            :loading="busy"
            :disabled="!codeReady"
            data-testid="tfa-confirm"
            @click="confirm"
          >
            {{ t('mh.tfa.confirm') }}
          </v-btn>
        </template>
        <template v-else-if="step === 'codes'">
          <v-spacer />
          <v-btn color="primary" variant="flat" data-testid="tfa-saved" @click="close">
            {{ t('mh.tfa.saved') }}
          </v-btn>
        </template>
        <template v-else>
          <v-btn variant="text" :disabled="busy" @click="toStep('state')">{{ t('common.cancel') }}</v-btn>
          <v-spacer />
          <v-btn
            color="error"
            variant="flat"
            :loading="busy"
            :disabled="!codeReady"
            data-testid="tfa-disable-confirm"
            @click="disable"
          >
            {{ t('mh.tfa.disableConfirm') }}
          </v-btn>
        </template>
      </v-card-actions>
    </v-card>
  </v-dialog>
</template>

<script setup lang="ts">
import { computed, nextTick, onBeforeUnmount, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import QRCode from 'qrcode'
import TwoFactorCodeInput from '@/components/common/TwoFactorCodeInput.vue'
import { useResponsiveDialog } from '@/composables/useResponsiveDialog'
import { deviceLabel } from '@/composables/useHideDeviceName'
import { useAgentStore, type Agent, type TwoFactorStepResult } from '@/stores/agents'
import {
  codeForWire,
  groupKey,
  recoveryCodesFile,
  supportsTwoFactor,
  twoFactorOn,
  twoFactorRefusalText,
  ungroupKey,
} from '@/utils/twoFactor'

type Step = 'state' | 'app' | 'scan' | 'codes' | 'disable'
type AuthApp = 'microsoft' | 'google'

const APPS: ReadonlyArray<{ id: AuthApp; icon: string }> = [
  { id: 'microsoft', icon: 'mdi-microsoft' },
  { id: 'google', icon: 'mdi-google' },
]

const props = defineProps<{
  modelValue: boolean
  tenantId: string
  agent: Agent
}>()

const emit = defineEmits<{
  (e: 'update:modelValue', v: boolean): void
}>()

const { t } = useI18n()
const { fullscreen } = useResponsiveDialog()
const agentStore = useAgentStore()

const open = computed({
  get: () => props.modelValue,
  set: (v) => emit('update:modelValue', v),
})

const step = ref<Step>('state')
/** The device's last word on its state: every answer carries it. */
const enabled = ref(false)
const app = ref<AuthApp>('microsoft')
/** ⚠️ Secrets, held only while the dialog is open and never logged. */
const secret = ref('')
/** `begin`'s setup id, sent back with `confirm`. */
const setupId = ref('')
const qrDataUrl = ref('')
const recoveryCodes = ref<string[]>([])
const code = ref('')
const qrFailed = ref(false)
const busy = ref(false)
const error = ref('')
const notice = ref('')
/** `confirm` answered `no_pending`: the setup must start again. */
const pendingGone = ref(false)
const keyCopied = ref(false)
const codesCopied = ref(false)
const codeInput = ref<{ focus: () => void } | null>(null)
/** The last code the device refused. Sending it again would only spend one
 *  of the tries before the device locks. */
let refusedCode = ''
/** Bumped on every close and step change, so an answer that arrives after
 *  either is dropped instead of writing a secret back into the dialog. */
let gen = 0

const supported = computed(() => supportsTwoFactor(props.agent?.capabilities))
const name = computed(() => deviceLabel(props.agent))
const version = computed(() => props.agent?.agent_version || '?')
const groupedKey = computed(() => groupKey(secret.value))
const appName = computed(() => t(`mh.tfa.app.${app.value}`))
const otherApp = computed<AuthApp>(() => (app.value === 'microsoft' ? 'google' : 'microsoft'))
const codeReady = computed(() => !!codeForWire(code.value, step.value === 'disable'))
const appSteps = computed(() =>
  app.value === 'microsoft'
    ? [
        t('mh.tfa.steps.microsoft.s1'),
        t('mh.tfa.steps.microsoft.s2'),
        t('mh.tfa.steps.microsoft.s3'),
        t('mh.tfa.steps.last'),
      ]
    : [
        t('mh.tfa.steps.google.s1'),
        t('mh.tfa.steps.google.s2'),
        t('mh.tfa.steps.google.s3', { name: name.value }),
        t('mh.tfa.steps.last'),
      ],
)

/** Forget everything secret and every message. */
function clearSecrets() {
  gen++
  secret.value = ''
  setupId.value = ''
  qrDataUrl.value = ''
  recoveryCodes.value = []
  code.value = ''
  refusedCode = ''
  qrFailed.value = false
  pendingGone.value = false
  keyCopied.value = false
  codesCopied.value = false
  busy.value = false
  error.value = ''
  notice.value = ''
}

watch(
  () => props.modelValue,
  (v) => {
    clearSecrets()
    step.value = 'state'
    if (v) enabled.value = twoFactorOn(props.agent?.capabilities)
  },
  { immediate: true },
)

onBeforeUnmount(clearSecrets)

function close() {
  open.value = false
}

function toStep(s: Step) {
  clearSecrets()
  step.value = s
}

/** Take the device's state from an answer; `true` when it did the step. */
function take(r: TwoFactorStepResult): boolean {
  if (typeof r.enabled === 'boolean') enabled.value = r.enabled
  if (!r.refused) return true
  error.value = twoFactorRefusalText(r.refused, {
    retryAfterSecs: r.retry_after_secs,
    message: r.message,
  })
  return false
}

function failed(e: unknown) {
  error.value = (e instanceof Error && e.message) || t('mh.tfa.reason.other')
}

function refocus() {
  void nextTick(() => codeInput.value?.focus())
}

function chooseApp(a: AuthApp) {
  app.value = a
  void begin()
}

async function begin() {
  if (busy.value) return
  const g = gen
  busy.value = true
  error.value = ''
  pendingGone.value = false
  code.value = ''
  refusedCode = ''
  try {
    const r = await agentStore.twoFactorStep(props.tenantId, props.agent.id, { op: 'begin' })
    if (g !== gen) return
    if (!take(r)) {
      // Someone switched it on meanwhile: show the state, with the reason.
      if (r.refused === 'already_on') step.value = 'state'
      return
    }
    if (!r.secret || !r.otpauth_uri) {
      error.value = t('mh.tfa.reason.other')
      return
    }
    secret.value = r.secret
    setupId.value = r.setup_id ?? ''
    qrDataUrl.value = ''
    qrFailed.value = false
    step.value = 'scan'
    try {
      const url = await QRCode.toDataURL(r.otpauth_uri, {
        errorCorrectionLevel: 'M',
        margin: 1,
        width: 200,
      })
      if (g === gen) qrDataUrl.value = url
    } catch {
      // The key is on screen beside it; typing it in works in both apps.
      if (g === gen) qrFailed.value = true
    }
  } catch (e) {
    if (g === gen) failed(e)
  } finally {
    if (g === gen) busy.value = false
  }
}

async function confirm() {
  const c = codeForWire(code.value, false)
  if (!c || busy.value || pendingGone.value) return
  if (c === refusedCode) {
    error.value = t('mh.tfa.code.reused')
    return
  }
  const g = gen
  busy.value = true
  error.value = ''
  try {
    const r = await agentStore.twoFactorStep(props.tenantId, props.agent.id, {
      op: 'confirm',
      code: c,
      setup_id: setupId.value,
    })
    if (g !== gen) return
    code.value = ''
    if (!take(r)) {
      refusedCode = c
      if (r.refused === 'no_pending') pendingGone.value = true
      else if (r.refused === 'already_on') step.value = 'state'
      else refocus()
      return
    }
    secret.value = ''
    qrDataUrl.value = ''
    recoveryCodes.value = r.recovery_codes ?? []
    step.value = 'codes'
  } catch (e) {
    if (g === gen) failed(e)
  } finally {
    if (g === gen) busy.value = false
  }
}

async function disable() {
  const c = codeForWire(code.value, true)
  if (!c || busy.value) return
  if (c === refusedCode) {
    error.value = t('mh.tfa.code.reused')
    return
  }
  const g = gen
  busy.value = true
  error.value = ''
  try {
    const r = await agentStore.twoFactorStep(props.tenantId, props.agent.id, { op: 'disable', code: c })
    if (g !== gen) return
    code.value = ''
    if (!take(r)) {
      refusedCode = c
      if (r.refused === 'already_off') step.value = 'state'
      else refocus()
      return
    }
    step.value = 'state'
    notice.value = t('mh.tfa.disabledDone')
  } catch (e) {
    if (g === gen) failed(e)
  } finally {
    if (g === gen) busy.value = false
  }
}

async function copyText(text: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(text)
    return true
  } catch {
    // Clipboard permission denied: the text is on screen to select by hand.
    return false
  }
}

async function copyKey() {
  keyCopied.value = await copyText(ungroupKey(secret.value))
}

async function copyCodes() {
  codesCopied.value = await copyText(recoveryCodes.value.join('\n'))
}

function downloadCodes() {
  const text = recoveryCodesFile(name.value, recoveryCodes.value, new Date())
  const url = URL.createObjectURL(new Blob([text], { type: 'text/plain;charset=utf-8' }))
  const a = document.createElement('a')
  a.href = url
  a.download = `meshharbor-recovery-codes-${name.value.replace(/[^\w.-]+/g, '_') || 'device'}.txt`
  document.body.appendChild(a)
  a.click()
  a.remove()
  URL.revokeObjectURL(url)
}
</script>

<style scoped>
/* Dark-on-white in either theme: a scanner reads a light QR code on a dark
   card badly or not at all. */
.tfa-qr {
  flex: none;
  width: 216px;
  height: 216px;
  padding: 8px;
  border-radius: 8px;
  background: #fff;
  display: flex;
  align-items: center;
  justify-content: center;
}
.tfa-scan-side {
  min-width: 220px;
}
.tfa-key {
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  font-size: 1.05rem;
  letter-spacing: 0.06em;
  word-break: break-all;
  user-select: all;
}
.tfa-codes {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 6px 16px;
  padding: 12px 16px;
  border-radius: 6px;
  background: rgba(var(--v-theme-on-surface), 0.04);
}
.tfa-codes code {
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  font-size: 1rem;
  user-select: all;
}
</style>
