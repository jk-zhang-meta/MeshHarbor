<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 G ROX EOOD -->
<template>
  <v-dialog v-model="open" max-width="760" scrollable :fullscreen="fullscreen">
    <v-card>
      <v-card-title class="d-flex align-center">
        <v-icon icon="mdi-cog-transfer-outline" color="primary" class="mr-2" />
        <!-- The span shrinks with an ellipsis (min-width: 0), so the title's own
             buttons stay on screen: a title never wraps, and a long device name
             used to push Close or Refresh past the edge on a phone. -->
        <span class="text-truncate" style="min-width: 0">{{ tr('mh.rcfg.title', { name: deviceLabel(agent) }) }}</span>
      </v-card-title>

      <v-card-text>
        <!-- Lead with what this screen IS. Every other dialog here writes a
             server-side policy that takes effect the moment it saves; this one
             writes a REQUEST that a device may decline, and a reader who
             assumes otherwise will misread everything below it. -->
        <v-alert
          type="info"
          variant="tonal"
          density="compact"
          class="mb-4"
          icon="mdi-transfer-right"
        >
          <i18n-t keypath="mh.rcfg.intro" tag="span" scope="global">
            <template #key><code>remote_config_enabled</code></template>
          </i18n-t>
        </v-alert>

        <!-- Where the last request actually got to. This is the whole reason
             the device reports back; without it, "saved" is all we could
             honestly say, and "saved" is not the question anyone is asking. -->
        <v-alert
          v-if="status"
          :type="status.type"
          variant="tonal"
          density="compact"
          class="mb-4"
          :icon="status.icon"
        >
          <div class="font-weight-medium">{{ status.title }}</div>
          <div class="text-body-2 mt-1">{{ status.detail }}</div>
          <div v-if="reportedKeys.live.length" class="text-body-2 mt-2">
            {{ tr('mh.rcfg.inForce') }} <strong>{{ reportedKeys.live.join(', ') }}</strong>
          </div>
          <div v-if="reportedKeys.needsRestart.length" class="text-body-2 mt-1">
            {{ tr('mh.rcfg.waitingRestart') }}
            <strong>{{ reportedKeys.needsRestart.join(', ') }}</strong>
          </div>
          <div v-if="report?.detail" class="text-body-2 mt-2 font-italic">
            {{ report.detail }}
          </div>
        </v-alert>

        <!-- ── Remote execution ──────────────────────────────────────────── -->
        <div class="text-subtitle-2 mb-1">{{ tr('mh.rcfg.exec') }}</div>
        <ManagedSwitch
          v-model="draft.exec_enabled"
          :disabled="!mayGrantExec"
          :label="tr('mh.rcfg.execSwitch')"
        />
        <div class="text-caption text-medium-emphasis mb-1 ml-1">
          <i18n-t keypath="mh.rcfg.execHint" tag="span" scope="global">
            <template #root><strong>root</strong></template>
            <template #signedIn><strong>{{ tr('mh.exec.signedIn') }}</strong></template>
            <template #system><strong>SYSTEM</strong></template>
          </i18n-t>
        </div>
        <div v-if="!mayGrantExec" class="text-caption text-error mb-4 ml-1">
          <i18n-t keypath="mh.rcfg.needExec" tag="span" scope="global">
            <template #perm><strong>EXEC_DEVICE</strong></template>
          </i18n-t>
        </div>
        <div v-else class="mb-4" />

        <!-- ── SSH ───────────────────────────────────────────────────────── -->
        <div class="text-subtitle-2 mb-1">SSH</div>
        <ManagedSwitch
          v-model="draft.ssh_enabled"
          :disabled="!mayGrantSsh"
          :label="tr('mh.rcfg.sshSwitch')"
        />

        <v-expand-transition>
          <div v-if="sshDetailsShown">
            <v-textarea
              v-model="authorizedKeysText"
              :disabled="!mayGrantSsh"
              :label="tr('mh.rcfg.keys')"
              placeholder="ssh-ed25519 AAAAC3Nza… you@laptop"
              rows="3"
              density="compact"
              variant="outlined"
              class="mt-3"
              hide-details
              persistent-placeholder
            />
            <div class="text-caption text-medium-emphasis mb-3 ml-1">
              <i18n-t keypath="mh.rcfg.keysHint" tag="span" scope="global">
                <template #nobody><strong>{{ tr('mh.rcfg.nobody') }}</strong></template>
              </i18n-t>
            </div>

            <v-select
              v-model="draft.ssh_account_mode"
              :disabled="!mayGrantSsh"
              :items="accountOptions"
              :label="tr('mh.rcfg.accountMode')"
              density="compact"
              variant="outlined"
              clearable
              hide-details
              class="mb-1"
            />
            <div class="text-caption text-medium-emphasis mb-3 ml-1">
              <i18n-t keypath="mh.rcfg.accountHint" tag="span" scope="global">
                <template #onDevice><em>{{ tr('mh.rcfg.onDevice') }}</em></template>
                <template #nothing><strong>{{ tr('mh.rcfg.nothing') }}</strong></template>
              </i18n-t>
            </div>

            <v-text-field
              v-model="sshPortText"
              :disabled="!mayGrantSsh"
              :label="tr('mh.rcfg.port')"
              density="compact"
              variant="outlined"
              type="number"
              hide-details
              class="mb-1"
            />
            <div class="text-caption text-medium-emphasis mb-3 ml-1">
              <i18n-t keypath="mh.rcfg.portHint" tag="span" scope="global">
                <template #sshd><code>sshd</code></template>
              </i18n-t>
            </div>
          </div>
        </v-expand-transition>

        <div v-if="!mayGrantSsh" class="text-caption text-error mb-4 ml-1">
          <i18n-t keypath="mh.rcfg.needSsh" tag="span" scope="global">
            <template #perm><strong>SSH_DEVICE</strong></template>
          </i18n-t>
        </div>

        <!-- ── Video encoders (FR-77) ───────────────────────────────────── -->
        <div class="text-subtitle-2 mb-1 mt-2">{{ tr('mh.rcfg.encoders') }}</div>
        <v-text-field
          v-model="encoderDenyText"
          :label="tr('mh.rcfg.cellsDeny')"
          placeholder="hevc_qsv:yuv444, hevc_vaapi:yuv444"
          density="compact"
          variant="outlined"
          hide-details
          persistent-placeholder
          class="mb-1"
        />
        <div class="text-caption text-medium-emphasis mb-4 ml-1">
          <i18n-t keypath="mh.rcfg.cellsHint" tag="span" scope="global">
            <template #form><code>name:chroma</code></template>
            <template #builtin><code>hevc_qsv:yuv444, hevc_vaapi:yuv444</code></template>
            <template #none><code>none</code></template>
          </i18n-t>
        </div>
        <v-text-field
          v-model="fpsDenyText"
          :label="tr('mh.rcfg.fpsDeny')"
          placeholder="hevc_qsv:120, *:144"
          density="compact"
          variant="outlined"
          hide-details
          persistent-placeholder
          class="mb-1"
        />
        <div class="text-caption text-medium-emphasis mb-4 ml-1">
          <i18n-t keypath="mh.rcfg.fpsHint" tag="span" scope="global">
            <template #form><code>name:fps</code></template>
            <template #star><code>*</code></template>
            <template #none><code>none</code></template>
          </i18n-t>
        </div>

        <!-- The combination checks. Each of these produces a device that is
             "on" and reaches nobody — the exact silent-nothing this feature
             exists to remove, so it must be caught here rather than discovered
             later by someone whose ssh just hangs up on them. -->
        <v-alert
          v-for="w in combinationWarnings"
          :key="w"
          type="warning"
          variant="tonal"
          density="compact"
          class="mb-2"
          icon="mdi-alert-outline"
        >
          {{ w }}
        </v-alert>

        <!-- The gates this dialog cannot reach, in the order the device
             evaluates them. Without these an admin sets everything here and is
             left wondering why nothing happened. -->
        <v-alert
          v-if="orgExecDisabled && draft.exec_enabled === true"
          type="info"
          variant="tonal"
          density="compact"
          class="mb-2"
        >
          {{ tr('mh.exec.orgOff') }}
        </v-alert>
        <v-alert
          v-if="orgSshDisabled && draft.ssh_enabled === true"
          type="info"
          variant="tonal"
          density="compact"
          class="mb-2"
        >
          {{ tr('mh.rcfg.sshOrgOff') }}
        </v-alert>

        <v-alert
          v-if="error"
          type="error"
          variant="tonal"
          density="compact"
          class="mt-2"
        >
          {{ error }}
        </v-alert>
      </v-card-text>

      <!-- Wraps: three buttons in one row overflowed a phone to the LEFT
           (the dialog right-aligns its actions), clipping "Stop managing". -->
      <v-card-actions class="flex-wrap">
        <v-btn
          v-if="hasRequest"
          variant="text"
          color="error"
          :loading="clearing"
          @click="clearAll"
        >
          {{ tr('mh.rcfg.stop') }}
        </v-btn>
        <v-spacer />
        <v-btn variant="text" @click="close">{{ tr('common.cancel') }}</v-btn>
        <v-btn color="primary" :loading="saving" :disabled="!dirty" @click="save">
          {{ tr('mh.rcfg.request') }}
        </v-btn>
      </v-card-actions>
    </v-card>
  </v-dialog>
</template>

<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { useResponsiveDialog } from '@/composables/useResponsiveDialog'
import { deviceLabel } from '@/composables/useHideDeviceName'
import { useAgentStore, type Agent, type DesiredConfig } from '@/stores/agents'
import { useTenantStore } from '@/stores/tenant'
import { canGrantDeviceExec, canGrantDeviceSsh } from '@/utils/permissions'
import ManagedSwitch from './ManagedSwitch.vue'

const props = defineProps<{
  modelValue: boolean
  tenantId: string
  agent: Agent
}>()

const emit = defineEmits<{
  (e: 'update:modelValue', v: boolean): void
  (e: 'saved'): void
}>()

const { t: tr } = useI18n()
const { fullscreen } = useResponsiveDialog()
const open = computed({
  get: () => props.modelValue,
  set: (v) => emit('update:modelValue', v),
})

const agentStore = useAgentStore()
const tenantStore = useTenantStore()
const saving = ref(false)
const clearing = ref(false)
const error = ref('')
const sshDetailsTouched = ref(false)
const agent = computed(() => props.agent)

/** Only the managed keys. `undefined` is "leave the device alone", which is
 *  why every field is optional rather than defaulted — a struct of plain
 *  values could not say "don't touch the rest", so toggling exec would
 *  silently assert a value for every other key on the surface. */
type Draft = Omit<DesiredConfig, 'revision' | 'updated_by' | 'updated_at'>

const draft = ref<Draft>({})
const original = ref('')

/** You cannot grant a permission you do not hold (#600/#605). The server
 *  enforces this in `remote_config::decide`; mirroring it here only avoids
 *  offering a control whose save would 403. */
const mayGrantExec = computed(() =>
  canGrantDeviceExec(tenantStore.myPermissions, tenantStore.isOwner),
)
const mayGrantSsh = computed(() =>
  canGrantDeviceSsh(tenantStore.myPermissions, tenantStore.isOwner),
)

/** Show the SSH details whenever ANY ssh key is under management — not just
 *  when `ssh_enabled` is.
 *
 *  Keying this on `ssh_enabled` alone hid keys that were being pushed: a device
 *  managed as "authorized keys, but leave the switch alone" opened with the
 *  section collapsed, so an operator could neither see nor edit them — and the
 *  draft still carried them, so saving silently re-asserted a list they had
 *  never been shown. */
const sshDetailsShown = computed(
  () =>
    sshDetailsTouched.value ||
    draft.value.ssh_enabled !== undefined ||
    draft.value.ssh_authorized_keys !== undefined ||
    draft.value.ssh_account_mode !== undefined ||
    draft.value.ssh_port !== undefined,
)

const orgExecDisabled = computed(() => agentStore.orgExecEnabled === false)
const orgSshDisabled = computed(() => agentStore.orgSshEnabled === false)

const remoteConfig = computed(() => agent.value?.remote_config)
const report = computed(() => remoteConfig.value?.report)
const hasRequest = computed(() => !!remoteConfig.value)

/** Only the keys the device confirmed for the CURRENT revision. A report about
 *  an older revision describes a different request, and showing its key lists
 *  next to this one's switches would attribute them to the wrong change. */
const reportedKeys = computed(() => {
  const r = report.value
  const fresh = r && r.revision === remoteConfig.value?.desired.revision
  return {
    live: fresh ? r.live : [],
    needsRestart: fresh ? r.needs_restart : [],
  }
})

/** One line per state, each naming the ACTION the reader can take. "It didn't
 *  work" is not a status; "set this key on the host" is. */
const status = computed<{ type: 'success' | 'info' | 'warning' | 'error'; icon: string; title: string; detail: string } | null>(() => {
  const rc = remoteConfig.value
  if (!rc) return null
  switch (rc.state) {
    case 'applied':
      return {
        type: 'success',
        icon: 'mdi-check-circle-outline',
        title: tr('mh.rcfg.st.applied'),
        detail: tr('mh.rcfg.st.appliedDetail'),
      }
    case 'needs_restart':
      return {
        type: 'warning',
        icon: 'mdi-restart-alert',
        title: tr('mh.rcfg.st.restart'),
        detail: tr('mh.rcfg.st.restartDetail'),
      }
    case 'refused':
      return {
        type: 'warning',
        icon: 'mdi-hand-back-left-outline',
        title:
          report.value?.outcome === 'not_primary'
            ? tr('mh.rcfg.st.secondary')
            : tr('mh.rcfg.st.notOptedIn'),
        detail:
          report.value?.outcome === 'not_primary'
            ? tr('mh.rcfg.st.secondaryDetail')
            : tr('mh.rcfg.st.notOptedInDetail', { cmd: '`mh config set remote_config_enabled true`' }),
      }
    case 'failed':
      return {
        type: 'error',
        icon: 'mdi-alert-circle-outline',
        title: tr('mh.rcfg.st.failed'),
        detail: tr('mh.rcfg.st.failedDetail'),
      }
    case 'pending':
      return {
        type: 'info',
        icon: 'mdi-clock-outline',
        title: tr('mh.rcfg.st.pending'),
        detail: tr('mh.rcfg.st.pendingDetail'),
      }
    case 'reports_unsupported':
      return {
        type: 'info',
        icon: 'mdi-help-circle-outline',
        title: tr('mh.rcfg.st.noReport'),
        detail: tr('mh.rcfg.st.noReportDetail', { v: agent.value?.agent_version ?? '?' }),
      }
    case 'push_unsupported':
      return {
        type: 'warning',
        icon: 'mdi-update',
        title: tr('mh.rcfg.st.tooOld'),
        detail: tr('mh.rcfg.st.tooOldDetail', { v: agent.value?.agent_version ?? '?' }),
      }
    default:
      return null
  }
})

/** Combinations that produce a device which is "on" and reaches nobody. */
const combinationWarnings = computed<string[]>(() => {
  const out: string[] = []
  const d = draft.value
  if (d.ssh_enabled === true) {
    const keys = d.ssh_authorized_keys
    if (keys && keys.length === 0) {
      out.push(tr('mh.rcfg.warn.emptyKeys'))
    }
    if (keys === undefined && !d.ssh_account_mode) {
      out.push(tr('mh.rcfg.warn.sshAlone'))
    } else if (keys && keys.length > 0 && !d.ssh_account_mode) {
      out.push(tr('mh.rcfg.warn.noAccount'))
    }
  }
  return out
})

const authorizedKeysText = computed({
  get: () => (draft.value.ssh_authorized_keys ?? []).join('\n'),
  set: (v: string) => {
    sshDetailsTouched.value = true
    // A blank box is an EMPTY LIST, not "unmanaged" — the user typed into it.
    // Unmanaged is expressed by never touching it, which is why the getter
    // renders `undefined` as '' and this setter only ever runs on input.
    draft.value.ssh_authorized_keys = v
      .split('\n')
      .map((l) => l.trim())
      .filter((l) => l.length > 0)
  },
})

const sshPortText = computed({
  get: () => (draft.value.ssh_port === undefined ? '' : String(draft.value.ssh_port)),
  set: (v: string) => {
    sshDetailsTouched.value = true
    const n = Number.parseInt(v, 10)
    draft.value.ssh_port = v.trim() === '' || Number.isNaN(n) ? undefined : n
  },
})


/** FR-77 — the cell denylist. A blank box is "not managed" (undefined), so
 *  clearing it hands the key back to the device; the word `none` is how an
 *  operator says "deny nothing" (a config key cannot carry an empty list). */
const encoderDenyText = computed({
  get: () => draft.value.encoder_cells_deny ?? '',
  set: (v: string) => {
    const t = v.trim()
    draft.value.encoder_cells_deny = t === '' ? undefined : t
  },
})
/** FR-119 P2b — the frame-rate denylist, the same shape: a blank box is "not
 *  managed", and `none` says "deny nothing". */
const fpsDenyText = computed({
  get: () => draft.value.fps_deny ?? '',
  set: (v: string) => {
    const t = v.trim()
    draft.value.fps_deny = t === '' ? undefined : t
  },
})
const accountOptions = computed(() => [
  { title: tr('mh.sshp.opt.signedIn'), value: 'console_user' },
  { title: tr('mh.rcfg.daemonAccount'), value: 'daemon' },
])

const dirty = computed(() => JSON.stringify(draft.value) !== original.value)

watch(
  () => props.modelValue,
  (v) => {
    if (!v) return
    error.value = ''
    sshDetailsTouched.value = false
    const d = remoteConfig.value?.desired
    draft.value = {
      exec_enabled: d?.exec_enabled,
      ssh_enabled: d?.ssh_enabled,
      ssh_authorized_keys: d?.ssh_authorized_keys,
      ssh_account_mode: d?.ssh_account_mode,
      ssh_port: d?.ssh_port,
      encoder_cells_deny: d?.encoder_cells_deny,
      fps_deny: d?.fps_deny,
    }
    original.value = JSON.stringify(draft.value)
    if (agentStore.orgExecEnabled === null) void agentStore.fetchOrgExecEnabled(props.tenantId)
    if (agentStore.orgSshEnabled === null) void agentStore.fetchOrgSshEnabled(props.tenantId)
  },
)

async function submit(body: Draft) {
  error.value = ''
  try {
    await agentStore.updateDesiredConfig(props.tenantId, agent.value.id, body)
    emit('saved')
    open.value = false
  } catch (e) {
    // A 403 here is the "you cannot grant what you do not hold" rule, and the
    // dialog stays OPEN so the admin sees which bit they are missing rather
    // than walking away believing the change landed.
    error.value = e instanceof Error ? e.message : tr('mh.rcfg.saveFailed')
  }
}

async function save() {
  saving.value = true
  try {
    await submit(draft.value)
  } finally {
    saving.value = false
  }
}

/** Stop managing every key — an empty request, which the device reads as
 *  "nothing to reconcile". Deliberately NOT the same as switching everything
 *  off: this leaves the device with whatever it has, which is what an operator
 *  handing a machine back to its owner actually wants. */
async function clearAll() {
  clearing.value = true
  try {
    await submit({})
  } finally {
    clearing.value = false
  }
}

function close() {
  open.value = false
}
</script>
