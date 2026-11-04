<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 G ROX EOOD -->
<template>
  <v-dialog v-model="open" max-width="720" scrollable :fullscreen="fullscreen">
    <v-card>
      <v-card-title class="d-flex align-center">
        <v-icon icon="mdi-shield-key-outline" color="primary" class="mr-2" />
        <!-- The span shrinks with an ellipsis (min-width: 0), so the title's own
             buttons stay on screen: a title never wraps, and a long device name
             used to push Close or Refresh past the edge on a phone. -->
        <span class="text-truncate" style="min-width: 0">{{ t('mh.exec.title', { name: deviceLabel(agent) }) }}</span>
      </v-card-title>

      <v-card-text>
        <!-- The single most important sentence in this dialog. An operator
             deciding whether to flip the switch needs to know it grants root,
             not read it in an incident review afterwards. -->
        <v-alert
          type="warning"
          variant="tonal"
          density="compact"
          class="mb-4"
          icon="mdi-shield-alert-outline"
        >
          <i18n-t keypath="mh.exec.warn" tag="span" scope="global">
            <template #root><strong>root</strong></template>
            <template #system><strong>SYSTEM</strong></template>
            <template #signedIn><strong>{{ t('mh.exec.signedIn') }}</strong></template>
          </i18n-t>
        </v-alert>

        <!-- FR-94 — on Windows, WHO runs a command depends on whether an
             administrator anchored the device. Said here, beside the switch
             that grants it, not discovered in the audit afterwards. -->
        <v-alert
          v-if="agent?.os === 'windows'"
          :type="anchored ? 'success' : 'info'"
          variant="tonal"
          density="compact"
          class="mb-4"
          data-testid="exec-identity"
        >
          <template v-if="anchored">
            <i18n-t keypath="mh.exec.anchored" tag="span" scope="global">
              <template #when>{{ anchoredWhen }}</template>
              <template #system><strong>SYSTEM</strong></template>
            </i18n-t>
            <v-btn
              size="small"
              variant="text"
              color="error"
              class="ml-1"
              :loading="unanchoring"
              data-testid="exec-unanchor"
              @click="unanchor"
            >
              {{ t('mh.exec.unanchor') }}
            </v-btn>
          </template>
          <template v-else>
            <i18n-t keypath="mh.exec.notAnchored" tag="span" scope="global">
              <template #signedIn><strong>{{ t('mh.exec.signedIn') }}</strong></template>
            </i18n-t>
            <code>meshharbord anchor create --server … --token … --device {{ agent.id }}</code>
          </template>
        </v-alert>
        <v-alert
          v-if="unanchorError"
          type="error"
          variant="tonal"
          density="compact"
          class="mb-4"
        >
          {{ unanchorError }}
        </v-alert>

        <v-switch
          v-model="modeOn"
          color="primary"
          hide-details
          density="compact"
          :label="t('mh.exec.accept')"
        />

        <v-switch
          v-model="draft.can_originate"
          color="primary"
          hide-details
          density="compact"
          class="mt-2"
          :label="t('mh.exec.originate')"
        />
        <div class="text-caption text-medium-emphasis mb-4 ml-10">
          {{ t('mh.exec.originateHint') }}
        </div>

        <!-- FR-94 P4 — which account the device's SYSTEM service runs a
             command as on Windows. FR-97 P5a — on Linux and macOS, whom the
             agent itself runs it as, where its agent can drop to the person
             at the screen (or a stored policy already says so). -->
        <template v-if="offersRunAs">
          <v-select
            v-model="runAs"
            :items="runAsOptions"
            :label="t('mh.exec.runAs')"
            density="compact"
            variant="outlined"
            class="mt-4"
            hide-details
            data-testid="exec-run-as"
          />
          <div v-if="isWindows" class="text-caption text-medium-emphasis mb-4">
            <i18n-t keypath="mh.exec.runAsWin" tag="span" scope="global">
              <template #system><strong>SYSTEM</strong></template>
              <template #signedIn><strong>{{ t('mh.exec.runAsSignedIn') }}</strong></template>
            </i18n-t>
          </div>
          <div v-else class="text-caption text-medium-emphasis mb-4" data-testid="exec-run-as-unix">
            <i18n-t keypath="mh.exec.runAsUnix" tag="span" scope="global">
              <template #root><strong>root</strong></template>
              <template #person><strong>{{ t('mh.exec.runAsPerson') }}</strong></template>
            </i18n-t>
            <template v-if="!agentDropsToPerson">
              {{ t('mh.exec.runAsTooOld') }}
            </template>
          </div>
        </template>

        <v-select
          v-model="draft.consent_mode"
          :items="consentOptions"
          :label="t('mh.policy.label.consent')"
          density="compact"
          variant="outlined"
          class="mt-4"
          hide-details
        />
        <div class="text-caption text-medium-emphasis mb-4">
          <i18n-t keypath="mh.exec.consentHint" tag="span" scope="global">
            <template #prompt><strong>{{ t('mh.exec.prompt') }}</strong></template>
            <template #unattended><strong>{{ t('mh.exec.unattended') }}</strong></template>
          </i18n-t>
        </div>

        <v-select
          v-model="draft.allowed_user_ids"
          :items="memberOptions"
          :label="t('mh.exec.users')"
          density="compact"
          variant="outlined"
          multiple
          chips
          closable-chips
          hide-details
          class="mb-4"
        />

        <v-select
          v-model="draft.shells"
          :items="shellOptions"
          :label="t('mh.exec.shells')"
          density="compact"
          variant="outlined"
          multiple
          chips
          closable-chips
          hide-details
        />

        <!-- Two gates this dialog cannot set, surfaced so an admin doesn't
             flip everything here and then wonder why commands still fail. -->
        <v-alert
          v-if="orgDisabled"
          type="info"
          variant="tonal"
          density="compact"
          class="mt-4"
        >
          {{ t('mh.exec.orgOff') }}
        </v-alert>
        <v-alert type="info" variant="tonal" density="compact" class="mt-4">
          <i18n-t keypath="mh.exec.deviceSwitch" tag="span" scope="global">
            <template #cmd><code>meshharbor config set exec_enabled true</code></template>
          </i18n-t>
          <template v-if="anchored">
            <i18n-t keypath="mh.exec.anchorSwitch" tag="span" scope="global">
              <template #cmd><code>meshharbord anchor exec on</code></template>
            </i18n-t>
          </template>
        </v-alert>
      </v-card-text>

      <v-card-actions>
        <v-spacer />
        <v-btn variant="text" @click="close">{{ t('common.cancel') }}</v-btn>
        <v-btn color="primary" :loading="saving" @click="save">{{ t('common.save') }}</v-btn>
      </v-card-actions>
    </v-card>
  </v-dialog>
</template>

<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { useResponsiveDialog } from '@/composables/useResponsiveDialog'
import { deviceLabel } from '@/composables/useHideDeviceName'
import { useAgentStore, type Agent, type ExecPolicy } from '@/stores/agents'
import { dropsToConsoleUser } from '@/utils/sshIdentity'

const props = defineProps<{
  modelValue: boolean
  tenantId: string
  agent: Agent
}>()

const emit = defineEmits<{
  (e: 'update:modelValue', v: boolean): void
  (e: 'saved'): void
}>()

const { t } = useI18n()
const { fullscreen } = useResponsiveDialog()
const open = computed({
  get: () => props.modelValue,
  set: (v) => emit('update:modelValue', v),
})

const agentStore = useAgentStore()
const saving = ref(false)
const agent = computed(() => props.agent)
const orgDisabled = computed(() => agentStore.orgExecEnabled === false)

// FR-94 — the device's exec identity on Windows.
const anchored = computed(() => !!agent.value?.exec_anchor)
const anchoredWhen = computed(() => {
  const at = agent.value?.exec_anchor?.anchored_at
  const d = at ? new Date(at) : null
  return d && !Number.isNaN(d.getTime()) ? d.toLocaleDateString() : ''
})
const unanchoring = ref(false)
const unanchorError = ref<string | null>(null)

async function unanchor() {
  unanchoring.value = true
  unanchorError.value = null
  try {
    await agentStore.unanchorDevice(props.tenantId, agent.value.id)
  } catch (e) {
    unanchorError.value = (e as Error).message
  } finally {
    unanchoring.value = false
  }
}

/** A closed default, so a dialog opened on a device with no policy row can
 *  only ever be saved MORE permissive by an explicit click. */
function emptyPolicy(): ExecPolicy {
  return {
    mode: 'off',
    can_originate: false,
    allowed_user_ids: [],
    allowed_role_ids: [],
    consent_mode: null,
    shells: [],
  }
}

const draft = ref<ExecPolicy>(emptyPolicy())

/** Bound separately from `draft.mode` so the switch is a plain boolean; the
 *  wire type is an enum because `off | on` will grow (e.g. a read-only verb
 *  tier) and a bool could not. */
const modeOn = computed({
  get: () => draft.value.mode === 'on',
  set: (v: boolean) => {
    draft.value.mode = v ? 'on' : 'off'
  },
})

const consentOptions = computed(() => [
  { title: t('mh.exec.consent.prompt'), value: null },
  { title: t('mh.exec.consent.auto'), value: 'auto' },
])

// FR-94 P4 — unset reads as SYSTEM, the server's default.
const runAs = computed({
  get: () => draft.value.run_as ?? 'system',
  set: (v: 'system' | 'console_user') => {
    draft.value.run_as = v
  },
})

const isWindows = computed(() => agent.value?.os === 'windows')
/** FR-97 P5a — a Linux or macOS agent that says `console-user`. */
const agentDropsToPerson = computed(() => dropsToConsoleUser(agent.value?.capabilities?.rpc))
/** Windows always; elsewhere where the agent can, or where a stored policy
 *  already names the person, so it can be switched back to root here. */
const offersRunAs = computed(
  () => isWindows.value || agentDropsToPerson.value || draft.value.run_as === 'console_user',
)

const runAsOptions = computed(() =>
  isWindows.value
    ? [
        { title: t('mh.exec.opt.system'), value: 'system' },
        { title: t('mh.exec.opt.signedIn'), value: 'console_user' },
      ]
    : [
        { title: t('mh.exec.opt.root'), value: 'system' },
        { title: t('mh.exec.opt.person'), value: 'console_user' },
      ],
)

const memberOptions = computed(() =>
  agentStore.tenantMembers.map((m) => ({
    title: m.display_name || m.nickname || m.user_id,
    value: m.user_id,
  })),
)

const shellOptions = computed(() =>
  agent.value?.os === 'windows' ? ['powershell', 'pwsh', 'cmd'] : ['bash', 'sh'],
)

watch(
  () => props.modelValue,
  (v) => {
    if (!v) return
    draft.value = { ...emptyPolicy(), ...(agent.value?.exec_policy ?? {}) }
    if (!agentStore.tenantMembers.length) {
      void agentStore.fetchTenantMembers(props.tenantId)
    }
    if (agentStore.orgExecEnabled === null) {
      void agentStore.fetchOrgExecEnabled(props.tenantId)
    }
  },
)

async function save() {
  saving.value = true
  try {
    await agentStore.updateExecPolicy(props.tenantId, agent.value.id, draft.value)
    emit('saved')
    open.value = false
  } finally {
    saving.value = false
  }
}

function close() {
  open.value = false
}
</script>
