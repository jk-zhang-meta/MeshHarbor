<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 G ROX EOOD -->
<template>
  <v-dialog v-model="open" max-width="720" scrollable :fullscreen="fullscreen">
    <v-card>
      <v-card-title class="d-flex align-center">
        <v-icon icon="mdi-console-network-outline" color="primary" class="mr-2" />
        <!-- The span shrinks with an ellipsis (min-width: 0), so the title's own
             buttons stay on screen: a title never wraps, and a long device name
             used to push Close or Refresh past the edge on a phone. -->
        <span class="text-truncate" style="min-width: 0">{{ t('mh.sshp.title', { name: deviceLabel(agent) }) }}</span>
      </v-card-title>

      <v-card-text>
        <!-- What an admin must know BEFORE flipping the switch, not in an
             incident review afterwards. An SSH session is strictly more than
             a bounded command: it is interactive and it lasts. -->
        <v-alert
          type="warning"
          variant="tonal"
          density="compact"
          class="mb-4"
          icon="mdi-shield-alert-outline"
        >
          <i18n-t keypath="mh.sshp.warn" tag="span" scope="global">
            <template #shell><strong>{{ t('mh.sshp.shell') }}</strong></template>
          </i18n-t>
        </v-alert>

        <v-switch
          v-model="modeOn"
          color="primary"
          hide-details
          density="compact"
          :label="t('mh.sshp.accept')"
        />

        <v-switch
          v-model="draft.can_originate"
          color="primary"
          hide-details
          density="compact"
          class="mt-2"
          :label="t('mh.sshp.originate')"
        />
        <div class="text-caption text-medium-emphasis mb-4 ml-10">
          {{ t('mh.exec.originateHint') }}
        </div>

        <v-select
          v-model="draft.account_mode"
          :items="accountOptions"
          :label="t('mh.sshp.runAs')"
          density="compact"
          variant="outlined"
          class="mt-4"
          hide-details
        />
        <v-alert
          v-if="coercedFromConsoleUser"
          type="warning"
          variant="tonal"
          density="compact"
          class="mt-2"
        >
          <i18n-t keypath="mh.sshp.coerced" tag="span" scope="global">
            <template #signedIn><strong>{{ t('mh.sshp.signedInLower') }}</strong></template>
          </i18n-t>
        </v-alert>
        <div
          v-if="isWindows && servedBySystem"
          class="text-caption text-medium-emphasis mb-4"
          data-test="ssh-identity-service"
        >
          <i18n-t keypath="mh.sshp.idService" tag="span" scope="global">
            <template #service><strong>{{ t('mh.sshp.systemService') }}</strong></template>
            <template #signedIn><strong>{{ t('mh.sshp.signedIn') }}</strong></template>
            <template #daemon><strong>{{ t('mh.sshp.daemon') }}</strong></template>
            <template #system><strong>SYSTEM</strong></template>
          </i18n-t>
        </div>
        <div
          v-else-if="isWindows"
          class="text-caption text-medium-emphasis mb-4"
          data-test="ssh-identity-agent"
        >
          <i18n-t keypath="mh.sshp.idAgent" tag="span" scope="global">
            <template #daemon><strong>{{ t('mh.sshp.daemon') }}</strong></template>
            <template #system><strong>SYSTEM</strong></template>
            <template #signedInLower><strong>{{ t('mh.sshp.signedInLower') }}</strong></template>
            <template #signedIn><strong>{{ t('mh.sshp.signedIn') }}</strong></template>
            <template #cmd><code>roomlerd anchor ssh system</code></template>
          </i18n-t>
        </div>
        <div v-else class="text-caption text-medium-emphasis mb-4" data-test="ssh-identity-unix">
          <i18n-t keypath="mh.sshp.idUnixNamed" tag="span" scope="global">
            <template #named><strong>{{ t('mh.sshp.namedAccount') }}</strong></template>
          </i18n-t>
          <template v-if="offersConsoleUser">
            <i18n-t keypath="mh.sshp.idUnixPerson" tag="span" scope="global">
              <template #person><strong>{{ t('mh.exec.runAsPerson') }}</strong></template>
            </i18n-t>
          </template>
          <i18n-t keypath="mh.sshp.idUnixDaemon" tag="span" scope="global">
            <template #daemon><strong>{{ t('mh.sshp.daemon') }}</strong></template>
            <template #root><strong>root</strong></template>
          </i18n-t>
          <template v-if="!offersConsoleUser">
            {{ t('mh.sshp.personNeedsNewer') }}
          </template>
        </div>

        <v-text-field
          v-if="draft.account_mode === 'named'"
          v-model="namedAccount"
          :label="t('mh.sshp.accountName')"
          density="compact"
          variant="outlined"
          class="mb-1"
          hide-details
          :placeholder="t('mh.sshp.accountPlaceholder')"
        />
        <div v-if="draft.account_mode === 'named'" class="text-caption text-medium-emphasis mb-4">
          {{ t('mh.sshp.unixOnly') }}
        </div>

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
          <i18n-t keypath="mh.sshp.consentHint" tag="span" scope="global">
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

        <!-- The two gates this dialog cannot set. Without these an admin
             flips everything here and then wonders why sessions still fail. -->
        <v-alert
          v-if="orgDisabled"
          type="info"
          variant="tonal"
          density="compact"
          class="mt-4"
        >
          {{ t('mh.sshp.orgOff') }}
        </v-alert>
        <v-alert type="info" variant="tonal" density="compact" class="mt-4">
          <i18n-t keypath="mh.exec.deviceSwitch" tag="span" scope="global">
            <template #cmd><code>roomler config set ssh_enabled true</code></template>
          </i18n-t>
        </v-alert>

        <v-alert
          v-if="error"
          type="error"
          variant="tonal"
          density="compact"
          class="mt-4"
        >
          {{ error }}
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
import { useAgentStore, type Agent, type SshPolicy } from '@/stores/agents'
import { dropsToConsoleUser, servesSshAsSystem } from '@/utils/sshIdentity'

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
const error = ref('')
const agent = computed(() => props.agent)
const orgDisabled = computed(() => agentStore.orgSshEnabled === false)

const isWindows = computed(() => agent.value?.os === 'windows')

/** `console_user` is the person at the device's screen: on Windows by their
 *  session token (`WTSQueryUserToken` + `CreateProcessAsUserW`), and on Linux
 *  and macOS (FR-97 P5a) by the agent's own drop to them, which only an agent
 *  saying `console-user` makes — an older one refuses it outright
 *  (`agents/meshharbord/src/exec.rs`, `pty/unix.rs`). Offering it there produces
 *  a policy that agent can never honour, and the failure surfaces at CONNECT
 *  time — at a shell prompt, about a field that lives in this dialog. The
 *  server refuses to store it too. */
const offersConsoleUser = computed(
  () => isWindows.value || dropsToConsoleUser(agent.value?.capabilities?.rpc),
)

/** FR-105 — does this device serve SSH through its SYSTEM service now? Then
 *  both Windows identities are definite: SYSTEM, and the person at the
 *  console. Without it, `daemon` is whatever the agent runs as, which on an
 *  attended install is the signed-in user, not SYSTEM. */
const servedBySystem = computed(() => servesSshAsSystem(agent.value?.capabilities?.rpc))

/** A closed default, so a dialog opened on a device with no policy row can
 *  only ever be saved MORE permissive by an explicit click. On Windows that is
 *  `console_user` — if someone turns SSH on without reading the account
 *  selector, the quiet outcome must not be a root shell. Off Windows the same
 *  intent picks `named` with an EMPTY account, which is inert until someone
 *  types one: still not a root shell, and still not a click away from one. */
function emptyPolicy(windows: boolean): SshPolicy {
  return {
    mode: 'off',
    can_originate: false,
    allowed_user_ids: [],
    allowed_role_ids: [],
    account_mode: windows ? 'console_user' : 'named',
    account: null,
    consent_mode: null,
  }
}

const coercedFromConsoleUser = ref(false)
/** Conservative until the dialog opens and the device OS is known. */
const draft = ref<SshPolicy>(emptyPolicy(false))

/** Bound separately from `draft.mode` so the switch is a plain boolean; the
 *  wire type is an enum because `off | on` will grow and a bool could not. */
const modeOn = computed({
  get: () => draft.value.mode === 'on',
  set: (v: boolean) => {
    draft.value.mode = v ? 'on' : 'off'
  },
})

/** `account` is `string | null` on the wire but a text field yields `''`.
 *  Normalising here keeps an empty box from being saved as a named account
 *  with an empty name. */
const namedAccount = computed({
  get: () => draft.value.account ?? '',
  set: (v: string) => {
    draft.value.account = v.trim() === '' ? null : v
  },
})

const accountOptions = computed(() => [
  ...(offersConsoleUser.value
    ? [
        {
          title: isWindows.value ? t('mh.sshp.opt.signedIn') : t('mh.exec.opt.person'),
          value: 'console_user',
        },
      ]
    : []),
  {
    title: !isWindows.value
      ? t('mh.sshp.opt.daemonRoot')
      : servedBySystem.value
        ? t('mh.sshp.opt.daemonSystem')
        : t('mh.sshp.opt.daemonAgent'),
    value: 'daemon',
  },
  { title: t('mh.sshp.opt.named'), value: 'named' },
])

const consentOptions = computed(() => [
  { title: t('mh.exec.consent.prompt'), value: null },
  { title: t('mh.sshp.consentAuto'), value: 'auto' },
])

const memberOptions = computed(() =>
  agentStore.tenantMembers.map((m) => ({
    title: m.display_name || m.nickname || m.user_id,
    value: m.user_id,
  })),
)

watch(
  () => props.modelValue,
  (v) => {
    if (!v) return
    error.value = ''
    coercedFromConsoleUser.value = false
    draft.value = { ...emptyPolicy(isWindows.value), ...(agent.value?.ssh_policy ?? {}) }
    // A policy stored before this gate existed can still say `console_user` on a Unix
    // device whose agent cannot honour it. Show the corrected value with the reason
    // rather than a select with no matching option — the dialog is where it gets
    // fixed, so it should present the fix.
    if (!offersConsoleUser.value && draft.value.account_mode === 'console_user') {
      draft.value.account_mode = 'named'
      coercedFromConsoleUser.value = true
    }
    if (!agentStore.tenantMembers.length) {
      void agentStore.fetchTenantMembers(props.tenantId)
    }
    if (agentStore.orgSshEnabled === null) {
      void agentStore.fetchOrgSshEnabled(props.tenantId)
    }
  },
)

async function save() {
  saving.value = true
  error.value = ''
  try {
    await agentStore.updateSshPolicy(props.tenantId, agent.value.id, draft.value)
    emit('saved')
    open.value = false
  } catch (e) {
    // The server refuses a prompt policy for an agent that would ignore it
    // (pre-P5d). Surfacing that here rather than closing is the point: the
    // admin must not walk away believing a prompt is enforced.
    error.value = e instanceof Error ? e.message : t('mh.ext.saveFailed')
  } finally {
    saving.value = false
  }
}

function close() {
  open.value = false
}
</script>
