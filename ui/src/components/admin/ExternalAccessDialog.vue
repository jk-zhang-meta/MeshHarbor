<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 G ROX EOOD -->
<template>
  <v-dialog v-model="open" max-width="760" scrollable :fullscreen="fullscreen">
    <v-card>
      <v-card-title class="d-flex align-center">
        <v-icon icon="mdi-account-arrow-right-outline" color="primary" class="mr-2" />
        <!-- The span shrinks with an ellipsis (min-width: 0), so the title's own
             buttons stay on screen: a title never wraps, and a long device name
             used to push Close or Refresh past the edge on a phone. -->
        <span class="text-truncate" style="min-width: 0">{{ t('mh.ext.title', { name: deviceLabel(agent) }) }}</span>
      </v-card-title>

      <v-card-text>
        <!-- What an admin must understand BEFORE the switch, not in an
             incident review afterwards. Every other policy in this product
             decides what a COLLEAGUE may do; this one admits a stranger. -->
        <v-alert
          type="warning"
          variant="tonal"
          density="compact"
          class="mb-4"
          icon="mdi-shield-account-outline"
        >
          <i18n-t keypath="mh.ext.warn" tag="span" scope="global">
            <template #notMember><strong>{{ t('mh.ext.notMember') }}</strong></template>
            <template #onMachine><strong>{{ t('mh.ext.onMachine') }}</strong></template>
          </i18n-t>
        </v-alert>

        <v-switch
          v-model="draft.approved"
          color="primary"
          hide-details
          density="compact"
          :disabled="!supported && !alreadyApproved"
          :label="t('mh.ext.allow')"
        />
        <div class="text-caption text-medium-emphasis mb-4 ml-10">
          {{ t('mh.ext.allowHint') }}
        </div>

        <v-select
          v-model="ceiling"
          :items="ceilingOptions"
          :label="t('mh.ext.ceiling')"
          density="compact"
          variant="outlined"
          class="mt-4"
          hide-details
        />
        <div class="text-caption text-medium-emphasis mb-4">
          <i18n-t keypath="mh.ext.ceilingHint" tag="span" scope="global">
            <template #viewOnly><strong>{{ t('mh.ext.viewOnly') }}</strong></template>
          </i18n-t>
        </div>

        <v-text-field
          v-model="expiryLocal"
          type="datetime-local"
          :label="t('mh.ext.expires')"
          density="compact"
          variant="outlined"
          class="mt-4"
          hide-details
          clearable
        />
        <div class="text-caption text-medium-emphasis mb-4">
          {{ t('mh.ext.expiresHint') }}
        </div>

        <!-- The connect code. Not a secret, but it IS the address, so it sits
             behind this dialog rather than on the device list. -->
        <v-divider class="my-4" />
        <div class="text-subtitle-2 mb-1">{{ t('mh.ext.code') }}</div>
        <div class="d-flex align-center flex-wrap ga-2 mb-1">
          <code v-if="connectCode" class="text-h6">{{ connectCode }}</code>
          <span v-else class="text-medium-emphasis">{{ t('mh.ext.codeNone') }}</span>
          <v-spacer />
          <v-btn
            size="small"
            variant="tonal"
            :loading="rotating"
            prepend-icon="mdi-autorenew"
            @click="rotate"
          >
            {{ connectCode ? t('mh.ext.rotate') : t('mh.ext.create') }}
          </v-btn>
        </div>
        <div class="text-caption text-medium-emphasis mb-4">
          {{ t('mh.ext.codeHint') }}
        </div>

        <!-- The three gates this dialog cannot set. Without these an admin
             sets everything here and then wonders why nobody can connect. -->
        <v-alert v-if="orgDisabled" type="info" variant="tonal" density="compact" class="mt-4">
          {{ t('mh.ext.orgOff') }}
        </v-alert>
        <v-alert
          v-if="!supported"
          type="warning"
          variant="tonal"
          density="compact"
          class="mt-4"
        >
          {{ t('mh.ext.tooOld') }}
        </v-alert>
        <v-alert type="info" variant="tonal" density="compact" class="mt-4">
          <i18n-t keypath="mh.ext.devicePassword" tag="span" scope="global">
            <template #cmd><code>mh rc password set</code></template>
          </i18n-t>
        </v-alert>

        <v-alert v-if="error" type="error" variant="tonal" density="compact" class="mt-4">
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
import { useAgentStore, type Agent, type ExternalAccessPolicy } from '@/stores/agents'

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
const rotating = ref(false)
const error = ref('')
const connectCode = ref<string | null>(null)
const agent = computed(() => props.agent)
const orgDisabled = computed(() => agentStore.orgExternalAccessEnabled === false)

/** Gate 3 as the device last advertised it. An agent that cannot say "this
 *  controller is from outside your organization" must not be approvable —
 *  the server refuses it too, and disabling the switch here means the admin
 *  finds out before they save rather than after. */
const supported = computed(() => (agent.value?.capabilities?.rpc ?? []).includes('external-access'))

/** An already-approved device stays togglable even when unsupported, so an
 *  approval can always be taken away. Otherwise a device that downgraded to
 *  an older agent would be stuck approved. */
const alreadyApproved = computed(() => agent.value?.external_access_policy?.approved === true)

/** A closed default, so a dialog opened on a device with no policy can only
 *  ever be saved MORE permissive by an explicit click. */
function emptyPolicy(): ExternalAccessPolicy {
  return { approved: false, max_permissions: null, expires_at: null }
}

const draft = ref<ExternalAccessPolicy>(emptyPolicy())

/** The ceiling as a plain choice. `null` means "the server's default", which
 *  IS view+input — so the option says so rather than reading as "unset". */
const ceilingOptions = computed(() => [
  { title: t('mh.ext.ceil.viewInput'), value: 'VIEW | INPUT' },
  { title: t('mh.ext.ceil.view'), value: 'VIEW' },
  { title: t('mh.ext.ceil.clipboard'), value: 'VIEW | INPUT | CLIPBOARD' },
  { title: t('mh.ext.ceil.files'), value: 'VIEW | INPUT | CLIPBOARD | FILES' },
])

const ceiling = computed({
  get: () => draft.value.max_permissions ?? 'VIEW | INPUT',
  set: (v: string) => {
    draft.value.max_permissions = v
  },
})

/** `<input type="datetime-local">` speaks local wall-clock with no zone; the
 *  wire is an ISO instant. Converting in one place keeps a picker that reads
 *  "17:00" from being stored as 17:00 UTC. */
const expiryLocal = computed({
  get: () => {
    const iso = draft.value.expires_at
    if (!iso) return ''
    const d = new Date(iso)
    if (Number.isNaN(d.getTime())) return ''
    const pad = (n: number) => String(n).padStart(2, '0')
    return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`
  },
  set: (v: string | null) => {
    if (!v) {
      draft.value.expires_at = null
      return
    }
    const d = new Date(v)
    draft.value.expires_at = Number.isNaN(d.getTime()) ? null : d.toISOString()
  },
})

watch(
  () => props.modelValue,
  (v) => {
    if (!v) return
    error.value = ''
    draft.value = { ...emptyPolicy(), ...(agent.value?.external_access_policy ?? {}) }
    connectCode.value =
      agentStore.externalDevices.find((d) => d.id === agent.value?.id)?.connect_code ?? null
    if (agentStore.orgExternalAccessEnabled === null) {
      void agentStore.fetchExternalAccess(props.tenantId)
    }
  },
)

async function rotate() {
  rotating.value = true
  error.value = ''
  try {
    connectCode.value = await agentStore.rotateConnectCode(props.tenantId, agent.value.id)
  } catch (e) {
    error.value = e instanceof Error ? e.message : t('mh.ext.rotateFailed')
  } finally {
    rotating.value = false
  }
}

async function save() {
  saving.value = true
  error.value = ''
  try {
    await agentStore.updateExternalAccessPolicy(props.tenantId, agent.value.id, draft.value)
    await agentStore.fetchExternalAccess(props.tenantId)
    emit('saved')
    open.value = false
  } catch (e) {
    // Keep the dialog OPEN on a refusal. The server refuses an approval on a
    // device whose agent is too old, and on a caller without REMOTE_CONTROL —
    // closing silently would leave the admin believing a stranger can connect.
    error.value = e instanceof Error ? e.message : t('mh.ext.saveFailed')
  } finally {
    saving.value = false
  }
}

function close() {
  open.value = false
}
</script>
