<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 G ROX EOOD -->
<template>
  <v-dialog :model-value="modelValue" max-width="520" @update:model-value="emit('update:modelValue', $event)">
    <v-card v-if="device">
      <v-card-title>{{ t('mh.devEdit.title') }}</v-card-title>
      <v-card-text>
        <v-text-field
          v-model="name"
          :disabled="saving"
          :label="t('mh.devEdit.name')"
          density="comfortable"
          :hint="nameHint"
          persistent-hint
          class="mb-3"
        />
        <v-text-field
          v-model="displayName"
          :disabled="saving"
          :label="t('mh.devEdit.displayName')"
          density="comfortable"
          :hint="t('mh.devEdit.displayNameHint')"
          persistent-hint
          class="mb-3"
        />
        <v-combobox
          v-model="tags"
          :disabled="saving"
          :label="t('mh.devEdit.tags')"
          multiple
          chips
          closable-chips
          density="comfortable"
          :hint="t('mh.devEdit.tagsHint')"
          persistent-hint
        />
        <v-alert v-if="dnsNote" type="info" variant="tonal" density="compact" class="mt-3">
          {{ dnsNote }}
        </v-alert>
        <div v-if="device.kind === 'agent' && (savedName || device.name_sync)" class="mt-3">
          <DeviceNameSyncStatus :sync="currentSync" />
          <p class="text-caption mt-2">{{ t(`mh.nameSync.${syncPresentation.key}Hint`) }}</p>
          <v-btn v-if="syncPresentation.key === 'failed'" variant="text" size="small" :disabled="dirty || saving" :loading="saving" @click="retryNameSync">
            {{ t('mh.nameSync.retry') }}
          </v-btn>
        </div>
        <v-alert v-if="error" type="error" variant="tonal" density="compact" class="mt-3">
          {{ error }}
        </v-alert>
      </v-card-text>
      <v-card-actions>
        <v-spacer />
        <v-btn variant="text" @click="emit('update:modelValue', false)">{{ $t('common.cancel') }}</v-btn>
        <v-btn color="primary" variant="flat" :loading="saving" :disabled="!dirty" @click="save">
          {{ $t('common.save') }}
        </v-btn>
      </v-card-actions>
    </v-card>
  </v-dialog>
</template>

<script setup lang="ts">
import { computed, onUnmounted, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { useAgentStore } from '@/stores/agents'
import { useTunnelClientStore } from '@/stores/tunnelClients'
import DeviceNameSyncStatus from './DeviceNameSyncStatus.vue'
import { nameSyncPresentation, shouldAcceptNameSync, type NameSync } from '@/utils/nameSync'

/** The subset of a device row the dialog edits — works for both kinds. */
export interface EditableDevice {
  kind: 'agent' | 'tunnel_client'
  id: string
  name: string
  display_name?: string
  tags?: string[]
  name_sync?: NameSync
}

const props = defineProps<{
  modelValue: boolean
  tenantId: string
  device: EditableDevice | null
}>()

const emit = defineEmits<{
  'update:modelValue': [value: boolean]
  /** Fired after a successful save so the host can refresh its rows. */
  saved: [
    result: {
      id: string
      kind: 'agent' | 'tunnel_client'
      name: string
      display_name?: string
      tags: string[]
      dnsRenamed?: boolean
      dnsName?: string
      nameSync?: NameSync
    },
  ]
}>()

const { t } = useI18n()
const agentStore = useAgentStore()
const tunnelClientStore = useTunnelClientStore()

const name = ref('')
const displayName = ref('')
const tags = ref<string[]>([])
const saving = ref(false)
const error = ref<string | null>(null)
const dnsNote = ref<string | null>(null)
const savedName = ref(false)
const savedSync = ref<NameSync>()
const savedSnapshot = ref<{ name: string; display_name?: string; tags?: string[] }>()
const currentSync = computed(() => {
  const live = agentStore.agents.find((a) => a.id === props.device?.id && a.tenant_id === props.tenantId)?.name_sync
  const base = savedSync.value ?? props.device?.name_sync
  return live && shouldAcceptNameSync(base, live) ? live : base
})
const syncPresentation = computed(() => nameSyncPresentation(currentSync.value))
let poll: ReturnType<typeof setTimeout> | undefined
let pollGeneration = 0
function stopPolling() { pollGeneration++; clearTimeout(poll) }
function pollUntilAcknowledged() {
  stopPolling()
  const generation = pollGeneration
  const target = props.device
  const tenant = props.tenantId
  let attempts = 0
  async function check() {
    if (generation !== pollGeneration || !props.modelValue || !target || syncPresentation.value.key !== 'pending' || attempts++ >= 30) return
    try { await agentStore.fetchAgent(tenant, target.id) } catch { /* Leave pending, never invent acknowledgement. */ }
    if (generation === pollGeneration) poll = setTimeout(check, 2000)
  }
  poll = setTimeout(check, 2000)
}
onUnmounted(stopPolling)

watch(
  () => [props.modelValue, props.device] as const,
  ([open, device]) => {
    stopPolling()
    if (open && device) {
      name.value = device.name
      displayName.value = device.display_name ?? ''
      tags.value = [...(device.tags ?? [])]
      error.value = null
      dnsNote.value = null
      savedName.value = false
      savedSync.value = undefined
      savedSnapshot.value = undefined
      if (device.kind === 'agent') pollUntilAcknowledged()
    }
  },
  { immediate: true },
)

const nameHint = computed(() =>
  props.device?.kind === 'agent'
    ? t('mh.devEdit.nameHintAgent')
    : t('mh.devEdit.nameHintClient'),
)

const dirty = computed(() => {
  const d = savedSnapshot.value ?? props.device
  if (!d) return false
  return (
    name.value.trim() !== d.name ||
    displayName.value.trim() !== (d.display_name ?? '') ||
    JSON.stringify(tags.value) !== JSON.stringify(d.tags ?? [])
  )
})

async function retryNameSync() {
  const d = props.device
  if (!d || d.kind !== 'agent' || saving.value || dirty.value) return
  saving.value = true
  error.value = null
  try {
    const canonical = agentStore.agents.find(a => a.id === d.id && a.tenant_id === props.tenantId)?.name ?? savedSnapshot.value?.name ?? d.name
    const result = await agentStore.updateDevice(props.tenantId, d.id, { name: canonical })
    savedName.value = true
    savedSync.value = result.nameSync
    pollUntilAcknowledged()
  } catch (e) { error.value = (e as Error).message }
  finally { saving.value = false }
}

async function save() {
  const d = props.device
  if (!d) return
  const trimmed = name.value.trim()
  if (!trimmed) {
    error.value = t('mh.devEdit.nameEmpty')
    return
  }
  saving.value = true
  error.value = null
  try {
    const previous = savedSnapshot.value ?? d
    const fields: { name?: string; display_name?: string; tags?: string[] } = {}
    if (trimmed !== previous.name) fields.name = trimmed
    // Empty string CLEARS the display name (the server's convention).
    if (displayName.value.trim() !== (previous.display_name ?? ''))
      fields.display_name = displayName.value.trim()
    if (JSON.stringify(tags.value) !== JSON.stringify(previous.tags ?? [])) fields.tags = tags.value
    const result =
      d.kind === 'agent'
        ? await agentStore.updateDevice(props.tenantId, d.id, fields)
        : await tunnelClientStore.updateClient(props.tenantId, d.id, fields)
    const nameSync = 'nameSync' in result ? result.nameSync as NameSync | undefined : undefined
    if (d.kind === 'agent' && fields.name !== undefined) {
      savedName.value = true
      savedSync.value = nameSync
      pollUntilAcknowledged()
    }
    if (fields.name !== undefined) {
      if (result.dnsRenamed && result.dnsName) {
        dnsNote.value = t('mh.devEdit.dnsRenamed', { name: result.dnsName })
      } else if (result.dnsRenamed === false) {
        dnsNote.value = t('mh.devEdit.dnsKept')
      }
    }
    savedSnapshot.value = { name: trimmed, display_name: displayName.value.trim(), tags: [...tags.value] }
    emit('saved', {
      id: d.id,
      kind: d.kind,
      name: trimmed,
      display_name: displayName.value.trim() || undefined,
      tags: tags.value,
      dnsRenamed: result.dnsRenamed,
      dnsName: result.dnsName,
      nameSync,
    })
    // Keep the dialog open only when there's a DNS note worth reading.
    if (!dnsNote.value && !savedName.value) emit('update:modelValue', false)
  } catch (e) {
    error.value = (e as Error).message
  } finally {
    saving.value = false
  }
}
</script>
