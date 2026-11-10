<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 G ROX EOOD -->
<template>
  <v-dialog :model-value="modelValue" max-width="520" @update:model-value="emit('update:modelValue', $event)">
    <v-card v-if="device">
      <v-card-title>{{ t('mh.devEdit.title') }}</v-card-title>
      <v-card-text>
        <v-text-field
          v-model="name"
          :label="t('mh.devEdit.name')"
          density="comfortable"
          :hint="nameHint"
          persistent-hint
          class="mb-3"
        />
        <v-text-field
          v-model="displayName"
          :label="t('mh.devEdit.displayName')"
          density="comfortable"
          :hint="t('mh.devEdit.displayNameHint')"
          persistent-hint
          class="mb-3"
        />
        <v-combobox
          v-model="tags"
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
import { computed, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { useAgentStore } from '@/stores/agents'
import { useTunnelClientStore } from '@/stores/tunnelClients'

/** The subset of a device row the dialog edits — works for both kinds. */
export interface EditableDevice {
  kind: 'agent' | 'tunnel_client'
  id: string
  name: string
  display_name?: string
  tags?: string[]
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

watch(
  () => [props.modelValue, props.device] as const,
  ([open, device]) => {
    if (open && device) {
      name.value = device.name
      displayName.value = device.display_name ?? ''
      tags.value = [...(device.tags ?? [])]
      error.value = null
      dnsNote.value = null
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
  const d = props.device
  if (!d) return false
  return (
    name.value.trim() !== d.name ||
    displayName.value.trim() !== (d.display_name ?? '') ||
    JSON.stringify(tags.value) !== JSON.stringify(d.tags ?? [])
  )
})

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
    const fields: { name?: string; display_name?: string; tags?: string[] } = {}
    if (trimmed !== d.name) fields.name = trimmed
    // Empty string CLEARS the display name (the server's convention).
    if (displayName.value.trim() !== (d.display_name ?? ''))
      fields.display_name = displayName.value.trim()
    if (JSON.stringify(tags.value) !== JSON.stringify(d.tags ?? [])) fields.tags = tags.value
    const result =
      d.kind === 'agent'
        ? await agentStore.updateDevice(props.tenantId, d.id, fields)
        : await tunnelClientStore.updateClient(props.tenantId, d.id, fields)
    if (fields.name !== undefined) {
      if (result.dnsRenamed && result.dnsName) {
        dnsNote.value = t('mh.devEdit.dnsRenamed', { name: result.dnsName })
      } else if (result.dnsRenamed === false) {
        dnsNote.value = t('mh.devEdit.dnsKept')
      }
    }
    emit('saved', {
      id: d.id,
      kind: d.kind,
      name: trimmed,
      display_name: displayName.value.trim() || undefined,
      tags: tags.value,
      dnsRenamed: result.dnsRenamed,
      dnsName: result.dnsName,
    })
    // Keep the dialog open only when there's a DNS note worth reading.
    if (!dnsNote.value) emit('update:modelValue', false)
  } catch (e) {
    error.value = (e as Error).message
  } finally {
    saving.value = false
  }
}
</script>
