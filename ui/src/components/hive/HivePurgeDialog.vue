<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 G ROX EOOD -->
<!--
  FR-90 P2j-3 — a session deleted for good (P2g-2): from every device that
  held it, where it runs, each copy and where it ran before, the account's
  part on each too; and at once its room, its core memory snapshot and its
  approvals. It cannot be undone, so the owner types the session's title to
  confirm. Then the purge is followed device by device until each answered:
  one offline is purged when it next connects.

  The room goes with it, so this lives in the sessions list, not the room.
-->
<template>
  <v-dialog
    :model-value="modelValue"
    max-width="560"
    scrollable
    :fullscreen="fullscreen"
    @update:model-value="(v: boolean) => emit('update:modelValue', v)"
  >
    <v-card v-if="session">
      <v-card-title class="d-flex align-center">
        <span class="text-wrap">{{ $t('hive.purge.title') }}</span>
        <v-spacer />
        <v-btn icon="mdi-close" variant="text" size="small" :aria-label="$t('common.close')" @click="emit('update:modelValue', false)" />
      </v-card-title>
      <v-card-text>
        <template v-if="!started">
          <p class="text-body-2 mb-2" data-testid="hive-purge-explain">{{ $t('hive.purge.explain', { title: session.title }) }}</p>
          <p class="text-body-2 mb-2">{{ $t('hive.purge.atOnce') }}</p>
          <p class="text-body-2 text-medium-emphasis mb-3">{{ $t('hive.purge.forksKeep') }}</p>
          <v-text-field
            v-model="typed"
            :label="$t('hive.purge.confirm', { title: confirmWord })"
            density="compact"
            autocomplete="off"
            data-testid="hive-purge-confirm"
          />
          <v-alert
            v-if="refusal"
            type="warning"
            variant="tonal"
            density="compact"
            class="mt-2"
            data-testid="hive-purge-refused"
          >
            {{ refusal }}
          </v-alert>
        </template>
        <template v-else>
          <p class="text-body-2 mb-1" data-testid="hive-purge-status">{{ statusText }}</p>
          <p v-if="forks" class="text-caption text-medium-emphasis mb-1" data-testid="hive-purge-forks">
            {{ $t('hive.purge.forks', { n: forks }) }}
          </p>
          <v-list density="compact" data-testid="hive-purge-devices">
            <v-list-item
              v-for="d in purge?.devices ?? []"
              :key="d.device_id"
              :data-device="d.device_id"
              :data-state="d.state"
              data-testid="hive-purge-device"
            >
              <v-list-item-title>{{ nameOf(d.device_id) }}</v-list-item-title>
              <v-list-item-subtitle>{{ partsText(d) }}</v-list-item-subtitle>
              <template #append>
                <v-chip size="small" variant="tonal" :color="d.state === 'done' ? 'success' : undefined">
                  {{ $t(`hive.purge.state.${d.state}`, d.state) }}
                </v-chip>
              </template>
            </v-list-item>
          </v-list>
        </template>
        <div v-if="error" class="text-caption text-error mt-2" data-testid="hive-purge-error">{{ error }}</div>
      </v-card-text>
      <v-card-actions>
        <v-spacer />
        <v-btn variant="text" @click="emit('update:modelValue', false)">{{ $t('common.close') }}</v-btn>
        <v-btn
          v-if="!started"
          color="error"
          variant="flat"
          :loading="busy"
          :disabled="!confirmed"
          data-testid="hive-purge-submit"
          @click="purgeNow"
        >
          {{ $t('hive.purge.submit') }}
        </v-btn>
      </v-card-actions>
    </v-card>
  </v-dialog>
</template>

<script setup lang="ts">
import { computed, onBeforeUnmount, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { useHiveStore, type HivePurge, type HiveSession } from '@/stores/hive'
import { useAgentStore } from '@/stores/agents'
import { useResponsiveDialog } from '@/composables/useResponsiveDialog'

const props = defineProps<{ modelValue: boolean; tenantId: string; session: HiveSession | null }>()
const emit = defineEmits<{ 'update:modelValue': [value: boolean] }>()
// FR-120 P2 — full screen on a phone.
const { fullscreen } = useResponsiveDialog()
const hive = useHiveStore()
const agents = useAgentStore()
const { t } = useI18n()

/** How often a purge still waiting on a device is read again. */
const POLL_MS = 5000

const typed = ref('')
const busy = ref(false)
const error = ref<string | null>(null)
const refusal = ref<string | null>(null)
/** The purge answered `purging` or `purged`: from then on, its progress. */
const started = ref(false)
const purge = ref<HivePurge | null>(null)
const forks = ref(0)
let timer: ReturnType<typeof setTimeout> | null = null

/** What the owner types: the title, or the id of a session with none. */
const confirmWord = computed(() => props.session?.title?.trim() || props.session?.id || '')
const confirmed = computed(() => confirmWord.value !== '' && typed.value.trim() === confirmWord.value)

const settled = computed(() => !!purge.value && (!!purge.value.done_at || purge.value.devices.every((d) => d.state !== 'pending')))

const statusText = computed(() => {
  const p = purge.value
  if (!p) return t('hive.purge.sent')
  if (settled.value) return t('hive.purge.done')
  const answered = p.devices.filter((d) => d.state !== 'pending').length
  return t('hive.purge.going', { done: answered, total: p.devices.length })
})

function nameOf(deviceId: string): string {
  const a = agents.agents.find((x) => x.id === deviceId)
  return a ? a.display_name || a.name : t('hive.purge.someDevice')
}

function partsText(d: HivePurge['devices'][number]): string {
  if (d.state === 'closed') return t(`hive.purge.closed.${d.closed ?? 'other'}`, d.closed ?? '')
  if (d.state === 'pending') return t('hive.purge.pendingDetail')
  const part = (w?: string) => (w ? t(`hive.purge.part.${w}`, w) : t('hive.purge.part.unknown'))
  const parts = t('hive.purge.parts', { store: part(d.store), account: part(d.account) })
  return d.detail ? `${parts} · ${d.detail}` : parts
}

function stopPolling(): void {
  if (timer) clearTimeout(timer)
  timer = null
}

/** Read the purge again while a device it names has not answered. */
function poll(): void {
  stopPolling()
  if (settled.value || !props.modelValue || !props.session) return
  timer = setTimeout(async () => {
    timer = null
    if (!props.session) return
    try {
      purge.value = await hive.fetchPurge(props.tenantId, props.session.id)
    } catch (e) {
      error.value = (e as Error).message
      return
    }
    poll()
  }, POLL_MS)
}

async function readNames(): Promise<void> {
  for (const d of purge.value?.devices ?? []) {
    if (!agents.agents.some((a) => a.id === d.device_id)) {
      await agents.fetchAgent(props.tenantId, d.device_id).catch(() => {})
    }
  }
}

async function purgeNow(): Promise<void> {
  const s = props.session
  if (!s || !confirmed.value || busy.value) return
  busy.value = true
  error.value = null
  refusal.value = null
  try {
    const res = await hive.purge(props.tenantId, s.id)
    if (res.outcome === 'refused') {
      refusal.value = res.message ?? t('hive.purge.refused', { reason: res.reason ?? '' })
      return
    }
    started.value = true
    purge.value = res.purge ?? null
    forks.value = res.forks ?? 0
    void readNames()
    poll()
  } catch (e) {
    error.value = (e as Error).message
  } finally {
    busy.value = false
  }
}

watch(
  () => props.modelValue,
  (open) => {
    stopPolling()
    if (open) {
      typed.value = ''
      error.value = null
      refusal.value = null
      started.value = false
      purge.value = null
      forks.value = 0
    }
  },
)

onBeforeUnmount(stopPolling)
</script>
