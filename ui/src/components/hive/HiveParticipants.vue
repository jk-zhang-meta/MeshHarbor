<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 G ROX EOOD -->
<!--
  FR-90 P1c — who takes part in an agent session. A room has members; a
  session has DRIVERS: they prompt it and answer its approvals. Everyone else
  in the room reads it and talks there — nothing they write reaches the agent.

  The owner adds people (a reader or a driver), changes their part, and takes
  them out; everyone else sees who takes part. A driver needs "Run agent
  sessions" (HIVE_RUN), and the server says so when they lack it.
-->
<template>
  <v-dialog v-model="shown" max-width="560" scrollable :fullscreen="fullscreen">
    <template #activator="{ props: activator }">
      <v-btn
        v-bind="activator"
        size="small"
        variant="text"
        prepend-icon="mdi-account-multiple"
        data-testid="hive-people"
      >
        {{ $t('hive.people.button') }}
      </v-btn>
    </template>
    <v-card>
      <v-card-title class="d-flex align-center">
        <span class="text-wrap">{{ $t('hive.people.title') }}</span>
        <v-spacer />
        <v-btn icon="mdi-close" variant="text" size="small" :aria-label="$t('common.close')" @click="shown = false" />
      </v-card-title>
      <v-card-text>
        <p class="text-body-2 text-medium-emphasis mb-3">{{ $t('hive.people.explain') }}</p>
        <v-progress-linear v-if="loading" indeterminate class="mb-2" />
        <v-list density="compact" data-testid="hive-people-list">
          <v-list-item
            v-for="p in items"
            :key="p.user_id"
            :data-user="p.user_id"
            :data-role="p.role"
            data-testid="hive-person"
          >
            <v-list-item-title>{{ p.display_name || $t('hive.viewer.someone') }}</v-list-item-title>
            <template #append>
              <div v-if="mayManage && p.role !== 'owner'" class="d-flex align-center ga-1">
                <v-btn-toggle
                  :model-value="p.role"
                  density="compact"
                  variant="outlined"
                  mandatory
                  :disabled="busy !== null"
                  @update:model-value="(r: string) => setRole(p.user_id, r)"
                >
                  <v-btn value="reader" size="small" data-testid="hive-person-reader">
                    {{ $t('hive.people.role.reader') }}
                  </v-btn>
                  <v-btn v-if="!adopted" value="driver" size="small" data-testid="hive-person-driver">
                    {{ $t('hive.people.role.driver') }}
                  </v-btn>
                </v-btn-toggle>
                <v-btn
                  icon="mdi-close"
                  size="small"
                  variant="text"
                  :disabled="busy !== null"
                  :aria-label="$t('hive.people.remove')"
                  data-testid="hive-person-remove"
                  @click="remove(p.user_id)"
                />
              </div>
              <v-chip v-else size="small" variant="tonal">{{ $t(`hive.people.role.${p.role}`) }}</v-chip>
            </template>
          </v-list-item>
        </v-list>

        <div v-if="mayManage" class="mt-3">
          <v-autocomplete
            v-model="picked"
            :items="candidates"
            item-title="label"
            item-value="user_id"
            :loading="searching"
            :label="$t('hive.people.add')"
            :no-data-text="$t('hive.people.noMatch')"
            density="compact"
            variant="outlined"
            hide-details
            no-filter
            clearable
            data-testid="hive-people-pick"
            @update:search="search"
          />
          <div class="d-flex justify-end ga-2 mt-2">
            <v-btn
              size="small"
              variant="tonal"
              :disabled="!picked || busy !== null"
              data-testid="hive-people-add-reader"
              @click="add('reader')"
            >
              {{ $t('hive.people.addReader') }}
            </v-btn>
            <v-btn
              v-if="!adopted"
              size="small"
              color="primary"
              variant="flat"
              :disabled="!picked || busy !== null"
              data-testid="hive-people-add-driver"
              @click="add('driver')"
            >
              {{ $t('hive.people.addDriver') }}
            </v-btn>
          </div>
          <div v-if="adopted" class="text-caption text-medium-emphasis mt-1" data-testid="hive-people-readers-only">
            {{ $t('hive.people.adoptedReadersOnly') }}
          </div>
        </div>
        <div v-if="error" class="text-caption text-error mt-2" data-testid="hive-people-error">{{ error }}</div>
      </v-card-text>
      <v-card-actions>
        <v-spacer />
        <v-btn variant="text" @click="shown = false">{{ $t('common.close') }}</v-btn>
      </v-card-actions>
    </v-card>
  </v-dialog>
</template>

<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { api } from '@/api/client'
import { useHiveStore, type HiveParticipant, type HiveParticipants } from '@/stores/hive'
import { useResponsiveDialog } from '@/composables/useResponsiveDialog'

const props = withDefaults(
  defineProps<{
    tenantId: string
    sessionId: string
    /** P1j — an adopted session (a terminal's) takes readers only. */
    adopted?: boolean
  }>(),
  { adopted: false },
)
const hive = useHiveStore()

const shown = ref(false)
// FR-120 P2 — full screen on a phone (a centred 560 px box left ~264 px).
const { fullscreen } = useResponsiveDialog()
const loading = ref(false)
const items = ref<HiveParticipant[]>([])
const mayManage = ref(false)
const error = ref<string | null>(null)
/** The user whose change is in flight — one at a time. */
const busy = ref<string | null>(null)

interface Candidate {
  user_id: string
  label: string
}
const found = ref<Candidate[]>([])
const picked = ref<string | null>(null)
const searching = ref(false)
let searchSeq = 0

/** Org members not already taking part. */
const candidates = computed(() => {
  const taking = new Set(items.value.map((p) => p.user_id))
  return found.value.filter((c) => !taking.has(c.user_id))
})

function take(res: HiveParticipants): void {
  items.value = res.items
  mayManage.value = res.may_manage
}

async function load(): Promise<void> {
  loading.value = true
  error.value = null
  try {
    take(await hive.fetchParticipants(props.tenantId, props.sessionId))
  } catch (e) {
    error.value = (e as Error).message
  } finally {
    loading.value = false
  }
}

async function search(q: string | null): Promise<void> {
  if (!mayManage.value) return
  const seq = ++searchSeq
  searching.value = true
  try {
    const params = new URLSearchParams({ per_page: '20' })
    if (q?.trim()) params.set('q', q.trim())
    const res = await api.get<{ items: { user_id: string; display_name: string; email: string }[] }>(
      `/tenant/${props.tenantId}/member?${params.toString()}`,
    )
    if (seq !== searchSeq) return
    found.value = res.items.map((m) => ({
      user_id: m.user_id,
      label: m.email ? `${m.display_name} · ${m.email}` : m.display_name,
    }))
  } catch {
    if (seq === searchSeq) found.value = []
  } finally {
    if (seq === searchSeq) searching.value = false
  }
}

async function change(userId: string, run: () => Promise<HiveParticipants>): Promise<boolean> {
  if (busy.value) return false
  busy.value = userId
  error.value = null
  try {
    take(await run())
    return true
  } catch (e) {
    error.value = (e as Error).message
    return false
  } finally {
    busy.value = null
  }
}

async function add(role: 'driver' | 'reader'): Promise<void> {
  const userId = picked.value
  if (!userId) return
  if (await change(userId, () => hive.setParticipant(props.tenantId, props.sessionId, userId, role))) {
    picked.value = null
  }
}

async function setRole(userId: string, role: string): Promise<void> {
  if (role !== 'driver' && role !== 'reader') return
  await change(userId, () => hive.setParticipant(props.tenantId, props.sessionId, userId, role))
}

async function remove(userId: string): Promise<void> {
  await change(userId, () => hive.removeParticipant(props.tenantId, props.sessionId, userId))
}

watch(shown, (open) => {
  if (open) {
    void load().then(() => search(''))
  }
})
</script>
