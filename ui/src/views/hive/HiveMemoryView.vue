<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 G ROX EOOD -->
<!--
  FR-90 P1e — agent memory: the facts people keep for the org's agent
  sessions, in three scopes — the organization's (its administrators keep
  them), your own, and a device's. Each scope has a budget of characters; a
  fact that does not fit is refused in the server's words, and nothing is
  ever dropped to make room. A session gets a frozen copy when it starts,
  and only on a device whose owner turned core memory on.
-->
<template>
  <v-container fluid class="pa-2 pa-md-4 pa-xl-6">
    <div class="d-flex align-center mb-2 mb-md-4">
      <h1 class="text-h5 text-md-h4">{{ $t('hive.memory.title') }}</h1>
      <v-spacer />
      <v-chip v-if="view" size="small" variant="tonal" data-testid="hive-memory-rev">
        {{ $t('hive.memory.revision', { rev: view.brain_rev }) }}
      </v-chip>
    </div>
    <v-alert type="info" variant="tonal" density="compact" class="mb-2 mb-md-4" data-testid="hive-memory-about">
      {{ $t('hive.memory.about') }}
    </v-alert>
    <v-alert v-if="loadError" type="warning" variant="tonal" density="compact" class="mb-2">
      {{ loadError }}
    </v-alert>

    <!-- FR-120 P2 — from 600 px up a row of cards, as always; on a phone a
         list of expansion panels, each titled with how full its scope is. -->
    <component :is="xs ? VExpansionPanels : VRow" :multiple="xs || undefined">
      <HiveMemoryScope
        v-for="sec in sections"
        :key="sec.scope"
        :title="$t(`hive.memory.scope.${sec.scope}`)"
        :hint="$t(`hive.memory.scopeHint.${sec.scope}`)"
        :summary="sec.budget ? $t('hive.memory.budget', { used: sec.budget.used, budget: sec.budget.budget }) : ''"
        :data-testid="`hive-memory-scope-${sec.scope}`"
      >
        <v-autocomplete
          v-if="sec.scope === 'device'"
          v-model="deviceId"
          :items="deviceItems"
          :label="$t('hive.memory.device')"
          item-title="title"
          item-value="value"
          :loading="devices.loading"
          density="compact"
          clearable
          data-testid="hive-memory-device"
        />
        <template v-if="sec.scope !== 'device' || deviceId">
          <div v-if="sec.budget" class="mb-2" :data-testid="`hive-memory-budget-${sec.scope}`">
            <v-progress-linear
              :model-value="(100 * sec.budget.used) / sec.budget.budget"
              :color="sec.budget.used >= sec.budget.budget ? 'warning' : 'primary'"
              height="6"
              rounded
            />
            <div class="text-caption text-medium-emphasis mt-1">
              {{ $t('hive.memory.budget', { used: sec.budget.used, budget: sec.budget.budget }) }}
            </div>
          </div>
          <v-list density="compact" class="py-0">
            <v-list-item
              v-for="f in sec.facts"
              :key="f.id"
              class="px-0"
              data-testid="hive-memory-fact"
              :data-scope="f.scope"
            >
              <template #prepend>
                <v-chip size="x-small" variant="tonal" class="mr-2">{{ $t(`hive.memory.kind.${f.kind}`) }}</v-chip>
              </template>
              <v-list-item-title class="text-wrap text-body-2">{{ f.text }}</v-list-item-title>
              <template #append>
                <v-btn
                  icon="mdi-pencil-outline"
                  size="x-small"
                  variant="text"
                  :aria-label="$t('hive.memory.edit')"
                  data-testid="hive-memory-edit"
                  @click="openEdit(f)"
                />
                <v-btn
                  icon="mdi-archive-outline"
                  size="x-small"
                  variant="text"
                  :aria-label="$t('hive.memory.archive')"
                  :loading="busy === f.id"
                  data-testid="hive-memory-archive"
                  @click="archive(f)"
                />
              </template>
            </v-list-item>
          </v-list>
          <p v-if="sec.facts.length === 0" class="text-body-2 text-medium-emphasis my-2">
            {{ $t('hive.memory.empty') }}
          </p>
          <v-textarea
            v-model="drafts[sec.scope].text"
            :label="$t('hive.memory.newFact')"
            :counter="MAX_FACT_CHARS"
            :maxlength="MAX_FACT_CHARS"
            rows="2"
            auto-grow
            density="compact"
            class="mt-2"
            :data-testid="`hive-memory-text-${sec.scope}`"
          />
          <div class="d-flex align-center ga-2">
            <v-select
              v-model="drafts[sec.scope].kind"
              :items="kindItems"
              :label="$t('hive.memory.kindLabel')"
              density="compact"
              hide-details
              style="max-width: 12rem"
            />
            <v-spacer />
            <v-btn
              color="primary"
              variant="tonal"
              :disabled="!drafts[sec.scope].text.trim()"
              :loading="busy === sec.scope"
              :data-testid="`hive-memory-add-${sec.scope}`"
              @click="add(sec.scope)"
            >
              {{ $t('hive.memory.add') }}
            </v-btn>
          </div>
          <v-alert
            v-if="errors[sec.scope]"
            type="warning"
            variant="tonal"
            density="compact"
            class="mt-2"
            :data-testid="`hive-memory-error-${sec.scope}`"
          >
            {{ errors[sec.scope] }}
          </v-alert>
        </template>
      </HiveMemoryScope>
    </component>

    <v-dialog v-model="editing" max-width="560" scrollable :fullscreen="fullscreen">
      <v-card v-if="edit.fact">
        <v-card-title class="d-flex align-center">
          <span class="text-wrap">{{ $t('hive.memory.editTitle') }}</span>
          <v-spacer />
          <v-btn icon="mdi-close" variant="text" size="small" :aria-label="$t('common.close')" @click="editing = false" />
        </v-card-title>
        <v-card-text>
          <v-textarea
            v-model="edit.text"
            :counter="MAX_FACT_CHARS"
            :maxlength="MAX_FACT_CHARS"
            rows="3"
            auto-grow
            data-testid="hive-memory-edit-text"
          />
          <v-select v-model="edit.kind" :items="kindItems" :label="$t('hive.memory.kindLabel')" />
          <v-alert v-if="edit.error" type="warning" variant="tonal" density="compact" class="mt-2">
            {{ edit.error }}
          </v-alert>
        </v-card-text>
        <v-card-actions>
          <v-spacer />
          <v-btn @click="editing = false">{{ $t('common.cancel') }}</v-btn>
          <v-btn
            color="primary"
            :disabled="!edit.text.trim()"
            :loading="busy === edit.fact.id"
            data-testid="hive-memory-edit-save"
            @click="saveEdit"
          >
            {{ $t('common.save') }}
          </v-btn>
        </v-card-actions>
      </v-card>
    </v-dialog>
  </v-container>
</template>

<script setup lang="ts">
import { computed, onMounted, reactive, ref, watch } from 'vue'
import { useRoute } from 'vue-router'
import { useI18n } from 'vue-i18n'
import { useDisplay } from 'vuetify'
import { VExpansionPanels, VRow } from 'vuetify/components'
import {
  FACT_KINDS,
  MAX_FACT_CHARS,
  useHiveStore,
  type BrainBudget,
  type BrainFact,
  type BrainScope,
  type BrainView,
  type FactKind,
} from '@/stores/hive'
import { useDeviceStore } from '@/stores/devices'
import { useResponsiveDialog } from '@/composables/useResponsiveDialog'
import HiveMemoryScope from '@/components/hive/HiveMemoryScope.vue'

const route = useRoute()
const { t } = useI18n()
const hive = useHiveStore()
const devices = useDeviceStore()
const tenantId = computed(() => route.params.tenantId as string)

const view = ref<BrainView | null>(null)
const loadError = ref<string | null>(null)
const deviceId = ref<string | null>(null)
const busy = ref<string | null>(null)
const SCOPES: BrainScope[] = ['org', 'user', 'device']
const drafts = reactive(
  Object.fromEntries(SCOPES.map((s) => [s, { text: '', kind: 'convention' as FactKind }])) as Record<
    BrainScope,
    { text: string; kind: FactKind }
  >,
)
const errors = reactive<Record<BrainScope, string | null>>({ org: null, user: null, device: null })
const editing = ref(false)
// FR-120 P2 — the edit dialog covers the screen on a phone, and each scope
// is a panel there.
const { fullscreen } = useResponsiveDialog()
const { xs } = useDisplay()
const edit = reactive<{ fact: BrainFact | null; text: string; kind: FactKind; error: string | null }>({
  fact: null,
  text: '',
  kind: 'convention',
  error: null,
})

const kindItems = computed(() => FACT_KINDS.map((k) => ({ title: t(`hive.memory.kind.${k}`), value: k })))
const deviceItems = computed(() =>
  devices.items
    .filter((d) => d.kind === 'agent')
    .map((d) => ({ title: d.display_name || d.name, value: d.id })),
)

/** Each scope's facts and budget, as the last read had them. */
const sections = computed(() =>
  SCOPES.map((scope) => {
    const budget: BrainBudget | undefined = view.value?.budgets.find((b) => b.scope === scope)
    const facts = (view.value?.facts ?? []).filter((f) => f.scope === scope)
    return { scope, budget, facts }
  }),
)

// Only the latest read lands: a device picked while an earlier read is in
// flight must not be shown the other scope's facts.
let loadSeq = 0
async function load(): Promise<void> {
  const seq = ++loadSeq
  loadError.value = null
  try {
    const v = await hive.fetchBrain(tenantId.value, deviceId.value ?? undefined)
    if (seq === loadSeq) view.value = v
  } catch (e) {
    if (seq === loadSeq) loadError.value = (e as Error).message
  }
}

async function add(scope: BrainScope): Promise<void> {
  errors[scope] = null
  busy.value = scope
  try {
    await hive.keepFact(tenantId.value, {
      scope,
      owner_id: scope === 'device' ? (deviceId.value ?? undefined) : undefined,
      text: drafts[scope].text.trim(),
      kind: drafts[scope].kind,
    })
    drafts[scope].text = ''
    await load()
  } catch (e) {
    // The server's words: who may keep which memory, or how full the
    // budget is and what the fact needed.
    errors[scope] = (e as Error).message
  } finally {
    busy.value = null
  }
}

function openEdit(f: BrainFact): void {
  edit.fact = f
  edit.text = f.text
  edit.kind = f.kind
  edit.error = null
  editing.value = true
}

async function saveEdit(): Promise<void> {
  if (!edit.fact) return
  edit.error = null
  busy.value = edit.fact.id
  try {
    await hive.editFact(tenantId.value, edit.fact.id, {
      text: edit.text.trim(),
      kind: edit.kind,
      version: edit.fact.version,
    })
    editing.value = false
    await load()
  } catch (e) {
    edit.error = (e as Error).message
  } finally {
    busy.value = null
  }
}

async function archive(f: BrainFact): Promise<void> {
  errors[f.scope] = null
  busy.value = f.id
  try {
    await hive.archiveFact(tenantId.value, f.id)
    await load()
  } catch (e) {
    errors[f.scope] = (e as Error).message
  } finally {
    busy.value = null
  }
}

// A device chosen (or cleared) re-reads, so its facts and budget are its own.
watch(deviceId, () => {
  errors.device = null
  void load()
})

onMounted(async () => {
  await load()
  await devices.fetchDevices(tenantId.value, { kind: 'agent', perPage: 100 })
})
</script>
