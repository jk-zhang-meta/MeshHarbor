<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 G ROX EOOD -->
<template>
  <!-- FR-102 P10 — the alerts panel: the rows open now and the ones cleared
       in the last week, each a rule and a key with the numbers behind it.
       Days, counts and source names only — rendered as text, never
       v-html. "Evaluate now" runs every rule as the hourly job would; the
       dry run decides and writes nothing. -->
  <v-card>
    <v-card-title class="text-subtitle-1 d-flex align-center flex-wrap" style="gap: 8px">
      Alerts
      <v-chip v-if="alerts" size="x-small" variant="tonal" :color="alerts.enabled ? 'success' : 'grey'">
        {{ alerts.enabled ? 'evaluated hourly' : 'off on this server (MESHHARBOR__GROWTH__ALERTS)' }}
      </v-chip>
      <v-spacer />
      <v-btn size="x-small" variant="text" :loading="evaluating" @click="evaluate(true)">Dry run</v-btn>
      <v-btn
        size="x-small"
        variant="tonal"
        :loading="evaluating"
        :disabled="!alerts?.enabled"
        @click="evaluate(false)"
      >
        Evaluate now
      </v-btn>
    </v-card-title>
    <v-card-text>
      <v-alert v-if="message" type="error" variant="tonal" density="compact" class="mb-2">
        {{ message }}
      </v-alert>
      <template v-if="alerts">
        <div v-if="alerts.open.length === 0" class="text-body-2 text-medium-emphasis mb-2">
          Nothing open.
        </div>
        <v-table v-else density="compact" class="growth-wide mb-2">
          <thead>
            <tr>
              <th class="text-left">Rule</th>
              <th class="text-left">Key</th>
              <th class="text-left">Fired</th>
              <th class="text-left">Detail</th>
              <th class="text-left">Mailed</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="a in alerts.open" :key="a.id">
              <td><v-chip size="x-small" color="warning" variant="tonal">{{ a.rule }}</v-chip></td>
              <td>{{ a.key }}</td>
              <td>{{ a.fired_at.slice(0, 16).replace('T', ' ') }}</td>
              <td class="text-caption">{{ alertDetailLabel(a.detail) }}</td>
              <td class="text-caption">{{ a.mailed_on ?? 'not yet' }}</td>
            </tr>
          </tbody>
        </v-table>
        <div v-if="alerts.recent.length" class="text-caption text-medium-emphasis">
          Cleared recently:
          <span v-for="a in alerts.recent" :key="a.id" class="mr-2">
            {{ a.rule }}: {{ a.key }} ({{ a.fired_at.slice(0, 10) }} → {{ a.cleared_at?.slice(0, 10) ?? '—' }})
          </span>
        </div>
        <div v-if="evaluation" class="text-caption mt-2">
          Evaluated {{ evaluation.at.slice(0, 16).replace('T', ' ') }}{{ evaluation.dry_run ? ' (dry run)' : '' }}:
          {{ evaluation.verdicts.filter((v) => v.holds).length }} of {{ evaluation.verdicts.length }} hold ·
          fired {{ evaluation.fired.length }} · cleared {{ evaluation.cleared.length }} · mailed {{ evaluation.mailed }}
        </div>
        <v-expansion-panels variant="accordion" class="mt-2">
          <v-expansion-panel>
            <v-expansion-panel-title class="text-caption">The rules</v-expansion-panel-title>
            <v-expansion-panel-text>
              <div v-for="r in alerts.rules" :key="r.rule" class="text-caption mb-1">
                <strong>{{ r.rule }}</strong> ({{ r.keys.join(', ') }}) — {{ r.description }}
              </div>
            </v-expansion-panel-text>
          </v-expansion-panel>
        </v-expansion-panels>
      </template>
      <v-progress-circular v-else-if="loading" indeterminate size="20" />
    </v-card-text>
  </v-card>
</template>

<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { useGrowthStore, alertDetailLabel, type AlertsResponse, type AlertEvaluation } from '@/stores/growth'

const store = useGrowthStore()
const alerts = ref<AlertsResponse | null>(null)
const evaluation = ref<AlertEvaluation | null>(null)
const loading = ref(false)
const evaluating = ref(false)
const message = ref<string | null>(null)

async function load() {
  loading.value = true
  try {
    alerts.value = await store.fetchAlerts()
    message.value = null
  } catch (e) {
    message.value = e instanceof Error ? e.message : 'alerts failed'
  } finally {
    loading.value = false
  }
}

async function evaluate(dryRun: boolean) {
  evaluating.value = true
  try {
    evaluation.value = await store.evaluateAlerts(dryRun)
    if (!dryRun) await load()
  } catch (e) {
    message.value = e instanceof Error ? e.message : 'evaluation failed'
  } finally {
    evaluating.value = false
  }
}

onMounted(load)
</script>

<style scoped>
.growth-wide {
  max-width: 100%;
  overflow-x: auto;
}
</style>
