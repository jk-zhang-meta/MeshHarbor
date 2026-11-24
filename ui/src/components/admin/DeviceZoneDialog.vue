<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 G ROX EOOD -->
<template>
  <v-dialog v-model="open" max-width="580" scrollable :fullscreen="fullscreen">
    <v-card>
      <v-card-title class="d-flex align-center">
        <v-icon icon="mdi-map-marker-path" color="primary" class="mr-2" />
        <span class="text-truncate" style="min-width: 0">
          {{ t('mh.zoneAssign.title', { name: deviceLabel(row ?? agent) }) }}
        </span>
      </v-card-title>

      <v-card-text>
        <div
          v-if="loc.hasAny || currentZone.hasZone"
          class="d-flex align-center flex-wrap ga-2 pa-3 mb-4 rounded border text-body-2"
          data-testid="zone-dialog-detected-location"
        >
          <template v-if="loc.hasAny">
            <span class="text-medium-emphasis">{{ t('mh.zoneAssign.detectedLocation') }}:</span>
            <span v-if="loc.countryCode" class="geo-code-pill">{{ loc.countryCode }}</span>
            <span v-if="loc.locationText" class="font-weight-medium">{{ loc.locationText }}</span>
            <span
              v-if="loc.physicalIp"
              class="text-caption text-medium-emphasis"
              data-testid="zone-dialog-physical-ip"
            >
              {{ t('mh.dev.physicalEgress') }}: <span class="text-mono">{{ loc.physicalIp }}</span>
            </span>
            <span
              v-if="loc.publicIp"
              class="text-caption text-medium-emphasis"
              data-testid="zone-dialog-current-ip"
            >
              <template v-if="loc.physicalIp">{{ t('mh.dev.currentEgress') }}: </template>
              <span class="text-mono">{{ loc.publicIp }}</span>
            </span>
          </template>
          <v-spacer v-if="loc.hasAny && currentZone.hasZone" />
          <v-chip
            v-if="currentZone.hasZone"
            size="x-small"
            :color="zoneChipColor(currentZone)"
            variant="tonal"
            :prepend-icon="zoneChipIcon(currentZone)"
            :title="formatZoneTooltip(currentZone, t)"
            :data-zone-source="currentZone.zoneSource || undefined"
            data-testid="zone-dialog-current-chip"
          >
            {{ formatZoneChipLabel(currentZone, t) }}
          </v-chip>
        </div>

        <v-radio-group v-model="mode" hide-details>
          <!-- Option 1: Auto (GeoIP-based) -->
          <v-sheet
            border
            rounded
            class="pa-3 mb-3 policy-choice"
            :class="{ 'policy-choice--active': mode === 'auto' }"
            data-testid="zone-opt-auto"
            @click="mode = 'auto'"
          >
            <div class="d-flex align-start ga-2">
              <v-radio value="auto" density="compact" hide-details class="mt-0 pt-0 flex-grow-0" />
              <div class="flex-grow-1">
                <div class="text-body-2 font-weight-medium d-flex align-center flex-wrap ga-2">
                  <span>{{ t('mh.zoneAssign.autoLabel') }}</span>
                  <v-chip
                    v-if="predictedAutoZone"
                    size="x-small"
                    color="secondary"
                    variant="tonal"
                  >
                    {{ t('mh.zoneAssign.autoMatches', { zone: predictedAutoZone.name }) }}
                  </v-chip>
                </div>
                <div class="text-caption text-medium-emphasis mt-1">
                  {{ t('mh.zoneAssign.autoDesc') }}
                </div>
              </div>
            </div>
          </v-sheet>

          <!-- Option 2: Pinned to a specific logical zone -->
          <v-sheet
            border
            rounded
            class="pa-3 policy-choice"
            :class="{ 'policy-choice--active': mode === 'pinned' }"
            data-testid="zone-opt-pinned"
            @click="selectPinnedMode"
          >
            <div class="d-flex align-start ga-2">
              <v-radio
                value="pinned"
                color="primary"
                density="compact"
                hide-details
                class="mt-0 pt-0 flex-grow-0"
              />
              <div class="flex-grow-1" style="min-width: 0">
                <div class="text-body-2 font-weight-medium d-flex align-center flex-wrap ga-2">
                  <span>{{ t('mh.zoneAssign.pinnedLabel') }}</span>
                  <v-chip
                    v-if="mode === 'pinned' && selectedZoneName"
                    size="x-small"
                    color="primary"
                    variant="tonal"
                    prepend-icon="mdi-pin-outline"
                  >
                    {{ selectedZoneName }}
                  </v-chip>
                </div>
                <div class="text-caption text-medium-emphasis mt-1 mb-2">
                  {{ t('mh.zoneAssign.pinnedDesc') }}
                </div>

                <div
                  v-if="catalogReady && zoneSelectItems.length === 0"
                  class="text-caption text-warning"
                >
                  {{ t('mh.zoneAssign.noZonesConfigured') }}
                </div>
                <v-select
                  v-else
                  v-model="selectedZoneId"
                  :items="zoneSelectItems"
                  item-title="title"
                  item-value="value"
                  :label="t('mh.zoneAssign.selectZoneLabel')"
                  :loading="zonesStore.loading"
                  :disabled="!catalogReady"
                  density="compact"
                  variant="outlined"
                  hide-details
                  data-testid="zone-pinned-select"
                  @click.stop="mode = 'pinned'"
                  @update:model-value="mode = 'pinned'"
                />
              </div>
            </div>
          </v-sheet>
        </v-radio-group>

        <v-alert
          v-if="error || zonesStore.error"
          type="error"
          variant="tonal"
          density="compact"
          class="mt-4"
          data-testid="zone-dialog-error-alert"
        >
          {{ error || zonesStore.error }}
        </v-alert>
      </v-card-text>

      <v-card-actions>
        <v-spacer />
        <v-btn variant="text" @click="close">{{ t('common.cancel') }}</v-btn>
        <v-btn
          color="primary"
          variant="flat"
          :loading="saving"
          :disabled="!catalogReady || (mode === 'pinned' && !selectedZoneId)"
          data-testid="zone-assignment-save"
          @click="save"
        >
          {{ t('common.save') }}
        </v-btn>
      </v-card-actions>
    </v-card>
  </v-dialog>
</template>

<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { useResponsiveDialog } from '@/composables/useResponsiveDialog'
import { useSnackbar } from '@/composables/useSnackbar'
import { deviceLabel } from '@/composables/useHideDeviceName'
import { useAgentStore, type Agent } from '@/stores/agents'
import { useDeviceStore, type DeviceRow } from '@/stores/devices'
import { useNetworkZonesStore, type NetworkZone } from '@/stores/networkZones'
import {
  formatDeviceLocation,
  formatDeviceZone,
  formatZoneChipLabel,
  formatZoneTooltip,
  zoneChipColor,
  zoneChipIcon,
  type ZoneSource,
} from '@/utils/deviceLocation'

const props = defineProps<{
  modelValue: boolean
  tenantId: string
  agent: Agent
  row?: DeviceRow | null
}>()

const emit = defineEmits<{
  (e: 'update:modelValue', v: boolean): void
  (
    e: 'saved',
    resp: {
      agent_id: string
      pinned_zone_id: string | null
      effective_zone_id: string | null
      effective_zone_name: string | null
      zone_source?: ZoneSource | null
    },
  ): void
}>()

const { t } = useI18n()
const { fullscreen } = useResponsiveDialog()
const { showSuccess } = useSnackbar()
const agentStore = useAgentStore()
const deviceStore = useDeviceStore()
const zonesStore = useNetworkZonesStore()

const open = computed({
  get: () => props.modelValue,
  set: (v) => emit('update:modelValue', v),
})

const saving = ref(false)
const error = ref('')
const mode = ref<'auto' | 'pinned'>('auto')
const selectedZoneId = ref('')

const loc = computed(() => formatDeviceLocation(props.row ?? undefined, props.agent))
const catalogReady = computed(
  () =>
    Boolean(props.tenantId) &&
    !zonesStore.loading &&
    zonesStore.error === null &&
    zonesStore.loadedTenantId === props.tenantId,
)
const tenantZones = computed<NetworkZone[]>(() =>
  catalogReady.value ? zonesStore.zones : [],
)

const currentZone = computed(() => {
  const id =
    props.row?.effective_zone_id ||
    props.agent.effective_zone_id ||
    props.row?.pinned_zone_id ||
    props.agent.pinned_zone_id
  return formatDeviceZone(
    props.row ?? undefined,
    props.agent,
    zonesStore.zoneById(id, props.tenantId)?.name ?? null,
  )
})

const predictedAutoZone = computed<NetworkZone | undefined>(() => {
  if (tenantZones.value.length === 0) return undefined
  const cc = loc.value.countryCode
  if (cc) {
    const matched = tenantZones.value.find((z) => !z.is_centre && z.auto_countries.includes(cc))
    if (matched) return matched
  }
  return tenantZones.value.find((z) => z.is_default && !z.is_centre)
})

const zoneSelectItems = computed(() => {
  const items = tenantZones.value.map((z) => ({
    title: `${z.name} (${z.id})`,
    value: z.id,
  }))
  const curPinned = (props.row?.pinned_zone_id ?? props.agent.pinned_zone_id ?? '').trim()
  if (curPinned && !items.some((i) => i.value === curPinned)) {
    items.push({
      title: `${curPinned} (${t('mh.zoneAssign.missingZone')})`,
      value: curPinned,
    })
  }
  return items
})

const selectedZoneName = computed(() => {
  const z = zonesStore.zoneById(selectedZoneId.value, props.tenantId)
  return z ? z.name : selectedZoneId.value
})

function syncInitialState() {
  error.value = ''
  const curPinned = (props.row?.pinned_zone_id ?? props.agent.pinned_zone_id ?? '').trim()
  const curEffective = (props.row?.effective_zone_id ?? props.agent.effective_zone_id ?? '').trim()
  if (curPinned) {
    mode.value = 'pinned'
    selectedZoneId.value = curPinned
  } else {
    mode.value = 'auto'
    selectedZoneId.value = curEffective || tenantZones.value[0]?.id || ''
  }
}

function selectPinnedMode() {
  mode.value = 'pinned'
  if (!selectedZoneId.value && zoneSelectItems.value.length > 0) {
    selectedZoneId.value = zoneSelectItems.value[0]!.value
  }
}

let dialogSeq = 0
let saveSeq = 0

watch(
  [() => props.modelValue, () => props.agent.id, () => props.tenantId],
  async ([v, , tid]) => {
    const seq = ++dialogSeq
    saveSeq++
    saving.value = false
    if (!v) return
    syncInitialState()
    await zonesStore.fetchZones(tid)
    if (seq !== dialogSeq || !props.modelValue || props.tenantId !== tid) return
    if (!selectedZoneId.value && tenantZones.value.length > 0) {
      selectedZoneId.value =
        (props.row?.effective_zone_id ?? props.agent.effective_zone_id ?? '').trim() ||
        tenantZones.value[0]!.id
    }
  },
  { immediate: true },
)

async function save() {
  if (!catalogReady.value) {
    error.value = zonesStore.error || t('mh.zoneAssign.saveFailed')
    return
  }
  const nextPinned = mode.value === 'pinned' ? selectedZoneId.value.trim() || null : null
  if (mode.value === 'pinned' && !nextPinned) return
  const saveTid = props.tenantId
  const saveAgentId = props.agent.id
  const seq = dialogSeq
  const mySave = ++saveSeq
  saving.value = true
  error.value = ''
  try {
    const resp = await agentStore.updateZoneAssignment(saveTid, saveAgentId, nextPinned)
    if (seq !== dialogSeq || props.tenantId !== saveTid || props.agent.id !== saveAgentId) {
      return
    }
    deviceStore.patchRow({
      id: saveAgentId,
      ...(resp.country_code !== undefined ? { country_code: resp.country_code } : {}),
      pinned_zone_id: resp.pinned_zone_id,
      effective_zone_id: resp.effective_zone_id,
      effective_zone_name: resp.effective_zone_name,
      ...(resp.zone_source !== undefined ? { zone_source: resp.zone_source } : {}),
    })
    const name = deviceLabel(props.row ?? props.agent)
    const zLabel = resp.effective_zone_name || resp.pinned_zone_id || ''
    showSuccess(
      resp.pinned_zone_id
        ? t('mh.zoneAssign.savedPinned', { name, zone: zLabel })
        : t('mh.zoneAssign.savedAuto', { name }),
    )
    emit('saved', resp)
    open.value = false
  } catch (e) {
    if (seq === dialogSeq && props.tenantId === saveTid && props.agent.id === saveAgentId) {
      error.value = e instanceof Error ? e.message : t('mh.zoneAssign.saveFailed')
    }
  } finally {
    if (mySave === saveSeq) {
      saving.value = false
    }
  }
}

function close() {
  open.value = false
}
</script>

<style scoped>
.policy-choice {
  cursor: pointer;
  transition: border-color 140ms ease, background-color 140ms ease;
}
.policy-choice--active {
  border-color: rgb(var(--v-theme-primary)) !important;
  background-color: rgba(var(--v-theme-primary), 0.04);
}
.geo-code-pill {
  display: inline-block;
  padding: 0 5px;
  border-radius: 4px;
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  font-size: 10px;
  font-weight: 600;
  line-height: 16px;
  letter-spacing: 0.4px;
  background: rgba(var(--v-theme-on-surface), 0.07);
  border: 1px solid rgba(var(--v-theme-on-surface), 0.14);
}
</style>
