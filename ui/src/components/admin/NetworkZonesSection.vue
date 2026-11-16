<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 G ROX EOOD -->
<template>
  <v-card v-if="isAdmin" class="mt-4" data-testid="network-zones-section">
    <v-card-title class="d-flex align-center flex-wrap ga-2">
      <v-icon icon="mdi-earth-box" color="primary" class="mr-2" />
      {{ t('mh.zones.sectionTitle') }}
      <v-chip v-if="store.revision > 0" size="x-small" variant="tonal" class="text-mono">
        r{{ store.revision }}
      </v-chip>
      <v-spacer />
      <div class="d-flex align-center flex-wrap ga-2">
        <v-btn
          size="small"
          variant="tonal"
          color="primary"
          prepend-icon="mdi-auto-fix"
          :disabled="!canEditCurrentTenant"
          data-testid="zones-preset-cn-btn"
          @click="applyCnPreset"
        >
          {{ t('mh.zones.presetCnBtn') }}
        </v-btn>
        <v-btn
          size="small"
          color="primary"
          prepend-icon="mdi-plus"
          :disabled="!canEditCurrentTenant"
          data-testid="zones-add-btn"
          @click="addZone"
        >
          {{ t('mh.zones.addZoneBtn') }}
        </v-btn>
      </div>
    </v-card-title>

    <v-card-text>
      <p class="text-body-2 text-medium-emphasis mb-3">
        {{ t('mh.zones.sectionSubtitle') }}
      </p>
      <v-alert
        v-if="validationError || actionError || store.error"
        type="error"
        variant="tonal"
        density="compact"
        closable
        class="mb-4"
        data-testid="zones-error-alert"
        @click:close="validationError = ''; actionError = ''; store.error = null"
      >
        {{ validationError || actionError || store.error }}
      </v-alert>

      <!-- Empty state for Admins -->
      <v-sheet
        v-if="isAdmin && canEditCurrentTenant && draftZones.length === 0"
        border
        rounded
        class="pa-4 text-body-2 zone-empty-box"
        data-testid="zones-empty-state"
      >
        <div class="font-weight-medium mb-1">{{ t('mh.zones.emptyTitle') }}</div>
        <div class="text-caption text-medium-emphasis mb-3">
          {{ t('mh.zones.emptyHint') }}
        </div>
        <div class="d-flex flex-wrap ga-2">
          <v-btn
            size="small"
            variant="flat"
            color="primary"
            prepend-icon="mdi-auto-fix"
            @click="applyCnPreset"
          >
            {{ t('mh.zones.presetCnBtn') }}
          </v-btn>
          <v-btn
            size="small"
            variant="outlined"
            prepend-icon="mdi-plus"
            @click="addZone"
          >
            {{ t('mh.zones.addZoneBtn') }}
          </v-btn>
        </div>
      </v-sheet>

      <!-- Editable Zone Designer Grid (ADMINISTRATOR) -->
      <v-row v-else-if="isAdmin" dense>
        <v-col
          v-for="(z, idx) in draftZones"
          :key="z._uid"
          cols="12"
          lg="6"
        >
          <v-sheet
            border
            rounded
            class="pa-3 h-100 d-flex flex-column ga-3 zone-card"
            :class="{ 'zone-card--default': z.is_default }"
            :data-testid="`zone-card-${z.id || idx}`"
          >
            <div class="d-flex align-center flex-wrap ga-2">
              <v-icon
                :icon="z.is_default ? 'mdi-shield-home-outline' : 'mdi-map-marker-radius-outline'"
                :color="z.is_default ? 'primary' : 'secondary'"
                size="small"
              />
              <span class="font-weight-medium text-body-2">
                {{ z.name.trim() || z.id.trim() || t('mh.zones.untitled') }}
              </span>
              <span v-if="z.id.trim()" class="zone-slug-pill text-mono">{{ z.id.trim() }}</span>
              <v-chip
                v-if="z.is_default"
                size="x-small"
                color="primary"
                variant="tonal"
              >
                {{ t('mh.zones.defaultBadge') }}
              </v-chip>
              <v-spacer />
              <v-switch
                :model-value="z.is_default"
                color="primary"
                density="compact"
                hide-details
                inset
                :label="t('mh.zones.defaultToggle')"
                class="zone-default-switch mr-1"
                :data-testid="`zone-default-toggle-${idx}`"
                @update:model-value="(v) => toggleDefault(idx, Boolean(v))"
              />
              <v-btn
                icon="mdi-delete-outline"
                size="x-small"
                variant="text"
                color="error"
                :aria-label="t('mh.zones.deleteZoneAria', { name: z.name || z.id })"
                :data-testid="`zone-delete-btn-${idx}`"
                @click="removeZone(idx)"
              />
            </div>

            <v-row dense>
              <v-col cols="12" sm="7">
                <v-text-field
                  :model-value="z.name"
                  :label="t('mh.zones.fieldName')"
                  :placeholder="t('mh.zones.namePlaceholder')"
                  density="compact"
                  variant="outlined"
                  hide-details
                  :data-testid="`zone-name-input-${idx}`"
                  @update:model-value="(v) => onNameInput(idx, String(v ?? ''))"
                />
              </v-col>
              <v-col cols="12" sm="5">
                <v-text-field
                  :model-value="z.id"
                  :label="t('mh.zones.fieldId')"
                  :placeholder="t('mh.zones.idPlaceholder')"
                  density="compact"
                  variant="outlined"
                  hide-details
                  class="text-mono"
                  :data-testid="`zone-id-input-${idx}`"
                  @update:model-value="(v) => onIdInput(idx, String(v ?? ''))"
                />
              </v-col>
            </v-row>

            <v-combobox
              :model-value="z.auto_countries"
              :items="ISO_COUNTRY_CODES"
              :label="t('mh.zones.fieldCountries')"
              :placeholder="t('mh.zones.countriesPlaceholder')"
              :hint="
                z.is_default && z.auto_countries.length === 0
                  ? t('mh.zones.countriesDefaultHint')
                  : t('mh.zones.countriesHint')
              "
              persistent-hint
              multiple
              chips
              closable-chips
              density="compact"
              variant="outlined"
              :data-testid="`zone-countries-input-${idx}`"
              @update:model-value="(vals) => onCountriesChange(idx, vals)"
            >
              <template #item="{ props: itemProps, item }">
                <v-list-item v-bind="itemProps" :title="countryOptionLabel(String(item.raw ?? item.value ?? ''))" />
              </template>
            </v-combobox>

            <v-select
              v-model="z.gateway_relay_ids"
              :items="routerOptionsFor(z)"
              item-title="title"
              item-value="value"
              :label="t('mh.zones.fieldRouters')"
              :no-data-text="t('mh.zones.noRoutersAvailable')"
              :hint="
                peerRelayStore.relays.length === 0
                  ? t('mh.zones.noRoutersHint')
                  : t('mh.zones.routersHint')
              "
              persistent-hint
              multiple
              chips
              closable-chips
              density="compact"
              variant="outlined"
              :data-testid="`zone-routers-select-${idx}`"
            >
              <template #item="{ props: itemProps, item }">
                <v-list-item v-bind="itemProps" :title="item.raw.name">
                  <template #prepend>
                    <v-icon
                      size="x-small"
                      :color="item.raw.online ? 'success' : 'grey'"
                      class="mr-2"
                    >
                      {{ item.raw.online ? 'mdi-circle' : 'mdi-circle-outline' }}
                    </v-icon>
                  </template>
                  <template #subtitle>
                    <span>{{ item.raw.stateText }}</span>
                    <span v-if="item.raw.locationText"> · {{ item.raw.locationText }}</span>
                  </template>
                </v-list-item>
              </template>
            </v-select>

            <v-select
              v-model="z.cross_zone_mode"
              :items="crossZoneModeItems"
              item-title="title"
              item-value="value"
              :label="t('mh.zones.fieldCrossZoneMode')"
              density="compact"
              variant="outlined"
              hide-details
              :data-testid="`zone-mode-select-${idx}`"
            />
          </v-sheet>
        </v-col>
      </v-row>

      <!-- Save / Reset Bar (ADMINISTRATOR) -->
      <div
        v-if="isAdmin && (draftZones.length > 0 || store.zones.length > 0)"
        class="d-flex align-center justify-end flex-wrap ga-2 mt-4"
      >
        <span v-if="isDirty" class="text-caption text-warning mr-2" data-testid="zones-unsaved-hint">
          {{ t('mh.zones.unsavedHint') }}
        </span>
        <v-btn
          v-if="isDirty"
          size="small"
          variant="text"
          :disabled="saving || !canEditCurrentTenant"
          data-testid="zones-reset-btn"
          @click="syncDraftFromStore"
        >
          {{ t('mh.zones.discardBtn') }}
        </v-btn>
        <v-btn
          size="small"
          color="primary"
          variant="flat"
          prepend-icon="mdi-content-save-outline"
          :loading="saving"
          :disabled="!canEditCurrentTenant"
          data-testid="zones-save-btn"
          @click="saveAll"
        >
          {{ t('mh.zones.saveBtn') }}
        </v-btn>
      </div>
    </v-card-text>
  </v-card>
</template>

<script setup lang="ts">
import { computed, onMounted, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { useSnackbar } from '@/composables/useSnackbar'
import { deviceLabel } from '@/composables/useHideDeviceName'
import { useAgentStore, type Agent } from '@/stores/agents'
import { useDeviceStore } from '@/stores/devices'
import { useTenantStore } from '@/stores/tenant'
import { usePeerRelaysStore } from '@/stores/peerRelays'
import {
  ZONE_ID_PATTERN,
  buildCnNonCnPreset,
  suggestZoneSlug,
  useNetworkZonesStore,
  type CrossZoneMode,
  type NetworkZone,
} from '@/stores/networkZones'
import { formatDeviceLocation } from '@/utils/deviceLocation'
import { canManageRelays } from '@/utils/permissions'

interface DraftZone extends NetworkZone {
  _uid: number
  _idTouched: boolean
}

const ISO_COUNTRY_CODES = [
  'CN',
  'HK',
  'MO',
  'TW',
  'SG',
  'JP',
  'KR',
  'US',
  'CA',
  'GB',
  'DE',
  'FR',
  'NL',
  'AU',
]

const props = defineProps<{ tenantId: string }>()
const emit = defineEmits<{ (e: 'saved', zones: NetworkZone[]): void }>()

const { t } = useI18n()
const { showSuccess } = useSnackbar()
const store = useNetworkZonesStore()
const peerRelayStore = usePeerRelaysStore()
const agentStore = useAgentStore()
const deviceStore = useDeviceStore()
const tenantStore = useTenantStore()

const isAdmin = computed(() =>
  canManageRelays(tenantStore.myPermissions, tenantStore.isOwner),
)

let nextUid = 1
let loadSeq = 0
const draftTenantId = ref<string | null>(null)
const loadFailed = ref(false)
const draftZones = ref<DraftZone[]>([])
const saving = ref(false)
const validationError = ref('')
const actionError = ref('')

const canEditCurrentTenant = computed(
  () =>
    !store.loading &&
    !loadFailed.value &&
    draftTenantId.value === props.tenantId &&
    store.loadedTenantId === props.tenantId,
)

const agentById = computed(() => {
  const m = new Map<string, Agent>()
  for (const a of agentStore.agents) m.set(a.id, a)
  return m
})

const crossZoneModeItems = computed(() => [
  { title: t('mh.zones.modeRouterOnly'), value: 'router_only' as CrossZoneMode },
  { title: t('mh.zones.modeDirectPreferred'), value: 'direct_preferred' as CrossZoneMode },
])

function toDraft(z: NetworkZone, idTouched = true): DraftZone {
  return {
    _uid: nextUid++,
    _idTouched: idTouched,
    id: z.id,
    name: z.name,
    auto_countries: [...z.auto_countries],
    is_default: z.is_default,
    gateway_relay_ids: [...z.gateway_relay_ids],
    cross_zone_mode: z.cross_zone_mode,
  }
}

function stripDraft(z: DraftZone): NetworkZone {
  return {
    id: z.id.trim().toLowerCase(),
    name: z.name.trim(),
    auto_countries: z.auto_countries.map((c) => c.trim().toUpperCase()).filter(Boolean),
    is_default: Boolean(z.is_default),
    gateway_relay_ids: [...new Set(z.gateway_relay_ids.map((r) => r.trim()).filter(Boolean))],
    cross_zone_mode: z.cross_zone_mode === 'direct_preferred' ? 'direct_preferred' : 'router_only',
  }
}

function syncDraftFromStore() {
  validationError.value = ''
  actionError.value = ''
  draftZones.value = store.zones.map((z) => toDraft(z, true))
}

const isDirty = computed(() => {
  const current = JSON.stringify(draftZones.value.map(stripDraft))
  const saved = JSON.stringify(store.zones)
  return current !== saved
})

function countryOptionLabel(code: string): string {
  const c = code.trim().toUpperCase()
  const key = `mh.zones.country.${c}`
  const localized = t(key)
  return localized !== key ? `${c} — ${localized}` : c
}

interface RouterOption {
  value: string
  title: string
  name: string
  online: boolean
  stateText: string
  locationText: string
}

function routerOptionsFor(zone: DraftZone): RouterOption[] {
  const opts: RouterOption[] = []
  const seen = new Set<string>()
  for (const r of peerRelayStore.relays) {
    seen.add(r.id)
    const a = agentById.value.get(r.id)
    const name = a ? deviceLabel(a) : r.name
    const online = a ? a.is_online : r.status === 'online'
    const stateText = r.serving
      ? t('mh.peerRelay.servingOn')
      : online
        ? t('mh.dev.presence.online')
        : t('mh.dev.presence.offline')
    const loc = formatDeviceLocation(a)
    const locParts = [loc.countryCode, loc.locationText].filter(Boolean).join(' · ')
    opts.push({
      value: r.id,
      name,
      online,
      stateText,
      locationText: locParts,
      title: locParts ? `${name} (${locParts})` : name,
    })
  }
  // Preserve any existing gateway_relay_id not yet loaded in peerRelayStore.relays
  for (const existingId of zone.gateway_relay_ids) {
    if (!existingId || seen.has(existingId)) continue
    seen.add(existingId)
    const a = agentById.value.get(existingId)
    const name = a ? deviceLabel(a) : existingId.slice(0, 8)
    opts.push({
      value: existingId,
      name,
      online: Boolean(a?.is_online),
      stateText: t('mh.zones.routerUnlisted'),
      locationText: '',
      title: name,
    })
  }
  return opts
}

function applyCnPreset() {
  validationError.value = ''
  const preset = buildCnNonCnPreset(peerRelayStore.relays, agentById.value, {
    cnName: t('mh.zones.presetCnName'),
    nonCnName: t('mh.zones.presetNonCnName'),
  })
  draftZones.value = preset.map((z) => toDraft(z, true))
}

function addZone() {
  validationError.value = ''
  const idx = draftZones.value.length + 1
  const usedIds = new Set(draftZones.value.map((z) => z.id.trim().toLowerCase()))
  let suggestedId = `zone-${idx}`
  let n = idx
  while (usedIds.has(suggestedId)) {
    n += 1
    suggestedId = `zone-${n}`
  }
  draftZones.value.push({
    _uid: nextUid++,
    _idTouched: false,
    id: suggestedId,
    name: '',
    auto_countries: [],
    is_default: draftZones.value.length === 0,
    gateway_relay_ids: [],
    cross_zone_mode: 'router_only',
  })
}

function removeZone(idx: number) {
  validationError.value = ''
  draftZones.value.splice(idx, 1)
}

function toggleDefault(idx: number, enabled: boolean) {
  const target = draftZones.value[idx]
  if (!target) return
  if (enabled) {
    for (let i = 0; i < draftZones.value.length; i++) {
      draftZones.value[i]!.is_default = i === idx
    }
  } else {
    target.is_default = false
  }
}

function onNameInput(idx: number, val: string) {
  const z = draftZones.value[idx]
  if (!z) return
  z.name = val
  if (!z._idTouched) {
    z.id = suggestZoneSlug(val, idx + 1)
  }
}

function onIdInput(idx: number, val: string) {
  const z = draftZones.value[idx]
  if (!z) return
  z._idTouched = true
  z.id = val
    .toLowerCase()
    .replace(/[^a-z0-9_-]/g, '')
    .replace(/^[-_]+/, '')
    .slice(0, 32)
}

function onCountriesChange(idx: number, rawVals: unknown) {
  const z = draftZones.value[idx]
  if (!z || !Array.isArray(rawVals)) return
  const out: string[] = []
  const seen = new Set<string>()
  for (const entry of rawVals) {
    const raw =
      typeof entry === 'string'
        ? entry
        : entry && typeof entry === 'object' && 'value' in entry
          ? String((entry as { value: unknown }).value ?? '')
          : ''
    for (const part of raw.split(/[\s,，;]+/)) {
      const code = part.trim().toUpperCase()
      if (!code) continue
      if (!/^[A-Z]{2}$/.test(code)) {
        validationError.value = t('mh.zones.errInvalidCountry', { code })
        continue
      }
      if (!seen.has(code)) {
        seen.add(code)
        out.push(code)
      }
    }
  }
  z.auto_countries = out
}

function validateZones(zones: NetworkZone[]): string | null {
  const seenIds = new Set<string>()
  const countryOwner = new Map<string, string>()
  let defaultCount = 0

  for (const z of zones) {
    if (!z.name) {
      return t('mh.zones.errEmptyName')
    }
    if (!z.id || !ZONE_ID_PATTERN.test(z.id) || z.id.length > 32) {
      return t('mh.zones.errInvalidId', { id: z.id || '—' })
    }
    if (seenIds.has(z.id)) {
      return t('mh.zones.errDuplicateId', { id: z.id })
    }
    seenIds.add(z.id)
    if (z.is_default) defaultCount += 1
    for (const c of z.auto_countries) {
      if (!/^[A-Z]{2}$/.test(c)) {
        return t('mh.zones.errInvalidCountry', { code: c })
      }
      const prev = countryOwner.get(c)
      if (prev) {
        return t('mh.zones.errDuplicateCountry', { code: c, z1: prev, z2: z.name })
      }
      countryOwner.set(c, z.name)
    }
  }
  if (defaultCount > 1) {
    return t('mh.zones.errMultipleDefaults')
  }
  return null
}

let activeSaveSeq = 0

async function saveAll() {
  validationError.value = ''
  actionError.value = ''
  const saveTid = props.tenantId
  const saveLoadSeq = loadSeq
  if (!canEditCurrentTenant.value) {
    actionError.value = store.error || t('mh.zones.saveFailed')
    return
  }
  const payload = draftZones.value.map(stripDraft)
  const err = validateZones(payload)
  if (err) {
    validationError.value = err
    return
  }
  const mySave = ++activeSaveSeq
  saving.value = true
  try {
    const resp = await store.saveZones(saveTid, payload)
    if (saveLoadSeq !== loadSeq || props.tenantId !== saveTid) {
      return
    }
    if (store.loadedTenantId !== saveTid || store.error !== null) {
      draftTenantId.value = null
      loadFailed.value = true
      actionError.value = store.error || t('mh.zones.saveFailed')
      return
    }
    draftTenantId.value = saveTid
    syncDraftFromStore()
    showSuccess(t('mh.zones.saved'))
    emit('saved', resp.zones)
    // Refresh device & agent feeds so resolved effective_zone_name badges update immediately.
    void agentStore.fetchAgents(saveTid)
    void deviceStore.fetchDevices(saveTid).catch(() => {})
  } catch (e) {
    if (saveLoadSeq === loadSeq && props.tenantId === saveTid) {
      if (store.loadedTenantId !== saveTid || store.error !== null) {
        draftTenantId.value = null
        loadFailed.value = true
      }
      actionError.value = e instanceof Error ? e.message : t('mh.zones.saveFailed')
    }
  } finally {
    if (mySave === activeSaveSeq) {
      saving.value = false
    }
  }
}

async function loadInitial(tid: string) {
  const seq = ++loadSeq
  activeSaveSeq++
  saving.value = false
  draftTenantId.value = null
  loadFailed.value = false
  draftZones.value = []
  validationError.value = ''
  actionError.value = ''
  if (!tid) return
  await tenantStore.ensureMyMembership(tid)
  if (seq !== loadSeq || tid !== props.tenantId || !isAdmin.value) return
  const resp = await store.fetchZones(tid)
  if (seq !== loadSeq || tid !== props.tenantId) return
  if (!resp || store.loadedTenantId !== tid) {
    loadFailed.value = true
    actionError.value = store.error || t('mh.zones.saveFailed')
    return
  }
  draftTenantId.value = tid
  loadFailed.value = false
  syncDraftFromStore()
  if (peerRelayStore.relays.length === 0) {
    void peerRelayStore.fetchSettings(tid)
  }
}

onMounted(() => {
  void loadInitial(props.tenantId)
})

watch(
  [() => props.tenantId, isAdmin],
  ([tid, admin]) => {
    if (!tid || !admin) {
      loadSeq++
      activeSaveSeq++
      saving.value = false
      draftTenantId.value = null
      loadFailed.value = false
      draftZones.value = []
      return
    }
    void loadInitial(tid)
  },
)

// Keep draft synchronized if store.zones loads externally for the SAME tenant before draft initializes
watch(
  () => store.zones,
  () => {
    if (
      !saving.value &&
      !loadFailed.value &&
      draftTenantId.value === null &&
      store.loadedTenantId === props.tenantId &&
      draftZones.value.length === 0 &&
      store.zones.length > 0
    ) {
      draftTenantId.value = props.tenantId
      syncDraftFromStore()
    }
  },
)
</script>

<style scoped>
.zone-card {
  transition: border-color 140ms ease, background-color 140ms ease;
}
.zone-card--default {
  border-color: rgba(var(--v-theme-primary), 0.45) !important;
  background-color: rgba(var(--v-theme-primary), 0.025);
}
.zone-empty-box {
  border-style: dashed !important;
  background-color: rgba(var(--v-theme-on-surface), 0.02);
}
.zone-slug-pill {
  display: inline-block;
  padding: 0 6px;
  border-radius: 4px;
  font-size: 11px;
  font-weight: 600;
  line-height: 18px;
  background: rgba(var(--v-theme-on-surface), 0.07);
  border: 1px solid rgba(var(--v-theme-on-surface), 0.14);
}
.zone-default-switch :deep(.v-label) {
  font-size: 12px;
}
</style>
