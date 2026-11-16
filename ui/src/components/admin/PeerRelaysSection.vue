<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 G ROX EOOD -->
<template>
  <v-card v-if="isAdmin" class="mt-4" data-testid="peer-relays-section">
    <v-card-title class="d-flex align-center flex-wrap ga-2">
      <v-icon icon="mdi-swap-horizontal-circle-outline" color="primary" class="mr-2" />
      {{ t('mh.peerRelay.sectionTitle') }}
      <v-spacer />
      <v-btn
        size="small"
        color="primary"
        prepend-icon="mdi-plus"
        :disabled="candidateAgents.length === 0"
        data-testid="peer-relay-designate-btn"
        @click="openPicker"
      >
        {{ t('mh.peerRelay.designateBtn') }}
      </v-btn>
    </v-card-title>

    <v-card-text>
      <p class="text-body-2 text-medium-emphasis mb-3">
        {{ t('mh.peerRelay.sectionSubtitle') }} {{ t('mh.peerRelay.autoActivateInfo') }}
      </p>

      <div class="d-flex align-center flex-wrap ga-3 mb-4">
        <v-select
          :model-value="store.mode ?? 'off'"
          :items="modeItems"
          :label="t('mh.peerRelay.modeLabel')"
          :loading="savingMode"
          :disabled="savingMode || store.loading"
          density="compact"
          variant="outlined"
          hide-details
          style="max-width: 420px; min-width: 260px"
          data-testid="peer-relay-mode-select"
          @update:model-value="onModeChange"
        />
      </div>

      <v-alert
        v-if="store.error || actionError"
        type="error"
        variant="tonal"
        density="compact"
        closable
        class="mb-4"
        @click:close="store.error = null; actionError = ''"
      >
        {{ actionError || store.error }}
      </v-alert>

      <div v-if="store.relays.length === 0" class="text-body-2 text-medium-emphasis">
        {{ t('mh.peerRelay.noRelays') }}
      </div>
      <v-table v-else density="compact" class="table-stack-xs">
        <thead>
          <tr>
            <th>{{ t('mh.peerRelay.colDevice') }}</th>
            <th>{{ t('mh.peerRelay.colZone') }}</th>
            <th>{{ t('mh.peerRelay.colState') }}</th>
            <th>{{ t('mh.peerRelay.colEndpoints') }}</th>
            <th>{{ t('mh.peerRelay.colBackbone') }}</th>
            <th class="text-right">{{ t('mh.peerRelay.colActions') }}</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="r in store.relays" :key="r.id">
            <td :data-label="t('mh.peerRelay.colDevice')" class="font-weight-medium">
              {{ relayDisplayName(r.id, r.name) }}
            </td>
            <td :data-label="t('mh.peerRelay.colZone')">
              <v-chip
                v-if="relayZoneInfo(r.id).hasZone"
                size="x-small"
                :color="relayZoneInfo(r.id).pinned ? 'primary' : 'secondary'"
                variant="tonal"
                :prepend-icon="relayZoneInfo(r.id).pinned ? 'mdi-pin-outline' : 'mdi-map-marker-radius-outline'"
              >
                {{ relayZoneInfo(r.id).badgeText }}
              </v-chip>
              <span v-else class="text-caption text-medium-emphasis">—</span>
            </td>
            <td :data-label="t('mh.peerRelay.colState')">
              <v-chip
                size="x-small"
                :color="r.serving ? 'success' : 'info'"
                variant="tonal"
              >
                {{ r.serving ? t('mh.peerRelay.servingOn') : t('mh.peerRelay.servingPending') }}
              </v-chip>
            </td>
            <td :data-label="t('mh.peerRelay.colEndpoints')">
              <span v-if="r.static_endpoints.length" class="text-mono text-caption">
                {{ r.static_endpoints.join(', ') }}
              </span>
              <span v-else class="text-caption text-medium-emphasis">
                {{ t('mh.peerRelay.autoDetected') }}
              </span>
            </td>
            <td :data-label="t('mh.peerRelay.colBackbone')">
              <div class="d-flex flex-wrap align-center ga-1">
                <v-chip
                  v-if="sameZonePeerCount(r.id) > 0"
                  size="x-small"
                  variant="tonal"
                >
                  {{ t('mh.peerRelay.sameZoneAutoMesh', { count: sameZonePeerCount(r.id) }) }}
                </v-chip>
                <v-chip
                  v-for="edge in r.approved_backbone_edges ?? []"
                  :key="edge.relay_agent_id"
                  size="x-small"
                  :color="edge.cross_border ? 'warning' : 'primary'"
                  variant="tonal"
                >
                  → {{ relayDisplayName(edge.relay_agent_id, edge.relay_agent_id.slice(0, 6)) }}
                  ({{ edge.endpoint }})
                  <template v-if="edge.cross_border"> · {{ t('mh.peerRelay.crossBorderTag') }}</template>
                </v-chip>
                <span
                  v-if="sameZonePeerCount(r.id) === 0 && !(r.approved_backbone_edges?.length)"
                  class="text-caption text-medium-emphasis"
                >
                  —
                </span>
              </div>
            </td>
            <td class="text-right">
              <v-btn
                v-if="agentById.get(r.id)"
                size="x-small"
                variant="text"
                icon="mdi-pencil-outline"
                :aria-label="t('common.edit')"
                @click="editRelay(agentById.get(r.id)!)"
              />
              <v-btn
                size="x-small"
                variant="text"
                color="error"
                :loading="revokingId === r.id"
                @click="revokeRelay(r.id, r.name)"
              >
                {{ t('mh.peerRelay.revoke') }}
              </v-btn>
            </td>
          </tr>
        </tbody>
      </v-table>
    </v-card-text>

    <v-dialog v-model="pickerOpen" max-width="440">
      <v-card>
        <v-card-title>{{ t('mh.peerRelay.pickDeviceTitle') }}</v-card-title>
        <v-card-text>
          <v-select
            v-model="pickedAgentId"
            :items="candidateItems"
            :label="t('mh.peerRelay.pickDeviceLabel')"
            density="compact"
            variant="outlined"
            hide-details
          />
        </v-card-text>
        <v-card-actions>
          <v-spacer />
          <v-btn variant="text" @click="pickerOpen = false">{{ t('common.cancel') }}</v-btn>
          <v-btn
            color="primary"
            variant="flat"
            :disabled="!pickedAgentId"
            @click="confirmPick"
          >
            {{ t('mh.peerRelay.pickContinue') }}
          </v-btn>
        </v-card-actions>
      </v-card>
    </v-dialog>

    <v-dialog v-model="linkDialogOpen" max-width="560">
      <v-card>
        <v-card-title>{{ t('mh.peerRelay.linkDialogTitle') }}</v-card-title>
        <v-card-text>
          <p class="text-body-2 text-medium-emphasis mb-3">
            {{ t('mh.peerRelay.linkDialogHint') }}
          </p>
          <v-alert
            v-if="linkError"
            type="error"
            variant="tonal"
            density="compact"
            class="mb-3"
          >
            {{ linkError }}
          </v-alert>
          <v-select
            v-model="linkForm.relayA"
            :items="relaySelectItems"
            :label="t('mh.peerRelay.linkRouterA')"
            density="compact"
            variant="outlined"
            class="mb-2"
            data-testid="cross-zone-relay-a"
          />
          <v-text-field
            v-model="linkForm.endpointA"
            :label="t('mh.peerRelay.linkEndpointA')"
            placeholder="172.31.8.41:3478"
            density="compact"
            variant="outlined"
            class="mb-3"
            data-testid="cross-zone-endpoint-a"
          />
          <v-select
            v-model="linkForm.relayB"
            :items="relaySelectItems"
            :label="t('mh.peerRelay.linkRouterB')"
            density="compact"
            variant="outlined"
            class="mb-2"
            data-testid="cross-zone-relay-b"
          />
          <v-text-field
            v-model="linkForm.endpointB"
            :label="t('mh.peerRelay.linkEndpointB')"
            placeholder="10.42.2.114:3478"
            density="compact"
            variant="outlined"
            hide-details
            data-testid="cross-zone-endpoint-b"
          />
        </v-card-text>
        <v-card-actions>
          <v-spacer />
          <v-btn variant="text" :disabled="savingLink" @click="linkDialogOpen = false">
            {{ t('common.cancel') }}
          </v-btn>
          <v-btn
            color="primary"
            variant="flat"
            :loading="savingLink"
            data-testid="cross-zone-link-save"
            @click="saveBidirectionalLink"
          >
            {{ t('mh.peerRelay.linkSave') }}
          </v-btn>
        </v-card-actions>
      </v-card>
    </v-dialog>

    <PeerRelayPolicyDialog
      v-if="policyTarget"
      v-model="policyDialogOpen"
      :tenant-id="tenantId"
      :agent="policyTarget"
    />
  </v-card>
</template>

<script setup lang="ts">
import { computed, onMounted, reactive, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { useSnackbar } from '@/composables/useSnackbar'
import { deviceLabel } from '@/composables/useHideDeviceName'
import { useAgentStore, type Agent } from '@/stores/agents'
import { useDeviceStore } from '@/stores/devices'
import { useTenantStore } from '@/stores/tenant'
import { useNetworkZonesStore } from '@/stores/networkZones'
import { usePeerRelaysStore, type PeerRelayMode } from '@/stores/peerRelays'
import { formatDeviceZone } from '@/utils/deviceLocation'
import { canManageRelays } from '@/utils/permissions'
import PeerRelayPolicyDialog from './PeerRelayPolicyDialog.vue'

const props = defineProps<{ tenantId: string }>()

const { t } = useI18n()
const { showSuccess } = useSnackbar()
const store = usePeerRelaysStore()
const agentStore = useAgentStore()
const deviceStore = useDeviceStore()
const zonesStore = useNetworkZonesStore()
const tenantStore = useTenantStore()

const isAdmin = computed(() =>
  canManageRelays(tenantStore.myPermissions, tenantStore.isOwner),
)

const savingMode = ref(false)
const revokingId = ref<string | null>(null)
const actionError = ref('')

const pickerOpen = ref(false)
const pickedAgentId = ref('')
const policyDialogOpen = ref(false)
const policyTarget = ref<Agent | null>(null)

const modeItems = computed(() => [
  { title: t('mh.peerRelay.modeOff'), value: 'off' as PeerRelayMode },
  { title: t('mh.peerRelay.modeWarn'), value: 'warn' as PeerRelayMode },
  { title: t('mh.peerRelay.modeOn'), value: 'on' as PeerRelayMode },
  { title: t('mh.peerRelay.modeAuto'), value: 'auto' as PeerRelayMode },
])

const agentById = computed(() => {
  const m = new Map<string, Agent>()
  for (const a of agentStore.agents) m.set(a.id, a)
  return m
})

const candidateAgents = computed(() => {
  const approved = new Set(store.relays.map((r) => r.id))
  return agentStore.agents.filter((a) => !approved.has(a.id))
})

const candidateItems = computed(() =>
  candidateAgents.value.map((a) => ({
    title: deviceLabel(a),
    value: a.id,
  })),
)

function relayDisplayName(agentId: string, fallback: string): string {
  const a = agentById.value.get(agentId)
  return a ? deviceLabel(a) : fallback
}

const deviceRowById = computed(() => {
  const m = new Map<string, (typeof deviceStore.items)[number]>()
  for (const d of deviceStore.items) m.set(d.id, d)
  return m
})

function relayZoneInfo(agentId: string) {
  const a = agentById.value.get(agentId)
  const row = deviceRowById.value.get(agentId)
  const zid =
    row?.effective_zone_id ||
    a?.effective_zone_id ||
    row?.pinned_zone_id ||
    a?.pinned_zone_id ||
    zonesStore.zones.find((z) => z.gateway_relay_ids.includes(agentId))?.id ||
    null
  const knownName = zonesStore.zoneById(zid)?.name ?? null
  return formatDeviceZone(row ?? (zid ? { effective_zone_id: zid } : null), a, knownName)
}

function sameZonePeerCount(agentId: string): number {
  const z = relayZoneInfo(agentId).zoneId
  if (!z) return 0
  return store.relays.filter((r) => r.id !== agentId && relayZoneInfo(r.id).zoneId === z).length
}

const linkDialogOpen = ref(false)
const savingLink = ref(false)
const linkError = ref('')
const linkForm = reactive({
  relayA: '',
  endpointA: '',
  relayB: '',
  endpointB: '',
})

const relaySelectItems = computed(() =>
  store.relays.map((r) => {
    const z = relayZoneInfo(r.id)
    const name = relayDisplayName(r.id, r.name)
    return {
      title: z.hasZone ? `${name} · ${z.badgeText}` : name,
      value: r.id,
    }
  }),
)

function validHostPort(raw: string): boolean {
  const s = raw.trim()
  if (!s || /\s/.test(s)) return false
  const m = s.match(/^(?:\[([0-9a-fA-F:]+)\]|([0-9]{1,3}(?:\.[0-9]{1,3}){3})):([0-9]{1,5})$/)
  if (!m) return false
  const port = Number(m[3])
  return Number.isInteger(port) && port >= 1 && port <= 65535
}

function openLinkDialog() {
  linkError.value = ''
  linkForm.relayA = store.relays[0]?.id ?? ''
  linkForm.relayB = store.relays[1]?.id ?? ''
  const existingAB = store.relays[0]?.approved_backbone_edges?.find(
    (e) => e.relay_agent_id === linkForm.relayB,
  )
  const existingBA = store.relays[1]?.approved_backbone_edges?.find(
    (e) => e.relay_agent_id === linkForm.relayA,
  )
  linkForm.endpointB = existingAB?.endpoint ?? ''
  linkForm.endpointA = existingBA?.endpoint ?? ''
  linkDialogOpen.value = true
}

async function saveBidirectionalLink() {
  linkError.value = ''
  const a = store.relays.find((r) => r.id === linkForm.relayA)
  const b = store.relays.find((r) => r.id === linkForm.relayB)
  const epA = linkForm.endpointA.trim()
  const epB = linkForm.endpointB.trim()
  if (!a || !b || a.id === b.id || !validHostPort(epA) || !validHostPort(epB)) {
    linkError.value = t('mh.peerRelay.backboneInvalid')
    return
  }
  savingLink.value = true
  try {
    const edgesA = [
      ...(a.approved_backbone_edges ?? []).filter((e) => e.relay_agent_id !== b.id),
      { relay_agent_id: b.id, endpoint: epB, cross_border: true },
    ]
    const edgesB = [
      ...(b.approved_backbone_edges ?? []).filter((e) => e.relay_agent_id !== a.id),
      { relay_agent_id: a.id, endpoint: epA, cross_border: true },
    ]
    await store.setDevicePolicy(props.tenantId, a.id, {
      serve: true,
      static_endpoints: [...a.static_endpoints],
      approved_backbone_edges: edgesA,
    })
    await store.setDevicePolicy(props.tenantId, b.id, {
      serve: true,
      static_endpoints: [...b.static_endpoints],
      approved_backbone_edges: edgesB,
    })
    await store.fetchSettings(props.tenantId)
    linkDialogOpen.value = false
    showSuccess(
      t('mh.peerRelay.linkSaved', {
        a: relayDisplayName(a.id, a.name),
        b: relayDisplayName(b.id, b.name),
      }),
    )
  } catch (e) {
    linkError.value = e instanceof Error ? e.message : t('mh.peerRelay.saveFailed')
  } finally {
    savingLink.value = false
  }
}

async function onModeChange(next: PeerRelayMode | null) {
  if (!next || next === store.mode) return
  savingMode.value = true
  actionError.value = ''
  try {
    await store.setMode(props.tenantId, next)
    showSuccess(t('mh.peerRelay.modeSaved'))
  } catch (e) {
    actionError.value = e instanceof Error ? e.message : t('mh.peerRelay.saveFailed')
  } finally {
    savingMode.value = false
  }
}

function openPicker() {
  pickedAgentId.value = candidateAgents.value[0]?.id ?? ''
  pickerOpen.value = true
}

function confirmPick() {
  const a = agentById.value.get(pickedAgentId.value)
  pickerOpen.value = false
  if (a) {
    editRelay({
      ...a,
      peer_relay_policy: { serve: true, static_endpoints: [], approved_backbone_edges: [] },
    })
  }
}

function editRelay(a: Agent) {
  policyTarget.value = a
  policyDialogOpen.value = true
}

async function revokeRelay(agentId: string, fallbackName: string) {
  revokingId.value = agentId
  actionError.value = ''
  try {
    await store.setDevicePolicy(props.tenantId, agentId, {
      serve: false,
      static_endpoints: [],
      approved_backbone_edges: [],
    })
    const idx = agentStore.agents.findIndex((a) => a.id === agentId)
    if (idx !== -1) {
      agentStore.agents[idx]!.peer_relay_policy = {
        serve: false,
        static_endpoints: [],
        approved_backbone_edges: [],
      }
    }
    showSuccess(t('mh.peerRelay.savedDisabled', { name: relayDisplayName(agentId, fallbackName) }))
  } catch (e) {
    actionError.value = e instanceof Error ? e.message : t('mh.peerRelay.saveFailed')
  } finally {
    revokingId.value = null
  }
}

onMounted(() => {
  void store.fetchSettings(props.tenantId)
})

watch(
  () => props.tenantId,
  (tid) => {
    if (tid) void store.fetchSettings(tid)
  },
)
</script>
