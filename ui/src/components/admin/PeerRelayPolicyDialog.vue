<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 G ROX EOOD -->
<template>
  <v-dialog v-model="open" max-width="680" scrollable :fullscreen="fullscreen">
    <v-card>
      <v-card-title class="d-flex align-center">
        <v-icon icon="mdi-swap-horizontal-circle-outline" color="primary" class="mr-2" />
        <span class="text-truncate" style="min-width: 0">
          {{ t('mh.peerRelay.dialogTitle', { name: deviceLabel(agent) }) }}
        </span>
      </v-card-title>

      <v-card-text>
        <v-alert
          type="info"
          variant="tonal"
          density="compact"
          class="mb-4"
          icon="mdi-lightning-bolt-outline"
          data-testid="peer-relay-auto-activate-info"
        >
          {{ t('mh.peerRelay.autoActivateInfo') }}
        </v-alert>

        <v-switch
          v-model="serve"
          color="primary"
          density="compact"
          hide-details
          :label="t('mh.peerRelay.serveSwitch')"
          data-testid="peer-relay-serve-switch"
        />

        <v-expand-transition>
          <div v-if="serve" class="mt-4">
            <div class="text-subtitle-2 mb-1">{{ t('mh.peerRelay.staticTitle') }}</div>
            <div class="text-caption text-medium-emphasis mb-2">
              {{ t('mh.peerRelay.staticHint') }}
            </div>
            <div v-if="staticEndpoints.length" class="d-flex flex-wrap ga-2 mb-2">
              <v-chip
                v-for="ep in staticEndpoints"
                :key="ep"
                closable
                size="small"
                variant="tonal"
                color="primary"
                class="text-mono"
                @click:close="removeStaticEndpoint(ep)"
              >
                {{ ep }}
              </v-chip>
            </div>
            <v-text-field
              v-model="staticInput"
              :label="t('mh.peerRelay.staticAdd')"
              :placeholder="t('mh.peerRelay.staticPlaceholder')"
              density="compact"
              variant="outlined"
              :error-messages="staticError ? [staticError] : []"
              append-inner-icon="mdi-plus"
              @click:append-inner="addStaticEndpoint"
              @keyup.enter="addStaticEndpoint"
            />

            <v-divider class="my-4" />

            <div class="text-subtitle-2 mb-1">{{ t('mh.peerRelay.backboneTitle') }}</div>
            <div class="text-caption text-medium-emphasis mb-3">
              {{ t('mh.peerRelay.backboneHint') }}
            </div>

            <div v-if="backboneEdges.length" class="d-flex flex-column ga-2 mb-3">
              <v-sheet
                v-for="edge in backboneEdges"
                :key="edge.relay_agent_id"
                border
                rounded
                class="d-flex align-center flex-wrap ga-2 px-3 py-2"
              >
                <span class="font-weight-medium text-body-2">{{ relayName(edge.relay_agent_id) }}</span>
                <span class="text-mono text-caption text-medium-emphasis">{{ edge.endpoint }}</span>
                <v-chip
                  v-if="edge.cross_border"
                  size="x-small"
                  color="warning"
                  variant="tonal"
                >
                  {{ t('mh.peerRelay.crossBorderTag') }}
                </v-chip>
                <v-spacer />
                <v-btn
                  icon="mdi-close"
                  size="x-small"
                  variant="text"
                  @click="removeBackboneEdge(edge.relay_agent_id)"
                />
              </v-sheet>
            </div>

            <div v-if="otherRelayOptions.length === 0" class="text-caption text-medium-emphasis">
              {{ t('mh.peerRelay.backboneNoOtherRelays') }}
            </div>
            <div v-else-if="backboneEdges.length < MAX_PEER_RELAY_BACKBONE_EDGES" class="d-flex flex-wrap align-center ga-2">
              <v-select
                v-model="edgeTargetId"
                :items="otherRelayOptions"
                :label="t('mh.peerRelay.backboneTarget')"
                density="compact"
                variant="outlined"
                hide-details
                style="min-width: 190px; flex: 1 1 190px"
              />
              <v-text-field
                v-model="edgeEndpoint"
                :label="t('mh.peerRelay.backboneEndpoint')"
                placeholder="10.20.0.2:3478"
                density="compact"
                variant="outlined"
                hide-details
                style="min-width: 180px; flex: 1 1 180px"
                @keyup.enter="addBackboneEdge"
              />
              <v-checkbox
                v-model="edgeCrossBorder"
                :label="t('mh.peerRelay.backboneCrossBorder')"
                density="compact"
                hide-details
              />
              <v-btn size="small" variant="tonal" color="primary" prepend-icon="mdi-plus" @click="addBackboneEdge">
                {{ t('mh.peerRelay.backboneAdd') }}
              </v-btn>
            </div>
            <div v-if="backboneError" class="text-caption text-error mt-1">
              {{ backboneError }}
            </div>
          </div>
        </v-expand-transition>

        <v-alert v-if="error" type="error" variant="tonal" density="compact" class="mt-4">
          {{ error }}
        </v-alert>
      </v-card-text>

      <v-card-actions>
        <v-spacer />
        <v-btn variant="text" @click="close">{{ t('common.cancel') }}</v-btn>
        <v-btn
          color="primary"
          variant="flat"
          :loading="saving"
          data-testid="peer-relay-save"
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
import { useTenantStore } from '@/stores/tenant'
import { canManageRelays } from '@/utils/permissions'
import {
  MAX_PEER_RELAY_BACKBONE_EDGES,
  usePeerRelaysStore,
  type PeerRelayBackboneEdge,
} from '@/stores/peerRelays'

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
const { showSuccess } = useSnackbar()
const peerRelayStore = usePeerRelaysStore()
const agentStore = useAgentStore()
const tenantStore = useTenantStore()
const isAdmin = computed(() =>
  canManageRelays(tenantStore.myPermissions, tenantStore.isOwner),
)

const open = computed({
  get: () => props.modelValue,
  set: (v) => emit('update:modelValue', v),
})

const serve = ref(false)
const staticEndpoints = ref<string[]>([])
const backboneEdges = ref<PeerRelayBackboneEdge[]>([])
const staticInput = ref('')
const staticError = ref('')
const edgeTargetId = ref('')
const edgeEndpoint = ref('')
const edgeCrossBorder = ref(false)
const backboneError = ref('')
const saving = ref(false)
const error = ref('')

function isValidSocketLiteral(raw: string): boolean {
  const s = raw.trim()
  const v4 = /^(\d{1,3}\.){3}\d{1,3}:(\d{1,5})$/.exec(s)
  if (v4) {
    const [host, portStr] = s.split(':')
    const port = Number(portStr)
    if (port < 1 || port > 65535) return false
    return host!.split('.').every((o) => Number(o) >= 0 && Number(o) <= 255)
  }
  const v6 = /^\[([0-9a-fA-F:]+)\]:(\d{1,5})$/.exec(s)
  if (v6) {
    const port = Number(v6[2])
    return port >= 1 && port <= 65535
  }
  return false
}

const otherRelayOptions = computed(() => {
  const used = new Set(backboneEdges.value.map((e) => e.relay_agent_id))
  return peerRelayStore.relays
    .filter((r) => r.id !== props.agent.id && !used.has(r.id))
    .map((r) => {
      const full = agentStore.agents.find((a) => a.id === r.id)
      return {
        title: full ? deviceLabel(full) : r.name,
        value: r.id,
      }
    })
})

function relayName(agentId: string): string {
  const full = agentStore.agents.find((a) => a.id === agentId)
  if (full) return deviceLabel(full)
  return peerRelayStore.relays.find((r) => r.id === agentId)?.name ?? agentId.slice(0, 8)
}

watch(
  [() => props.modelValue, () => props.agent.id],
  ([v]) => {
    if (!v) return
    error.value = ''
    staticError.value = ''
    backboneError.value = ''
    staticInput.value = ''
    edgeTargetId.value = ''
    edgeEndpoint.value = ''
    edgeCrossBorder.value = false

    const existing = peerRelayStore.relayForAgent(props.agent.id)
    const fallback = props.agent.peer_relay_policy
    serve.value = existing ? true : fallback?.serve === true
    staticEndpoints.value = [...(existing?.static_endpoints ?? fallback?.static_endpoints ?? [])]
    backboneEdges.value = (
      existing?.approved_backbone_edges ??
      fallback?.approved_backbone_edges ??
      []
    ).map((e) => ({ ...e }))
  },
  { immediate: true },
)

function addStaticEndpoint() {
  const val = staticInput.value.trim()
  if (!isValidSocketLiteral(val)) {
    staticError.value = t('mh.peerRelay.staticInvalid')
    return
  }
  if (!staticEndpoints.value.includes(val)) {
    staticEndpoints.value.push(val)
  }
  staticInput.value = ''
  staticError.value = ''
}

function removeStaticEndpoint(ep: string) {
  staticEndpoints.value = staticEndpoints.value.filter((x) => x !== ep)
}

function addBackboneEdge() {
  const ep = edgeEndpoint.value.trim()
  if (
    !edgeTargetId.value ||
    edgeTargetId.value === props.agent.id ||
    !isValidSocketLiteral(ep)
  ) {
    backboneError.value = t('mh.peerRelay.backboneInvalid')
    return
  }
  backboneEdges.value.push({
    relay_agent_id: edgeTargetId.value,
    endpoint: ep,
    ...(edgeCrossBorder.value ? { cross_border: true } : {}),
  })
  edgeTargetId.value = ''
  edgeEndpoint.value = ''
  edgeCrossBorder.value = false
  backboneError.value = ''
}

function removeBackboneEdge(relayAgentId: string) {
  backboneEdges.value = backboneEdges.value.filter((e) => e.relay_agent_id !== relayAgentId)
}

async function save() {
  if (!isAdmin.value) {
    error.value = t('mh.peerRelay.saveFailed')
    return
  }
  saving.value = true
  error.value = ''
  try {
    // Allow unadded text in staticInput to be validated/included on Save if non-empty
    if (serve.value && staticInput.value.trim()) {
      addStaticEndpoint()
      if (staticError.value) {
        saving.value = false
        return
      }
    }
    const policy = serve.value
      ? {
          serve: true,
          static_endpoints: staticEndpoints.value,
          approved_backbone_edges: backboneEdges.value,
        }
      : {
          serve: false,
          static_endpoints: [],
          approved_backbone_edges: [],
        }
    await peerRelayStore.setDevicePolicy(props.tenantId, props.agent.id, policy)
    const idx = agentStore.agents.findIndex((a) => a.id === props.agent.id)
    if (idx !== -1) {
      agentStore.agents[idx]!.peer_relay_policy = policy
    }
    const name = deviceLabel(props.agent)
    showSuccess(
      serve.value
        ? t('mh.peerRelay.savedEnabled', { name })
        : t('mh.peerRelay.savedDisabled', { name }),
    )
    emit('saved')
    open.value = false
  } catch (e) {
    error.value = e instanceof Error ? e.message : t('mh.peerRelay.saveFailed')
  } finally {
    saving.value = false
  }
}

function close() {
  open.value = false
}
</script>
