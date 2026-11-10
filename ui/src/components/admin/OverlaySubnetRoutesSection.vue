<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 G ROX EOOD -->
<template>
  <v-card>
    <v-card-title class="d-flex align-center">
      <span>{{ $t('nav.subnetRoutes') }}</span>
      <v-chip
        v-if="nodeFilter"
        size="small"
        variant="tonal"
        closable
        class="ml-3"
        @click:close="clearNodeFilter"
      >
        {{ filteredNodeName ?? $t('mh.routes.deviceFilter') }}
      </v-chip>
      <v-spacer />
      <v-btn
        prepend-icon="mdi-refresh"
        variant="text"
        size="small"
        :loading="store.loading"
        @click="refresh"
      >
        {{ $t('common.refresh') }}
      </v-btn>
    </v-card-title>

    <v-card-text>
      <v-alert
        v-if="store.error"
        type="error"
        variant="tonal"
        closable
        @click:close="store.error = null"
        class="mb-4"
      >
        {{ store.error }}
      </v-alert>

      <p class="text-medium-emphasis mb-4">
        {{ $t('mh.routes.intro1') }}
        <code>overlay_advertised_routes</code>{{ $t('mh.routes.intro2') }}
      </p>

      <div
        v-if="store.loading && store.nodes.length === 0"
        class="d-flex justify-center pa-8"
      >
        <v-progress-circular indeterminate />
      </div>

      <p
        v-else-if="advertisingNodes.length === 0"
        class="text-medium-emphasis"
      >
        {{ $t('mh.routes.empty') }}
      </p>

      <!-- A card per node below 600 px (table-stack-xs): the exit-node switch
           and Save were ~300 px off-screen on a phone, so ticking a route
           changed nothing anyone could see. -->
      <v-table v-else density="compact" class="table-stack-xs">
        <thead>
          <tr>
            <th>{{ $t('mh.routes.col.node') }}</th>
            <th>{{ $t('mh.routes.col.ip') }}</th>
            <th>{{ $t('mh.routes.col.routes') }}</th>
            <th>{{ $t('mh.routes.col.exit') }}</th>
            <th class="text-right">{{ $t('mh.topo.col.actions') }}</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="n in advertisingNodes" :key="n.id">
            <td :data-label="$t('mh.routes.col.node')">
              <div class="font-weight-medium">
                {{ nodeLabel(n) || $t('mh.routes.unnamed') }}
                <v-chip
                  size="x-small"
                  :color="n.online ? 'success' : undefined"
                  variant="tonal"
                  class="ml-1"
                >
                  {{ n.online ? $t('mh.topo.online') : $t('mh.topo.offline') }}
                </v-chip>
                <v-chip
                  v-if="n.os"
                  size="x-small"
                  variant="outlined"
                  class="ml-1"
                >
                  {{ osLabel(n.os) }}
                </v-chip>
              </div>
              <div class="text-caption text-medium-emphasis">{{ n.kind }}</div>
            </td>
            <td :data-label="$t('mh.routes.col.ip')">
              <div>{{ n.overlay_ip }}</div>
              <div class="text-caption text-medium-emphasis">
                {{ deriveOverlayV6(n.overlay_ip) }}
              </div>
            </td>
            <td :data-label="$t('mh.routes.col.routes')">
              <span
                v-if="n.advertised_routes.length === 0"
                class="text-caption text-medium-emphasis"
              >
                —
              </span>
              <v-checkbox
                v-for="cidr in n.advertised_routes"
                :key="cidr"
                :label="cidr"
                :model-value="draft[n.id]?.has(cidr) ?? false"
                density="compact"
                hide-details
                @update:model-value="(v) => toggle(n.id, cidr, v)"
              />
            </td>
            <td :data-label="$t('mh.routes.col.exit')">
              <v-switch
                :model-value="n.is_exit_node"
                :disabled="(!n.can_be_exit_node && !n.is_exit_node) || exitSaving === n.id"
                :loading="exitSaving === n.id"
                color="warning"
                density="compact"
                hide-details
                :label="n.is_exit_node ? $t('mh.routes.col.exit') : (n.can_be_exit_node ? $t('mh.topo.off') : $t('mh.routes.na'))"
                @update:model-value="(v) => toggleExitNode(n, v)"
              />
              <div
                v-if="n.route_offer_withheld"
                class="text-caption text-warning"
              >
                {{ $t('mh.routes.withheld', { why: n.route_offer_withheld }) }}
              </div>
              <div
                v-else-if="n.is_exit_node && !n.can_be_exit_node"
                class="text-caption text-medium-emphasis"
              >
                {{ $t('mh.routes.noLongerOffered') }}
              </div>
              <div
                v-else-if="!n.can_be_exit_node"
                class="text-caption text-medium-emphasis"
              >
                {{ $t('mh.routes.enableHint') }}
              </div>
            </td>
            <td class="text-right">
              <v-btn
                color="primary"
                variant="flat"
                size="small"
                :loading="saving === n.id"
                :disabled="!dirty(n)"
                @click="save(n)"
              >
                {{ $t('common.save') }}
              </v-btn>
            </td>
          </tr>
        </tbody>
      </v-table>
    </v-card-text>
  </v-card>
</template>

<script setup lang="ts">
import { computed, reactive, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import {
  deriveOverlayV6,
  useOverlayRoutesStore,
  type OverlayNode,
} from '@/stores/overlayRoutes'
import { useNodeLabel } from '@/composables/useNodeLabel'

const props = defineProps<{ tenantId: string }>()
const store = useOverlayRoutesStore()

// nodeId → editable Set of approved CIDRs (seeded from the server state).
const draft = reactive<Record<string, Set<string>>>({})
const saving = ref<string | null>(null)
const exitSaving = ref<string | null>(null)

// `?node=<id>` deep link from a device row's action menu (2026-08-04):
// scope the grid to that one machine so it's obvious which device the
// routes belong to; the chip clears back to the full list.
const route = useRoute()
const router = useRouter()
const nodeFilter = computed(() => (route.query.node as string) || null)
// Nodes by their device's name, as the Devices row the deep link came from
// showed it (FR-116) — `node.name` is a lossy DNS label.
const { nodeLabel, ensureLoaded } = useNodeLabel()
const filteredNodeName = computed(() => {
  const n = store.nodes.find((x) => x.id === nodeFilter.value)
  return n ? nodeLabel(n) : null
})
function clearNodeFilter() {
  router.replace({ query: { ...route.query, node: undefined } })
}

// Show nodes advertising subnet routes OR eligible to be an exit node (a pure
// exit node advertises only 0.0.0.0/0, which the server filters out of
// advertised_routes — so key off can_be_exit_node too). FR-97 P0b — and a
// node that withheld its offer (it advertises nothing, so it would otherwise
// vanish with no word of why), and an approved exit whose device stopped
// offering, so the approval can still be seen and switched off.
const advertisingNodes = computed(() =>
  store.nodes.filter(
    (n) =>
      (n.advertised_routes.length > 0 ||
        n.can_be_exit_node ||
        n.is_exit_node ||
        !!n.route_offer_withheld) &&
      (!nodeFilter.value || n.id === nodeFilter.value),
  ),
)

// FR-97 P0b — the backing agent's OS, as the admin reads it.
function osLabel(os: 'linux' | 'macos' | 'windows'): string {
  return os === 'macos' ? 'macOS' : os === 'windows' ? 'Windows' : 'Linux'
}

function seedDraft() {
  for (const n of store.nodes) {
    draft[n.id] = new Set(n.approved_routes)
  }
}

watch(() => store.nodes, seedDraft, { immediate: true })

function toggle(nodeId: string, cidr: string, checked: boolean | null) {
  const set = draft[nodeId] ?? (draft[nodeId] = new Set<string>())
  if (checked) set.add(cidr)
  else set.delete(cidr)
}

function dirty(n: OverlayNode): boolean {
  const set = draft[n.id] ?? new Set<string>()
  if (set.size !== n.approved_routes.length) return true
  return n.approved_routes.some((r) => !set.has(r))
}

async function save(n: OverlayNode) {
  saving.value = n.id
  try {
    await store.setApprovedRoutes(
      props.tenantId,
      n.id,
      Array.from(draft[n.id] ?? []),
    )
  } finally {
    saving.value = null
  }
}

async function toggleExitNode(n: OverlayNode, enabled: boolean | null) {
  exitSaving.value = n.id
  try {
    await store.setExitNode(props.tenantId, n.id, enabled === true)
  } finally {
    exitSaving.value = null
  }
}

async function refresh() {
  ensureLoaded(props.tenantId, { tunnels: true })
  await store.fetchNodes(props.tenantId)
}

refresh()
</script>
