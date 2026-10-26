<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 G ROX EOOD -->
<template>
  <v-card>
    <!-- The caption lives in a wrapping subtitle: inside the title (which
         never wraps) its one long line pushed Refresh and New rule past the
         card's edge below ~800 px — no rule could be created on a phone. -->
    <v-card-title class="d-flex align-center flex-wrap ga-2">
      <span>Overlay ACL</span>
      <v-spacer />
      <v-btn
        prepend-icon="mdi-refresh"
        variant="text"
        size="small"
        class="d-none d-sm-inline-flex"
        :loading="store.loading"
        @click="refresh"
      >
        Refresh
      </v-btn>
      <v-btn
        icon="mdi-refresh"
        variant="text"
        size="small"
        class="d-sm-none"
        aria-label="Refresh"
        :loading="store.loading"
        @click="refresh"
      />
      <v-btn
        prepend-icon="mdi-plus"
        color="primary"
        variant="flat"
        size="small"
        @click="openCreate"
      >
        New rule
      </v-btn>
    </v-card-title>
    <v-card-subtitle class="text-wrap pb-2">
      Peer visibility + routes — enforced on direct, TURN-relayed and
      DERP-relayed paths alike
    </v-card-subtitle>

    <v-card-text>
      <v-alert
        v-if="store.error"
        type="error"
        variant="tonal"
        closable
        class="mb-4"
        @click:close="store.error = null"
      >
        {{ store.error }}
      </v-alert>

      <!-- Posture. The whole feature is inert until this leaves `off`, so it
           leads rather than hiding in a settings corner. -->
      <div class="d-flex align-center flex-wrap ga-3 mb-4">
        <v-select
          :model-value="store.mode"
          :items="modeItems"
          label="Enforcement"
          variant="outlined"
          density="compact"
          hide-details
          style="max-width: 260px"
          :loading="modeSaving"
          @update:model-value="changeMode"
        />
        <span class="text-caption text-medium-emphasis" style="flex: 1 1 320px">
          {{ modeHint }}
        </span>
      </div>

      <v-alert
        v-if="store.mode === 'warn' && narrowedRules > 0"
        type="info"
        variant="tonal"
        density="compact"
        class="mb-4"
      >
        {{ narrowedRules }} rule(s) narrow ports or protocol. Each node enforces
        those on the traffic it receives only under <code>enforce</code>; in
        <code>warn</code> they are <strong>not checked</strong>. Either way a
        port-narrowed rule makes the whole peer visible.
      </v-alert>

      <p v-if="!store.loading && store.policies.length === 0" class="text-medium-emphasis">
        No overlay rules yet. While enforcement is <code>off</code> every node
        sees every peer and all of its approved routes — the pre-ACL behaviour.
        Add rules, switch to <code>warn</code> to see what they would deny
        against real traffic, then <code>enforce</code>.
      </p>

      <div v-if="store.loading && store.policies.length === 0" class="d-flex justify-center pa-8">
        <v-progress-circular indeterminate />
      </div>

      <!-- A card per rule below 600 px (table-stack-xs): the destinations and
           the edit/delete actions were off-screen to the right on a phone. -->
      <v-table v-else-if="store.policies.length > 0" density="compact" class="table-stack-xs">
        <thead>
          <tr>
            <th>Name</th>
            <th>Sources</th>
            <th>Via</th>
            <th>Destinations</th>
            <th class="text-right">Actions</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="p in store.policies" :key="p.id">
            <td data-label="Name">
              <div class="font-weight-medium">
                {{ p.name }}
                <v-chip v-if="!p.enabled" size="x-small" variant="tonal" class="ml-1">
                  disabled
                </v-chip>
              </div>
            </td>
            <td data-label="Sources">
              <v-chip
                v-for="(s, i) in p.sources"
                :key="`s-${i}`"
                size="x-small"
                variant="tonal"
                class="mr-1 mb-1"
              >
                {{ selectorLabel(s) }}
              </v-chip>
            </td>
            <td data-label="Via">
              <v-chip
                v-for="(t, i) in p.via"
                :key="`t-${i}`"
                size="x-small"
                variant="tonal"
                class="mr-1 mb-1"
              >
                {{ targetLabel(t) }}
              </v-chip>
            </td>
            <td data-label="Destinations">
              <div v-for="(d, i) in p.destinations" :key="`d-${i}`" class="text-caption">
                <code class="text-break">{{ d.cidr }}:{{ portLabel(d.port_range) }}</code>
                <span class="text-medium-emphasis">/{{ d.proto }}</span>
              </div>
            </td>
            <td class="text-right">
              <v-btn icon="mdi-pencil" size="small" variant="text" @click="openEdit(p)" />
              <v-btn
                icon="mdi-delete"
                size="small"
                variant="text"
                color="error"
                @click="confirmDelete(p)"
              />
            </td>
          </tr>
        </tbody>
      </v-table>
    </v-card-text>

    <!-- Create / edit ─────────────────────────────────────────────── -->
    <v-dialog v-model="editDialog" max-width="900" persistent scrollable :fullscreen="fullscreen">
      <v-card>
        <v-card-title>{{ editingId ? 'Edit overlay rule' : 'New overlay rule' }}</v-card-title>
        <v-card-text>
          <v-alert
            v-if="formError"
            type="error"
            variant="tonal"
            closable
            class="mb-4"
            @click:close="formError = null"
          >
            {{ formError }}
          </v-alert>

          <div class="d-flex align-center ga-3 mb-4">
            <v-text-field
              v-model="form.name"
              label="Name"
              placeholder="e.g. devs-reach-k8s-dev"
              variant="outlined"
              density="compact"
              hide-details
              style="flex: 1"
            />
            <v-switch
              v-model="form.enabled"
              label="Enabled"
              color="primary"
              density="compact"
              hide-details
            />
          </div>

          <!-- Sources -->
          <div class="d-flex align-center flex-wrap ga-1 mb-2">
            <strong>Sources</strong>
            <span class="text-medium-emphasis text-caption ml-2">
              Which nodes this rule grants access FROM.
            </span>
            <v-spacer />
            <v-btn size="x-small" variant="tonal" prepend-icon="mdi-plus" @click="addSource">
              Add source
            </v-btn>
          </div>
          <div
            v-for="(s, i) in form.sources"
            :key="`fs-${i}`"
            class="d-flex align-center flex-wrap mb-2 ga-2"
          >
            <v-select
              :model-value="s.kind"
              :items="sourceKinds"
              variant="outlined"
              density="compact"
              hide-details
              style="max-width: 200px"
              @update:model-value="(k) => setSourceKind(i, k)"
            />
            <v-select
              v-if="s.kind === 'node_id'"
              v-model="s.id"
              :items="nodeItems"
              label="Node"
              variant="outlined"
              density="compact"
              hide-details
              style="flex: 1 1 240px"
            />
            <v-select
              v-else-if="s.kind === 'role_id'"
              v-model="s.id"
              :items="roleItems"
              label="Role"
              variant="outlined"
              density="compact"
              hide-details
              style="flex: 1 1 240px"
            />
            <v-select
              v-else-if="s.kind === 'user_id'"
              v-model="s.id"
              :items="memberItems"
              label="User"
              variant="outlined"
              density="compact"
              hide-details
              style="flex: 1 1 240px"
            />
            <span v-else class="text-medium-emphasis text-caption">
              (every node in the tenant)
            </span>
            <v-btn icon="mdi-close" size="x-small" variant="text" @click="form.sources.splice(i, 1)" />
          </div>

          <v-divider class="my-4" />

          <!-- Via -->
          <div class="d-flex align-center flex-wrap ga-1 mb-2">
            <strong>Via</strong>
            <span class="text-medium-emphasis text-caption ml-2">
              The peer they may reach — and the gateway for its subnet routes.
            </span>
            <v-spacer />
            <v-btn size="x-small" variant="tonal" prepend-icon="mdi-plus" @click="addVia">
              Add node
            </v-btn>
          </div>
          <div
            v-for="(t, i) in form.via"
            :key="`fv-${i}`"
            class="d-flex align-center flex-wrap mb-2 ga-2"
          >
            <v-select
              :model-value="t.kind"
              :items="viaKinds"
              variant="outlined"
              density="compact"
              hide-details
              style="max-width: 200px"
              @update:model-value="(k) => setViaKind(i, k)"
            />
            <v-select
              v-if="t.kind === 'node_id'"
              v-model="t.id"
              :items="nodeItems"
              label="Node"
              variant="outlined"
              density="compact"
              hide-details
              style="flex: 1 1 240px"
            />
            <span v-else class="text-medium-emphasis text-caption">
              (every node in the tenant)
            </span>
            <v-btn icon="mdi-close" size="x-small" variant="text" @click="form.via.splice(i, 1)" />
          </div>

          <v-divider class="my-4" />

          <!-- Destinations -->
          <div class="d-flex align-center flex-wrap ga-1 mb-2">
            <strong>Destinations</strong>
            <span class="text-medium-emphasis text-caption ml-2">
              CIDRs only — the overlay is L3, so hostnames can never match.
            </span>
            <v-spacer />
            <v-btn size="x-small" variant="tonal" prepend-icon="mdi-plus" @click="addDest">
              Add CIDR
            </v-btn>
          </div>
          <div
            v-for="(d, i) in form.destinations"
            :key="`fd-${i}`"
            class="d-flex align-center flex-wrap mb-2 ga-2"
          >
            <v-text-field
              v-model="d.cidr"
              label="CIDR (e.g. 10.84.6.0/24)"
              variant="outlined"
              density="compact"
              hide-details
              style="flex: 1 1 220px"
            />
            <v-text-field
              v-model.number="d.port_range.low"
              label="Port (low)"
              type="number"
              variant="outlined"
              density="compact"
              hide-details
              style="max-width: 120px"
            />
            <v-text-field
              v-model.number="d.port_range.high"
              label="Port (high)"
              type="number"
              variant="outlined"
              density="compact"
              hide-details
              style="max-width: 120px"
            />
            <v-select
              v-model="d.proto"
              :items="protoKinds"
              label="Proto"
              variant="outlined"
              density="compact"
              hide-details
              style="max-width: 120px"
            />
            <v-btn
              icon="mdi-close"
              size="x-small"
              variant="text"
              @click="form.destinations.splice(i, 1)"
            />
          </div>
        </v-card-text>
        <v-card-actions>
          <v-spacer />
          <v-btn @click="editDialog = false">Cancel</v-btn>
          <v-btn color="primary" :loading="saving" @click="save">
            {{ editingId ? 'Save changes' : 'Create rule' }}
          </v-btn>
        </v-card-actions>
      </v-card>
    </v-dialog>

    <!-- Delete confirm ────────────────────────────────────────────── -->
    <v-dialog v-model="deleteDialog" max-width="500">
      <v-card>
        <v-card-title>Delete overlay rule?</v-card-title>
        <v-card-text>
          <strong>{{ deleteTarget?.name }}</strong> will be removed. If this was
          the only rule granting a peer, nodes relying on it lose that peer on
          the next netmap push.
        </v-card-text>
        <v-card-actions>
          <v-spacer />
          <v-btn @click="deleteDialog = false">Cancel</v-btn>
          <v-btn color="error" :loading="deleting" @click="doDelete">Delete</v-btn>
        </v-card-actions>
      </v-card>
    </v-dialog>
  </v-card>
</template>

<script setup lang="ts">
import { computed, reactive, ref } from 'vue'
import {
  useOverlayAclStore,
  type OverlayAclMode,
  type OverlayPolicy,
  type OverlayRule,
  type OverlaySelector,
  type OverlayTarget,
} from '@/stores/overlayAcl'
import { useOverlayRoutesStore } from '@/stores/overlayRoutes'
import { useNodeLabel } from '@/composables/useNodeLabel'
import { useResponsiveDialog } from '@/composables/useResponsiveDialog'
import { useRoleStore } from '@/stores/role'
import { useMembersStore, type Member } from '@/stores/members'

const props = defineProps<{ tenantId: string }>()
const store = useOverlayAclStore()
const nodesStore = useOverlayRoutesStore()
const roleStore = useRoleStore()
const membersStore = useMembersStore()

const modeItems = [
  { title: 'Off — no enforcement (default)', value: 'off' },
  { title: 'Warn — log what would be denied', value: 'warn' },
  { title: 'Enforce — apply the rules', value: 'enforce' },
]
const sourceKinds = [
  { title: 'All nodes', value: 'all_nodes' },
  { title: 'Node', value: 'node_id' },
  { title: 'User', value: 'user_id' },
  { title: 'Role', value: 'role_id' },
]
const viaKinds = [
  { title: 'All nodes', value: 'all_nodes' },
  { title: 'Node', value: 'node_id' },
]
const protoKinds = [
  { title: 'Any', value: 'any' },
  { title: 'TCP', value: 'tcp' },
  { title: 'UDP', value: 'udp' },
]

// Pickers over what the existing stores already expose — never hand-typed
// ObjectIds (the tunnel-policy form's worst trait).
// Nodes by their device's name (FR-116), the DNS label only for a node
// whose device is not known here.
const { nodeLabel, ensureLoaded } = useNodeLabel()
const { fullscreen } = useResponsiveDialog()
const nodeItems = computed(() =>
  nodesStore.nodes.map((n) => ({
    title: `${nodeLabel(n) || '(unnamed)'} — ${n.overlay_ip}`,
    value: n.id,
  })),
)
const roleItems = computed(() =>
  roleStore.roles.map((r) => ({ title: r.name, value: r.id })),
)
// The members store exposes its rows as `items` (not `members`) and is
// page-1-only (25 rows) — fine for a small tenant, but a larger one needs a
// search endpoint before this picker is complete.
const memberItems = computed(() =>
  membersStore.items.map((m: Member) => ({
    title: m.display_name || m.nickname || m.user_id,
    value: m.user_id,
  })),
)

const modeHint = computed(() => {
  switch (store.mode) {
    case 'off':
      return 'Rules are stored but ignored — every node sees every peer, as before.'
    case 'warn':
      return 'Rules are evaluated and denials are logged, but the permissive netmap still ships. Use this to validate rules against real traffic.'
    default:
      return 'Rules are applied. A node that no rule grants loses the peer, and an installed peer is explicitly torn down.'
  }
})

const narrowedRules = computed(() =>
  store.policies
    .flatMap((p) => p.destinations)
    .filter((d) => d.proto !== 'any' || d.port_range.low !== 1 || d.port_range.high !== 65535)
    .length,
)

const modeSaving = ref(false)
async function changeMode(next: OverlayAclMode | null) {
  if (!next) return
  modeSaving.value = true
  try {
    await store.setMode(props.tenantId, next)
  } catch (e) {
    store.error = (e as Error).message
  } finally {
    modeSaving.value = false
  }
}

const editDialog = ref(false)
const editingId = ref<string | null>(null)
const saving = ref(false)
const formError = ref<string | null>(null)

function emptyForm() {
  return {
    name: '',
    enabled: true,
    sources: [{ kind: 'all_nodes' } as OverlaySelector],
    via: [{ kind: 'all_nodes' } as OverlayTarget],
    destinations: [
      { cidr: '', port_range: { low: 1, high: 65535 }, proto: 'any' } as OverlayRule,
    ],
  }
}
const form = reactive(emptyForm())

function openCreate() {
  editingId.value = null
  formError.value = null
  Object.assign(form, emptyForm())
  editDialog.value = true
}

function openEdit(p: OverlayPolicy) {
  editingId.value = p.id
  formError.value = null
  form.name = p.name
  form.enabled = p.enabled
  form.sources = p.sources.map((s) => ({ ...s }))
  form.via = p.via.map((t) => ({ ...t }))
  form.destinations = p.destinations.map((d) => ({
    ...d,
    port_range: { ...d.port_range },
  }))
  editDialog.value = true
}

function addSource() {
  form.sources.push({ kind: 'node_id', id: '' } as OverlaySelector)
}
function setSourceKind(i: number, kind: string) {
  form.sources[i] =
    kind === 'all_nodes'
      ? ({ kind: 'all_nodes' } as OverlaySelector)
      : ({ kind, id: '' } as OverlaySelector)
}
function addVia() {
  form.via.push({ kind: 'node_id', id: '' } as OverlayTarget)
}
function setViaKind(i: number, kind: string) {
  form.via[i] =
    kind === 'all_nodes'
      ? ({ kind: 'all_nodes' } as OverlayTarget)
      : ({ kind: 'node_id', id: '' } as OverlayTarget)
}
function addDest() {
  form.destinations.push({
    cidr: '',
    port_range: { low: 1, high: 65535 },
    proto: 'any',
  })
}

function validate(): string | null {
  if (!form.name.trim()) return 'Name is required.'
  if (!form.sources.length) return 'At least one source is required.'
  if (!form.via.length) return 'At least one via node is required.'
  if (!form.destinations.length) return 'At least one destination is required.'
  for (const s of form.sources) {
    if (s.kind !== 'all_nodes' && !s.id) return 'Every non-catch-all source needs a selection.'
  }
  for (const t of form.via) {
    if (t.kind === 'node_id' && !t.id) return 'Every node target needs a selection.'
  }
  for (const d of form.destinations) {
    if (!d.cidr.trim()) return 'Every destination needs a CIDR.'
    // Mirrors the server check: a bare address never matches, which is the
    // single most common way to author a silently-dead rule.
    if (!/^[0-9a-fA-F:.]+\/\d{1,3}$/.test(d.cidr.trim())) {
      return `"${d.cidr}" is not a CIDR — a single address needs a prefix, e.g. 10.0.0.5/32.`
    }
    if (!d.port_range.low || d.port_range.high < d.port_range.low) {
      return `"${d.cidr}" has an invalid port range.`
    }
  }
  return null
}

async function save() {
  const err = validate()
  if (err) {
    formError.value = err
    return
  }
  saving.value = true
  formError.value = null
  try {
    const payload = {
      name: form.name.trim(),
      enabled: form.enabled,
      sources: form.sources,
      via: form.via,
      destinations: form.destinations,
    }
    if (editingId.value) await store.updatePolicy(props.tenantId, editingId.value, payload)
    else await store.createPolicy(props.tenantId, payload)
    editDialog.value = false
  } catch (e) {
    formError.value = (e as Error).message
  } finally {
    saving.value = false
  }
}

const deleteDialog = ref(false)
const deleteTarget = ref<OverlayPolicy | null>(null)
const deleting = ref(false)

function confirmDelete(p: OverlayPolicy) {
  deleteTarget.value = p
  deleteDialog.value = true
}
async function doDelete() {
  if (!deleteTarget.value) return
  deleting.value = true
  try {
    await store.deletePolicy(props.tenantId, deleteTarget.value.id)
    deleteDialog.value = false
    deleteTarget.value = null
  } catch (e) {
    store.error = (e as Error).message
  } finally {
    deleting.value = false
  }
}

function selectorLabel(s: OverlaySelector): string {
  if (s.kind === 'all_nodes') return 'All nodes'
  if (s.kind === 'node_id') return nodeItems.value.find((n) => n.value === s.id)?.title ?? 'Node'
  if (s.kind === 'role_id') return roleItems.value.find((r) => r.value === s.id)?.title ?? 'Role'
  return memberItems.value.find((m) => m.value === s.id)?.title ?? 'User'
}
function targetLabel(t: OverlayTarget): string {
  if (t.kind === 'all_nodes') return 'All nodes'
  return nodeItems.value.find((n) => n.value === t.id)?.title ?? 'Node'
}
function portLabel(r: { low: number; high: number }): string {
  if (r.low === 1 && r.high === 65535) return 'any'
  return r.low === r.high ? `${r.low}` : `${r.low}-${r.high}`
}

async function refresh() {
  ensureLoaded(props.tenantId, { tunnels: true })
  await Promise.all([
    store.fetchPolicies(props.tenantId),
    nodesStore.fetchNodes(props.tenantId),
    roleStore.fetchRoles(props.tenantId),
    membersStore.fetchMembers(props.tenantId),
  ])
}

refresh()
</script>
