<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 G ROX EOOD -->
<template>
  <!-- MeshHarbor #20 — managed forwards. Every change is planned first (a dry
       run that stores nothing), and each forward shows v039's layers apart:
       desired, applied (the ingress node's own ack) and verified (its next
       inventory shows the forward in effect). -->
  <div>
    <p class="text-body-2 text-medium-emphasis mb-3">
      A managed forward listens on one address of an ingress node, admits only its source CIDRs and
      relays to a destination. Every change is checked first: port collisions, overlaps, loops, the
      regional gate and, for the nft backend, the ingress's forwarding settings, which MeshHarbor
      reports and never changes.
    </p>
    <div class="d-flex mb-3">
      <v-spacer />
      <v-btn color="primary" prepend-icon="mdi-plus" data-testid="mf-new" @click="openNew">New forward</v-btn>
    </div>
    <v-alert v-if="store.error" type="error" variant="tonal" class="mb-3" data-testid="mf-error">
      {{ store.error }}
    </v-alert>
    <v-alert v-if="notice" type="warning" variant="tonal" class="mb-3" closable data-testid="mf-notice" @click:close="notice = ''">
      {{ notice }}
    </v-alert>
    <v-progress-linear v-if="store.loading" indeterminate class="mb-2" />
    <p v-if="!store.loading && !store.error && store.items.length === 0" class="text-medium-emphasis" data-testid="mf-empty">
      No managed forward yet.
    </p>
    <v-table v-if="store.items.length" density="compact">
      <thead>
        <tr>
          <th>name</th>
          <th>ingress</th>
          <th>listen</th>
          <th>sources</th>
          <th>destination</th>
          <th>backend</th>
          <th>applied</th>
          <th>verified</th>
          <th>enabled</th>
          <th />
        </tr>
      </thead>
      <tbody>
        <tr v-for="f in store.items" :key="f.id" :data-testid="`mf-row-${f.id}`">
          <td>{{ f.spec.name }} <span class="text-caption text-medium-emphasis">r{{ f.revision }}</span></td>
          <td>{{ nameOf(f.spec.ingress_agent_id) }}</td>
          <td><code>{{ f.spec.proto }} {{ endpoint(f.spec.bind_addr, f.spec.port) }}</code></td>
          <td><code>{{ f.spec.sources.join(' ') }}</code></td>
          <td><code>{{ endpoint(f.spec.dest_addr, f.spec.dest_port) }}</code></td>
          <td>{{ f.spec.backend }} · {{ f.spec.nat === 'masquerade' ? 'masquerade' : 'source kept' }}</td>
          <td>
            <v-chip :color="appliedColor(f.status.applied)" size="x-small" label :title="f.status.error ?? ''">
              {{ f.status.applied.replace('_', ' ') }}
            </v-chip>
          </td>
          <td>
            <v-chip :color="verifiedColor(f.status.verified)" size="x-small" label>{{ f.status.verified }}</v-chip>
          </td>
          <td>
            <v-switch
              :model-value="f.spec.desired === 'enabled'"
              density="compact"
              hide-details
              color="primary"
              :disabled="busy === f.id"
              :data-testid="`mf-toggle-${f.id}`"
              @update:model-value="toggle(f, !!$event)"
            />
          </td>
          <td class="text-no-wrap">
            <v-btn icon="mdi-pencil" size="small" variant="text" :data-testid="`mf-edit-${f.id}`" @click="openEdit(f)" />
            <v-btn icon="mdi-delete" size="small" variant="text" color="error" :disabled="busy === f.id" :data-testid="`mf-delete-${f.id}`" @click="remove(f)" />
          </td>
        </tr>
      </tbody>
    </v-table>

    <v-dialog v-model="dialog" max-width="720">
      <v-card>
        <v-card-title>{{ editing ? `Edit ${editing.spec.name}` : 'New forward' }}</v-card-title>
        <v-card-text>
          <v-row dense>
            <v-col cols="12" sm="6"><v-text-field v-model="form.name" label="Name" density="compact" /></v-col>
            <v-col cols="12" sm="6">
              <v-select v-model="form.ingress_agent_id" :items="agentItems" label="Ingress node" density="compact" />
            </v-col>
            <v-col cols="12" sm="5"><v-text-field v-model="form.bind_addr" label="Listen address" density="compact" /></v-col>
            <v-col cols="6" sm="4"><v-text-field v-model.number="form.port" type="number" label="Listen port" density="compact" /></v-col>
            <v-col cols="6" sm="3"><v-select v-model="form.proto" :items="['tcp', 'udp']" label="Protocol" density="compact" /></v-col>
            <v-col cols="12">
              <v-text-field v-model="sources" label="Allowed sources (CIDRs, space or comma separated)" density="compact" />
            </v-col>
            <v-col cols="12" sm="8"><v-text-field v-model="form.dest_addr" label="Destination address" density="compact" /></v-col>
            <v-col cols="12" sm="4"><v-text-field v-model.number="form.dest_port" type="number" label="Destination port" density="compact" /></v-col>
            <v-col cols="12" sm="6">
              <v-select v-model="form.backend" :items="backendItems" label="Backend" density="compact" />
            </v-col>
            <v-col cols="12" sm="6">
              <v-select v-model="form.nat" :items="natItems" label="Source address" density="compact" />
            </v-col>
            <v-col cols="12">
              <v-checkbox
                v-model="form.public_listener"
                label="Public listener (needed for a wildcard address; sources must still be narrower than /0)"
                density="compact"
                hide-details
              />
            </v-col>
          </v-row>
          <v-alert v-if="result" :type="result.ok ? 'success' : 'error'" variant="tonal" density="compact" class="mt-2" data-testid="mf-plan">
            {{ result.ok ? `Plan passes (${result.backend} backend).` : 'Plan refused; nothing was stored or sent to a node.' }}
          </v-alert>
          <v-list v-if="result" density="compact">
            <v-list-item v-for="c in result.checks" :key="c.name" :data-testid="`mf-check-${c.name.replace(/ /g, '-')}`">
              <template #prepend>
                <v-icon :color="verdictColor(c.verdict)" :icon="icon[c.verdict]" size="small" />
              </template>
              <v-list-item-title>{{ c.name }}</v-list-item-title>
              <v-list-item-subtitle class="text-wrap">{{ c.detail }}</v-list-item-subtitle>
            </v-list-item>
          </v-list>
          <v-alert v-if="formError" type="error" variant="tonal" density="compact" class="mt-2">{{ formError }}</v-alert>
        </v-card-text>
        <v-card-actions>
          <v-spacer />
          <v-btn variant="text" @click="dialog = false">Cancel</v-btn>
          <v-btn variant="tonal" :loading="checking" data-testid="mf-check" @click="check">Check plan</v-btn>
          <v-btn color="primary" :disabled="!result?.ok || !planFresh" :loading="saving" data-testid="mf-save" @click="save">
            {{ editing ? 'Save' : 'Create' }}
          </v-btn>
        </v-card-actions>
      </v-card>
    </v-dialog>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, ref, watch } from 'vue'
import { useAgentStore } from '@/stores/agents'
import {
  appliedColor,
  endpoint,
  useManagedForwardStore,
  verdictColor,
  verifiedColor,
  type ForwardSpec,
  type ForwardView,
  type MutationResult,
  type Plan,
  type Verdict,
} from '@/stores/managedForward'

const props = defineProps<{ tenantId: string }>()
const store = useManagedForwardStore()
const agents = useAgentStore()

const icon: Record<Verdict, string> = {
  pass: 'mdi-check-circle',
  warn: 'mdi-alert',
  fail: 'mdi-close-circle',
  unknown: 'mdi-help-circle',
}
const backendItems = [
  { title: 'userspace relay (any OS)', value: 'userspace' },
  { title: 'nft DNAT (Linux, root, commit-confirm)', value: 'nft' },
]

const blank = (): ForwardSpec => ({
  name: '',
  ingress_agent_id: '',
  bind_addr: '',
  port: 0,
  proto: 'tcp',
  sources: [],
  dest_agent_id: null,
  dest_addr: '',
  dest_port: 0,
  nat: 'masquerade',
  backend: 'userspace',
  desired: 'enabled',
  public_listener: false,
})

const dialog = ref(false)
const editing = ref<ForwardView | null>(null)
const form = ref<ForwardSpec>(blank())
const sources = ref('')
const result = ref<Plan | null>(null)
/** The plan shown was made for the form as it is now. */
const planFresh = ref(false)
const checking = ref(false)
const saving = ref(false)
const formError = ref('')
const notice = ref('')
const busy = ref<string | null>(null)

// Keeping the client's source needs the native backend; the userspace relay
// would have to masquerade, and the planner refuses rather than convert.
const natItems = computed(() => [
  { title: 'masquerade (the destination sees the ingress)', value: 'masquerade' },
  { title: 'keep the client address (nft only)', value: 'preserve_source', props: { disabled: form.value.backend !== 'nft' } },
])
const agentItems = computed(() => agents.agents.map((a) => ({ title: a.display_name ?? a.name, value: a.id })))

watch(
  () => form.value.backend,
  (b) => {
    if (b !== 'nft') form.value.nat = 'masquerade'
  },
)
watch([form, sources], () => (planFresh.value = false), { deep: true })

const nameOf = (id: string) => {
  const a = agents.agents.find((x) => x.id === id)
  return a ? (a.display_name ?? a.name) : id
}

function spec(): ForwardSpec {
  return {
    ...form.value,
    sources: sources.value.split(/[\s,]+/).filter(Boolean),
    port: Number(form.value.port) || 0,
    dest_port: Number(form.value.dest_port) || 0,
  }
}

function reset() {
  result.value = null
  planFresh.value = false
  formError.value = ''
}

function openNew() {
  editing.value = null
  form.value = blank()
  sources.value = ''
  reset()
  dialog.value = true
}

function openEdit(f: ForwardView) {
  editing.value = f
  form.value = { ...blank(), ...f.spec }
  sources.value = f.spec.sources.join(' ')
  reset()
  dialog.value = true
}

async function check() {
  checking.value = true
  formError.value = ''
  const p = await store.plan(props.tenantId, spec())
  checking.value = false
  if (p) {
    result.value = p
    planFresh.value = true
  } else {
    formError.value = store.error ?? 'The plan could not be made.'
  }
}

/** Act on a mutation's outcome; `true` when it was stored. */
function settle(out: MutationResult | null, inDialog: boolean): boolean {
  if (!out || out.kind === 'ok') return true
  if (out.kind === 'refused') {
    if (inDialog) {
      result.value = out.plan
      planFresh.value = true
    } else {
      notice.value = `Refused: ${out.plan.checks.filter((c) => c.verdict === 'fail' || c.verdict === 'unknown').map((c) => `${c.name} (${c.detail})`).join('; ')}`
    }
  } else if (out.kind === 'conflict') {
    notice.value = 'This forward changed since it was loaded; the list was reloaded. Check it again.'
    if (inDialog) dialog.value = false
  } else if (inDialog) {
    formError.value = out.message
  } else {
    notice.value = out.message
  }
  return false
}

async function save() {
  saving.value = true
  const s = spec()
  const out = editing.value ? await store.update(props.tenantId, editing.value, s) : await store.create(props.tenantId, s)
  saving.value = false
  if (settle(out, true)) dialog.value = false
}

async function toggle(f: ForwardView, on: boolean) {
  busy.value = f.id
  settle(await store.setDesired(props.tenantId, f, on ? 'enabled' : 'disabled'), false)
  busy.value = null
}

async function remove(f: ForwardView) {
  if (!window.confirm(`Remove the forward "${f.spec.name}"? The ingress node stops it at once.`)) return
  busy.value = f.id
  settle(await store.remove(props.tenantId, f), false)
  busy.value = null
}

onMounted(() => {
  void store.fetchList(props.tenantId)
  if (agents.agents.length === 0) void agents.fetchAgents(props.tenantId)
})
</script>
