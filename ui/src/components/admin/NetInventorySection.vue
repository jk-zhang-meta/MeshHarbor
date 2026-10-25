<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 G ROX EOOD -->
<template>
  <!-- MeshHarbor #19 — REPORTED configuration only: what each node read from
       its own kernel. Not an observed flow, not a desired or applied state,
       not an ACL grant; a route here is no evidence a path works. -->
  <div>
    <p class="text-body-2 text-medium-emphasis mb-3">
      Reported configuration: what each node read from its own kernel (host network namespace
      only). It is not evidence that a path works and grants no access; the overlay ACL decides
      that. Freshness is the server's clock.
    </p>
    <v-alert v-if="store.error" type="error" variant="tonal" class="mb-3" data-testid="inv-error">
      {{ store.error }}
    </v-alert>
    <v-progress-linear v-if="store.loading" indeterminate class="mb-2" />
    <p v-if="!store.loading && !store.error && store.items.length === 0" class="text-medium-emphasis" data-testid="inv-empty">
      No node has reported an inventory yet.
    </p>
    <v-expansion-panels v-model="open" multiple>
      <v-expansion-panel v-for="n in store.items" :key="n.agent_id" :value="n.agent_id" :data-testid="`inv-node-${n.agent_id}`">
        <v-expansion-panel-title>
          <div class="d-flex flex-wrap align-center ga-2">
            <strong>{{ nameOf(n.agent_id) }}</strong>
            <v-chip :color="n.fresh ? 'success' : 'warning'" size="x-small" label>
              {{ n.fresh ? 'fresh' : 'stale' }}
            </v-chip>
            <span class="text-caption text-medium-emphasis">reported {{ when(n.received_at) }} · {{ n.os }}</span>
            <v-chip
              v-for="s in SECTIONS"
              :key="s"
              :color="stateColor(n[s].state)"
              size="x-small"
              variant="tonal"
              :title="`${n[s].state}: ${n[s].reported} of ${n[s].total}`"
            >
              {{ label[s] }} {{ n[s].state === 'complete' ? n[s].total : `${n[s].reported}/${n[s].total} ${n[s].state}` }}
            </v-chip>
          </div>
        </v-expansion-panel-title>
        <v-expansion-panel-text>
          <template v-if="store.details[n.agent_id]">
            <div class="text-caption mb-2">
              forwarding: IPv4 {{ flag(inv(n).forwarding.ipv4) }}, IPv6 {{ flag(inv(n).forwarding.ipv6) }} ·
              namespaces: {{ inv(n).namespaces }}
            </div>
            <v-tabs v-model="tab[n.agent_id]" density="compact" color="primary">
              <v-tab v-for="s in SECTIONS" :key="s" :value="s">{{ label[s] }}</v-tab>
            </v-tabs>
            <v-alert v-if="note(n)" type="info" variant="tonal" density="compact" class="my-2">{{ note(n) }}</v-alert>
            <v-table density="compact" class="mt-2">
              <thead>
                <tr><th v-for="c in columns[tab[n.agent_id] ?? 'interfaces']" :key="c">{{ c }}</th></tr>
              </thead>
              <tbody>
                <tr v-for="(row, i) in rows(n)" :key="i">
                  <td v-for="(cell, j) in row" :key="j"><code>{{ cell }}</code></td>
                </tr>
              </tbody>
            </v-table>
          </template>
          <v-progress-linear v-else indeterminate />
        </v-expansion-panel-text>
      </v-expansion-panel>
    </v-expansion-panels>
  </div>
</template>

<script setup lang="ts">
import { onMounted, reactive, ref, watch } from 'vue'
import { useAgentStore } from '@/stores/agents'
import {
  SECTIONS,
  stateColor,
  useNetInventoryStore,
  type InventorySummary,
  type NetInventory,
  type SectionName,
} from '@/stores/netInventory'

const props = defineProps<{ tenantId: string }>()
const store = useNetInventoryStore()
const agents = useAgentStore()
const open = ref<string[]>([])
const tab = reactive<Record<string, SectionName>>({})

const label: Record<SectionName, string> = {
  interfaces: 'interfaces',
  routes: 'routes',
  rules: 'rules',
  listeners: 'listeners',
  firewall_chains: 'fw chains',
  firewall_rules: 'fw rules',
}

const columns: Record<SectionName, string[]> = {
  interfaces: ['name', 'kind', 'up', 'mtu', 'addresses'],
  routes: ['family', 'table', 'destination', 'type', 'gateway', 'device', 'protocol', 'metric'],
  rules: ['family', 'priority', 'selector', 'action'],
  listeners: ['proto', 'address', 'port', 'process'],
  firewall_chains: ['owner', 'family', 'table', 'chain', 'hook', 'type', 'priority', 'policy'],
  firewall_rules: ['owner', 'family', 'table', 'chain', 'matches', 'verdict', 'target', 'packets'],
}

const dash = (v: unknown) => (v === undefined || v === null || v === '' ? '—' : String(v))
const flag = (v?: boolean) => (v === undefined ? 'unknown' : v ? 'on' : 'off')
const when = (iso: string) => new Date(iso).toLocaleString()
const nameOf = (id: string) => {
  const a = agents.agents.find((x) => x.id === id)
  return a ? (a.display_name ?? a.name) : id
}
const inv = (n: InventorySummary): NetInventory => store.details[n.agent_id]!.inventory

function note(n: InventorySummary): string | undefined {
  return inv(n)[tab[n.agent_id] ?? 'interfaces'].note
}

function rows(n: InventorySummary): string[][] {
  const i = inv(n)
  switch (tab[n.agent_id] ?? 'interfaces') {
    case 'interfaces':
      return i.interfaces.items.map((x) => [x.name, dash(x.kind), x.up ? 'up' : 'down', dash(x.mtu), x.addrs.join(' ') || '—'])
    case 'routes':
      return i.routes.items.map((x) => [x.family, x.table, x.dst, x.kind, dash(x.gateway), dash(x.dev), dash(x.protocol), dash(x.metric)])
    case 'rules':
      return i.rules.items.map((x) => [x.family, String(x.priority), x.selector, x.action])
    case 'listeners':
      return i.listeners.items.map((x) => [x.proto, x.addr, String(x.port), dash(x.process)])
    case 'firewall_chains':
      return i.firewall_chains.items.map((x) => [x.owner, x.family, x.table, x.name, dash(x.hook), dash(x.chain_type), dash(x.priority), dash(x.policy)])
    case 'firewall_rules':
      return i.firewall_rules.items.map((x) => [x.owner, x.family, x.table, x.chain, x.matches || '—', x.verdict, dash(x.target), dash(x.packets)])
  }
}

watch(open, (ids) => {
  for (const id of ids) {
    if (!store.details[id]) void store.fetchDetail(props.tenantId, id)
  }
})

onMounted(() => {
  void store.fetchList(props.tenantId)
  if (agents.agents.length === 0) void agents.fetchAgents(props.tenantId)
})
</script>
