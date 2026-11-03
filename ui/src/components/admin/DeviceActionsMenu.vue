<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 G ROX EOOD -->
<template>
  <!-- ONE action menu for a device row, used by the desktop grid and the phone
       card alike. Each used to carry its own copy, and the copies drifted: the
       phone's lost "Edit name & tags" and its two overlay links lost the
       tenant id (`/tenant//network/acl`). The menu only says WHICH action was
       picked; the page that owns the dialogs does the rest. -->
  <v-menu v-if="row.kind === 'agent' && agent">
    <template #activator="{ props: menuProps }">
      <v-btn
        v-bind="menuProps"
        icon="mdi-dots-vertical"
        size="small"
        variant="text"
        :aria-label="t('mh.devMenu.aria', { name: label })"
      />
    </template>
    <v-list density="compact" min-width="230">
      <v-list-subheader>{{ t('mh.devMenu.sec.maintenance') }}</v-list-subheader>
      <v-list-item
        prepend-icon="mdi-update"
        :title="t('mh.devMenu.update')"
        :subtitle="updateBlocked"
        :disabled="updateBusy || !!updateBlocked"
        @click="emit('action', 'update')"
      />
      <v-list-item
        v-if="networkMounted"
        prepend-icon="mdi-key-change"
        :title="t('mh.devMenu.rotateKey')"
        :disabled="rotateKeyBusy"
        @click="emit('action', 'rotate-key')"
      />
      <v-list-subheader>{{ t('mh.devMenu.sec.diagnostics') }}</v-list-subheader>
      <v-list-item
        prepend-icon="mdi-alert-circle-outline"
        :title="t('mh.devMenu.crashes')"
        @click="emit('action', 'crashes')"
      />
      <v-list-item
        prepend-icon="mdi-text-box-search-outline"
        :title="t('mh.devMenu.logs')"
        @click="emit('action', 'logs')"
      />
      <v-list-item
        prepend-icon="mdi-console"
        :title="t('mh.devMenu.console')"
        @click="emit('action', 'console')"
      />
      <v-list-subheader>{{ t('mh.devMenu.sec.access') }}</v-list-subheader>
      <v-list-item
        prepend-icon="mdi-rename-box"
        :title="t('mh.devMenu.edit')"
        @click="emit('action', 'edit')"
      />
      <v-list-item
        prepend-icon="mdi-domain-plus"
        :title="t('mh.devMenu.joinOrg')"
        @click="emit('action', 'join-org')"
      />
      <v-list-item
        prepend-icon="mdi-account-switch"
        :title="t('mh.devMenu.reassign')"
        @click="emit('action', 'reassign')"
      />
      <v-list-item
        prepend-icon="mdi-shield-key-outline"
        :title="t('mh.devMenu.execPolicy')"
        @click="emit('action', 'exec-policy')"
      />
      <v-list-item
        v-if="networkMounted"
        prepend-icon="mdi-console-network-outline"
        :title="t('mh.devMenu.sshPolicy')"
        @click="emit('action', 'ssh-policy')"
      />
      <!-- FR-52 gate 2. Distinct from every policy above it: those decide
           what a COLLEAGUE may do, this one admits someone outside the
           organization. -->
      <v-list-item
        prepend-icon="mdi-account-arrow-right-outline"
        :title="t('mh.devMenu.externalAccess')"
        @click="emit('action', 'external-access')"
      />
      <!-- Writes an INTENT the device may refuse (step 5 of
           docs/remote-config.md) — unlike the two policies above, which take
           effect the moment they save. The dialog leads with that
           difference. -->
      <v-list-item
        prepend-icon="mdi-cog-transfer-outline"
        :title="t('mh.devMenu.remoteConfig')"
        @click="emit('action', 'remote-config')"
      />
      <v-list-subheader>{{ t('mh.devMenu.sec.network') }}</v-list-subheader>
      <v-list-item
        prepend-icon="mdi-ip-network-outline"
        :title="t('mh.devMenu.routes')"
        @click="emit('action', 'routes')"
      />
      <v-list-item
        v-if="node"
        prepend-icon="mdi-lan-disconnect"
        :title="node.will_rejoin ? t('mh.devMenu.evict') : t('mh.devMenu.removeMesh')"
        @click="emit('action', 'evict')"
      />
      <v-list-item
        v-if="node"
        prepend-icon="mdi-lan-connect"
        :title="t('mh.devMenu.overlayRoutes')"
        :to="{ path: `/tenant/${tenantId}/network/subnet-routes`, query: { node: node.id } }"
      />
      <v-list-item
        prepend-icon="mdi-shield-lock-outline"
        :title="t('mh.devMenu.overlayAcl')"
        :to="{ path: `/tenant/${tenantId}/network/acl`, query: { tab: 'overlay' } }"
      />
      <v-divider />
      <v-list-item
        prepend-icon="mdi-delete"
        :title="t('mh.devMenu.delete')"
        base-color="error"
        @click="emit('action', 'delete')"
      />
    </v-list>
  </v-menu>
  <v-menu v-else-if="row.kind === 'tunnel_client'">
    <template #activator="{ props: menuProps }">
      <v-btn
        v-bind="menuProps"
        icon="mdi-dots-vertical"
        size="small"
        variant="text"
        :aria-label="t('mh.devMenu.aria', { name: label })"
      />
    </template>
    <v-list density="compact" min-width="230">
      <v-list-item
        prepend-icon="mdi-rename-box"
        :title="t('mh.devMenu.edit')"
        @click="emit('action', 'edit')"
      />
      <v-list-subheader>{{ t('mh.devMenu.sec.network') }}</v-list-subheader>
      <v-list-item
        v-if="node"
        prepend-icon="mdi-lan-disconnect"
        :title="node.will_rejoin ? t('mh.devMenu.evict') : t('mh.devMenu.removeMesh')"
        @click="emit('action', 'evict')"
      />
      <v-divider />
      <v-list-item
        v-if="client"
        prepend-icon="mdi-delete"
        :title="t('mh.devMenu.deleteTunnel')"
        base-color="error"
        @click="emit('action', 'delete-tunnel')"
      />
    </v-list>
  </v-menu>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import { useI18n } from 'vue-i18n'
import type { Agent } from '@/stores/agents'
import type { DeviceRow } from '@/stores/devices'
import type { OverlayNode } from '@/stores/overlayRoutes'
import type { TunnelClient } from '@/stores/tunnelClients'

/** What the menu can ask for. The page maps each to its dialog or request. */
export type DeviceAction =
  | 'update'
  | 'rotate-key'
  | 'crashes'
  | 'logs'
  | 'console'
  | 'edit'
  | 'join-org'
  | 'reassign'
  | 'exec-policy'
  | 'ssh-policy'
  | 'external-access'
  | 'remote-config'
  | 'routes'
  | 'evict'
  | 'delete'
  | 'delete-tunnel'

const props = defineProps<{
  tenantId: string
  row: DeviceRow
  /** The full agent, for an agent row — no agent, no menu (its actions all
   *  need one). */
  agent?: Agent
  /** The tunnel client, for a tunnel row — its delete needs the record. */
  client?: TunnelClient
  /** The device's overlay node, when it holds an address. */
  node?: OverlayNode
  /** FR-69 P9 — the overlay-key rotation and the SSH policy are the network
   *  module's routes; a menu item that leads to a 404 is worse than none. */
  networkMounted?: boolean
  updateBusy?: boolean
  rotateKeyBusy?: boolean
  /** Why "Update now" will not take, when it will not (FR-67 P7). */
  updateBlocked?: string
}>()

const emit = defineEmits<{ action: [action: DeviceAction] }>()
const { t } = useI18n()

const label = computed(() => props.row.display_name || props.row.name)
</script>
