<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 G ROX EOOD -->
<template>
  <v-container fluid class="pa-2 pa-md-4 pa-xl-6">
    <h1 class="text-h5 text-md-h4 mb-2 mb-md-4">{{ $t('nav.devices') }}</h1>
    <agents-section :tenant-id="tenantId" />
    <!-- Admin-only Logical Network Zones designer (ADMINISTRATOR / owner). -->
    <network-zones-section v-if="caps.has('network') && isAdmin" :tenant-id="tenantId" />
    <!-- Admin-only organization Relay Node management (ADMINISTRATOR / owner). -->
    <peer-relays-section v-if="caps.has('network') && isAdmin" :tenant-id="tenantId" />
    <!-- FR-51 P4 — renders only when the org's ephemeral-key switch is ON
         (the component fetches the switch itself and stays empty otherwise). -->
    <enroll-keys-section :tenant-id="tenantId" />
    <!-- Temporary devices: invitations, conversions and their history.
         Renders nothing on a server without the feature. -->
    <temporary-devices-section :tenant-id="tenantId" />
    <accepted-invitations-section :tenant-id="tenantId" />
  </v-container>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import { useRoute } from 'vue-router'
import AgentsSection from '@/components/admin/AgentsSection.vue'
import NetworkZonesSection from '@/components/admin/NetworkZonesSection.vue'
import PeerRelaysSection from '@/components/admin/PeerRelaysSection.vue'
import EnrollKeysSection from '@/components/admin/EnrollKeysSection.vue'
import TemporaryDevicesSection from '@/components/admin/TemporaryDevicesSection.vue'
import AcceptedInvitationsSection from '@/components/admin/AcceptedInvitationsSection.vue'
import { useCapabilitiesStore } from '@/stores/capabilities'
import { useTenantStore } from '@/stores/tenant'
import { canManageRelays } from '@/utils/permissions'

const route = useRoute()
const caps = useCapabilitiesStore()
const tenantStore = useTenantStore()
const tenantId = computed(() => route.params.tenantId as string)
const isAdmin = computed(() =>
  canManageRelays(tenantStore.myPermissions, tenantStore.isOwner),
)
</script>
