<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 G ROX EOOD -->
<template>
  <v-container fluid class="pa-2 pa-md-4 pa-xl-6">
    <h1 class="text-h5 text-md-h4 mb-2 mb-md-4">{{ $t('nav.devices') }}</h1>
    <agents-section :tenant-id="tenantId" />
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
import EnrollKeysSection from '@/components/admin/EnrollKeysSection.vue'
import TemporaryDevicesSection from '@/components/admin/TemporaryDevicesSection.vue'
import AcceptedInvitationsSection from '@/components/admin/AcceptedInvitationsSection.vue'

const route = useRoute()
const tenantId = computed(() => route.params.tenantId as string)
</script>
