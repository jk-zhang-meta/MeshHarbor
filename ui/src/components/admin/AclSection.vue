<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 G ROX EOOD -->
<template>
  <!-- One ACL page, two enforcement planes (2026-08-04). They are separate
       backend systems on purpose — tunnel ACL gates flows an AGENT dials
       for you (host allowlists + session ceilings, default deny); overlay
       ACL is L3 peer visibility + routes, enforced on direct, TURN-relayed
       and DERP-relayed paths alike (netmap shaping + DERP gate). The tabs
       give operators the single place the old split IA lacked. -->
  <div>
    <v-tabs v-model="tab" class="mb-3" color="primary">
      <v-tab value="overlay">{{ $t('mh.acl.title') }}</v-tab>
      <v-tab value="tunnel">{{ $t('mh.acl.tunnelTitle') }}</v-tab>
    </v-tabs>
    <v-window v-model="tab">
      <v-window-item value="overlay">
        <OverlayAclSection :tenant-id="tenantId" />
      </v-window-item>
      <v-window-item value="tunnel">
        <TunnelPoliciesSection :tenant-id="tenantId" />
      </v-window-item>
    </v-window>
  </div>
</template>

<script setup lang="ts">
import { ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import OverlayAclSection from './OverlayAclSection.vue'
import TunnelPoliciesSection from './TunnelPoliciesSection.vue'

defineProps<{ tenantId: string }>()

const route = useRoute()
const router = useRouter()
// `?tab=tunnel|overlay` — deep-linkable (device rows + the old
// /network/overlay-acl redirect land on a specific tab).
const tab = ref((route.query.tab as string) === 'tunnel' ? 'tunnel' : 'overlay')
watch(tab, (t) => {
  router.replace({ query: { ...route.query, tab: t } })
})
</script>
