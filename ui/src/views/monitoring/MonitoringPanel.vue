<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 G ROX EOOD -->
<template>
  <v-container fluid class="pa-2 pa-md-4 pa-xl-6">
    <div class="d-flex align-center justify-space-between flex-wrap ga-2 mb-3">
      <div>
        <h1 class="text-h5 text-md-h4">{{ t('mh.monitoring.title') }}</h1>
        <p class="text-body-2 text-medium-emphasis mt-1 mb-0">
          {{ t('mh.monitoring.subtitle') }}
        </p>
      </div>
    </div>

    <v-tabs
      :model-value="activeTab"
      color="primary"
      density="comfortable"
      class="mb-4"
    >
      <v-tab
        v-if="canSeeMonitoring"
        value="monitoring-live"
        :to="{ name: 'monitoring-live', params: { tenantId } }"
        prepend-icon="mdi-radar"
      >
        {{ t('mh.monitoring.tabs.live') }}
      </v-tab>
      <v-tab
        v-if="canSeeMonitoring"
        value="monitoring-history"
        :to="{ name: 'monitoring-history', params: { tenantId } }"
        prepend-icon="mdi-history"
      >
        {{ t('mh.monitoring.tabs.history') }}
      </v-tab>
      <v-tab
        v-if="canSeeExec"
        value="monitoring-exec"
        :to="{ name: 'monitoring-exec', params: { tenantId } }"
        prepend-icon="mdi-console-line"
      >
        {{ t('nav.execAudit') }}
      </v-tab>
    </v-tabs>

    <router-view />
  </v-container>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import { useRoute } from 'vue-router'
import { useI18n } from 'vue-i18n'
import { useTenantStore } from '@/stores/tenant'
import { canViewExecAudit, canViewMonitoring } from '@/utils/permissions'

const { t } = useI18n()
const route = useRoute()
const tenantStore = useTenantStore()

const tenantId = computed(() => String(route.params.tenantId || tenantStore.current?.id || ''))
const activeTab = computed(() => String(route.name || 'monitoring-live'))
const canSeeMonitoring = computed(() =>
  canViewMonitoring(tenantStore.myPermissions, tenantStore.isOwner),
)
const canSeeExec = computed(() =>
  canViewExecAudit(tenantStore.myPermissions, tenantStore.isOwner),
)
</script>
