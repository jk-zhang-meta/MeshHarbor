<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<template>
  <div class="text-caption" data-testid="device-feature-summary">
    <span v-if="enabled === null">{{ t('deviceFeatures.legacy') }}</span>
    <span v-else-if="!enabled.length">{{ t('deviceFeatures.none') }}</span>
    <template v-else>
      <span>{{ enabled.map(key => t(`deviceFeatures.${key}`)).join(' · ') }}</span>
      <div v-if="enabled.includes('network')" class="text-medium-emphasis">{{ t('deviceFeatures.networkWarning') }}</div>
    </template>
    <div v-if="revocationPending === true" class="text-warning" role="status" data-testid="device-feature-revocation-pending">{{ t('deviceFeatures.revocationPending') }}</div>
  </div>
</template>
<script setup lang="ts">
import { computed } from 'vue'
import { useI18n } from 'vue-i18n'
import { enabledDeviceFeatures } from '@/utils/deviceFeatures'
const props = defineProps<{ features?: unknown; revocationPending?: boolean }>()
const { t } = useI18n()
const enabled = computed(() => enabledDeviceFeatures(props.features))
</script>
