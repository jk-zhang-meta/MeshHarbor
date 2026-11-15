<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<template>
  <span role="status" aria-live="polite" class="device-name-sync">
    <v-chip :color="presentation.color" size="x-small" variant="tonal" :title="t(`mh.nameSync.${presentation.key}Hint`)">
      {{ t(`mh.nameSync.${presentation.key}`) }}
    </v-chip>
  </span>
</template>
<script setup lang="ts">
import { computed } from 'vue'
import { useI18n } from 'vue-i18n'
import { nameSyncPresentation, type NameSync } from '@/utils/nameSync'
const props = defineProps<{ sync?: NameSync }>()
const { t } = useI18n()
const presentation = computed(() => nameSyncPresentation(props.sync))
</script>
