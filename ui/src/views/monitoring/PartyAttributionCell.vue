<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 G ROX EOOD -->
<template>
  <div class="party-cell">
    <div v-if="party.device_name" class="party-cell__device">
      <v-icon size="15" class="mr-1 text-medium-emphasis">{{ osIcon }}</v-icon>
      <span class="font-weight-medium text-body-2">{{ party.device_name }}</span>
    </div>

    <div v-if="party.account_name || party.account_username" class="party-cell__account">
      <v-icon size="14" class="mr-1 text-medium-emphasis">mdi-account-outline</v-icon>
      <span class="text-caption font-weight-medium">{{ party.account_name || party.account_username }}</span>
      <span
        v-if="party.account_username && party.account_username !== party.account_name"
        class="text-caption text-medium-emphasis ml-1"
      >
        @{{ party.account_username }}
      </span>
    </div>

    <div class="party-cell__badges">
      <v-chip
        size="x-small"
        variant="tonal"
        :color="badgeColor"
        :prepend-icon="badgeIcon"
      >
        {{ badgeLabel }}
      </v-chip>
      <span v-if="extraMeta" class="text-caption text-medium-emphasis">
        {{ extraMeta }}
      </span>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import { useI18n } from 'vue-i18n'
import type { PartyAttribution } from '@/api/monitoring'

const props = defineProps<{
  party: PartyAttribution
}>()

const { t } = useI18n()

const osIcon = computed(() => {
  const os = (props.party.device_os || '').toLowerCase()
  if (os.includes('mac') || os.includes('darwin')) return 'mdi-apple'
  if (os.includes('win')) return 'mdi-microsoft-windows'
  if (os.includes('linux')) return 'mdi-linux'
  return 'mdi-monitor'
})

const badgeColor = computed(() => {
  switch (props.party.attribution_kind) {
    case 'device_invite':
      return 'info'
    case 'member_invite':
      return 'primary'
    case 'device_share':
      return 'secondary'
    case 'external':
      return 'warning'
    case 'key_list':
      return 'deep-orange'
    default:
      return 'default'
  }
})

const badgeIcon = computed(() => {
  switch (props.party.attribution_kind) {
    case 'device_invite':
      return 'mdi-ticket-confirmation-outline'
    case 'member_invite':
      return 'mdi-account-plus-outline'
    case 'device_share':
      return 'mdi-share-variant-outline'
    case 'external':
      return 'mdi-earth'
    case 'key_list':
      return 'mdi-key-outline'
    default:
      return 'mdi-shield-account-outline'
  }
})

const badgeLabel = computed(() => {
  const kind = props.party.attribution_kind
  return t(`mh.monitoring.attribution.${kind}`)
})

const extraMeta = computed(() => {
  const parts: string[] = []
  if (props.party.invite_or_share_label) {
    parts.push(props.party.invite_or_share_label)
  }
  if (props.party.inviter_or_owner_name) {
    const key =
      props.party.attribution_kind === 'device_share'
        ? 'mh.monitoring.attribution.sharedBy'
        : 'mh.monitoring.attribution.invitedBy'
    parts.push(t(key, { name: props.party.inviter_or_owner_name }))
  }
  return parts.join(' · ')
})
</script>

<style scoped>
.party-cell {
  display: flex;
  flex-direction: column;
  gap: 2px;
  padding: 4px 0;
  min-width: 170px;
}

.party-cell__device,
.party-cell__account {
  display: flex;
  align-items: center;
  line-height: 1.3;
}

.party-cell__badges {
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  gap: 6px;
  margin-top: 2px;
}
</style>
