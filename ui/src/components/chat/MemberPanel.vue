<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 G ROX EOOD -->
<template>
  <div class="member-panel">
    <v-text-field
      v-model="search"
      :placeholder="t('mh.chat.searchMembers')"
      density="compact"
      variant="outlined"
      hide-details
      prepend-inner-icon="mdi-magnify"
      class="mx-3 mt-3"
    />

    <v-list density="compact" class="mt-2">
      <v-list-item v-if="loading" class="text-center">
        <v-progress-circular indeterminate size="24" />
      </v-list-item>

      <v-list-item
        v-for="member in filteredMembers"
        :key="member.id"
        :to="member.user_id ? { name: 'profile', params: { userId: member.user_id } } : undefined"
      >
        <template #prepend>
          <v-avatar size="32" color="primary">
            <v-img v-if="member.avatar" :src="member.avatar" />
            <span v-else class="text-caption">{{ (member.display_name || '?').charAt(0).toUpperCase() }}</span>
          </v-avatar>
        </template>
        <v-list-item-title>{{ member.display_name || 'Unknown' }}</v-list-item-title>
        <v-list-item-subtitle v-if="member.username">@{{ member.username }}</v-list-item-subtitle>
      </v-list-item>

      <v-list-item v-if="!loading && filteredMembers.length === 0">
        <v-list-item-title class="text-medium-emphasis">{{ t('mh.chat.noMembers') }}</v-list-item-title>
      </v-list-item>
    </v-list>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, watch } from 'vue'
import { api } from '@/api/client'
import { useI18n } from 'vue-i18n'

const { t } = useI18n()

interface Member {
  id: string
  user_id?: string
  display_name: string
  username?: string
  avatar?: string
  joined_at: string
}

const props = defineProps<{
  tenantId: string
  roomId: string
}>()

const search = ref('')
const members = ref<Member[]>([])
const loading = ref(false)

const filteredMembers = computed(() => {
  if (!search.value) return members.value
  const q = search.value.toLowerCase()
  return members.value.filter(
    (m) =>
      (m.display_name || '').toLowerCase().includes(q) ||
      (m.username || '').toLowerCase().includes(q),
  )
})

async function fetchMembers() {
  if (!props.tenantId || !props.roomId) return
  loading.value = true
  try {
    const data = await api.get<{ items: Member[] }>(
      `/tenant/${props.tenantId}/room/${props.roomId}/member`,
    )
    members.value = data.items
  } catch {
    // non-critical
  } finally {
    loading.value = false
  }
}

watch(() => props.roomId, fetchMembers)
onMounted(fetchMembers)
</script>

<style scoped>
.member-panel {
  overflow-y: auto;
}
</style>
