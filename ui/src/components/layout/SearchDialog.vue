<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 G ROX EOOD -->
<template>
  <v-dialog v-model="dialogModel" max-width="600" scrollable :fullscreen="fullscreen">
    <v-card>
      <v-card-title class="d-flex align-center pa-3">
        <!-- Full screen on a phone leaves no scrim to tap: this is the way out. -->
        <v-btn
          v-if="fullscreen"
          icon="mdi-arrow-left"
          size="small"
          variant="text"
          class="mr-1"
          :aria-label="t('mh.search.close')"
          @click="dialogModel = false"
        />
        <v-icon v-else class="mr-2" size="small">mdi-magnify</v-icon>
        <v-text-field
          ref="searchInput"
          v-model="query"
          :placeholder="t('mh.search.placeholder')"
          variant="plain"
          hide-details
          autofocus
          density="compact"
          @keydown.esc="dialogModel = false"
        />
        <!-- A key a touch keyboard does not have. -->
        <v-chip v-if="!fullscreen" size="x-small" variant="outlined" class="ml-2">ESC</v-chip>
      </v-card-title>
      <v-divider />
      <v-card-text :style="fullscreen ? undefined : 'max-height: 400px; overflow-y: auto;'" class="pa-0">
        <div v-if="loading" class="text-center pa-4">
          <v-progress-circular indeterminate size="24" />
        </div>
        <div v-else-if="!query" class="text-center pa-4 text-medium-emphasis">
          {{ t('mh.search.intro') }}
        </div>
        <div v-else-if="noResults" class="text-center pa-4 text-medium-emphasis">
          {{ t('mh.search.noResults', { query }) }}
        </div>
        <div v-else>
          <!-- People -->
          <div v-if="results.users.length > 0">
            <div class="text-overline px-4 pt-2">{{ t('mh.search.people') }}</div>
            <v-list density="compact">
              <v-list-item
                v-for="user in results.users"
                :key="user.id"
                @click="goToProfile(user)"
              >
                <template #prepend>
                  <v-avatar size="24" color="primary">
                    <span class="text-caption">{{ (user.display_name || '?')[0].toUpperCase() }}</span>
                  </v-avatar>
                </template>
                <v-list-item-title>{{ user.display_name }}</v-list-item-title>
                <v-list-item-subtitle>@{{ user.username }}</v-list-item-subtitle>
              </v-list-item>
            </v-list>
          </div>
        </div>
      </v-card-text>
    </v-card>
  </v-dialog>
</template>

<script setup lang="ts">
import { ref, computed, watch } from 'vue'
import { useRouter } from 'vue-router'
import { api } from '@/api/client'
import { useTenantStore } from '@/stores/tenant'
import { useResponsiveDialog } from '@/composables/useResponsiveDialog'
import { useI18n } from 'vue-i18n'

const { t } = useI18n()

interface SearchUserResult {
  id: string
  display_name: string
  username: string
  avatar?: string
}

interface SearchResultsData {
  users: SearchUserResult[]
}

const props = defineProps<{
  modelValue: boolean
}>()

const emit = defineEmits<{
  'update:modelValue': [value: boolean]
}>()

const dialogModel = computed({
  get: () => props.modelValue,
  set: (val) => emit('update:modelValue', val),
})

const router = useRouter()
const tenantStore = useTenantStore()
const { fullscreen } = useResponsiveDialog()

const query = ref('')
const loading = ref(false)
const searchInput = ref<HTMLInputElement | null>(null)

const results = ref<SearchResultsData>({
  users: [],
})

const noResults = computed(() => {
  return (
    query.value.trim().length > 0 &&
    !loading.value &&
    results.value.users.length === 0
  )
})

let debounceTimer: ReturnType<typeof setTimeout> | null = null

watch(query, (val) => {
  if (debounceTimer) clearTimeout(debounceTimer)
  const q = val.trim()
  if (!q) {
    results.value = { users: [] }
    loading.value = false
    return
  }
  loading.value = true
  debounceTimer = setTimeout(() => {
    doSearch(q)
  }, 300)
})

watch(dialogModel, (val) => {
  if (!val) {
    query.value = ''
    results.value = { users: [] }
    loading.value = false
  }
})

async function doSearch(q: string) {
  const tenantId = tenantStore.current?.id
  if (!tenantId) {
    loading.value = false
    return
  }
  try {
    const data = await api.get<Partial<SearchResultsData>>(
      `/tenant/${tenantId}/search?q=${encodeURIComponent(q)}&limit=20`,
    )
    if (query.value.trim() === q) {
      results.value = { users: data.users ?? [] }
    }
  } catch {
    results.value = { users: [] }
  } finally {
    loading.value = false
  }
}

function goToProfile(user: SearchUserResult) {
  router.push({ name: 'profile', params: { userId: user.id } })
  dialogModel.value = false
}
</script>
