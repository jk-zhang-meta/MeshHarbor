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
          <!-- Devices -->
          <div v-if="results.devices.length > 0">
            <div class="text-overline px-4 pt-2">{{ t('mh.search.devices') }}</div>
            <v-list density="compact">
              <v-list-item
                v-for="device in results.devices"
                :key="device.id"
                @click="goToDevice(device)"
              >
                <template #prepend>
                  <span
                    class="mh-presence__dot mr-3"
                    :class="`mh-presence--${device.presence === 'online' || device.presence === 'stale' ? device.presence : 'offline'}`"
                    aria-hidden="true"
                  />
                </template>
                <v-list-item-title>{{ device.display_name || device.name }}</v-list-item-title>
                <v-list-item-subtitle>{{ device.overlay_ip || device.kind }}</v-list-item-subtitle>
              </v-list-item>
            </v-list>
          </div>

          <!-- People -->
          <div v-if="results.users.length > 0">
            <div class="text-overline px-4 pt-2">{{ t('mh.search.people') }}</div>
            <v-list density="compact">
              <v-list-item
                v-for="user in results.users"
                :key="user.user_id"
                @click="goToProfile(user)"
              >
                <template #prepend>
                  <v-avatar size="24" color="primary">
                    <span class="text-caption">{{ (user.display_name || '?')[0].toUpperCase() }}</span>
                  </v-avatar>
                </template>
                <v-list-item-title>{{ user.display_name }}</v-list-item-title>
                <v-list-item-subtitle v-if="user.email">{{ user.email }}</v-list-item-subtitle>
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
import { useCapabilitiesStore } from '@/stores/capabilities'
import { useResponsiveDialog } from '@/composables/useResponsiveDialog'
import { useI18n } from 'vue-i18n'

const { t } = useI18n()

interface SearchDeviceResult {
  id: string
  kind: string
  name: string
  display_name?: string
  presence: 'online' | 'stale' | 'offline'
  overlay_ip?: string | null
}

interface SearchMemberResult {
  user_id: string
  display_name: string
  email?: string
}

interface SearchResultsData {
  devices: SearchDeviceResult[]
  users: SearchMemberResult[]
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
const caps = useCapabilitiesStore()
const { fullscreen } = useResponsiveDialog()

const query = ref('')
const loading = ref(false)
const searchInput = ref<HTMLInputElement | null>(null)

const results = ref<SearchResultsData>({
  devices: [],
  users: [],
})

const noResults = computed(() => {
  return (
    query.value.trim().length > 0 &&
    !loading.value &&
    results.value.devices.length === 0 &&
    results.value.users.length === 0
  )
})

let debounceTimer: ReturnType<typeof setTimeout> | null = null

watch(query, (val) => {
  if (debounceTimer) clearTimeout(debounceTimer)
  const q = val.trim()
  if (!q) {
    results.value = { devices: [], users: [] }
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
    results.value = { devices: [], users: [] }
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
    const enc = encodeURIComponent(q)
    const [devRes, memRes] = await Promise.allSettled([
      caps.has('fleet')
        ? api.get<{ items: SearchDeviceResult[] }>(
            `/tenant/${tenantId}/device?q=${enc}&per_page=10&sort=status`,
          )
        : Promise.resolve({ items: [] as SearchDeviceResult[] }),
      api.get<{ items: SearchMemberResult[] }>(
        `/tenant/${tenantId}/member?q=${enc}&per_page=10`,
      ),
    ])
    if (query.value.trim() === q) {
      results.value = {
        devices: devRes.status === 'fulfilled' ? (devRes.value.items ?? []) : [],
        users: memRes.status === 'fulfilled' ? (memRes.value.items ?? []) : [],
      }
    }
  } catch {
    results.value = { devices: [], users: [] }
  } finally {
    loading.value = false
  }
}

function goToDevice(device: SearchDeviceResult) {
  const tenantId = tenantStore.current?.id
  if (!tenantId) return
  if (device.kind === 'agent' && device.presence !== 'offline' && caps.has('remote')) {
    router.push({ name: 'agent-remote', params: { tenantId, agentId: device.id } })
  } else {
    router.push({ name: 'devices', params: { tenantId } })
  }
  dialogModel.value = false
}

function goToProfile(user: SearchMemberResult) {
  router.push({ name: 'profile', params: { userId: user.user_id } })
  dialogModel.value = false
}
</script>
