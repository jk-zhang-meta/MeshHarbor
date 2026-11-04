<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 G ROX EOOD -->
<template>
  <v-dialog v-model="open" max-width="600" scrollable>
    <v-card>
      <v-card-title class="d-flex align-center">
        <span>{{ t('mh.chat.gifs') }}</span>
        <v-spacer />
        <v-btn icon="mdi-close" size="small" variant="text" @click="open = false" />
      </v-card-title>

      <v-tabs v-model="tab" density="compact">
        <v-tab value="search">{{ t('common.search') }}</v-tab>
        <v-tab value="trending">{{ t('mh.chat.trending') }}</v-tab>
      </v-tabs>

      <v-card-text class="pa-3">
        <v-text-field
          v-if="tab === 'search'"
          v-model="query"
          :placeholder="t('mh.chat.searchGifs')"
          variant="outlined"
          density="compact"
          hide-details
          prepend-inner-icon="mdi-magnify"
          class="mb-3"
        />

        <div v-if="loading && gifs.length === 0" class="text-center pa-4">
          <v-progress-circular indeterminate />
        </div>

        <div v-else-if="gifs.length === 0" class="text-center pa-4 text-medium-emphasis">
          {{ tab === 'search' && !query ? 'Type to search GIFs' : 'No GIFs found' }}
        </div>

        <div v-else class="giphy-grid">
          <div
            v-for="gif in gifs"
            :key="gif.id"
            class="giphy-item"
            @click="selectGif(gif)"
          >
            <img
              :src="gif.images.fixed_height_still.url"
              :alt="gif.title"
              :width="gif.images.fixed_height_still.width"
              :height="gif.images.fixed_height_still.height"
              loading="lazy"
              @mouseenter="($event.target as HTMLImageElement).src = gif.images.fixed_height.url"
              @mouseleave="($event.target as HTMLImageElement).src = gif.images.fixed_height_still.url"
            />
          </div>
        </div>

        <div v-if="hasMore" class="text-center mt-3">
          <v-btn variant="text" :loading="loading" @click="loadMore">{{ t('common.loadMore') }}</v-btn>
        </div>

        <div class="text-center mt-2 text-caption text-medium-emphasis">
          {{ t('mh.chat.poweredByGiphy') }}
        </div>
      </v-card-text>
    </v-card>
  </v-dialog>
</template>

<script setup lang="ts">
import { ref, computed, watch } from 'vue'
import { api } from '@/api/client'
import { useI18n } from 'vue-i18n'

const { t } = useI18n()

interface GiphyImage {
  url: string
  width: string
  height: string
}

interface GiphyGif {
  id: string
  title: string
  images: {
    fixed_height: GiphyImage
    fixed_height_still: GiphyImage
  }
}

interface GiphyResponse {
  data: GiphyGif[]
  pagination: {
    total_count: number
    count: number
    offset: number
  }
}

const props = defineProps<{
  modelValue: boolean
}>()

const emit = defineEmits<{
  'update:modelValue': [value: boolean]
  select: [url: string]
}>()

const open = computed({
  get: () => props.modelValue,
  set: (val) => emit('update:modelValue', val),
})

const tab = ref<'search' | 'trending'>('search')
const query = ref('')
const gifs = ref<GiphyGif[]>([])
const loading = ref(false)
const offset = ref(0)
const totalCount = ref(0)
const LIMIT = 25

let debounceTimer: ReturnType<typeof setTimeout> | null = null

const hasMore = computed(() => offset.value + LIMIT < totalCount.value)

watch(query, (val) => {
  if (debounceTimer) clearTimeout(debounceTimer)
  if (!val.trim()) {
    gifs.value = []
    offset.value = 0
    totalCount.value = 0
    return
  }
  debounceTimer = setTimeout(() => {
    offset.value = 0
    fetchGifs()
  }, 500)
})

watch(tab, () => {
  gifs.value = []
  offset.value = 0
  totalCount.value = 0
  if (tab.value === 'trending') {
    fetchGifs()
  }
})

watch(open, (val) => {
  if (val) {
    gifs.value = []
    offset.value = 0
    query.value = ''
    tab.value = 'search'
  }
})

async function fetchGifs() {
  loading.value = true
  try {
    const endpoint =
      tab.value === 'search'
        ? `/giphy/search?q=${encodeURIComponent(query.value)}&limit=${LIMIT}&offset=${offset.value}`
        : `/giphy/trending?limit=${LIMIT}&offset=${offset.value}`

    const result = await api.get<GiphyResponse>(endpoint)
    if (offset.value === 0) {
      gifs.value = result.data
    } else {
      gifs.value.push(...result.data)
    }
    totalCount.value = result.pagination.total_count
  } finally {
    loading.value = false
  }
}

function loadMore() {
  offset.value += LIMIT
  fetchGifs()
}

function selectGif(gif: GiphyGif) {
  emit('select', gif.images.fixed_height.url)
  open.value = false
}
</script>

<style scoped>
.giphy-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(150px, 1fr));
  gap: 8px;
}
.giphy-item {
  cursor: pointer;
  border-radius: 4px;
  overflow: hidden;
  line-height: 0;
}
.giphy-item:hover {
  outline: 2px solid rgb(var(--v-theme-primary));
}
.giphy-item img {
  width: 100%;
  height: auto;
  display: block;
}
</style>
