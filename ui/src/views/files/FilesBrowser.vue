<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 G ROX EOOD -->
<template>
  <v-container fluid class="pa-2 pa-md-4 pa-xl-6">
    <div class="d-flex align-center flex-wrap ga-2 mb-2 mb-md-4">
      <h1 class="text-h5 text-md-h4">{{ $t('nav.files') }}</h1>
      <v-spacer />
      <!-- FR-11: server-side search over filename / display name.
           FR-116: a row of its own on a phone, under the title; the view
           toggle and Upload take the next one. -->
      <v-text-field
        v-model="gridSearch"
        density="compact"
        hide-details
        clearable
        prepend-inner-icon="mdi-magnify"
        :placeholder="t('mh.files.search')"
        :style="xs ? 'flex: 1 1 100%' : 'max-width: 240px'"
        :class="xs ? 'order-1' : 'flex-grow-0'"
      />
      <v-btn
        icon="mdi-table-cog"
        size="small"
        variant="text"
        :color="colsCustomized ? 'primary' : undefined"
        :title="t('mh.files.columns')"
        :aria-label="t('mh.files.columns')"
        @click="colDialogOpen = true"
      />
      <v-btn-toggle v-model="viewMode" mandatory density="compact" :class="{ 'order-2': xs }">
        <v-btn value="all" size="small">{{ t('mh.files.all') }}</v-btn>
        <v-btn value="room" size="small" :disabled="!currentRoomId">{{ t('mh.files.room') }}</v-btn>
      </v-btn-toggle>
      <v-btn
        color="primary"
        prepend-icon="mdi-upload"
        :class="{ 'order-2 flex-grow-1': xs }"
        @click="triggerUpload"
        :disabled="!currentRoomId"
      >
        {{ $t('files.upload') }}
      </v-btn>
      <input
        ref="fileInputRef"
        type="file"
        hidden
        multiple
        @change="handleFileSelect"
      />
    </div>

    <v-card>
      <v-data-table-server
        v-model:page="gridPage"
        v-model:items-per-page="gridPerPage"
        :headers="effectiveHeaders"
        :items="fileStore.files"
        :items-length="fileStore.total"
        :loading="fileStore.loading"
        :items-per-page-options="[10, 25, 50, 100]"
        density="compact"
        class="files-table"
        :class="{ 'files-table--stacked': xs }"
        item-value="id"
        :mobile="xs"
        @update:options="onGridOptions"
      >
        <template #item.filename="{ item }">
          <v-icon size="small" class="mr-2">{{ fileIcon(item.content_type) }}</v-icon>
          {{ item.filename }}
        </template>
        <template #item.room="{ item }">
          <router-link
            v-if="item.room_id"
            :to="{ name: 'room-chat', params: { tenantId: tenantId, roomId: item.room_id } }"
            class="text-decoration-none"
          >
            {{ item.room_name || item.room_id }}
          </router-link>
          <span v-else class="text-medium-emphasis">—</span>
        </template>
        <template #item.content_type="{ item }">
          {{ item.content_type }}
        </template>
        <template #item.size="{ item }">
          {{ formatSize(item.size) }}
        </template>
        <template #item.created_at="{ item }">
          {{ new Date(item.created_at).toLocaleDateString() }}
        </template>
        <template #item.actions="{ item }">
          <div class="text-no-wrap">
            <v-btn
              icon="mdi-download"
              size="small"
              variant="text"
              :href="fileStore.downloadUrl(tenantId, item.id)"
            />
            <v-btn
              icon="mdi-delete"
              size="small"
              variant="text"
              color="error"
              @click="handleDelete(item.id)"
            />
          </div>
        </template>
        <template #no-data>
          <div class="text-center pa-4 pa-md-6 text-medium-emphasis">
            {{ $t('files.noFiles') }}
          </div>
        </template>
      </v-data-table-server>
    </v-card>

    <GridColumnPickerDialog
      v-model="colDialogOpen"
      :entries="colEntries"
      @toggle="colToggle"
      @reorder="colReorder"
      @reset="colReset"
    />

    <!-- Upload progress -->
    <v-snackbar v-model="uploading" timeout="-1">
      {{ t('mh.files.uploading') }}
      <v-progress-linear indeterminate color="primary" />
    </v-snackbar>
  </v-container>
</template>

<script setup lang="ts">
import { ref, computed, watch } from 'vue'
import { useRoute } from 'vue-router'
import { useDisplay } from 'vuetify'
import { useFileStore } from '@/stores/files'
import { useRoomStore } from '@/stores/rooms'
import { useAuthStore } from '@/stores/auth'
import { useGridColumns } from '@/composables/useGridColumns'
import GridColumnPickerDialog from '@/components/common/GridColumnPickerDialog.vue'
import { useI18n } from 'vue-i18n'

const { t } = useI18n()

const route = useRoute()
const fileStore = useFileStore()
const roomStore = useRoomStore()
const auth = useAuthStore()
// FR-116 — below 600 px each file is a stacked row (Vuetify's mobile rows,
// from the same headers): only the name fitted, and Download / Delete were
// behind a sideways scroll inside the table.
const { xs } = useDisplay()

const tenantId = computed(() => route.params.tenantId as string)
const currentRoomId = computed(() => roomStore.current?.id || roomStore.rooms[0]?.id || '')
const fileInputRef = ref<HTMLInputElement | null>(null)
const uploading = ref(false)
const viewMode = ref<'all' | 'room'>('all')

// ── grid state (devices-grid kit, FR-11) ───────────────────────────

const gridPage = ref(1)
const gridPerPage = ref(25)
const gridSearch = ref('')
const gridSort = ref<string | undefined>(undefined)
const gridDir = ref<'asc' | 'desc' | undefined>(undefined)

const fileHeaders = computed(() => {
  const cols = [
    // Sortable keys double as the server whitelist (filename | size | created_at).
    { title: t('mh.files.col.name'), key: 'filename', sortable: true },
    { title: t('mh.files.col.room'), key: 'room', sortable: false },
    { title: t('mh.files.col.type'), key: 'content_type', sortable: false },
    { title: t('mh.files.col.size'), key: 'size', sortable: true },
    { title: t('mh.files.col.uploaded'), key: 'created_at', sortable: true },
    { title: t('mh.files.col.actions'), key: 'actions', sortable: false, align: 'end' as const },
  ]
  return viewMode.value === 'all' ? cols : cols.filter((c) => c.key !== 'room')
})
const colDialogOpen = ref(false)
const {
  effectiveHeaders,
  entries: colEntries,
  toggle: colToggle,
  reorder: colReorder,
  reset: colReset,
  customized: colsCustomized,
} = useGridColumns({
  headers: fileHeaders,
  gridId: 'files',
  scope: () => `${auth.user?.id ?? 'anon'}:${tenantId.value}`,
})

function fetchGrid() {
  const opts = {
    page: gridPage.value,
    perPage: gridPerPage.value,
    q: gridSearch.value || undefined,
    sort: gridSort.value,
    dir: gridDir.value,
  }
  if (viewMode.value === 'all') {
    void fileStore.fetchTenantFiles(tenantId.value, opts)
  } else if (currentRoomId.value) {
    void fileStore.fetchFiles(tenantId.value, currentRoomId.value, opts)
  }
}

/** v-data-table-server fires this once on mount too — it is the grid's ONLY
 *  fetch trigger for page/sort changes (a separate onMounted fetch would
 *  double-load). */
function onGridOptions(opts: {
  page: number
  itemsPerPage: number
  sortBy: Array<{ key: string; order: 'asc' | 'desc' }>
}) {
  gridPage.value = opts.page
  gridPerPage.value = opts.itemsPerPage
  gridSort.value = opts.sortBy[0]?.key
  gridDir.value = opts.sortBy[0]?.order
  fetchGrid()
}

let gridSearchTimer: ReturnType<typeof setTimeout> | undefined
watch(gridSearch, () => {
  if (gridSearchTimer) clearTimeout(gridSearchTimer)
  gridSearchTimer = setTimeout(() => {
    if (gridPage.value !== 1) gridPage.value = 1 // options handler fetches
    else fetchGrid()
  }, 300)
})

watch(viewMode, () => {
  if (gridPage.value !== 1) gridPage.value = 1 // options handler fetches
  else fetchGrid()
})

function triggerUpload() {
  fileInputRef.value?.click()
}

async function handleFileSelect(event: Event) {
  const input = event.target as HTMLInputElement
  const files = input.files
  if (!files?.length) return

  uploading.value = true
  const roomId = currentRoomId.value
  if (!roomId) return

  for (const file of files) {
    await fileStore.uploadFile(tenantId.value, roomId, file)
  }
  uploading.value = false
  input.value = ''
  fetchGrid()
}

async function handleDelete(fileId: string) {
  await fileStore.deleteFile(tenantId.value, fileId)
  fetchGrid()
}

function fileIcon(contentType: string): string {
  if (contentType.startsWith('image/')) return 'mdi-image'
  if (contentType.startsWith('video/')) return 'mdi-video'
  if (contentType.startsWith('audio/')) return 'mdi-music'
  if (contentType.includes('pdf')) return 'mdi-file-pdf-box'
  if (contentType.includes('spreadsheet') || contentType.includes('excel')) return 'mdi-file-excel'
  if (contentType.includes('document') || contentType.includes('word')) return 'mdi-file-word'
  return 'mdi-file'
}

function formatSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
}
</script>

<style scoped>
/* Never squeeze the columns into the viewport — cells keep their natural
   width and the WRAPPER scrolls horizontally (house rule: wide tables
   scroll in their own container). FR-116: the desktop layout only — in the
   stacked rows of a phone these rules pushed every value off the edge. */
.files-table :deep(.v-table__wrapper) {
  overflow-x: auto;
}
.files-table:not(.files-table--stacked) :deep(table) {
  width: max-content;
  min-width: 100%;
}
.files-table:not(.files-table--stacked) :deep(th),
.files-table:not(.files-table--stacked) :deep(td) {
  white-space: nowrap;
}
/* FR-116 — a stacked row's value can be one long unbroken token (an email,
   a file name): it wraps rather than widening the row past the screen. */
.files-table--stacked :deep(.v-data-table__td-value) {
  min-width: 0;
  overflow-wrap: anywhere;
}
</style>
