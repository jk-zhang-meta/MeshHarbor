<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 G ROX EOOD -->
<!--
  FR-90 — your agent sessions: start one on a device, see where each stands,
  open its room, stop it. The list is the server's RECORD — the transcript
  itself lives on the device and is read in the session's room.

  P2i-3 — and, where the organization's copies can be searched, a search box:
  what is typed travels to the archive replica alone, over a peer of its own
  (`useHiveSearch`), and so does every hit.
-->
<template>
  <v-container fluid class="pa-2 pa-md-4 pa-xl-6">
    <div class="d-flex align-center mb-2 mb-md-4">
      <h1 class="text-h5 text-md-h4">{{ $t('hive.title') }}</h1>
      <v-spacer />
      <v-btn color="primary" prepend-icon="mdi-plus" data-testid="hive-start-open" @click="openStart">
        {{ $t('hive.start.button') }}
      </v-btn>
    </div>

    <v-text-field
      v-if="searchable"
      v-model="query"
      :label="$t('hive.search.label')"
      :hint="$t('hive.search.hint')"
      persistent-hint
      prepend-inner-icon="mdi-magnify"
      clearable
      :maxlength="MAX_QUERY_CHARS"
      :loading="search.searching.value"
      variant="outlined"
      density="comfortable"
      class="mb-2 mb-md-4"
      data-testid="hive-search"
      @keydown.enter="searchNow"
    />

    <div v-if="searchActive" data-testid="hive-search-results">
      <v-alert
        v-if="search.status.value === 'refused'"
        type="info"
        variant="tonal"
        density="compact"
        class="mb-2"
        data-testid="hive-search-refused"
      >
        {{ refusalText }}
      </v-alert>
      <v-alert
        v-else-if="search.error.value"
        type="warning"
        variant="tonal"
        density="compact"
        class="mb-2"
        data-testid="hive-search-error"
      >
        {{ $t('hive.search.failed', { error: search.error.value }) }}
      </v-alert>
      <v-alert v-if="openError" type="warning" variant="tonal" density="compact" class="mb-2">
        {{ openError }}
      </v-alert>
      <p
        v-if="search.answered.value === query?.trim() && search.hits.value.length === 0"
        class="text-body-2 text-medium-emphasis"
        data-testid="hive-search-none"
      >
        {{ $t('hive.search.none') }}
      </p>
      <v-list v-if="search.hits.value.length" lines="two">
        <v-list-item
          v-for="(h, i) in search.hits.value"
          :key="`${h.session}:${h.seq}:${i}`"
          :data-testid="`hive-hit-${i}`"
          @click="openHit(h)"
        >
          <template #prepend>
            <v-icon>mdi-text-search</v-icon>
          </template>
          <v-list-item-title>{{ hitTitle(h) }}</v-list-item-title>
          <!-- The device marks a match [ ]: drawn as <mark> from text, never as HTML. -->
          <v-list-item-subtitle class="hive-snippet" data-testid="hive-hit-snippet">
            <template v-for="(p, k) in snippetParts(h.snippet)" :key="k">
              <mark v-if="p.mark">{{ p.text }}</mark><span v-else>{{ p.text }}</span>
            </template>
          </v-list-item-subtitle>
        </v-list-item>
      </v-list>
      <p v-if="search.searched.value !== null" class="text-caption text-medium-emphasis mt-1" data-testid="hive-search-scope">
        {{ $t('hive.search.scope', { n: search.searched.value }) }}
      </p>
    </div>

    <v-card v-else-if="hive.loading && hive.sessions.length === 0">
      <v-card-text class="text-center"><v-progress-circular indeterminate /></v-card-text>
    </v-card>

    <v-card
      v-else-if="hive.sessions.length === 0"
      variant="outlined"
      class="text-center pa-4 pa-md-6 pa-lg-8"
    >
      <v-icon size="48" color="medium-emphasis" class="mb-2">mdi-robot-outline</v-icon>
      <h2 class="text-h6 mb-2">{{ $t('hive.empty.title') }}</h2>
      <p class="text-body-2 text-medium-emphasis">{{ $t('hive.empty.body') }}</p>
    </v-card>

    <v-list v-else lines="two">
      <v-list-item
        v-for="s in hive.sessions"
        :key="s.id"
        :to="s.room_id ? `/tenant/${tenantId}/room/${s.room_id}` : undefined"
        :data-testid="`hive-session-${s.id}`"
      >
        <template #prepend>
          <v-icon :color="statusColor(s.status)">{{ isLive(s) ? 'mdi-robot' : 'mdi-robot-off-outline' }}</v-icon>
        </template>
        <v-list-item-title>{{ s.title }}</v-list-item-title>
        <v-list-item-subtitle>
          <!-- FR-120 P2 — on a phone the state and "adopted" are words in this
               line, not chips beside it: chips and buttons left the title,
               device and folder 0–40 px at 360 px. -->
          <span v-if="xs" data-testid="hive-row-state">{{ $t(`hive.state.${s.status}`, s.status) }}<template v-if="isAdopted(s)"> · {{ $t('hive.adopted') }}</template> · </span>
          {{ agentLabel(s.device_id, s.device_name || s.device_id) }} · {{ s.folder }}
          <span v-if="s.account"> · {{ s.account }}</span>
          <span v-if="s.refusal"> · {{ s.refusal }}</span>
          <span v-else-if="s.end_reason"> · {{ s.end_reason }}</span>
        </v-list-item-subtitle>
        <!-- FR-120 P2 — on a phone the row's actions are one tap away in a
             menu; from 600 px they sit beside the row as before. -->
        <template v-if="xs" #append>
          <v-menu v-if="rowHasActions(s)" location="bottom end">
            <template #activator="{ props: menuProps }">
              <v-btn
                v-bind="menuProps"
                icon="mdi-dots-vertical"
                size="small"
                variant="text"
                :aria-label="$t('hive.rowActions')"
                :data-testid="`hive-row-menu-${s.id}`"
                @click.prevent.stop
              />
            </template>
            <v-list density="compact">
              <v-list-item
                v-if="isLive(s) && s.status !== 'stopping'"
                base-color="error"
                prepend-icon="mdi-stop"
                :title="isAdopted(s) ? $t('hive.stopMirroring') : $t('hive.stop')"
                @click="stopSession(s.id)"
              />
              <v-list-item
                v-if="copied && ownsIt(s)"
                prepend-icon="mdi-delete-forever-outline"
                :title="$t('hive.purge.open')"
                :data-testid="`hive-purge-open-${s.id}`"
                @click="askPurge(s)"
              />
            </v-list>
          </v-menu>
        </template>
        <template v-else #append>
          <v-chip size="small" variant="tonal" :color="statusColor(s.status)" class="mr-2">
            {{ $t(`hive.state.${s.status}`, s.status) }}
          </v-chip>
          <v-chip
            v-if="isAdopted(s)"
            size="small"
            variant="outlined"
            prepend-icon="mdi-console"
            class="mr-2"
            :title="$t('hive.adoptedExplain')"
            data-testid="hive-adopted"
          >
            {{ $t('hive.adopted') }}
          </v-chip>
          <v-btn
            v-if="isLive(s) && s.status !== 'stopping'"
            size="small"
            variant="text"
            color="error"
            :loading="stopping === s.id"
            @click.prevent.stop="stopSession(s.id)"
          >
            {{ isAdopted(s) ? $t('hive.stopMirroring') : $t('hive.stop') }}
          </v-btn>
          <!-- P2j-3 — only where sessions are copied (a purge is the replicaset's),
               on the owner's own sessions. -->
          <v-btn
            v-if="copied && ownsIt(s)"
            icon="mdi-delete-forever-outline"
            size="small"
            variant="text"
            :aria-label="$t('hive.purge.open')"
            :title="$t('hive.purge.open')"
            :data-testid="`hive-purge-open-${s.id}`"
            @click.prevent.stop="askPurge(s)"
          />
        </template>
      </v-list-item>
    </v-list>
    <!-- FR-120 P2 — every page of sessions, not only the first 50. -->
    <v-pagination
      v-if="pages > 1"
      v-model="page"
      :length="pages"
      :total-visible="xs ? 5 : 7"
      density="comfortable"
      class="mt-2"
      data-testid="hive-sessions-pager"
    />

    <v-dialog v-model="showStart" max-width="520" :fullscreen="fullscreen" scrollable>
      <v-card>
        <v-card-title class="d-flex align-center">
          <span class="text-wrap">{{ $t('hive.start.title') }}</span>
          <v-spacer />
          <v-btn icon="mdi-close" variant="text" size="small" :aria-label="$t('common.cancel')" @click="showStart = false" />
        </v-card-title>
        <v-card-text>
          <v-autocomplete
            v-model="form.device_id"
            :items="deviceItems"
            :label="$t('hive.start.device')"
            item-title="title"
            item-value="value"
            :loading="devices.loading"
            :no-data-text="$t('hive.start.noDevices')"
            data-testid="hive-start-device"
          />
          <v-text-field
            v-model="form.folder"
            :label="$t('hive.start.folder')"
            :hint="$t('hive.start.folderHint')"
            persistent-hint
            data-testid="hive-start-folder"
          />
          <v-text-field v-model="form.title" :label="$t('hive.start.sessionTitle')" class="mt-2" />
          <v-alert v-if="startError" type="warning" variant="tonal" density="compact" class="mt-2">
            {{ startError }}
          </v-alert>
        </v-card-text>
        <v-card-actions>
          <v-spacer />
          <v-btn @click="showStart = false">{{ $t('common.cancel') }}</v-btn>
          <v-btn
            color="primary"
            :loading="starting"
            :disabled="!form.device_id || !form.folder.trim()"
            data-testid="hive-start-submit"
            @click="startSession"
          >
            {{ $t('hive.start.submit') }}
          </v-btn>
        </v-card-actions>
      </v-card>
    </v-dialog>

    <hive-purge-dialog v-model="purgeShown" :tenant-id="tenantId" :session="purgeTarget" />
  </v-container>
</template>

<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, reactive, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useI18n } from 'vue-i18n'
import { isAdopted, isLive, useHiveStore, type HiveSession, type HiveSessionStatus } from '@/stores/hive'
import { useDeviceStore } from '@/stores/devices'
import { useAuthStore } from '@/stores/auth'
import { useNodeLabel } from '@/composables/useNodeLabel'
import { useDisplay } from 'vuetify'
import { useResponsiveDialog } from '@/composables/useResponsiveDialog'
import HivePurgeDialog from '@/components/hive/HivePurgeDialog.vue'
import { MAX_QUERY_CHARS, snippetParts, useHiveSearch, type SearchHit } from '@/composables/useHiveSearch'

const route = useRoute()
const router = useRouter()
const { t, te } = useI18n()
const hive = useHiveStore()
const devices = useDeviceStore()
const auth = useAuthStore()
const tenantId = computed(() => route.params.tenantId as string)
// FR-116 AC4 — a session names its device as the Devices page does: the
// session keeps the machine name it was made on (`device_name`), so a device
// renamed "Reception PC" read DESKTOP-… here. The join is the device id; the
// kept name only for a device this org no longer lists.
const { agentLabel, ensureLoaded } = useNodeLabel()

// ─── P2i-3 — the search box ────────────────────────────────────────────────

/** A search is asked this long after the last keystroke (Enter asks at once):
 *  the device takes one every 250 ms. */
const SEARCH_DEBOUNCE_MS = 300

const search = useHiveSearch()
const searchable = computed(() => hive.searchable[tenantId.value] === true)
const query = ref<string | null>('')
const searchActive = computed(() => searchable.value && (query.value ?? '').trim() !== '')
const openError = ref<string | null>(null)
let debounce: ReturnType<typeof setTimeout> | null = null

function stopDebounce(): void {
  if (debounce) clearTimeout(debounce)
  debounce = null
}

watch(query, (q) => {
  stopDebounce()
  openError.value = null
  const text = (q ?? '').trim()
  if (!text) {
    void search.run(tenantId.value, '')
    return
  }
  debounce = setTimeout(() => {
    debounce = null
    void search.run(tenantId.value, text)
  }, SEARCH_DEBOUNCE_MS)
})

function searchNow(): void {
  stopDebounce()
  void search.run(tenantId.value, query.value ?? '')
}

/** The refusal in words: a word this build knows, else the word itself,
 *  with the detail it came with. */
const refusalText = computed(() => {
  const word = search.reason.value ?? 'refused'
  const detail = search.detail.value
  const key = `hive.search.refused.${word}`
  const said = te(key) ? t(key) : t('hive.search.refusedOther', { reason: word })
  return detail ? `${said} (${detail})` : said
})

/** A session of yours by its title; one you read through a room says so
 *  until it is opened: titles are the server's, and a hit names an id. */
function hitTitle(h: SearchHit): string {
  return hive.sessions.find((s) => s.id === h.session)?.title || t('hive.search.otherSession')
}

async function openHit(h: SearchHit): Promise<void> {
  openError.value = null
  try {
    const known = hive.sessions.find((s) => s.id === h.session)
    const s = known?.room_id ? known : await hive.fetchSession(tenantId.value, h.session)
    if (s.room_id) await router.push(`/tenant/${tenantId.value}/room/${s.room_id}`)
    else openError.value = t('hive.search.noRoom')
  } catch (e) {
    openError.value = t('hive.search.openFailed', { message: (e as Error).message })
  }
}

// Another organization: its own box, its own peer.
watch(tenantId, (tid) => {
  stopDebounce()
  query.value = ''
  search.close()
  if (tid) void hive.checkSearchable(tid)
})

onBeforeUnmount(stopDebounce)

const showStart = ref(false)
const starting = ref(false)
const startError = ref<string | null>(null)
const stopping = ref<string | null>(null)
const form = reactive({ device_id: '' as string, folder: '', title: '' })

// ─── P2j-3 — a session deleted for good ────────────────────────────────────

/** Whether the server copies this organization's sessions: a purge is the
 *  replicaset's, and the route answers 404 everywhere else. */
const copied = computed(() => hive.copied[tenantId.value] === true)
/** Only its owner purges a session (`no_permission` otherwise), and the list
 *  also holds the sessions read from a room or a search hit. */
function ownsIt(s: HiveSession): boolean {
  return !!auth.user && s.owner_id === auth.user.id
}
const purgeShown = ref(false)
const purgeTarget = ref<HiveSession | null>(null)

// FR-120 P2 — a phone lays the row out differently (`xs`), and the Start
// dialog covers the screen there.
const { xs } = useDisplay()
const { fullscreen } = useResponsiveDialog()

/** Whether the row's ⋮ menu (a phone) has anything to offer. */
function rowHasActions(s: HiveSession): boolean {
  return (isLive(s) && s.status !== 'stopping') || (copied.value && ownsIt(s))
}

// FR-120 P2 — the list is paged (50 a page) and the view asked only for page 1.
const PER_PAGE = 50
const page = ref(1)
const pages = computed(() => Math.max(1, Math.ceil(hive.total / PER_PAGE)))
watch(page, (p) => void hive.fetchSessions(tenantId.value, p, PER_PAGE))

function askPurge(s: HiveSession): void {
  purgeTarget.value = s
  purgeShown.value = true
}

const deviceItems = computed(() =>
  devices.items
    .filter((d) => d.kind === 'agent' && d.presence === 'online')
    .map((d) => ({ title: d.display_name || d.name, value: d.id })),
)

function statusColor(s: HiveSessionStatus): string | undefined {
  switch (s) {
    case 'running':
    case 'awaiting_approval':
      return 'success'
    case 'idle':
    case 'starting':
      return 'info'
    case 'refused':
    case 'lost':
      return 'error'
    default:
      return undefined
  }
}

async function openStart(): Promise<void> {
  startError.value = null
  showStart.value = true
  await devices.fetchDevices(tenantId.value, { kind: 'agent', perPage: 100 })
}

async function startSession(): Promise<void> {
  starting.value = true
  startError.value = null
  try {
    const res = await hive.start(tenantId.value, {
      device_id: form.device_id,
      folder: form.folder.trim(),
      title: form.title.trim() || undefined,
    })
    if (res.outcome === 'refused') {
      startError.value = res.message ?? t('hive.start.refused', { reason: res.reason ?? '' })
      return
    }
    showStart.value = false
    if (res.session?.room_id) {
      await router.push(`/tenant/${tenantId.value}/room/${res.session.room_id}`)
    }
  } catch (e) {
    startError.value = (e as Error).message
  } finally {
    starting.value = false
  }
}

async function stopSession(id: string): Promise<void> {
  stopping.value = id
  try {
    await hive.stop(tenantId.value, id)
  } finally {
    stopping.value = null
  }
}

onMounted(() => {
  void hive.fetchSessions(tenantId.value)
  // Asked again at every visit: archive replicas come and go.
  void hive.checkSearchable(tenantId.value)
  // The devices each row is named by (the shell has usually loaded them).
  ensureLoaded(tenantId.value)
})
</script>

<style scoped>
.hive-snippet mark {
  background-color: rgba(var(--v-theme-primary), 0.2);
  color: inherit;
  border-radius: 2px;
  padding: 0 1px;
}
</style>
