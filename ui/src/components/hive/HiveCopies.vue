<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 G ROX EOOD -->
<!--
  FR-90 P2j-1 — a session's copies, from its room: each device that holds one,
  why (it runs it, the owner's own device, an archive replica), whether it
  took it, and how far behind the primary's its copy is; a move in flight;
  and the owner's Move, to the copy that holds the most.

  Shown only for a record that carries a replicaset: a server that copies
  nothing, and a session placed nowhere, have no copies to show. Freshness is
  the server's own count (`holds`), the rule a move is decided by.
-->
<template>
  <v-dialog v-if="hasCopies" v-model="shown" max-width="600" scrollable :fullscreen="fullscreen">
    <template #activator="{ props: activator }">
      <v-btn
        v-bind="activator"
        size="small"
        variant="text"
        prepend-icon="mdi-content-duplicate"
        data-testid="hive-copies-open"
      >
        {{ $t('hive.roomCopies.button') }}
      </v-btn>
    </template>
    <v-card>
      <v-card-title class="d-flex align-center">
        <span class="text-wrap">{{ $t('hive.roomCopies.title') }}</span>
        <v-spacer />
        <v-btn icon="mdi-close" variant="text" size="small" :aria-label="$t('common.close')" @click="shown = false" />
      </v-card-title>
      <v-card-text>
        <p class="text-body-2 text-medium-emphasis mb-3">{{ $t('hive.roomCopies.explain') }}</p>
        <v-progress-linear v-if="loading" indeterminate class="mb-2" />
        <v-alert
          v-if="session?.promotion"
          type="info"
          variant="tonal"
          density="compact"
          class="mb-2"
          data-testid="hive-copies-moving"
        >
          {{ movingText }}
        </v-alert>
        <p v-if="shortText" class="text-caption text-medium-emphasis mb-2" data-testid="hive-copies-short">
          {{ shortText }}
        </p>
        <v-list density="compact" data-testid="hive-copies-members">
          <v-list-item
            v-for="m in members"
            :key="m.device_id"
            :data-device="m.device_id"
            :data-role="m.role"
            data-testid="hive-copy"
          >
            <v-list-item-title>{{ nameOf(m.device_id) }}</v-list-item-title>
            <v-list-item-subtitle data-testid="hive-copy-freshness">{{ freshness(m) }}</v-list-item-subtitle>
            <template #append>
              <v-chip size="small" variant="tonal" class="mr-1">
                {{ $t(`hive.roomCopies.role.${m.role}`, m.role) }}
              </v-chip>
              <v-chip size="small" variant="outlined" :color="m.state === 'refused' ? 'error' : undefined">
                {{ stateText(m) }}
              </v-chip>
            </template>
          </v-list-item>
        </v-list>

        <div v-if="isOwner" class="mt-3" data-testid="hive-copies-move">
          <v-btn-toggle v-model="action" mandatory density="compact" variant="outlined" divided class="mb-2">
            <v-btn value="move" size="small" data-testid="hive-copies-action-move">
              {{ $t('hive.roomCopies.actions.move') }}
            </v-btn>
            <v-btn value="teleport" size="small" data-testid="hive-copies-action-teleport">
              {{ $t('hive.roomCopies.actions.teleport') }}
            </v-btn>
            <v-btn value="fork" size="small" data-testid="hive-copies-action-fork">
              {{ $t('hive.roomCopies.actions.fork') }}
            </v-btn>
          </v-btn-toggle>

          <!-- P2j-2 — to a device that holds no copy: it takes one while the session runs. -->
          <template v-if="action === 'teleport'">
            <p class="text-caption text-medium-emphasis mb-1">{{ $t('hive.roomCopies.teleportExplain') }}</p>
            <p v-if="notMovable" class="text-caption text-medium-emphasis" data-testid="hive-copies-not-movable">
              {{ notMovable }}
            </p>
            <template v-else-if="teleports.length">
              <v-radio-group v-model="teleportTo" density="compact" hide-details>
                <v-radio
                  v-for="d in teleports"
                  :key="d.id"
                  :value="d.id"
                  :label="d.display_name || d.name"
                  :data-testid="`hive-copies-teleport-to-${d.id}`"
                />
              </v-radio-group>
              <v-text-field
                v-model="folder"
                :label="$t('hive.roomCopies.folder')"
                :hint="$t('hive.roomCopies.folderHint')"
                persistent-hint
                density="compact"
                class="mt-2"
                data-testid="hive-copies-teleport-folder"
              />
              <div class="d-flex justify-end mt-2">
                <v-btn
                  color="primary"
                  variant="flat"
                  size="small"
                  :loading="moving"
                  :disabled="!teleportTo"
                  data-testid="hive-copies-teleport-submit"
                  @click="teleportNow"
                >
                  {{ $t('hive.roomCopies.move') }}
                </v-btn>
              </div>
            </template>
            <p v-else-if="!loadingDevices" class="text-caption text-medium-emphasis" data-testid="hive-copies-no-teleport">
              {{ $t('hive.roomCopies.noTeleport') }}
            </p>
          </template>

          <!-- P2j-2 — a new session from this one's conversation, in a folder of its own. -->
          <template v-else-if="action === 'fork'">
            <p class="text-caption text-medium-emphasis mb-1">{{ $t('hive.roomCopies.forkExplain') }}</p>
            <p v-if="notForkable" class="text-caption text-medium-emphasis" data-testid="hive-copies-not-forkable">
              {{ notForkable }}
            </p>
            <template v-else-if="forks.length">
              <v-radio-group v-model="forkOn" density="compact" hide-details>
                <v-radio
                  v-for="f in forks"
                  :key="f.device.id"
                  :value="f.device.id"
                  :label="forkLabel(f)"
                  :data-testid="`hive-copies-fork-on-${f.device.id}`"
                />
              </v-radio-group>
              <v-text-field
                v-model="forkFolder"
                :label="$t('hive.roomCopies.forkFolder')"
                :hint="$t('hive.roomCopies.forkFolderHint')"
                persistent-hint
                density="compact"
                class="mt-2"
                data-testid="hive-copies-fork-folder"
              />
              <v-text-field
                v-model="forkTitle"
                :label="$t('hive.roomCopies.forkName')"
                :placeholder="$t('hive.roomCopies.forkNameDefault', { title: session?.title ?? '' })"
                density="compact"
                class="mt-2"
                data-testid="hive-copies-fork-title"
              />
              <div class="d-flex justify-end mt-2">
                <v-btn
                  color="primary"
                  variant="flat"
                  size="small"
                  :loading="moving"
                  :disabled="!forkOn || !forkFolder.trim()"
                  data-testid="hive-copies-fork-submit"
                  @click="forkNow"
                >
                  {{ $t('hive.roomCopies.fork') }}
                </v-btn>
              </div>
            </template>
            <p v-else-if="!loadingDevices" class="text-caption text-medium-emphasis" data-testid="hive-copies-no-fork">
              {{ $t('hive.roomCopies.noFork') }}
            </p>
          </template>

          <template v-else>
            <div class="text-subtitle-2">{{ $t('hive.roomCopies.moveTitle') }}</div>
            <p class="text-caption text-medium-emphasis mb-1">{{ $t('hive.roomCopies.moveExplain') }}</p>
            <p v-if="notMovable" class="text-caption text-medium-emphasis" data-testid="hive-copies-not-movable">
              {{ notMovable }}
            </p>
            <template v-else-if="targets.length">
              <v-radio-group v-model="target" density="compact" hide-details>
                <v-radio
                  v-for="m in targets"
                  :key="m.device_id"
                  :value="m.device_id"
                  :label="nameOf(m.device_id)"
                  :data-testid="`hive-copies-target-${m.device_id}`"
                />
              </v-radio-group>
              <v-text-field
                v-model="folder"
                :label="$t('hive.roomCopies.folder')"
                :hint="$t('hive.roomCopies.folderHint')"
                persistent-hint
                density="compact"
                class="mt-2"
                data-testid="hive-copies-folder"
              />
              <p v-if="ahead" class="text-caption text-warning mt-2" data-testid="hive-copies-ahead">
                {{ $t('hive.roomCopies.ahead', { device: nameOf(ahead.device_id) }) }}
              </p>
              <div class="d-flex justify-end mt-2">
                <v-btn
                  color="primary"
                  variant="flat"
                  size="small"
                  :loading="moving"
                  :disabled="!target"
                  data-testid="hive-copies-move-submit"
                  @click="move"
                >
                  {{ $t('hive.roomCopies.move') }}
                </v-btn>
              </div>
            </template>
            <p v-else class="text-caption text-medium-emphasis" data-testid="hive-copies-no-target">
              {{ $t('hive.roomCopies.noTarget') }}
            </p>
          </template>
          <v-alert
            v-if="outcome"
            :type="outcome.kind"
            variant="tonal"
            density="compact"
            class="mt-2"
            data-testid="hive-copies-outcome"
          >
            {{ outcome.text }}
          </v-alert>
          <div v-if="forkRoom" class="d-flex justify-end mt-2">
            <v-btn size="small" variant="tonal" :to="forkRoom" data-testid="hive-copies-fork-room">
              {{ $t('hive.roomCopies.openFork') }}
            </v-btn>
          </div>
        </div>
        <div v-if="error" class="text-caption text-error mt-2" data-testid="hive-copies-error">{{ error }}</div>
      </v-card-text>
      <v-card-actions>
        <v-spacer />
        <v-btn variant="text" @click="shown = false">{{ $t('common.close') }}</v-btn>
      </v-card-actions>
    </v-card>
  </v-dialog>
</template>

<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { isLive, useHiveStore, type HiveReplicaMember, type HiveSession } from '@/stores/hive'
import { useAgentStore } from '@/stores/agents'
import { useAuthStore } from '@/stores/auth'
import { deviceLabel } from '@/composables/useHideDeviceName'
import { useResponsiveDialog } from '@/composables/useResponsiveDialog'
import {
  aheadOfTargets,
  behind,
  forkTargets,
  freshestTarget,
  moveTargets,
  primaryOf,
  teleportTargets,
} from '@/utils/hiveCopies'

const props = defineProps<{ tenantId: string; sessionId: string }>()
const hive = useHiveStore()
const agents = useAgentStore()
const auth = useAuthStore()
const { t } = useI18n()

const shown = ref(false)
// FR-120 P2 — full screen on a phone (a centred 600 px box left ~264 px).
const { fullscreen } = useResponsiveDialog()
const loading = ref(false)
const error = ref<string | null>(null)
/** The record as read when the dialog opened, then as each move answers. */
const read = ref<HiveSession | null>(null)
const target = ref<string | null>(null)
const folder = ref('')
const moving = ref(false)
const outcome = ref<{ kind: 'success' | 'warning' | 'error'; text: string } | null>(null)
/** P2j-2 — the owner's action: a move to a copy, to a device with none, or a fork. */
const action = ref<'move' | 'teleport' | 'fork'>('move')
const teleportTo = ref<string | null>(null)
const forkOn = ref<string | null>(null)
const forkFolder = ref('')
const forkTitle = ref('')
/** The room of the fork just made, to open it. */
const forkRoom = ref<string | null>(null)
const loadingDevices = ref(false)
let devicesRead = false

const session = computed<HiveSession | null>(
  () => read.value ?? hive.sessions.find((s) => s.id === props.sessionId) ?? null,
)
const hasCopies = computed(() => !!session.value?.replicaset)
const members = computed(() => session.value?.replicaset?.members ?? [])
const primary = computed(() => (session.value ? primaryOf(session.value) : undefined))
const targets = computed(() => (session.value ? moveTargets(session.value) : []))
const ahead = computed(() => (session.value ? aheadOfTargets(session.value) : undefined))
const teleports = computed(() => (session.value ? teleportTargets(session.value, agents.agents) : []))
const forks = computed(() => (session.value ? forkTargets(session.value, agents.agents) : []))
/** Only the owner moves a session; the server says so to anyone else. */
const isOwner = computed(() => !!session.value && !!auth.user && session.value.owner_id === auth.user.id)

/** Why it cannot move now, in words; null when it can. */
const notMovable = computed(() => {
  const s = session.value
  if (!s) return null
  if (s.origin === 'adopted') return t('hive.roomCopies.adoptedStays')
  if (s.promotion) return t('hive.roomCopies.alreadyMoving')
  if (!isLive(s) || s.status === 'stopping') return t('hive.roomCopies.notRunning')
  return null
})

/** Why it cannot be forked now, in words; null when it can. An ended session
 *  forks from its copies: only a terminal's, and one being moved, do not. */
const notForkable = computed(() => {
  const s = session.value
  if (!s) return null
  if (s.origin === 'adopted') return t('hive.roomCopies.adoptedNoFork')
  if (s.promotion) return t('hive.roomCopies.forkWhileMoving')
  return null
})

function forkLabel(f: { device: { name: string; display_name?: string }; holds: boolean }): string {
  const name = f.device.display_name || f.device.name
  return t(f.holds ? 'hive.roomCopies.forkFromCopy' : 'hive.roomCopies.forkTakesCopy', { device: name })
}

const movingText = computed(() => {
  const p = session.value?.promotion
  if (!p) return ''
  // FR-116 AC4 — the device as the Devices page names it; the move's kept
  // machine name (`to_name`) only for a device this org no longer lists.
  const listed = agents.agents.find((x) => x.id === p.to)
  return t('hive.roomCopies.moving', {
    device: listed ? deviceLabel(listed) : p.to_name || nameOf(p.to),
    step: t(`hive.roomCopies.step.${p.state}`, p.state),
  })
})

const shortText = computed(() => {
  const short = session.value?.replicaset?.short
  return short ? t(`hive.roomCopies.short.${short}`, short) : null
})

function nameOf(deviceId: string): string {
  const a = agents.agents.find((x) => x.id === deviceId)
  if (a) return a.display_name || a.name
  if (session.value && deviceId === session.value.device_id && session.value.device_name) {
    return session.value.device_name
  }
  return t('hive.roomCopies.someDevice')
}

function freshness(m: HiveReplicaMember): string {
  if (m.holds === undefined) return t('hive.roomCopies.noTip')
  if (m.role === 'primary') return t('hive.roomCopies.runsIt', { n: m.holds })
  const k = behind(m, primary.value)
  if (k === null) return t('hive.roomCopies.holds', { n: m.holds })
  return k === 0
    ? t('hive.roomCopies.upToDate', { n: m.holds })
    : t('hive.roomCopies.behind', { k, n: m.holds })
}

function stateText(m: HiveReplicaMember): string {
  const word = t(`hive.roomCopies.state.${m.state}`, m.state)
  return m.state === 'refused' && m.refusal ? `${word}: ${m.refusal}` : word
}

async function load(): Promise<void> {
  loading.value = true
  error.value = null
  outcome.value = null
  try {
    const s = await hive.fetchSession(props.tenantId, props.sessionId)
    read.value = s
    folder.value = s.folder
    target.value = freshestTarget(s)?.device_id ?? null
    // Each device by its name: one read per device the page has not seen.
    for (const m of s.replicaset?.members ?? []) {
      if (!agents.agents.some((a) => a.id === m.device_id)) {
        await agents.fetchAgent(props.tenantId, m.device_id).catch(() => {})
      }
    }
  } catch (e) {
    error.value = (e as Error).message
  } finally {
    loading.value = false
  }
}

async function move(): Promise<void> {
  const s = session.value
  if (!s || !target.value || moving.value) return
  moving.value = true
  outcome.value = null
  try {
    const typed = folder.value.trim()
    const res = await hive.promote(props.tenantId, props.sessionId, {
      device_id: target.value,
      // The folder only when it differs: the server keeps the one it runs in.
      ...(typed && typed !== s.folder ? { folder: typed } : {}),
    })
    if (res.session) read.value = res.session
    outcome.value =
      res.outcome === 'refused'
        ? { kind: 'warning', text: res.message ?? t('hive.roomCopies.refused', { reason: res.reason ?? '' }) }
        : { kind: 'success', text: t(`hive.roomCopies.outcome.${res.outcome}`) }
  } catch (e) {
    outcome.value = { kind: 'error', text: (e as Error).message }
  } finally {
    moving.value = false
  }
}

/** P2j-2 — the organization's devices, read once a dialog opening needs them:
 *  a teleport and a fork may go to a device that holds no copy. */
async function readDevices(): Promise<void> {
  if (devicesRead || loadingDevices.value) return
  loadingDevices.value = true
  try {
    await agents.fetchAgents(props.tenantId)
    devicesRead = true
  } finally {
    loadingDevices.value = false
  }
  teleportTo.value ??= teleports.value[0]?.id ?? null
  forkOn.value ??= forks.value[0]?.device.id ?? null
}

async function teleportNow(): Promise<void> {
  const s = session.value
  if (!s || !teleportTo.value || moving.value) return
  moving.value = true
  outcome.value = null
  try {
    const typed = folder.value.trim()
    const res = await hive.teleport(props.tenantId, props.sessionId, {
      device_id: teleportTo.value,
      ...(typed && typed !== s.folder ? { folder: typed } : {}),
    })
    if (res.session) read.value = res.session
    outcome.value =
      res.outcome === 'refused'
        ? { kind: 'warning', text: res.message ?? t('hive.roomCopies.refused', { reason: res.reason ?? '' }) }
        : { kind: 'success', text: t(`hive.roomCopies.outcome.${res.outcome}`) }
  } catch (e) {
    outcome.value = { kind: 'error', text: (e as Error).message }
  } finally {
    moving.value = false
  }
}

async function forkNow(): Promise<void> {
  if (!forkOn.value || !forkFolder.value.trim() || moving.value) return
  moving.value = true
  outcome.value = null
  forkRoom.value = null
  try {
    const title = forkTitle.value.trim()
    const res = await hive.fork(props.tenantId, props.sessionId, {
      device_id: forkOn.value,
      folder: forkFolder.value.trim(),
      ...(title ? { title } : {}),
    })
    if (res.outcome === 'refused') {
      outcome.value = { kind: 'warning', text: res.message ?? t('hive.roomCopies.refused', { reason: res.reason ?? '' }) }
      return
    }
    outcome.value = { kind: 'success', text: t(`hive.roomCopies.forkOutcome.${res.outcome}`) }
    // The fork is a session of its own, with its own room.
    if (res.session?.room_id) forkRoom.value = `/tenant/${props.tenantId}/room/${res.session.room_id}`
  } catch (e) {
    outcome.value = { kind: 'error', text: (e as Error).message }
  } finally {
    moving.value = false
  }
}

watch(action, (a) => {
  outcome.value = null
  forkRoom.value = null
  if (a !== 'move') void readDevices()
})

watch(shown, (open) => {
  if (open) void load()
  else {
    read.value = null
    action.value = 'move'
  }
})
</script>
