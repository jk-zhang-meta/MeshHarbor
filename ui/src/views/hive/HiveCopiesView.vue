<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 G ROX EOOD -->
<!--
  FR-90 P2h-2 — agent copies: where the organization's agent sessions are
  copied (its replica policy, read here), and its archive replicas. A device
  offers itself as one (its owner's `hive_archive`, the `hive-archive` word it
  advertises); an administrator designates it (the policy's
  `archive_devices`). Both halves are needed before it holds anything.
  "Add an archive replica" mints an enrollment token and shows how to run the
  archive replica image with it. Shown only where the server copies sessions
  at all (`hive.replicaset`). P2j-4: an administrator edits the policy's rules
  in place, from the revision read.
-->
<template>
  <v-container fluid class="pa-2 pa-md-4 pa-xl-6">
    <div class="d-flex align-center mb-2 mb-md-4">
      <h1 class="text-h5 text-md-h4">{{ $t('hive.copies.title') }}</h1>
      <v-spacer />
      <v-chip v-if="policy?.is_default" size="small" variant="tonal" data-testid="hive-copies-defaults">
        {{ $t('hive.copies.policy.defaults') }}
      </v-chip>
    </div>
    <v-alert type="info" variant="tonal" density="compact" class="mb-2 mb-md-4" data-testid="hive-copies-about">
      {{ $t('hive.copies.about') }}
    </v-alert>
    <v-alert v-if="off" type="info" variant="tonal" density="compact" class="mb-2" data-testid="hive-copies-off">
      {{ $t('hive.copies.off') }}
    </v-alert>
    <v-alert v-else-if="loadError" type="warning" variant="tonal" density="compact" class="mb-2">
      {{ loadError }}
    </v-alert>

    <v-row v-if="policy">
      <v-col cols="12" lg="5">
        <v-card variant="outlined" data-testid="hive-copies-policy">
          <v-card-title class="d-flex align-center text-subtitle-1">
            {{ $t('hive.copies.policy.title') }}
            <v-spacer />
            <v-btn
              v-if="canSet && !draft"
              icon="mdi-pencil-outline"
              size="small"
              variant="text"
              :aria-label="$t('hive.copies.rules.edit')"
              :title="$t('hive.copies.rules.edit')"
              :disabled="busy"
              data-testid="hive-copies-rules-edit"
              @click="startEdit"
            />
          </v-card-title>
          <!-- P2j-4 — the rules, edited in place by an administrator. -->
          <template v-if="draft">
            <v-card-text data-testid="hive-copies-rules">
              <v-alert
                v-if="rulesError"
                type="error"
                variant="tonal"
                density="compact"
                class="mb-3"
                data-testid="hive-copies-rules-error"
              >
                {{ rulesError }}
              </v-alert>
              <div class="d-flex ga-3">
                <v-select
                  v-model="draft.min"
                  :items="counts"
                  :label="$t('hive.copies.rules.min')"
                  density="compact"
                  hide-details="auto"
                  data-testid="hive-copies-rules-min"
                />
                <v-select
                  v-model="draft.max"
                  :items="counts"
                  :label="$t('hive.copies.rules.max')"
                  :error-messages="maxError"
                  density="compact"
                  hide-details="auto"
                  data-testid="hive-copies-rules-max"
                />
              </div>
              <div class="text-caption text-medium-emphasis mt-1 mb-2">
                {{ $t('hive.copies.rules.copiesHint', { max: HIVE_MAX_MEMBERS }) }}
              </div>
              <v-switch
                v-model="draft.archive"
                :label="$t('hive.copies.rules.archive')"
                color="primary"
                density="compact"
                hide-details
                inset
                data-testid="hive-copies-rules-archive"
              />
              <v-switch
                v-model="draft.prefer"
                :label="$t('hive.copies.rules.prefer')"
                color="primary"
                density="compact"
                hide-details
                inset
                data-testid="hive-copies-rules-prefer"
              />
              <v-combobox
                v-model="draft.tags"
                :items="knownTags"
                :label="$t('hive.copies.rules.restricted')"
                :hint="$t('hive.copies.rules.restrictedHint')"
                persistent-hint
                multiple
                chips
                closable-chips
                density="compact"
                class="mt-3"
                data-testid="hive-copies-rules-tags"
              />
              <v-text-field
                v-model="draft.retention"
                type="number"
                min="0"
                :max="HIVE_MAX_RETENTION_DAYS"
                :label="$t('hive.copies.rules.retention')"
                :hint="$t('hive.copies.rules.retentionHint', { max: HIVE_MAX_RETENTION_DAYS })"
                persistent-hint
                :error-messages="retentionError"
                density="compact"
                class="mt-3"
                data-testid="hive-copies-rules-retention"
              />
            </v-card-text>
            <v-card-actions>
              <v-spacer />
              <v-btn variant="text" :disabled="saving" data-testid="hive-copies-rules-cancel" @click="cancelEdit">
                {{ $t('common.cancel') }}
              </v-btn>
              <v-btn
                color="primary"
                variant="flat"
                :loading="saving"
                :disabled="!canSave"
                data-testid="hive-copies-rules-save"
                @click="saveRules"
              >
                {{ $t('common.save') }}
              </v-btn>
            </v-card-actions>
          </template>
          <template v-else>
            <v-alert
              v-if="rulesNote"
              type="success"
              variant="tonal"
              density="compact"
              class="mx-4"
              data-testid="hive-copies-rules-saved"
            >
              {{ rulesNote }}
            </v-alert>
            <v-list density="compact">
              <v-list-item
                prepend-icon="mdi-content-copy"
                :title="$t('hive.copies.policy.copies', { min: policy.replicaset.min, max: policy.replicaset.max })"
                data-testid="hive-copies-policy-copies"
              />
              <v-list-item
                prepend-icon="mdi-archive-outline"
                :title="policy.replicaset.archive ? $t('hive.copies.policy.archive') : $t('hive.copies.policy.archiveOff')"
              />
              <v-list-item
                v-if="policy.replicaset.prefer.includes('owner_devices')"
                prepend-icon="mdi-account-outline"
                :title="$t('hive.copies.policy.prefer')"
              />
              <v-list-item
                v-if="policy.replicaset.restricted_tags.length"
                prepend-icon="mdi-tag-outline"
                :title="$t('hive.copies.policy.restricted', { tags: policy.replicaset.restricted_tags.join(', ') })"
              />
              <v-list-item
                prepend-icon="mdi-calendar-clock"
                :title="
                  policy.retention_days > 0
                    ? $t('hive.copies.policy.retention', { days: policy.retention_days })
                    : $t('hive.copies.policy.retentionForever')
                "
                data-testid="hive-copies-policy-retention"
              />
            </v-list>
          </template>
        </v-card>
      </v-col>

      <v-col cols="12" lg="7">
        <v-card variant="outlined" data-testid="hive-copies-archive">
          <v-card-title class="d-flex align-center flex-wrap ga-2 text-subtitle-1">
            {{ $t('hive.copies.archive.title') }}
            <v-spacer />
            <v-btn
              v-if="canSet"
              size="small"
              variant="tonal"
              prepend-icon="mdi-plus"
              data-testid="hive-copies-add"
              @click="openAdd"
            >
              {{ $t('hive.copies.archive.add') }}
            </v-btn>
          </v-card-title>
          <v-card-subtitle class="text-wrap">{{ $t('hive.copies.archive.hint') }}</v-card-subtitle>
          <v-card-text>
            <v-alert
              v-if="!anyArchiveOnline"
              type="warning"
              variant="tonal"
              density="compact"
              class="mb-2"
              data-testid="hive-copies-unreadable"
            >
              {{ $t('hive.copies.archive.unreadable') }}
            </v-alert>
            <v-alert
              v-if="archiveError"
              type="error"
              variant="tonal"
              density="compact"
              class="mb-2"
              data-testid="hive-copies-archive-error"
            >
              {{ archiveError }}
            </v-alert>
            <div v-if="rows.length === 0" class="text-medium-emphasis" data-testid="hive-copies-none">
              {{ $t('hive.copies.archive.none') }}
            </div>
            <v-list v-else density="compact">
              <v-list-item v-for="r in rows" :key="r.id" :data-testid="`hive-copies-device-${r.id}`">
                <template #prepend>
                  <v-icon :color="r.online ? 'success' : 'grey'" size="x-small" class="me-2">mdi-circle</v-icon>
                </template>
                <v-list-item-title>{{ r.name }}</v-list-item-title>
                <v-list-item-subtitle class="text-wrap">
                  {{
                    r.gone
                      ? $t('hive.copies.archive.gone')
                      : r.offers
                        ? $t('hive.copies.archive.offers')
                        : $t('hive.copies.archive.notOffering')
                  }}
                </v-list-item-subtitle>
                <template #append>
                  <v-switch
                    :model-value="r.designated"
                    :disabled="!canSet || busy || !!draft || (r.gone && !r.designated)"
                    :label="$t('hive.copies.archive.designated')"
                    color="primary"
                    density="compact"
                    hide-details
                    inset
                    :data-testid="`hive-copies-designate-${r.id}`"
                    @update:model-value="(on) => designate(r.id, on === true)"
                  />
                </template>
              </v-list-item>
            </v-list>
          </v-card-text>
        </v-card>
      </v-col>
    </v-row>

    <v-dialog v-model="adding" max-width="760" scrollable>
      <v-card data-testid="hive-copies-add-dialog">
        <v-card-title class="text-subtitle-1">{{ $t('hive.copies.add.title') }}</v-card-title>
        <v-card-text>
          <p class="mb-2">{{ $t('hive.copies.add.intro') }}</p>
          <v-alert type="warning" variant="tonal" density="compact" class="mb-2">
            {{ $t('hive.copies.add.volume') }}
          </v-alert>
          <p class="mb-3 text-medium-emphasis">{{ $t('hive.copies.add.hostname') }}</p>
          <v-alert v-if="mintError" type="error" variant="tonal" density="compact" class="mb-2" data-testid="hive-copies-mint-error">
            {{ mintError }}
          </v-alert>
          <v-btn
            v-if="!minted"
            color="primary"
            :loading="minting"
            prepend-icon="mdi-key-outline"
            data-testid="hive-copies-mint"
            @click="mint"
          >
            {{ $t('hive.copies.add.mint') }}
          </v-btn>
          <template v-else>
            <p class="mb-2" data-testid="hive-copies-token-note">
              {{ $t('hive.copies.add.token', { minutes: Math.max(1, Math.round(minted.expires_in / 60)) }) }}
            </p>
            <div v-for="s in snippets" :key="s.key" class="mb-3">
              <div class="d-flex align-center mb-1">
                <span class="text-subtitle-2">{{ $t(`hive.copies.add.${s.key}`) }}</span>
                <v-spacer />
                <v-btn
                  size="x-small"
                  variant="text"
                  :prepend-icon="copied === s.key ? 'mdi-check' : 'mdi-content-copy'"
                  :data-testid="`hive-copies-copy-${s.key}`"
                  @click="copy(s.key, s.text)"
                >
                  {{ copied === s.key ? $t('hive.copies.add.copied') : $t('hive.copies.add.copy') }}
                </v-btn>
              </div>
              <pre class="hive-copies-snippet pa-2" :data-testid="`hive-copies-snippet-${s.key}`">{{ s.text }}</pre>
            </div>
            <p class="text-medium-emphasis">{{ $t('hive.copies.add.next') }}</p>
          </template>
        </v-card-text>
        <v-card-actions>
          <v-spacer />
          <v-btn data-testid="hive-copies-add-close" @click="closeAdd">{{ $t('hive.copies.add.close') }}</v-btn>
        </v-card-actions>
      </v-card>
    </v-dialog>
  </v-container>
</template>

<script setup lang="ts">
import { appOrigin } from '@/utils/deployment'
import { computed, onMounted, ref, watch } from 'vue'
import { useRoute } from 'vue-router'
import { useI18n } from 'vue-i18n'
import { ApiError } from '@/api/client'
import {
  HIVE_ARCHIVE_CAP,
  HIVE_MAX_MEMBERS,
  HIVE_MAX_RETENTION_DAYS,
  HIVE_PREFER_OWNER_DEVICES,
  useHiveStore,
  type HivePolicy,
} from '@/stores/hive'
import { useAgentStore, type EnrollmentToken } from '@/stores/agents'
import { useTenantStore } from '@/stores/tenant'
import { canSetHivePolicy } from '@/utils/permissions'

/** The archive replica image (`Dockerfile.hive-archive`), as the
 *  `Archive replica image` workflow publishes it. */
const ARCHIVE_IMAGE = 'ghcr.io/gjovanov/roomler-ai/hive-archive:latest'

const route = useRoute()
const { t } = useI18n()
const hive = useHiveStore()
const agents = useAgentStore()
const tenants = useTenantStore()
const tenantId = computed(() => route.params.tenantId as string)

const policy = ref<HivePolicy | null>(null)
const off = ref(false)
const loadError = ref<string | null>(null)
const archiveError = ref<string | null>(null)
const busy = ref(false)
/** Designated devices the agents page did not hold, read one by one; `null`
 *  = not a device of this organization any more. */
const resolved = ref<Record<string, { name: string; online: boolean; offers: boolean } | null>>({})

const canSet = computed(() => canSetHivePolicy(tenants.myPermissions, tenants.isOwner))

interface Row {
  id: string
  name: string
  online: boolean
  offers: boolean
  designated: boolean
  gone: boolean
}

function offersArchive(rpc: string[] | undefined): boolean {
  return (rpc ?? []).includes(HIVE_ARCHIVE_CAP)
}

/** Every device that offers itself as an archive replica, and every one the
 *  policy designates, once each: the designated first. */
const rows = computed<Row[]>(() => {
  const designated = new Set(policy.value?.archive_devices ?? [])
  const out: Row[] = []
  for (const a of agents.agents) {
    const offers = offersArchive(a.capabilities?.rpc)
    if (!offers && !designated.has(a.id)) continue
    out.push({
      id: a.id,
      name: a.display_name || a.name,
      online: a.is_online === true,
      offers,
      designated: designated.has(a.id),
      gone: false,
    })
  }
  for (const id of designated) {
    if (out.some((r) => r.id === id)) continue
    const r = resolved.value[id]
    out.push({
      id,
      name: r?.name ?? id,
      online: r?.online ?? false,
      offers: r?.offers ?? false,
      designated: true,
      gone: r === null,
    })
  }
  return out.sort((a, b) => Number(b.designated) - Number(a.designated) || a.name.localeCompare(b.name))
})

/** A designated archive replica that offers itself and is online: until
 *  one is, a session is readable only while one of its members is. */
const anyArchiveOnline = computed(() => rows.value.some((r) => r.designated && r.offers && r.online))

async function loadPolicy(): Promise<void> {
  loadError.value = null
  try {
    policy.value = await hive.fetchPolicy(tenantId.value)
    off.value = false
  } catch (e) {
    if (e instanceof ApiError && e.status === 404) {
      off.value = true
      policy.value = null
    } else {
      loadError.value = (e as Error).message
    }
  }
}

/** The designated devices the agents page did not hold (it stops at the
 *  server's 100-row page): each read on its own, so a designation is never
 *  shown as missing. */
async function resolveDesignated(): Promise<void> {
  for (const id of policy.value?.archive_devices ?? []) {
    if (agents.agents.some((a) => a.id === id) || id in resolved.value) continue
    try {
      const a = await agents.fetchAgent(tenantId.value, id)
      resolved.value = {
        ...resolved.value,
        [id]: { name: a.display_name || a.name, online: a.is_online === true, offers: offersArchive(a.capabilities?.rpc) },
      }
    } catch {
      resolved.value = { ...resolved.value, [id]: null }
    }
  }
}

async function load(): Promise<void> {
  await Promise.all([loadPolicy(), agents.fetchAgents(tenantId.value), tenants.ensureMyMembership(tenantId.value)])
  await resolveDesignated()
}

/** Designate a device an archive replica, or stop: the whole policy, from
 *  the revision read. One changed meanwhile is read again and said so. */
async function designate(id: string, on: boolean): Promise<void> {
  const p = policy.value
  if (!p || busy.value) return
  archiveError.value = null
  busy.value = true
  const archive_devices = p.archive_devices.filter((d) => d !== id)
  if (on) archive_devices.push(id)
  try {
    policy.value = await hive.putPolicy(tenantId.value, {
      replicaset: p.replicaset,
      retention_days: p.retention_days,
      archive_devices,
      revision: p.revision,
    })
  } catch (e) {
    if (e instanceof ApiError && e.status === 409) {
      archiveError.value = t('hive.copies.archive.stale')
      await loadPolicy()
    } else {
      // The server's words: a device that cannot be an archive replica, or
      // a caller who may not designate one.
      archiveError.value = (e as Error).message
    }
  } finally {
    busy.value = false
  }
}

// ─── P2j-4 — the policy's rules, edited by an administrator ───────────────

/** The rules as the form edits them, the days as typed. */
interface Draft {
  min: number
  max: number
  archive: boolean
  prefer: boolean
  tags: string[]
  retention: string
}

function draftOf(p: HivePolicy): Draft {
  return {
    min: p.replicaset.min,
    max: p.replicaset.max,
    archive: p.replicaset.archive,
    prefer: p.replicaset.prefer.includes(HIVE_PREFER_OWNER_DEVICES),
    tags: [...p.replicaset.restricted_tags],
    retention: String(p.retention_days),
  }
}

/** `prefer` as written: as read while its switch is unchanged, so a word a
 *  newer server knows survives the write. */
function preferOf(read: string[], on: boolean): string[] {
  if (on === read.includes(HIVE_PREFER_OWNER_DEVICES)) return [...read]
  return on ? [HIVE_PREFER_OWNER_DEVICES, ...read] : read.filter((w) => w !== HIVE_PREFER_OWNER_DEVICES)
}

const counts = Array.from({ length: HIVE_MAX_MEMBERS }, (_, i) => i + 1)
/** The policy the form was opened on. Its write names this revision, never
 *  a later one, so a change made meanwhile can only come back a 409. */
const editedFrom = ref<HivePolicy | null>(null)
const draft = ref<Draft | null>(null)
const saving = ref(false)
const rulesError = ref<string | null>(null)
const rulesNote = ref<string | null>(null)

/** The tags the organization's devices carry, offered first. */
const knownTags = computed(() => [...new Set(agents.agents.flatMap((a) => a.tags ?? []))].sort())

const maxError = computed<string[]>(() =>
  draft.value && draft.value.max < draft.value.min ? [t('hive.copies.rules.maxBelowMin')] : [],
)
/** The days typed, if they are a whole number the server keeps. */
const retentionDays = computed<number | null>(() => {
  const raw = String(draft.value?.retention ?? '').trim()
  if (!/^\d+$/.test(raw)) return null
  const n = Number(raw)
  return n <= HIVE_MAX_RETENTION_DAYS ? n : null
})
const retentionError = computed<string[]>(() =>
  draft.value && retentionDays.value === null
    ? [t('hive.copies.rules.retentionInvalid', { max: HIVE_MAX_RETENTION_DAYS })]
    : [],
)
const changed = computed(
  () => !!draft.value && !!editedFrom.value && JSON.stringify(draft.value) !== JSON.stringify(draftOf(editedFrom.value)),
)
const canSave = computed(
  () => changed.value && maxError.value.length === 0 && retentionDays.value !== null && !saving.value,
)

function startEdit(): void {
  const p = policy.value
  if (!p) return
  editedFrom.value = p
  draft.value = draftOf(p)
  rulesError.value = null
  rulesNote.value = null
}

function cancelEdit(): void {
  editedFrom.value = null
  draft.value = null
  rulesError.value = null
}

/** The whole policy, the rules as edited and everything else as read. One
 *  changed meanwhile is read again and shown as it is now, never written
 *  over in silence; any other refusal is the server's words, the draft
 *  kept. */
async function saveRules(): Promise<void> {
  const p = editedFrom.value
  const d = draft.value
  const days = retentionDays.value
  if (!p || !d || days === null || !canSave.value) return
  rulesError.value = null
  saving.value = true
  try {
    policy.value = await hive.putPolicy(tenantId.value, {
      replicaset: {
        ...p.replicaset,
        min: d.min,
        max: d.max,
        archive: d.archive,
        prefer: preferOf(p.replicaset.prefer, d.prefer),
        restricted_tags: [...d.tags],
      },
      retention_days: days,
      archive_devices: p.archive_devices,
      revision: p.revision,
    })
    cancelEdit()
    rulesNote.value = t('hive.copies.rules.saved')
  } catch (e) {
    if (e instanceof ApiError && e.status === 409) {
      await loadPolicy()
      if (policy.value && !loadError.value) startEdit()
      rulesError.value = t('hive.copies.rules.stale')
    } else {
      rulesError.value = (e as Error).message
    }
  } finally {
    saving.value = false
  }
}

const adding = ref(false)
const minting = ref(false)
const minted = ref<EnrollmentToken | null>(null)
const mintError = ref<string | null>(null)
const copied = ref<string | null>(null)

function openAdd(): void {
  minted.value = null
  mintError.value = null
  copied.value = null
  adding.value = true
}

/** The token is shown only while the dialog is open: closing it drops it. */
function closeAdd(): void {
  adding.value = false
  minted.value = null
  copied.value = null
}

async function mint(): Promise<void> {
  mintError.value = null
  minting.value = true
  try {
    minted.value = await agents.issueEnrollmentToken(tenantId.value)
  } catch (e) {
    mintError.value = (e as Error).message
  } finally {
    minting.value = false
  }
}

/** How to run the image with the minted token, against this server. */
const snippets = computed(() => {
  const token = minted.value?.enrollment_token ?? ''
  const server = appOrigin(window.location.origin)
  return [
    {
      key: 'docker',
      text: [
        'docker run -d --name hive-archive --hostname hive-archive-1 \\',
        '  --restart unless-stopped -v hive-archive:/data \\',
        `  -e ROOMLER_SERVER=${server} \\`,
        `  -e ROOMLER_ENROLL_TOKEN=${token} \\`,
        `  ${ARCHIVE_IMAGE}`,
      ].join('\n'),
    },
    {
      key: 'compose',
      text: [
        'services:',
        '  hive-archive:',
        `    image: ${ARCHIVE_IMAGE}`,
        '    hostname: hive-archive-1',
        '    restart: unless-stopped',
        '    volumes:',
        '      - hive-archive:/data',
        '    environment:',
        `      ROOMLER_SERVER: ${server}`,
        `      ROOMLER_ENROLL_TOKEN: ${token}`,
        'volumes:',
        '  hive-archive: {}',
      ].join('\n'),
    },
  ]
})

async function copy(key: string, text: string): Promise<void> {
  try {
    await navigator.clipboard.writeText(text)
    copied.value = key
  } catch (e) {
    // The snippet is on screen to copy by hand.
    console.warn('[hive] could not copy the snippet', e)
  }
}

watch(tenantId, () => {
  resolved.value = {}
  cancelEdit()
  rulesNote.value = null
  void load()
})

onMounted(() => {
  void load()
})
</script>

<style scoped>
.hive-copies-snippet {
  background: rgba(var(--v-theme-on-surface), 0.05);
  border-radius: 4px;
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  font-size: 0.8125rem;
  overflow-x: auto;
  white-space: pre;
}
</style>
