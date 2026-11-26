<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 G ROX EOOD -->
<!-- FR-51 P4 — ephemeral enrollment keys: mint / list / revoke.

     Renders NOTHING unless the org switch answered true (a member without
     MANAGE_TENANT gets null from the settings fetch, and the whole surface
     is meaningless while the class is off — SettingsSection owns the flip).
     The mint response's `key` is shown exactly ONCE: it is not stored and
     the list can never return it. -->
<template>
  <v-card v-if="agentStore.orgEphemeralKeysEnabled === true" class="mt-4">
    <v-card-title class="d-flex align-center flex-wrap ga-2">
      <v-icon icon="mdi-clock-fast" color="warning" class="mr-2" />
      {{ $t('mh.ek.title') }}
      <v-spacer />
      <v-btn
        color="primary"
        size="small"
        prepend-icon="mdi-key-plus"
        :loading="minting"
        @click="openMint"
      >
        {{ $t('mh.ek.mintKey') }}
      </v-btn>
    </v-card-title>
    <v-card-text>
      <p class="text-body-2 text-medium-emphasis mb-3">
        <i18n-t keypath="mh.ek.intro" tag="span">
          <template #selfRemoving><strong>{{ $t('mh.ek.selfRemoving') }}</strong></template>
          <template #new><em>{{ $t('mh.ek.new') }}</em></template>
        </i18n-t>
      </p>

      <!-- FR-116: `table-stack-xs` — on a phone each key is a block, with its
           state and Revoke on screen (both sat past the edge). FR-120 P4: the
           block is one line, the key's label, its state and Revoke, and opens
           on a tap for its uses, expiry, device deadline and mint date; 20 at
           a time. Six labelled blocks a key made the Devices page 2.5× its
           desktop height even with every device folded. One <template v-if>
           holds the table and its Show more, so the v-else below stays paired
           with it. -->
      <template v-if="keys.length">
        <v-table density="compact" class="table-stack-xs table-stack-xs--compact">
          <thead>
            <tr>
              <th>{{ $t('mh.ek.col.label') }}</th>
              <th>{{ $t('mh.ek.col.uses') }}</th>
              <th>{{ $t('mh.ek.col.expires') }}</th>
              <th>{{ $t('mh.ek.col.ttl') }}</th>
              <th>{{ $t('mh.ek.col.state') }}</th>
              <th class="text-right">{{ $t('mh.tp.col.actions') }}</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="k in visible" :key="k.id" :class="{ 'stack-open': isOpen(k.id) }">
              <td v-if="xs">
                <div class="d-flex align-center ga-2">
                  <button
                    type="button"
                    class="stack-toggle"
                    :aria-expanded="isOpen(k.id)"
                    data-testid="key-row-toggle"
                    @click="toggle(k.id)"
                  >
                    <span class="stack-toggle__text font-weight-medium">{{ k.label || $t('mh.ek.unnamed') }}</span>
                    <v-chip size="x-small" :color="keyState(k).color" variant="tonal" class="flex-shrink-0">
                      {{ keyState(k).text }}
                    </v-chip>
                    <v-icon size="small" class="flex-shrink-0" aria-hidden="true">
                      {{ isOpen(k.id) ? 'mdi-chevron-up' : 'mdi-chevron-down' }}
                    </v-icon>
                  </button>
                  <v-btn
                    v-if="!k.revoked_at"
                    size="x-small"
                    variant="text"
                    color="error"
                    class="flex-shrink-0"
                    :aria-label="$t('mh.ek.revokeAria', { key: k.label || k.id })"
                    @click="revoke(k)"
                  >
                    {{ $t('mh.ek.revoke') }}
                  </v-btn>
                </div>
              </td>
              <td v-else>
                <span class="font-weight-medium">{{ k.label || $t('mh.ek.unnamed') }}</span>
                <v-chip
                  v-if="k.gpu_server"
                  size="x-small"
                  color="info"
                  variant="tonal"
                  prepend-icon="mdi-expansion-card"
                  class="ml-1"
                >
                  GPU
                </v-chip>
                <div class="text-caption text-medium-emphasis">
                  {{ $t('mh.ek.minted', { when: fmtDate(k.created_at) }) }}
                </div>
              </td>
              <td v-if="xs" :data-label="$t('mh.ek.mintedLabel')" class="stack-detail">{{ fmtDate(k.created_at) }}</td>
              <td :data-label="$t('mh.ek.col.uses')" class="stack-detail">{{ k.uses }} / {{ k.max_uses }}</td>
              <td :data-label="$t('mh.ek.col.expires')" class="stack-detail" :title="k.expires_at">{{ fmtDate(k.expires_at) }}</td>
              <td :data-label="$t('mh.ek.col.ttl')" class="stack-detail">{{ k.ephemeral_ttl_secs ? `${k.ephemeral_ttl_secs}s` : 'default' }}</td>
              <td v-if="!xs" :data-label="$t('mh.ek.col.state')">
                <v-chip size="x-small" :color="keyState(k).color" variant="tonal">{{ keyState(k).text }}</v-chip>
              </td>
              <td v-if="!xs" class="text-right">
                <v-btn
                  v-if="!k.revoked_at"
                  size="x-small"
                  variant="text"
                  color="error"
                  :aria-label="$t('mh.ek.revokeAria', { key: k.label || k.id })"
                  @click="revoke(k)"
                >
                  {{ $t('mh.ek.revoke') }}
                </v-btn>
              </td>
            </tr>
          </tbody>
        </v-table>
        <div v-if="remaining" class="text-center mt-2">
          <v-btn variant="tonal" size="small" data-testid="keys-show-more" @click="showMore">
            {{ $t('mh.audit.showMore', { n: nextCount }) }}
          </v-btn>
        </div>
      </template>
      <div v-else class="text-center pa-4 text-medium-emphasis">
        {{ $t('mh.ek.empty') }}
      </div>

      <v-alert v-if="error" type="error" variant="tonal" density="compact" class="mt-3">
        {{ error }}
      </v-alert>
    </v-card-text>
  </v-card>

  <!-- Mint dialog. Two phases in one dialog: the form, then the one-time
       key reveal — deliberately not dismissible by a misclick once the key
       is showing (persistent), because there is no second look. -->
  <v-dialog v-model="mintOpen" max-width="560" :persistent="!!mintedKey" :fullscreen="fullscreen">
    <v-card>
      <v-card-title>
        {{ mintedKey ? $t('mh.ek.shownOnce') : $t('mh.ek.mintTitle') }}
      </v-card-title>
      <v-card-text v-if="!mintedKey">
        <v-text-field
          v-model="form.label"
          :label="$t('mh.ek.col.label')"
          placeholder="ci-runners"
          density="compact"
          :hint="$t('mh.ek.labelHint')"
          persistent-hint
          class="mb-2"
        />
        <v-text-field
          v-model.number="form.max_uses"
          :label="$t('mh.ek.maxUses')"
          type="number"
          density="compact"
          :hint="$t('mh.ek.maxUsesHint')"
          persistent-hint
          class="mb-2"
        />
        <v-text-field
          v-model.number="form.expires_in_days"
          :label="$t('mh.ek.expiresDays')"
          type="number"
          density="compact"
          :hint="$t('mh.ek.expiresHint')"
          persistent-hint
          class="mb-2"
        />
        <v-text-field
          v-model.number="form.ephemeral_ttl_secs"
          :label="$t('mh.ek.ttlLabel')"
          type="number"
          density="compact"
          :hint="$t('mh.ek.ttlHint')"
          persistent-hint
        />
        <v-checkbox
          v-model="form.gpu_server"
          density="compact"
          hide-details
          :label="$t('mh.ek.gpuServerLabel')"
          class="mt-2"
        />
        <p class="text-caption text-medium-emphasis mb-0">{{ $t('mh.ek.gpuServerHint') }}</p>
        <v-alert v-if="mintError" type="error" variant="tonal" density="compact" class="mt-3">
          {{ mintError }}
        </v-alert>
      </v-card-text>
      <v-card-text v-else>
        <v-alert type="warning" variant="tonal" density="compact" class="mb-3">
          <i18n-t keypath="mh.ek.copyNow" tag="span">
            <template #notStored><strong>{{ $t('mh.ek.notStored') }}</strong></template>
          </i18n-t>
        </v-alert>
        <v-textarea
          :model-value="mintedKey"
          readonly
          rows="4"
          density="compact"
          class="key-mono"
        />
        <v-btn
          block
          :prepend-icon="copied ? 'mdi-check' : 'mdi-content-copy'"
          :color="copied ? 'success' : 'primary'"
          variant="tonal"
          @click="copyKey"
        >
          {{ copied ? $t('mh.ek.copied') : $t('mh.ek.copyKey') }}
        </v-btn>
        <p class="text-caption text-medium-emphasis mt-3 mb-0">
          {{ $t('mh.ek.enrollWith') }}
          <code>meshharbord enroll --server {{ origin }} --token &lt;key&gt; --name &lt;label&gt; --ephemeral</code>
        </p>
      </v-card-text>
      <v-card-actions>
        <v-spacer />
        <v-btn v-if="!mintedKey" variant="text" @click="mintOpen = false">{{ $t('common.cancel') }}</v-btn>
        <v-btn v-if="!mintedKey" color="primary" :loading="minting" @click="mint">{{ $t('mh.ek.mint') }}</v-btn>
        <v-btn v-else color="primary" @click="closeMint">{{ $t('mh.ek.done') }}</v-btn>
      </v-card-actions>
    </v-card>
  </v-dialog>
</template>

<script setup lang="ts">
import { appOrigin } from '@/utils/deployment'
import { onMounted, reactive, ref, watch } from 'vue'
import { useDisplay } from 'vuetify'
import { useI18n } from 'vue-i18n'
import { useAgentStore, type EnrollmentKeyRow } from '@/stores/agents'
import { useOpenRows } from '@/composables/useOpenRows'
import { usePhoneSlice } from '@/composables/usePhoneSlice'
import { useResponsiveDialog } from '@/composables/useResponsiveDialog'

const props = defineProps<{ tenantId: string }>()
const { t } = useI18n()
const agentStore = useAgentStore()
const { fullscreen } = useResponsiveDialog()

const keys = ref<EnrollmentKeyRow[]>([])
// FR-120 P4 — on a phone a key is one line until tapped, 20 at a time.
const { xs } = useDisplay()
const { visible, remaining, nextCount, showMore } = usePhoneSlice(keys)
const { isOpen, toggle } = useOpenRows<string>()
const error = ref<string | null>(null)
const origin = appOrigin(window.location.origin)

const mintOpen = ref(false)
const minting = ref(false)
const mintError = ref<string | null>(null)
const mintedKey = ref<string | null>(null)
const copied = ref(false)
const form = reactive({
  label: '',
  max_uses: 100,
  expires_in_days: 30,
  ephemeral_ttl_secs: undefined as number | undefined,
  gpu_server: false,
})

function fmtDate(iso: string): string {
  const d = new Date(iso)
  return isNaN(d.getTime()) ? iso : d.toLocaleDateString()
}
function expired(k: EnrollmentKeyRow): boolean {
  const d = new Date(k.expires_at)
  return !isNaN(d.getTime()) && d.getTime() < Date.now()
}
/** A key's one state, in the order that decides it: revoked, expired,
 *  exhausted, else active. One chip for the desktop column and the phone line. */
function keyState(k: EnrollmentKeyRow): { text: string; color?: string } {
  if (k.revoked_at) return { text: t('mh.ek.state.revoked'), color: 'error' }
  if (expired(k)) return { text: t('mh.ek.state.expired') }
  if (k.uses >= k.max_uses) return { text: t('mh.ek.state.exhausted'), color: 'warning' }
  return { text: t('mh.ek.state.active'), color: 'success' }
}

async function refresh() {
  error.value = null
  try {
    keys.value = await agentStore.listEnrollKeys(props.tenantId)
  } catch (e) {
    error.value = (e as Error).message
  }
}

function openMint() {
  mintedKey.value = null
  mintError.value = null
  copied.value = false
  mintOpen.value = true
}

async function mint() {
  minting.value = true
  mintError.value = null
  try {
    const resp = await agentStore.mintEnrollKey(props.tenantId, {
      label: form.label || undefined,
      max_uses: form.max_uses || undefined,
      expires_in_secs: form.expires_in_days ? form.expires_in_days * 86_400 : undefined,
      ephemeral_ttl_secs: form.ephemeral_ttl_secs || undefined,
      gpu_server: form.gpu_server || undefined,
    })
    mintedKey.value = resp.key
    void refresh()
  } catch (e) {
    mintError.value = (e as Error).message
  } finally {
    minting.value = false
  }
}

async function copyKey() {
  if (!mintedKey.value) return
  try {
    await navigator.clipboard.writeText(mintedKey.value)
    copied.value = true
  } catch {
    // Clipboard can be unavailable (permissions, non-secure context); the
    // textarea stays selectable, so failing quietly beats a broken flow.
  }
}

function closeMint() {
  mintOpen.value = false
  // The reveal is over: never keep the secret in component state.
  mintedKey.value = null
}

async function revoke(k: EnrollmentKeyRow) {
  error.value = null
  try {
    await agentStore.revokeEnrollKey(props.tenantId, k.id)
    await refresh()
  } catch (e) {
    error.value = (e as Error).message
  }
}

onMounted(async () => {
  // The switch answer decides whether this card exists at all.
  await agentStore.fetchOrgEphemeralKeysEnabled(props.tenantId)
  if (agentStore.orgEphemeralKeysEnabled === true) void refresh()
})

// The org switch can flip while this page is open (SettingsSection).
watch(
  () => agentStore.orgEphemeralKeysEnabled,
  (v) => {
    if (v === true) void refresh()
  },
)
</script>

<style scoped>
.key-mono :deep(textarea) {
  font-family: monospace;
  font-size: 0.78rem;
}
</style>
