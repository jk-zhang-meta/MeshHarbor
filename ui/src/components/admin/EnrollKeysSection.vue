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
      Ephemeral enrollment keys
      <v-spacer />
      <v-btn
        color="primary"
        size="small"
        prepend-icon="mdi-key-plus"
        :loading="minting"
        @click="openMint"
      >
        Mint key
      </v-btn>
    </v-card-title>
    <v-card-text>
      <p class="text-body-2 text-medium-emphasis mb-3">
        A reusable credential that enrolls <strong>self-removing</strong> devices —
        CI runners, containers, autoscaled workers. Devices it mints are reaped
        after inactivity (or immediately on a clean stop), and a restart is a
        <em>new</em> device. Revoking a key stops new enrollments on the next
        use; devices it already minted die by their own deadline.
      </p>

      <!-- FR-116: `table-stack-xs` — on a phone each key is a block, with its
           state and Revoke on screen (both sat past the edge). -->
      <v-table v-if="keys.length" density="compact" class="table-stack-xs">
        <thead>
          <tr>
            <th>Label</th>
            <th>Uses</th>
            <th>Expires</th>
            <th>Device TTL</th>
            <th>State</th>
            <th class="text-right">Actions</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="k in keys" :key="k.id">
            <td>
              <span class="font-weight-medium">{{ k.label || '(unnamed)' }}</span>
              <div class="text-caption text-medium-emphasis">
                minted {{ fmtDate(k.created_at) }}
              </div>
            </td>
            <td data-label="Uses">{{ k.uses }} / {{ k.max_uses }}</td>
            <td data-label="Expires" :title="k.expires_at">{{ fmtDate(k.expires_at) }}</td>
            <td data-label="Device TTL">{{ k.ephemeral_ttl_secs ? `${k.ephemeral_ttl_secs}s` : 'default' }}</td>
            <td data-label="State">
              <v-chip v-if="k.revoked_at" size="x-small" color="error" variant="tonal">
                revoked
              </v-chip>
              <v-chip v-else-if="expired(k)" size="x-small" variant="tonal">expired</v-chip>
              <v-chip
                v-else-if="k.uses >= k.max_uses"
                size="x-small"
                color="warning"
                variant="tonal"
              >
                exhausted
              </v-chip>
              <v-chip v-else size="x-small" color="success" variant="tonal">active</v-chip>
            </td>
            <td class="text-right">
              <v-btn
                v-if="!k.revoked_at"
                size="x-small"
                variant="text"
                color="error"
                :aria-label="`Revoke key ${k.label || k.id}`"
                @click="revoke(k)"
              >
                Revoke
              </v-btn>
            </td>
          </tr>
        </tbody>
      </v-table>
      <div v-else class="text-center pa-4 text-medium-emphasis">
        No keys minted yet.
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
        {{ mintedKey ? 'Ephemeral key — shown once' : 'Mint ephemeral enrollment key' }}
      </v-card-title>
      <v-card-text v-if="!mintedKey">
        <v-text-field
          v-model="form.label"
          label="Label"
          placeholder="ci-runners"
          density="compact"
          hint="Display only — name the fleet this key serves"
          persistent-hint
          class="mb-2"
        />
        <v-text-field
          v-model.number="form.max_uses"
          label="Max uses"
          type="number"
          density="compact"
          hint="1–10 000; each enrollment consumes one"
          persistent-hint
          class="mb-2"
        />
        <v-text-field
          v-model.number="form.expires_in_days"
          label="Expires in (days)"
          type="number"
          density="compact"
          hint="Up to 90 days; the key is dead after this whatever its uses"
          persistent-hint
          class="mb-2"
        />
        <v-text-field
          v-model.number="form.ephemeral_ttl_secs"
          label="Device inactivity deadline (seconds, optional)"
          type="number"
          density="compact"
          hint="60s–7d; blank = server default (15 min). How long a silent device lives before the reaper removes it"
          persistent-hint
        />
        <v-alert v-if="mintError" type="error" variant="tonal" density="compact" class="mt-3">
          {{ mintError }}
        </v-alert>
      </v-card-text>
      <v-card-text v-else>
        <v-alert type="warning" variant="tonal" density="compact" class="mb-3">
          Copy it now — the key is <strong>not stored</strong> and cannot be
          shown again. Losing it means minting a new key.
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
          {{ copied ? 'Copied' : 'Copy key' }}
        </v-btn>
        <p class="text-caption text-medium-emphasis mt-3 mb-0">
          Enroll with:
          <code>roomlerd enroll --server {{ origin }} --token &lt;key&gt; --name &lt;label&gt; --ephemeral</code>
        </p>
      </v-card-text>
      <v-card-actions>
        <v-spacer />
        <v-btn v-if="!mintedKey" variant="text" @click="mintOpen = false">Cancel</v-btn>
        <v-btn v-if="!mintedKey" color="primary" :loading="minting" @click="mint">Mint</v-btn>
        <v-btn v-else color="primary" @click="closeMint">Done</v-btn>
      </v-card-actions>
    </v-card>
  </v-dialog>
</template>

<script setup lang="ts">
import { appOrigin } from '@/utils/deployment'
import { onMounted, reactive, ref, watch } from 'vue'
import { useAgentStore, type EnrollmentKeyRow } from '@/stores/agents'
import { useResponsiveDialog } from '@/composables/useResponsiveDialog'

const props = defineProps<{ tenantId: string }>()
const agentStore = useAgentStore()
const { fullscreen } = useResponsiveDialog()

const keys = ref<EnrollmentKeyRow[]>([])
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
})

function fmtDate(iso: string): string {
  const d = new Date(iso)
  return isNaN(d.getTime()) ? iso : d.toLocaleDateString()
}
function expired(k: EnrollmentKeyRow): boolean {
  const d = new Date(k.expires_at)
  return !isNaN(d.getTime()) && d.getTime() < Date.now()
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
