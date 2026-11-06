<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Unrouted: backend preview and revision-bound decision are not wired yet. -->
<template>
  <v-container data-testid="native-ssh-approval" class="py-6">
    <v-card max-width="680" class="mx-auto pa-4">
      <h1 class="text-h5 mb-3">Approve shared SSH</h1>
      <p class="mb-4">Continue only if you started this SSH request. Compare the approval code with your native client.</p>
      <v-alert v-if="error" type="error" role="alert" class="mb-3">{{ error }}</v-alert>
      <v-alert v-if="approved" type="success" data-testid="native-ssh-approved">
        Approved. Return to your native client to continue.
      </v-alert>
      <template v-else>
        <form @submit.prevent="loadPreview">
          <v-text-field v-model="authorizationId" label="Request ID" autocomplete="off" :spellcheck="false" :disabled="busy" data-testid="native-ssh-authorization-id" />
          <v-text-field v-model="userCode" label="Approval code" autocomplete="off" autocapitalize="off" :spellcheck="false" :disabled="busy" data-testid="native-ssh-user-code" />
          <v-btn type="button" :disabled="busy || !validInput" :loading="busy && !preview" data-testid="native-ssh-preview" @click="loadPreview">Preview request</v-btn>
        </form>
        <section v-if="preview" class="mt-5" aria-label="Requested SSH access">
          <p data-testid="native-ssh-recipient">Recipient: {{ preview.scope.recipient.display_name }} ({{ preview.scope.recipient.username }}) — {{ preview.scope.recipient.id }}</p>
          <p data-testid="native-ssh-device">Device: {{ preview.scope.device.name }} — {{ preview.scope.device.id }} ({{ preview.scope.device.os }})</p>
          <p data-testid="native-ssh-os-account">OS account: {{ preview.scope.ssh_account }}</p>
          <p>Approval request expires: <time data-testid="native-ssh-request-expiry" :datetime="expiryIso">{{ expiryText }}</time></p>
          <p data-testid="native-ssh-session-duration">Maximum SSH session: {{ preview.scope.session_secs }} seconds</p>
          <v-btn type="button" color="primary" class="mt-3" :disabled="busy" :loading="busy" data-testid="native-ssh-approve" @click="approve">Approve this SSH request</v-btn>
        </section>
      </template>
    </v-card>
  </v-container>
</template>

<script setup lang="ts">
import { computed, onBeforeUnmount, ref, watch } from 'vue'
import { useAuthStore } from '@/stores/auth'
import { appPath } from '@/utils/deployment'

interface PreviewScope {
  authorization_id: string
  recipient: { id: string; username: string; display_name: string }
  device: { id: string; name: string; os: string }
  ssh_account: string
  request_expires_at_ms: number
  session_secs: number
  scope_revision: string
}
interface PendingPreview { scope: PreviewScope; id: string; code: string }

const auth = useAuthStore()
const authorizationId = ref('')
const userCode = ref('')
const preview = ref<PendingPreview | null>(null)
const busy = ref(false)
const approved = ref(false)
const error = ref('')
let epoch = 0
let mounted = true
const validInput = computed(() => /^[a-f\d]{24}$/i.test(authorizationId.value.trim()) && /^[\w-]{12}$/.test(userCode.value.trim()))
const expiryIso = computed(() => preview.value ? new Date(preview.value.scope.request_expires_at_ms).toISOString() : '')
const expiryText = computed(() => preview.value ? new Date(preview.value.scope.request_expires_at_ms).toLocaleString() : '')

watch([authorizationId, userCode], () => { preview.value = null; error.value = ''; epoch++ })
watch(() => auth.user?.id, () => { preview.value = null; userCode.value = ''; error.value = ''; epoch++ })
onBeforeUnmount(() => { mounted = false; epoch++; userCode.value = ''; preview.value = null })

async function post(path: string, body: unknown): Promise<unknown> {
  const response = await fetch(appPath(path), {
    method: 'POST',
    credentials: 'same-origin',
    cache: 'no-store',
    headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
    body: JSON.stringify(body),
  })
  if (!response.ok) throw new Error('Request refused')
  return response.json()
}

// Select only the displayed scope, not unexpected response fields. None of
// these checks authenticate the backend or turn a revision into authority.
function readPreview(raw: unknown, id: string): PreviewScope {
  const p = raw as Partial<PreviewScope> | null
  const text = (v: unknown): v is string => typeof v === 'string' && v.length > 0
  if (!p || p.authorization_id !== id || !p.recipient || p.recipient.id !== auth.user?.id
    || !text(p.recipient.username) || !text(p.recipient.display_name)
    || !p.device || !text(p.device.id) || !text(p.device.name) || !text(p.device.os)
    || !text(p.ssh_account) || !text(p.scope_revision)
    || typeof p.request_expires_at_ms !== 'number' || !Number.isFinite(p.request_expires_at_ms)
    || p.request_expires_at_ms <= Date.now()
    || typeof p.session_secs !== 'number' || !Number.isSafeInteger(p.session_secs) || p.session_secs <= 0) {
    throw new Error('Invalid preview')
  }
  return {
    authorization_id: id,
    recipient: { id: p.recipient.id, username: p.recipient.username, display_name: p.recipient.display_name },
    device: { id: p.device.id, name: p.device.name, os: p.device.os },
    ssh_account: p.ssh_account,
    request_expires_at_ms: p.request_expires_at_ms,
    session_secs: p.session_secs,
    scope_revision: p.scope_revision,
  }
}

async function loadPreview() {
  if (busy.value || !validInput.value || !auth.user?.id) return
  const id = authorizationId.value.trim().toLowerCase()
  const code = userCode.value.trim() // Case-sensitive; never normalize the approval code.
  const request = ++epoch
  preview.value = null
  error.value = ''
  busy.value = true
  try {
    const raw = await post(`/api/native/share-ssh/authorizations/${id}/preview`, { user_code: code })
    if (mounted && request === epoch) preview.value = { scope: readPreview(raw, id), id, code }
  } catch {
    if (mounted && request === epoch) error.value = 'Could not preview this request. Check the code and request expiry.'
  } finally {
    if (mounted) busy.value = false
  }
}

async function approve() {
  const pending = preview.value
  if (busy.value || !pending || pending.scope.recipient.id !== auth.user?.id) return
  if (pending.scope.request_expires_at_ms <= Date.now()) {
    preview.value = null
    error.value = 'This request has expired. Start a new request in your native client.'
    return
  }
  const request = ++epoch
  busy.value = true
  error.value = ''
  try {
    // The opaque SERVER-issued revision is echoed unchanged. Only the backend
    // can recompute the current complete scope and decide whether it matches.
    const result = await post(`/api/native/share-ssh/authorizations/${pending.id}/decision`, {
      user_code: pending.code,
      approve: true,
      expected_scope_revision: pending.scope.scope_revision,
    })
    if (!result || (result as { status?: unknown }).status !== 'approved') throw new Error('Not approved')
    if (mounted && request === epoch) {
      approved.value = true
      preview.value = null
      userCode.value = ''
    }
  } catch {
    if (mounted && request === epoch) {
      preview.value = null
      error.value = 'Approval was not confirmed. Preview the request again before trying.'
    }
  } finally {
    if (mounted) busy.value = false
  }
}
</script>
