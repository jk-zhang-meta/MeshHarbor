<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<template>
  <v-container>
    <h1 class="text-h5 mb-3">Device shares</h1>
    <p class="mb-3">An explicit share grants one approved person access to one device. It does not add organization membership, LAN access, exit routing or resharing.</p>
    <v-alert v-if="error" type="error" class="mb-3">{{ error }}</v-alert>
    <v-tabs v-model="direction"><v-tab value="received">Shared with me</v-tab><v-tab value="sent">Shared by me</v-tab></v-tabs>
    <v-btn class="my-3" :loading="loading" @click="load">Refresh</v-btn>
    <v-progress-linear v-if="loading" indeterminate />
    <v-table><thead><tr><th>Device</th><th>Owner → Recipient</th><th>Services</th><th>Created</th><th>Expires</th><th>Record state</th><th>Revoked</th><th>Actions</th></tr></thead><tbody>
      <tr v-for="s in items" :key="s.id"><td>{{ s.device_id }}</td><td>{{ s.owner_user_id }} → {{ s.recipient_user_id }}</td><td>{{ serviceLabel(s) }}</td><td>{{ s.created_at_ms === undefined ? 'Not reported by this server' : new Date(s.created_at_ms).toLocaleString() }}</td><td>{{ new Date(s.expires_at_ms).toLocaleString() }}</td><td :data-testid="'share-state-' + s.id">{{ shareRecordState(s, now) }}<br /><small>Grant {{ s.id }} · revision {{ s.revision }}</small></td><td>{{ s.revoked_at_ms === null ? '—' : new Date(s.revoked_at_ms).toLocaleString() }}</td><td>
        <v-btn v-if="direction === 'received'" size="small" :disabled="!shareLive(s, now) || !sharedRemotePermissions(s.permissions)" :to="nativeDesktop ? undefined : { name: 'shared-remote', params: { shareId: s.id } }" :href="nativeDesktop ? sharedRemoteUrl(s) : undefined" :target="nativeDesktop ? '_blank' : undefined" :rel="nativeDesktop ? 'noopener noreferrer' : undefined">Open desktop / files</v-btn>
        <v-btn v-if="direction === 'received' && s.permissions.ssh" size="small" class="ml-2" data-testid="shared-ssh-open" :data-share-id="s.id" :disabled="!shareLive(s, now)" @click="openSsh(s)">SSH (native client)</v-btn>
        <v-btn v-if="direction === 'sent' && s.revoked_at_ms === null" size="small" color="error" :disabled="saving" @click="pendingRevoke = s">Revoke</v-btn>
        <span v-if="s.revoked_at_ms !== null">Revoked</span>
      </td></tr>
      <tr v-if="!loading && !items.length"><td colspan="8">No shares in this view.</td></tr>
    </tbody></v-table>
    <p class="text-body-2 mt-2">{{ total }} retained sharing records in this direction, not a unique-device count. Expired and revoked records remain visible. Each record identifies the device, grantor/recipient, permissions, creation, expiry, revocation and revision. Record state does not override device policy or consent.</p>
    <v-pagination v-model="page" :length="Math.max(1, Math.ceil(total / 20))" :disabled="loading" />
    <v-expansion-panels class="mt-4"><v-expansion-panel title="Share a device I own"><v-expansion-panel-text>
      <v-form @submit.prevent="create">
        <v-text-field data-testid="share-device-id" v-model="deviceId" label="Device ID (one device you own)" required />
        <v-text-field data-testid="share-recipient-id" v-model="recipientId" label="Approved recipient user ID" required />
        <v-checkbox data-testid="share-ssh-permission" v-model="ssh" label="SSH shell / exec (native client)" />
        <v-checkbox data-testid="share-desktop-permission" v-model="desktopView" label="View desktop" /><v-checkbox v-model="desktopControl" :disabled="!desktopView" label="Control desktop" />
        <v-checkbox data-testid="share-files-permission" v-model="files" label="Bidirectional file transfer (read AND write)" />
        <v-text-field v-model.number="hours" label="Expiry in hours (maximum 720)" type="number" min="1" max="720" />
        <v-alert type="info" variant="tonal" class="mb-3">Device consent and service settings still apply. Read-only file transfer is not supported by the current native file protocol. SSH sharing does not enable the device’s SSH service or organization policy. The approved recipient signs in through the native client with a hidden password prompt; a manually provisioned token file is optional. It does not enable desktop access or TCP forwarding.</v-alert>
        <v-btn data-testid="share-create" type="submit" color="primary" :loading="saving">Create explicit share</v-btn>
      </v-form>
    </v-expansion-panel-text></v-expansion-panel></v-expansion-panels>
    <v-dialog :model-value="sshShare !== null" max-width="760" @update:model-value="v => { if (!v) closeSsh() }">
      <v-card data-testid="shared-ssh-instructions">
        <v-card-title>SSH through the native client</v-card-title>
        <v-card-text>
          <v-alert type="info" variant="tonal" class="mb-3">This is an access check and instructions, not an SSH session or a browser terminal. Device consent and SSH policy still apply. The device runs its built-in SSH server; it does not need a system sshd.</v-alert>
          <v-progress-linear v-if="sshLoading" indeterminate data-testid="shared-ssh-loading" />
          <v-alert v-if="sshError" type="error" data-testid="shared-ssh-error">{{ sshError }}</v-alert>
          <template v-if="sshDevice">
            <p data-testid="shared-ssh-device">Shared device: {{ sshDevice.name }} ({{ sshDevice.id }})</p>
            <p>Server base URL: <code>{{ sshServerBase }}</code></p>
            <p class="mt-2">Public host key (the native client verifies this identity):</p>
            <pre class="text-wrap" data-testid="shared-ssh-host-key">{{ sshDevice.host_pubkey }}</pre>
            <p class="mt-3">Run the native CLI locally, replacing the server URL and account-name placeholders:</p>
            <pre class="text-wrap" data-testid="shared-ssh-command">roomlerd cli share-ssh --server YOUR_SERVER_BASE_URL --share {{ sshShare?.id }} --login --username YOUR_ACCOUNT_USERNAME</pre>
            <v-alert type="warning" variant="tonal" class="mt-3">The CLI still needs a local SSH client. With --login, enter your MeshHarbor account password at its hidden terminal prompt; the token remains in process memory. This page does not export your HttpOnly web session or launch a command. Never put a password or access token in a command, URL, or shared clipboard. MFA-required native access fails closed until a supported MFA handoff is available.</v-alert>
            <p class="mt-2">SSH grants shell/exec as the device’s configured OS account, not a sandbox. This share does not grant SFTP, SSH forwarding, LAN access, or organization membership. The CLI rechecks authorization when it connects; revocation or expiry refuses new access and terminates share-bound sessions.</p>
          </template>
        </v-card-text>
        <v-card-actions><v-spacer /><v-btn data-testid="shared-ssh-close" @click="closeSsh">Close</v-btn></v-card-actions>
      </v-card>
    </v-dialog>
    <v-dialog :model-value="pendingRevoke !== null" max-width="480" @update:model-value="v => { if (!v && !saving) pendingRevoke = null }"><v-card><v-card-title>Revoke this device share?</v-card-title><v-card-text>New access will be refused. Share-bound remote sessions are terminated by live server checks.</v-card-text><v-card-actions><v-spacer /><v-btn :disabled="saving" @click="pendingRevoke = null">Cancel</v-btn><v-btn color="error" :loading="saving" @click="revoke">Revoke</v-btn></v-card-actions></v-card></v-dialog>
  </v-container>
</template>
<script setup lang="ts">
import { computed, ref, watch, onBeforeUnmount } from 'vue'
import { useRoute } from 'vue-router'
import { api } from '@/api/client'
import { useAuthStore } from '@/stores/auth'
import { appOrigin } from '@/utils/deployment'
import { sharedRemotePermissions, shareLive, shareRecordState, type DeviceShare } from '@/utils/deviceShare'
const auth = useAuthStore(), route = useRoute()
const nativeDesktop = computed(() => route.query.desktop === '1')
const now = ref(Date.now()), recordClock = setInterval(() => { now.value = Date.now() }, 1000)
function sharedRemoteUrl(share: DeviceShare) { return `${appOrigin(window.location.origin).replace(/\/$/, '')}/device-shares/${encodeURIComponent(share.id)}/remote` }
const direction = ref<'received' | 'sent'>(route.query.direction === 'sent' ? 'sent' : 'received'), page = ref(1), total = ref(0)
const items = ref<DeviceShare[]>([]), loading = ref(false), saving = ref(false), error = ref('')
const deviceId = ref(''), recipientId = ref(''), hours = ref(24), desktopView = ref(true), desktopControl = ref(false), files = ref(false), ssh = ref(false)
const pendingRevoke = ref<DeviceShare | null>(null)
interface SharedSshDevice { id: string; name: string; host_pubkey: string }
const sshShare = ref<DeviceShare | null>(null), sshDevice = ref<SharedSshDevice | null>(null), sshLoading = ref(false), sshError = ref('')
const sshServerBase = appOrigin(window.location.origin)
let sshGeneration = 0
function closeSsh() { sshGeneration++; sshShare.value = null; sshDevice.value = null; sshError.value = ''; sshLoading.value = false }
async function openSsh(share: DeviceShare) {
  closeSsh()
  if (direction.value !== 'received' || !share.permissions.ssh || !shareLive(share)) return
  const user = auth.user?.id; if (!user) return
  sshShare.value = share; sshLoading.value = true
  const attempt = sshGeneration, identity = identityGeneration
  try {
    const device = await api.get<SharedSshDevice>(`/device-shares/${encodeURIComponent(share.id)}/ssh`)
    if (!alive || attempt !== sshGeneration || identity !== identityGeneration || auth.user?.id !== user) return
    if (device.id !== share.device_id) throw new Error('The shared device identity changed. Refresh the share list before trying again.')
    sshDevice.value = device
  } catch (e) { if (alive && attempt === sshGeneration && identity === identityGeneration && auth.user?.id === user) sshError.value = (e as Error).message || 'Could not check shared SSH access.' }
  finally { if (alive && attempt === sshGeneration && identity === identityGeneration && auth.user?.id === user) sshLoading.value = false }
}
let generation = 0, identityGeneration = 0, alive = true
function clearIdentity() { closeSsh(); ssh.value = false; identityGeneration++; generation++; items.value = []; total.value = 0; error.value = ''; pendingRevoke.value = null; deviceId.value = ''; recipientId.value = ''; saving.value = false; loading.value = false }
async function load() {
  const attempt = ++generation; const user = auth.user?.id
  if (!user) { clearIdentity(); return }
  loading.value = true; error.value = ''; items.value = []
  try { const result = await api.get<{ items: DeviceShare[]; total: number }>(`/device-shares?direction=${direction.value}&page=${page.value}&per_page=20`)
    if (!alive || attempt !== generation || auth.user?.id !== user) return
    items.value = result.items; total.value = result.total
  } catch (e) { if (attempt === generation && alive) error.value = (e as Error).message }
  finally { if (attempt === generation && alive) loading.value = false }
}
function serviceLabel(s: DeviceShare) { return [s.permissions.desktop_view ? 'Desktop' : '', s.permissions.desktop_control ? 'Control' : '', s.permissions.files_read && s.permissions.files_write ? 'Files read/write' : s.permissions.files_read ? 'Files read-only (unsupported)' : '', s.permissions.ssh ? 'SSH' : '', ...s.tcp_ports.map(p => `TCP ${p}`)].filter(Boolean).join(' · ') }
async function create() {
  if (saving.value) return
  if (!/^[a-f\d]{24}$/i.test(deviceId.value) || !/^[a-f\d]{24}$/i.test(recipientId.value) || !Number.isInteger(hours.value) || hours.value < 1 || hours.value > 720 || (!desktopView.value && !files.value && !ssh.value)) { error.value = 'Provide exact device/user IDs, a supported capability, and an expiry of 1–720 hours.'; return }
  const user = auth.user?.id, identity = identityGeneration, attempt = generation; saving.value = true; error.value = ''
  try { await api.post('/device-shares', { device_id: deviceId.value, recipient_user_id: recipientId.value, permissions: { ssh: ssh.value, desktop_view: desktopView.value, desktop_control: desktopView.value && desktopControl.value, files_read: files.value, files_write: files.value }, tcp_ports: [], expires_in_secs: hours.value * 3600 })
    if (!alive || attempt !== generation || identity !== identityGeneration || auth.user?.id !== user) return
    direction.value = 'sent'; page.value = 1; await load()
  } catch (e) { if (alive && identity === identityGeneration && attempt === generation && auth.user?.id === user) error.value = (e as Error).message }
  finally { if (alive && identity === identityGeneration && auth.user?.id === user) saving.value = false }
}
async function revoke() {
  const share = pendingRevoke.value; if (!share || saving.value) return
  const user = auth.user?.id; const identity = identityGeneration; const attempt = generation; saving.value = true; error.value = ''
  try { await api.post(`/device-shares/${share.id}/revoke`, { expected_revision: share.revision })
    if (!alive || attempt !== generation || identity !== identityGeneration || auth.user?.id !== user) return
    pendingRevoke.value = null; await load()
  } catch (e) { if (alive && identity === identityGeneration && attempt === generation && auth.user?.id === user) { error.value = (e as Error).message; if ((e as { status?: number }).status === 409) { pendingRevoke.value = null; await load() } } }
  finally { if (alive && identity === identityGeneration && auth.user?.id === user) saving.value = false }
}
watch(() => route.query.direction, value => { if (value === 'received' || value === 'sent') direction.value = value })
watch(direction, () => { closeSsh(); page.value = 1; void load() })
watch(page, () => { void load() })
watch(() => auth.user?.id, () => { clearIdentity(); void load() }, { immediate: true })
onBeforeUnmount(() => { alive = false; clearInterval(recordClock); clearIdentity() })
</script>
