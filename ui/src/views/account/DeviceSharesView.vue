<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<template>
  <v-container>
    <h1 class="text-h5 mb-3">{{ $t('mh.shares.title') }}</h1>
    <p class="mb-3">{{ $t('mh.shares.intro') }}</p>
    <v-alert v-if="error" type="error" class="mb-3">{{ error }}</v-alert>
    <v-tabs v-model="direction"><v-tab value="received">{{ $t('mh.shares.tabReceived') }}</v-tab><v-tab value="sent">{{ $t('mh.shares.tabSent') }}</v-tab></v-tabs>
    <v-btn class="my-3" :loading="loading" @click="load">{{ $t('common.refresh') }}</v-btn>
    <v-progress-linear v-if="loading" indeterminate />
    <v-table><thead><tr><th>{{ $t('mh.shares.col.device') }}</th><th>{{ $t('mh.shares.col.parties') }}</th><th>{{ $t('mh.shares.col.services') }}</th><th>{{ $t('mh.shares.col.created') }}</th><th>{{ $t('mh.shares.col.expires') }}</th><th>{{ $t('mh.shares.col.state') }}</th><th>{{ $t('mh.shares.col.revoked') }}</th><th>{{ $t('mh.shares.col.actions') }}</th></tr></thead><tbody>
      <tr v-for="s in items" :key="s.id"><td>{{ s.device_name ?? s.device_id }}<br v-if="s.device_name" /><small v-if="s.device_name"><code>{{ s.device_id }}</code></small></td><td>{{ s.owner_username ?? s.owner_user_id }} → {{ s.recipient_username ?? s.recipient_user_id }}</td><td>{{ serviceLabel(s) }}</td><td>{{ s.created_at_ms === undefined ? $t('mh.shares.notReported') : new Date(s.created_at_ms).toLocaleString() }}</td><td>{{ new Date(s.expires_at_ms).toLocaleString() }}</td><td :data-testid="'share-state-' + s.id">{{ recordStateLabel(shareRecordState(s, now)) }}<br /><small>{{ $t('mh.shares.grantRevision', { id: s.id, revision: s.revision }) }}</small></td><td>{{ s.revoked_at_ms === null ? '—' : new Date(s.revoked_at_ms).toLocaleString() }}</td><td>
        <v-btn v-if="direction === 'received'" size="small" :disabled="!shareLive(s, now) || !sharedRemotePermissions(s.permissions)" :to="nativeDesktop ? undefined : { name: 'shared-remote', params: { shareId: s.id } }" :href="nativeDesktop ? sharedRemoteUrl(s) : undefined" :target="nativeDesktop ? '_blank' : undefined" :rel="nativeDesktop ? 'noopener noreferrer' : undefined">{{ $t('mh.shares.openRemote') }}</v-btn>
        <v-btn v-if="direction === 'received' && s.permissions.ssh" size="small" class="ml-2" data-testid="shared-ssh-open" :data-share-id="s.id" :disabled="!shareLive(s, now)" @click="openSsh(s)">{{ $t('mh.shares.openSsh') }}</v-btn>
        <v-btn v-if="direction === 'sent' && s.revoked_at_ms === null" size="small" color="error" :disabled="saving" @click="pendingRevoke = s">{{ $t('mh.shares.revoke') }}</v-btn>
        <span v-if="s.revoked_at_ms !== null">{{ $t('mh.shares.revoked') }}</span>
      </td></tr>
      <tr v-if="!loading && !items.length"><td colspan="8">{{ $t('mh.shares.empty') }}</td></tr>
    </tbody></v-table>
    <p class="text-body-2 mt-2">{{ $t('mh.shares.listNote', { total }) }}</p>
    <v-pagination v-model="page" :length="Math.max(1, Math.ceil(total / 20))" :disabled="loading" />
    <v-expansion-panels v-model="panel" class="mt-4"><v-expansion-panel value="share" :title="$t('mh.shares.formTitle')"><v-expansion-panel-text>
      <v-form @submit.prevent="create">
        <v-select data-testid="share-device-id" v-model="deviceId" :items="ownedChoices" :loading="ownedLoading" :label="$t('mh.shares.device')" :no-data-text="$t('mh.shares.noOwned')" required />
        <v-text-field data-testid="share-recipient-id" v-model="recipientId" :label="$t('mh.shares.recipient')" :hint="$t('mh.shares.recipientHint')" persistent-hint autocomplete="off" required />
        <v-checkbox data-testid="share-ssh-permission" v-model="ssh" :label="$t('mh.shares.permSsh')" />
        <!-- The account the recipient's SSH — and, on Linux/macOS, their file transfers — run as:
             chosen here, never the device policy's (root). -->
        <v-text-field v-if="needsAccount" data-testid="share-ssh-account" v-model="sshAccount" :label="ssh ? $t('mh.shares.sshAccount') : $t('mh.shares.filesAccount')" :hint="ssh ? (files && unixDevice ? $t('mh.shares.sshFilesAccountHint') : $t('mh.shares.sshAccountHint')) : $t('mh.shares.filesAccountHint')" persistent-hint autocomplete="off" class="mb-2" />
        <!-- The device's own login accounts, asked of the device itself; or a new one it creates. -->
        <div v-if="needsAccount && deviceId" class="mb-3" data-testid="share-ssh-accounts">
          <v-progress-linear v-if="accountsLoading" indeterminate class="mb-1" />
          <div v-if="accounts.length" class="d-flex flex-wrap align-center ga-1">
            <span class="text-caption mr-1">{{ $t('mh.shares.acct.existing') }}</span>
            <v-chip v-for="a in accounts" :key="a.name" size="small" :color="sshAccount.trim() === a.name ? 'primary' : undefined" :data-testid="`share-ssh-account-${a.name}`" @click="sshAccount = a.name">
              {{ a.name }}<span v-if="a.admin" class="ml-1 text-caption">({{ $t('mh.shares.acct.admin') }})</span>
            </v-chip>
          </div>
          <p v-else-if="!accountsLoading && !accountsError" class="text-caption">{{ $t('mh.shares.acct.none') }}</p>
          <v-alert v-if="accountsError" type="info" variant="tonal" density="compact" class="mt-1" data-testid="share-ssh-accounts-error">{{ $t('mh.shares.acct.unavailable', { reason: accountsError }) }}</v-alert>
          <v-alert v-if="accountNotice" type="success" variant="tonal" density="compact" class="mt-1" data-testid="share-ssh-account-created">{{ accountNotice }}</v-alert>
          <div class="d-flex flex-wrap align-center ga-2 mt-2">
            <v-text-field v-model="newAccount" data-testid="share-new-account" :label="$t('mh.shares.acct.newName')" density="compact" hide-details autocomplete="off" style="max-width: 240px" />
            <v-checkbox v-model="newAdmin" data-testid="share-new-account-admin" :label="$t('mh.shares.acct.newAdmin')" density="compact" hide-details />
            <v-btn data-testid="share-new-account-create" variant="tonal" size="small" :loading="creatingAccount" @click="createAccount">{{ $t('mh.shares.acct.create') }}</v-btn>
          </div>
          <p class="text-caption mt-1">{{ $t('mh.shares.acct.note') }}</p>
        </div>
        <v-checkbox data-testid="share-desktop-permission" v-model="desktopView" :label="$t('mh.shares.permView')" /><v-checkbox v-model="desktopControl" :disabled="!desktopView" :label="$t('mh.shares.permControl')" />
        <v-checkbox data-testid="share-files-permission" v-model="files" :label="$t('mh.shares.permFiles')" />
        <v-text-field v-model.number="hours" :label="$t('mh.shares.hours')" type="number" min="1" max="720" />
        <v-alert type="info" variant="tonal" class="mb-3">{{ $t('mh.shares.formNote') }}</v-alert>
        <v-btn data-testid="share-create" type="submit" color="primary" :loading="saving">{{ $t('mh.shares.create') }}</v-btn>
      </v-form>
    </v-expansion-panel-text></v-expansion-panel></v-expansion-panels>
    <v-dialog :model-value="sshShare !== null" max-width="760" @update:model-value="v => { if (!v) closeSsh() }">
      <v-card data-testid="shared-ssh-instructions">
        <v-card-title>{{ $t('mh.shares.ssh.title') }}</v-card-title>
        <v-card-text>
          <v-alert type="info" variant="tonal" class="mb-3">{{ $t('mh.shares.ssh.intro') }}</v-alert>
          <v-progress-linear v-if="sshLoading" indeterminate data-testid="shared-ssh-loading" />
          <v-alert v-if="sshError" type="error" data-testid="shared-ssh-error">{{ sshError }}</v-alert>
          <template v-if="sshDevice">
            <p data-testid="shared-ssh-device">{{ $t('mh.shares.ssh.device', { name: sshDevice.name, id: sshDevice.id }) }}</p>
            <p>{{ $t('mh.shares.ssh.base') }} <code>{{ sshServerBase }}</code></p>
            <p class="mt-2">{{ $t('mh.shares.ssh.hostKey') }}</p>
            <pre class="text-wrap" data-testid="shared-ssh-host-key">{{ sshDevice.host_pubkey }}</pre>
            <p class="mt-3">{{ $t('mh.shares.ssh.run') }}</p>
            <pre class="text-wrap" data-testid="shared-ssh-command">meshharbord cli share-ssh --server YOUR_SERVER_BASE_URL --share {{ sshShare?.id }} --login --username YOUR_ACCOUNT_USERNAME</pre>
            <v-alert type="warning" variant="tonal" class="mt-3">{{ $t('mh.shares.ssh.warning') }}</v-alert>
            <p class="mt-2">{{ $t('mh.shares.ssh.scope') }}</p>
          </template>
        </v-card-text>
        <v-card-actions><v-spacer /><v-btn data-testid="shared-ssh-close" @click="closeSsh">{{ $t('common.close') }}</v-btn></v-card-actions>
      </v-card>
    </v-dialog>
    <v-dialog :model-value="pendingRevoke !== null" max-width="480" @update:model-value="v => { if (!v && !saving) pendingRevoke = null }"><v-card><v-card-title>{{ $t('mh.shares.revokeTitle') }}</v-card-title><v-card-text>{{ $t('mh.shares.revokeBody') }}</v-card-text><v-card-actions><v-spacer /><v-btn :disabled="saving" @click="pendingRevoke = null">{{ $t('common.cancel') }}</v-btn><v-btn color="error" :loading="saving" @click="revoke">{{ $t('mh.shares.revoke') }}</v-btn></v-card-actions></v-card></v-dialog>
  </v-container>
</template>
<script setup lang="ts">
import { computed, ref, watch, onBeforeUnmount } from 'vue'
import { useRoute } from 'vue-router'
import { useI18n } from 'vue-i18n'
import { api } from '@/api/client'
import { useAuthStore } from '@/stores/auth'
import { appOrigin } from '@/utils/deployment'
import { sharedRemotePermissions, shareLive, shareRecordState, type DeviceShare } from '@/utils/deviceShare'
const auth = useAuthStore(), route = useRoute(), { t } = useI18n()
const nativeDesktop = computed(() => route.query.desktop === '1')
const now = ref(Date.now()), recordClock = setInterval(() => { now.value = Date.now() }, 1000)
function sharedRemoteUrl(share: DeviceShare) { return `${appOrigin(window.location.origin).replace(/\/$/, '')}/device-shares/${encodeURIComponent(share.id)}/remote` }
const direction = ref<'received' | 'sent'>(route.query.direction === 'sent' ? 'sent' : 'received'), page = ref(1), total = ref(0)
const items = ref<DeviceShare[]>([]), loading = ref(false), saving = ref(false), error = ref('')
const deviceId = ref(''), recipientId = ref(''), hours = ref(24), desktopView = ref(true), desktopControl = ref(false), files = ref(false), ssh = ref(false), sshAccount = ref('')
// A recipient's file transfers never run as root/SYSTEM: on a Linux/macOS device they run as a
// chosen account, exactly as SSH does; a Windows device runs them as its own (per-user) user.
// An OS the listing did not report is treated as Linux/macOS — the server decides in the end.
const unixDevice = computed(() => owned.value.find(d => d.id === deviceId.value)?.os !== 'windows')
const needsAccount = computed(() => ssh.value || (files.value && unixDevice.value))
// The server's rule for a share account (a portable POSIX user name), checked here to answer early.
const SHARE_ACCOUNT = /^[a-z_][a-z0-9_-]{0,31}$/
interface LocalAccount { name: string; uid: number; admin: boolean }
const accounts = ref<LocalAccount[]>([]), accountsLoading = ref(false), accountsError = ref(''), accountNotice = ref('')
const newAccount = ref(''), newAdmin = ref(false), creatingAccount = ref(false)
let accountsGeneration = 0
/** Ask the device itself for its login accounts, for the device just chosen. */
async function loadAccounts() {
  const id = deviceId.value, attempt = ++accountsGeneration
  accounts.value = []; accountsError.value = ''; accountNotice.value = ''; accountsLoading.value = false
  if (!needsAccount.value || !OBJECT_ID.test(id ?? '')) return
  accountsLoading.value = true
  try {
    const r = await api.get<{ accounts?: LocalAccount[] }>(`/account/devices/${encodeURIComponent(id)}/local-accounts`)
    if (alive && attempt === accountsGeneration) accounts.value = r?.accounts ?? []
  } catch (e) { if (alive && attempt === accountsGeneration) accountsError.value = (e as Error).message }
  finally { if (alive && attempt === accountsGeneration) accountsLoading.value = false }
}
/** Have the device create an account — with or without the right to become root — and pick it. */
async function createAccount() {
  const name = newAccount.value.trim(), id = deviceId.value
  if (name === 'root' || !SHARE_ACCOUNT.test(name)) { accountsError.value = t('mh.shares.sshAccountInvalid'); return }
  if (creatingAccount.value || !OBJECT_ID.test(id ?? '')) return
  const attempt = ++accountsGeneration
  creatingAccount.value = true; accountsError.value = ''; accountNotice.value = ''
  try {
    const r = await api.post<{ accounts?: LocalAccount[] }>(`/account/devices/${encodeURIComponent(id)}/local-accounts`, { name, admin: newAdmin.value })
    if (!alive || attempt !== accountsGeneration) return
    accounts.value = r?.accounts ?? []; sshAccount.value = name; newAccount.value = ''; newAdmin.value = false
    accountNotice.value = t('mh.shares.acct.created', { name })
  } catch (e) { if (alive && attempt === accountsGeneration) accountsError.value = (e as Error).message }
  finally { if (alive) creatingAccount.value = false }
}
const pendingRevoke = ref<DeviceShare | null>(null)
// The share form picks from the devices this account owns — no one should need to know an id.
interface OwnedDevice { id: string; name: string; status: string; os?: 'linux' | 'macos' | 'windows' }
const owned = ref<OwnedDevice[]>([]), ownedLoading = ref(false), panel = ref<string[]>([])
const ownedChoices = computed(() => owned.value.map(d => ({ title: `${d.name} (${d.status})`, value: d.id })))
const OBJECT_ID = /^[a-f\d]{24}$/i
async function loadOwned() {
  const user = auth.user?.id; if (!user) return
  const identity = identityGeneration; ownedLoading.value = true
  try {
    const all: OwnedDevice[] = []
    // The directory pages by 25; four pages is far beyond a personal fleet.
    for (let p = 1; p <= 4; p++) {
      const r = await api.get<{ items: OwnedDevice[]; total: number }>(`/account/devices?page=${p}&per_page=25`)
      all.push(...r.items)
      if (all.length >= r.total || r.items.length === 0) break
    }
    if (alive && identity === identityGeneration && auth.user?.id === user) owned.value = all
  } catch (e) { if (alive && identity === identityGeneration) error.value = (e as Error).message }
  finally { if (alive && identity === identityGeneration) ownedLoading.value = false }
}
function preselect() {
  const wanted = route.query.share_device
  if (typeof wanted === 'string' && OBJECT_ID.test(wanted)) { deviceId.value = wanted; panel.value = ['share'] }
}
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
function clearIdentity() { closeSsh(); ssh.value = false; sshAccount.value = ''; identityGeneration++; generation++; items.value = []; total.value = 0; error.value = ''; pendingRevoke.value = null; deviceId.value = ''; recipientId.value = ''; saving.value = false; loading.value = false }
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
function serviceLabel(s: DeviceShare) { return [s.permissions.desktop_view ? t('mh.shares.svc.desktop') : '', s.permissions.desktop_control ? t('mh.shares.svc.control') : '', s.permissions.files_read && s.permissions.files_write ? t('mh.shares.svc.filesRw') : s.permissions.files_read ? t('mh.shares.svc.filesRo') : '', s.permissions.ssh ? (s.ssh_account ? t('mh.shares.svc.sshAs', { account: s.ssh_account }) : 'SSH') : '', ...s.tcp_ports.map(p => `TCP ${p}`)].filter(Boolean).join(' · ') }
const RECORD_STATE_KEYS = { 'Revoked': 'mh.shares.record.revoked', 'Expired': 'mh.shares.record.expired', 'Unrevoked / unexpired': 'mh.shares.record.live' } as const
function recordStateLabel(state: keyof typeof RECORD_STATE_KEYS) { return t(RECORD_STATE_KEYS[state]) }
async function create() {
  if (saving.value) return
  const recipient = recipientId.value.trim()
  if (!OBJECT_ID.test(deviceId.value ?? '') || !recipient || recipient.length > 320 || !Number.isInteger(hours.value) || hours.value < 1 || hours.value > 720 || (!desktopView.value && !files.value && !ssh.value)) { error.value = t('mh.shares.invalid'); return }
  const account = sshAccount.value.trim()
  const withAccount = needsAccount.value
  if (withAccount && account === 'root') { error.value = t('mh.shares.sshRootRefused'); return }
  if (withAccount && !SHARE_ACCOUNT.test(account)) { error.value = t(ssh.value ? 'mh.shares.sshAccountInvalid' : 'mh.shares.filesAccountInvalid'); return }
  const user = auth.user?.id, identity = identityGeneration, attempt = generation; saving.value = true; error.value = ''
  try { await api.post('/device-shares', { device_id: deviceId.value, recipient, permissions: { ssh: ssh.value, desktop_view: desktopView.value, desktop_control: desktopView.value && desktopControl.value, files_read: files.value, files_write: files.value }, tcp_ports: [], expires_in_secs: hours.value * 3600, ...(withAccount ? { ssh_account: account } : {}) })
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
watch([needsAccount, deviceId], () => { void loadAccounts() })
watch(() => auth.user?.id, () => { clearIdentity(); owned.value = []; void load(); void loadOwned(); preselect() }, { immediate: true })
watch(() => route.query.share_device, () => preselect())
onBeforeUnmount(() => { alive = false; clearInterval(recordClock); clearIdentity() })
</script>
