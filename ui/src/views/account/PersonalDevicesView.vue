<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<template>
  <v-container>
    <h1 class="text-h5 mb-3">My devices &amp; sharing</h1>
    <p class="mb-3">Only devices owned by this account, across your active organizations. Organization-wide visibility is not ownership.</p>
    <v-alert v-if="error" type="warning" class="mb-3" data-testid="personal-devices-error">{{ error }}</v-alert>
    <v-btn :loading="loading" class="mb-3" data-testid="personal-refresh" @click="load">Refresh account records</v-btn>
    <v-row>
      <v-col cols="12" md="4"><v-card variant="tonal" class="pa-4"><h2 class="text-subtitle-1">My devices</h2><strong class="text-h4" data-testid="owned-device-count">{{ owned?.total ?? '—' }}</strong><p>Owned devices in active, joined organizations.</p></v-card></v-col>
      <v-col v-for="bucket in buckets" :key="bucket.key" cols="12" md="4"><v-card variant="tonal" class="pa-4"><h2 class="text-subtitle-1">{{ bucket.label }}</h2><strong class="text-h4" :data-testid="bucket.key + '-device-count'">{{ summary?.[bucket.key].active_devices ?? '—' }}</strong><p>Distinct devices with unrevoked, unexpired shares.</p><p :data-testid="bucket.key + '-record-count'">{{ summary?.[bucket.key].active_grants ?? '—' }} current grants · {{ summary?.[bucket.key].total_records ?? '—' }} retained records</p><p>{{ summary?.[bucket.key].expired_records ?? '—' }} expired · {{ summary?.[bucket.key].revoked_records ?? '—' }} revoked</p></v-card></v-col>
    </v-row>
    <p class="text-body-2 my-3">A device shared more than once is counted once per direction. Retained records include expired and revoked shares. These are sharing-record states, not proof that a device is online or its service policy permits a connection.</p>
    <h2 class="text-h6 mt-4">Devices owned by me</h2>
    <v-progress-linear v-if="loading" indeterminate />
    <v-table data-testid="owned-devices-table"><thead><tr><th>Device / ID</th><th>Registered name</th><th>OS</th><th>Status</th><th>Organization</th><th>Access</th></tr></thead><tbody>
      <tr v-for="device in owned?.items ?? []" :key="device.id"><td>{{ device.name }}<br /><code>{{ device.id }}</code></td><td>{{ device.machine_name }}</td><td>{{ device.os }}</td><td>{{ device.status }}</td><td><code>{{ device.tenant_id }}</code></td><td><v-btn size="small" :disabled="device.status !== 'online'" :to="nativeDesktop ? undefined : { name: 'agent-remote', params: { tenantId: device.tenant_id, agentId: device.id } }" :href="nativeDesktop ? remoteUrl(device) : undefined" :target="nativeDesktop ? '_blank' : undefined" :rel="nativeDesktop ? 'noopener noreferrer' : undefined">Open desktop</v-btn></td></tr>
      <tr v-if="owned && owned.items.length === 0"><td colspan="6">{{ owned.total === 0 ? 'No devices owned by this account in active, joined organizations.' : 'No devices on this page. Refresh or choose another page.' }}</td></tr>
    </tbody></v-table>
    <v-pagination v-if="owned && owned.total > 25" v-model="page" :length="Math.ceil(owned.total / 25)" :disabled="loading" />
    <p class="text-body-2 mt-2">Device IDs and sharing records remain separate from connection state. Desktop access still requires the device's current service policy and consent.</p>
    <device-shares-view class="mt-6" />
  </v-container>
</template>
<script setup lang="ts">
import { computed, onBeforeUnmount, ref, watch } from 'vue'
import { useRoute } from 'vue-router'
import { api } from '@/api/client'
import { useAuthStore } from '@/stores/auth'
import { appOrigin } from '@/utils/deployment'
import DeviceSharesView from '@/views/account/DeviceSharesView.vue'
interface OwnedDevice { id: string; name: string; machine_name: string; os: string; status: string; tenant_id: string }
interface OwnedPage { items: OwnedDevice[]; page: number; total: number }
interface ShareCounts { active_devices: number; active_grants: number; total_records: number; expired_records: number; revoked_records: number }
interface Summary { own_devices: number; received: ShareCounts; sent: ShareCounts }
const auth = useAuthStore(), route = useRoute()
const page = ref(1), owned = ref<OwnedPage | null>(null), summary = ref<Summary | null>(null), loading = ref(false), error = ref('')
const nativeDesktop = computed(() => route.query.desktop === '1')
const buckets = [{ key: 'received', label: 'Shared with me' }, { key: 'sent', label: 'Shared by me' }] as const
const base = appOrigin(window.location.origin).replace(/\/$/, '')
function remoteUrl(device: OwnedDevice) { return `${base}/tenant/${encodeURIComponent(device.tenant_id)}/agent/${encodeURIComponent(device.id)}/remote` }
let generation = 0, alive = true
async function load() {
  const user = auth.user?.id, attempt = ++generation, requestedPage = page.value
  if (!user) { owned.value = null; summary.value = null; loading.value = false; error.value = ''; return }
  loading.value = true; error.value = ''
  try {
    const [devices, counts] = await Promise.all([api.get<OwnedPage>(`/account/devices?page=${requestedPage}&per_page=25`), api.get<Summary>('/account/devices/summary')])
    if (!alive || attempt !== generation || auth.user?.id !== user) return
    const count = (v: unknown) => Number.isSafeInteger(v) && (v as number) >= 0
    const bucket = (v: ShareCounts) => v && [v.active_devices, v.active_grants, v.total_records, v.expired_records, v.revoked_records].every(count) && v.active_devices <= v.active_grants && v.active_grants + v.expired_records + v.revoked_records === v.total_records
    if (!count(devices.total) || devices.page !== requestedPage || !Array.isArray(devices.items) || devices.items.length > 25 || devices.items.length > devices.total || !count(counts.own_devices) || !bucket(counts.received) || !bucket(counts.sent)) throw new Error('Invalid personal directory response')
    owned.value = devices; summary.value = counts
  } catch {
    if (alive && attempt === generation && auth.user?.id === user) error.value = 'Could not refresh personal device and sharing records. Previous records, if shown, may be stale. The server may need an update.'
  } finally { if (alive && attempt === generation && auth.user?.id === user) loading.value = false }
}
watch(() => auth.user?.id, () => { ++generation; owned.value = null; summary.value = null; error.value = ''; if (page.value !== 1) page.value = 1; else void load() }, { immediate: true })
watch(page, () => { void load() })
function visibleRefresh() { if (document.visibilityState === 'visible') void load() }
const refresh = setInterval(visibleRefresh, 30_000)
document.addEventListener('visibilitychange', visibleRefresh)
onBeforeUnmount(() => { alive = false; ++generation; clearInterval(refresh); document.removeEventListener('visibilitychange', visibleRefresh) })
</script>
