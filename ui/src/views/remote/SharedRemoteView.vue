<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<template>
  <v-container>
    <div class="d-flex align-center ga-2 mb-3"><v-btn :to="{ name: 'device-shares' }" variant="text">Back to shares</v-btn><h1 class="text-h5">{{ metadata?.display_name || metadata?.name || 'Shared device' }}</h1></div>
    <v-alert v-if="error || rc.error.value" type="error" class="mb-3">{{ error || rc.error.value }}</v-alert>
    <v-alert type="info" variant="tonal" class="mb-3">This is one explicitly shared device, not organization or LAN membership. Device consent still applies. Share revocation ends this session through live server checks.</v-alert>
    <v-alert v-if="metadata?.permissions.files_read && !metadata.permissions.files_write" type="warning" class="mb-3">Read-only file transfer is unsupported by the current bidirectional file protocol and is not enabled.</v-alert>
    <v-btn color="primary" :disabled="!metadata || !permissions || !['idle','closed','error'].includes(rc.phase.value)" @click="connect">Connect</v-btn>
    <v-btn class="ml-2" @click="rc.disconnect()">Disconnect</v-btn><span class="ml-3">{{ rc.phase.value }}</span>
    <div v-if="metadata?.permissions.desktop_view" ref="stage" tabindex="0" class="shared-stage mt-4">
      <video ref="video" v-show="!rc.webcodecsActive.value" autoplay playsinline muted />
      <canvas ref="canvas" v-show="rc.webcodecsActive.value" />
    </div>
    <section v-if="metadata?.permissions.files_read && metadata.permissions.files_write" class="mt-4">
      <h2 class="text-h6">Files (read and write)</h2>
      <div class="d-flex ga-2 align-center"><v-text-field v-model="directory" label="Remote directory" hide-details /><v-btn :disabled="rc.phase.value !== 'connected' || fileBusy" @click="browse(directory)">Browse</v-btn></div>
      <input type="file" :disabled="rc.phase.value !== 'connected' || fileBusy" aria-label="Upload file to shared device" class="my-3" @change="upload" />
      <p v-if="fileMessage">{{ fileMessage }}</p>
      <v-table><thead><tr><th>Name</th><th>Size</th><th>Action</th></tr></thead><tbody>
        <tr v-for="entry in listing?.entries ?? []" :key="entry.name"><td>{{ entry.name }}</td><td>{{ entry.size ?? '—' }}</td><td><v-btn size="small" :disabled="fileBusy" @click="entry.is_dir ? browse(joinPath(listing!.path, entry.name)) : download(joinPath(listing!.path, entry.name), entry.name)">{{ entry.is_dir ? 'Open directory' : 'Download' }}</v-btn></td></tr>
      </tbody></v-table>
    </section>
  </v-container>
</template>
<script setup lang="ts">
import { ref, computed, watch, onBeforeUnmount } from 'vue'
import { useRoute } from 'vue-router'
import { api } from '@/api/client'
import { useAuthStore } from '@/stores/auth'
import { useRemoteControl } from '@/composables/useRemoteControl'
import type { Agent } from '@/stores/agents'
import { sharedRemotePermissions, type DeviceSharePermissions } from '@/utils/deviceShare'
interface SharedDevice extends Pick<Agent, 'id' | 'os' | 'capabilities' | 'peer_auth_key'> { name: string; display_name: string | null; permissions: DeviceSharePermissions; share_grant_id: string; expires_at_ms: number }
const route = useRoute(), auth = useAuthStore()
const shareId = String(route.params.shareId)
const metadata = ref<SharedDevice | null>(null), error = ref('')
const rc = useRemoteControl(metadata, { userId: () => auth.user?.id ?? null, shareGrantId: () => shareId })
const permissions = computed(() => metadata.value ? sharedRemotePermissions(metadata.value.permissions) : '')
const video = ref<HTMLVideoElement | null>(null), canvas = ref<HTMLCanvasElement | null>(null), stage = ref<HTMLElement | null>(null)
const directory = ref('~'), fileBusy = ref(false), fileMessage = ref('')
const listing = ref<Awaited<ReturnType<typeof rc.listDir>> | null>(null)
let generation = 0, alive = true, detach: (() => void) | null = null
watch(canvas, value => { rc.webcodecsCanvasEl.value = value }, { flush: 'post' })
watch([rc.remoteStream, video], ([stream, el]) => { if (el) { el.srcObject = stream; if (stream) void el.play().catch(() => {}) } }, { flush: 'post' })
watch([rc.phase, stage], ([phase, el]) => { detach?.(); detach = null; if (phase === 'connected' && el && metadata.value?.permissions.desktop_control) detach = rc.attachInput(el) }, { flush: 'post' })
watch(() => auth.user?.id, async () => {
  const attempt = ++generation; rc.disconnect(); detach?.(); detach = null; metadata.value = null; listing.value = null; error.value = ''; fileMessage.value = ''; fileBusy.value = false
  if (!auth.user?.id) return
  try { const item = await api.get<SharedDevice>(`/device-shares/${shareId}/remote`); if (alive && attempt === generation) metadata.value = item }
  catch (e) { if (alive && attempt === generation) error.value = (e as Error).message }
}, { immediate: true })
function connect() { if (metadata.value && permissions.value) void rc.connect(metadata.value.id, permissions.value) }
function joinPath(base: string, name: string) { return /[\\/]$/.test(base) ? base + name : base + (base.includes('\\') ? '\\' : '/') + name }
async function browse(path: string) { const attempt = generation; fileBusy.value = true; try { const result = await rc.listDir(path); if (alive && attempt === generation) { listing.value = result; directory.value = result.path } } catch (e) { if (alive && attempt === generation) fileMessage.value = (e as Error).message } finally { if (alive && attempt === generation) fileBusy.value = false } }
async function upload(event: Event) {
  const input = event.target as HTMLInputElement
  const file = input.files?.[0]
  if (!file) return
  const attempt = generation
  fileBusy.value = true
  try {
    // Use only a successfully browsed, host-canonical directory. An edited
    // but unsubmitted path is not an upload destination; no listing retains
    // the transport's existing Downloads default.
    const [result] = await rc.uploadFiles([file], { destPath: listing.value?.path })
    if (!result || !result.ok) throw new Error(result?.error ?? 'Upload returned no result')
    if (alive && attempt === generation) fileMessage.value = `Uploaded ${result.bytes} bytes to ${result.path}`
  } catch (e) {
    if (alive && attempt === generation) fileMessage.value = (e as Error).message
  } finally {
    input.value = ''
    if (alive && attempt === generation) fileBusy.value = false
  }
}
async function download(path: string, name: string) { const attempt = generation; fileBusy.value = true; try { const result = await rc.downloadFile(path, name); if (alive && attempt === generation) fileMessage.value = `Downloaded ${result.bytes} bytes` } catch (e) { if (alive && attempt === generation) fileMessage.value = (e as Error).message } finally { if (alive && attempt === generation) fileBusy.value = false } }
onBeforeUnmount(() => { alive = false; generation++; detach?.(); rc.disconnect() })
</script>
<style scoped>
.shared-stage { position: relative; background: #111; width: 100%; min-height: 240px; outline: none; }
.shared-stage video, .shared-stage canvas { display: block; width: 100%; max-height: 72vh; object-fit: contain; }
</style>
