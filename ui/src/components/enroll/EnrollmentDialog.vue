<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 G ROX EOOD -->
<template>
  <v-dialog
    :model-value="modelValue"
    max-width="720"
    scrollable
    :fullscreen="fullscreen"
    @update:model-value="$emit('update:modelValue', $event)"
  >
    <v-card>
      <v-card-title>
        {{ kind === 'agent' ? 'Enroll a new device' : 'Enroll a tunnel client' }}
      </v-card-title>
      <v-card-text>
        <div v-if="loading" class="d-flex justify-center pa-4">
          <v-progress-circular indeterminate />
        </div>
        <v-alert v-else-if="error" type="error" variant="tonal">{{ error }}</v-alert>
        <template v-else-if="token">
          <p class="text-body-2 mb-2">
            The token below is <strong>single-use</strong> and expires in
            {{ Math.round((expiresIn || 600) / 60) }} minutes. Pick your platform —
            the recommended command installs everything and enrolls in one step.
          </p>

          <!-- Token block: click-to-copy, monospace. -->
          <v-textarea
            :model-value="token"
            readonly
            variant="outlined"
            density="compact"
            rows="3"
            auto-grow
            class="font-family-monospace mb-1"
            hide-details
            @click="copy('token', token)"
          />
          <div class="d-flex align-center mb-3">
            <v-btn
              prepend-icon="mdi-content-copy"
              size="small"
              variant="tonal"
              @click="copy('token', token)"
            >
              Copy token
            </v-btn>
            <span v-if="copiedId === 'token'" class="text-success text-caption ml-2">Copied</span>
          </div>

          <!-- Install scope (agent only) — wizard role vocabulary; tunnel
               clients are a per-user CLI with no scope choice. -->
          <template v-if="kind === 'agent'">
            <p class="text-body-2 font-weight-medium mb-1">Install scope</p>
            <!-- Stacked below 600 px: side by side, the three need ~480 px, and
                 the group scrolled inside itself — "This user only", the
                 install that needs no admin rights, sat out of sight. -->
            <v-btn-toggle
              v-model="scope"
              mandatory
              density="comfortable"
              variant="outlined"
              divided
              :direction="fullscreen ? 'vertical' : 'horizontal'"
              class="mb-1"
            >
              <v-btn value="system" size="small">Background service</v-btn>
              <v-btn value="machine" size="small">Attended service</v-btn>
              <v-btn value="user" size="small">This user only</v-btn>
            </v-btn-toggle>
            <p class="text-caption text-medium-emphasis mb-3">{{ scopeHint }}</p>
          </template>

          <v-tabs v-model="osTab" density="compact" class="mb-2">
            <v-tab v-for="os in commands" :key="os.os" :value="os.os">{{ os.title }}</v-tab>
          </v-tabs>
          <v-window v-model="osTab">
            <v-window-item v-for="os in commands" :key="os.os" :value="os.os">
              <v-alert
                v-if="os.note"
                type="info"
                variant="tonal"
                density="compact"
                class="text-caption mb-3"
              >
                {{ os.note }}
              </v-alert>
              <!-- FR-104 — the box shows what the token CARRIES (the server's
                   answer), never a wish: ticking it mints a new token. -->
              <template v-if="os.os === 'windows' && anchorOffered">
                <v-checkbox
                  :model-value="anchor === true"
                  density="compact"
                  hide-details
                  label="Also let administrators run commands as SYSTEM on this device"
                  data-test="enroll-anchor"
                  @update:model-value="$emit('update:anchor', $event === true)"
                />
                <p class="text-caption text-medium-emphasis mb-3">
                  The token can then also anchor the device it enrolls, once. Roomler Setup
                  does that itself after a second administrator prompt; after the script or a
                  manual install, run the anchor command below. Give this token only to the
                  person installing it as an administrator.
                </p>
              </template>
              <div v-for="block in os.blocks" :key="block.id" class="mb-3">
                <p class="text-body-2 font-weight-medium mb-1">{{ block.label }}</p>
                <template v-if="block.isDownload">
                  <v-btn
                    :href="block.command"
                    prepend-icon="mdi-download"
                    size="small"
                    variant="tonal"
                    target="_blank"
                  >
                    Download Roomler Setup
                  </v-btn>
                  <span class="text-caption text-medium-emphasis ml-2">
                    then paste the token into the wizard
                  </span>
                </template>
                <template v-else>
                  <pre class="enroll-cmd text-caption pa-2 rounded" @click="copy(block.id, block.command)">{{ block.command }}</pre>
                  <div class="d-flex align-center">
                    <v-btn
                      prepend-icon="mdi-content-copy"
                      size="x-small"
                      variant="text"
                      @click="copy(block.id, block.command)"
                    >
                      Copy
                    </v-btn>
                    <span v-if="copiedId === block.id" class="text-success text-caption ml-1">Copied</span>
                  </div>
                </template>
              </div>
            </v-window-item>
          </v-window>
        </template>
      </v-card-text>
      <v-card-actions>
        <v-spacer />
        <v-btn variant="text" @click="$emit('update:modelValue', false)">Close</v-btn>
      </v-card-actions>
    </v-card>
  </v-dialog>
</template>

<script setup lang="ts">
import { appOrigin } from '@/utils/deployment'
import { computed, ref } from 'vue'
import { useResponsiveDialog } from '@/composables/useResponsiveDialog'
import {
  enrollCommands,
  type DaemonScope,
  type EnrollKind,
  type EnrollOs,
} from '@/utils/enrollCommands'
import { trackGoal } from '@/utils/goals'

const { fullscreen } = useResponsiveDialog()
const props = defineProps<{
  modelValue: boolean
  kind: EnrollKind
  token: string | null
  expiresIn: number | null
  loading: boolean
  error: string | null
  /** FR-104 — the shown token may also anchor the device it enrolls. */
  anchor?: boolean
}>()

defineEmits<{
  (e: 'update:modelValue', v: boolean): void
  /** FR-104 — mint a new token with (or without) the anchor claim. */
  (e: 'update:anchor', v: boolean): void
}>()

// Default the OS tab to the visitor's own platform — they're usually
// enrolling the machine in front of them or one like it.
function detectOs(): EnrollOs {
  const ua = navigator.userAgent
  if (/Mac/i.test(ua)) return 'macos'
  if (/Linux/i.test(ua) && !/Android/i.test(ua)) return 'linux'
  return 'windows'
}
const osTab = ref<EnrollOs>(detectOs())

// Sticky across dialog reopens — handy when enrolling a fleet of
// same-shaped machines in a row.
const scope = ref<DaemonScope>('system')
const SCOPE_HINTS: Record<DaemonScope, string> = {
  system:
    'Starts before logon and survives logouts — recommended for servers and unattended machines.',
  machine: 'Machine-wide service that runs while a user is logged in.',
  user: 'Installs and autostarts for your account only — no admin rights needed.',
}
const scopeHint = computed(() => SCOPE_HINTS[scope.value])

// FR-104 — only a machine-wide Windows install has a SYSTEM service to anchor.
const anchorOffered = computed(() => props.kind === 'agent' && scope.value !== 'user')

const commands = computed(() =>
  enrollCommands(
    props.kind,
    appOrigin(window.location.origin),
    props.token,
    scope.value,
    props.anchor === true,
  ),
)

const copiedId = ref<string | null>(null)
function copy(id: string, text: string) {
  navigator.clipboard
    .writeText(text)
    .then(() => {
      // FR-88 §3b: an install/enroll COMMAND was copied — not the bare token.
      if (id !== 'token') trackGoal('install-copy')
      copiedId.value = id
      setTimeout(() => {
        if (copiedId.value === id) copiedId.value = null
      }, 2000)
    })
    .catch(() => {
      copiedId.value = null
    })
}
</script>

<style scoped>
.enroll-cmd {
  background: rgba(var(--v-theme-on-surface), 0.06);
  font-family: monospace;
  white-space: pre-wrap;
  word-break: break-all;
  cursor: pointer;
  margin: 0;
}
</style>
