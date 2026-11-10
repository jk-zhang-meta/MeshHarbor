<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 G ROX EOOD -->
<template>
  <!-- FR-116 — from 600 px up a column of cards, as always; on a phone a list
       of expansion panels, each titled with its gate's current state. -->
  <component
    :is="xs ? VExpansionPanels : 'div'"
    :class="{ 'd-flex flex-column ga-4': !xs }"
    :multiple="xs || undefined"
  >
    <SettingsGate :title="t('mh.settings.workspace')" :summary="tenantStore.current?.name ?? ''">
      <v-text-field
        :model-value="tenantStore.current?.name"
        :label="t('mh.settings.workspaceName')"
        disabled
      />
      <v-text-field
        :model-value="tenantStore.current?.slug"
        :label="t('mh.settings.slug')"
        disabled
      />
    </SettingsGate>

    <!-- Fleet RPC gate 1. Deliberately here rather than in the device list:
         this one switch governs every device in the org, so it belongs with
         org settings and needs MANAGE_TENANT, not fleet-admin rights. -->
    <SettingsGate
      :title="t('mh.settings.exec.title')"
      icon="mdi-console-network-outline"
      :summary="onOff(agentStore.orgExecEnabled)"
    >
      <v-alert
        type="warning"
        variant="tonal"
        density="compact"
        class="mb-4"
        icon="mdi-shield-alert-outline"
      >
        <i18n-t keypath="mh.settings.exec.warn" tag="span" scope="global">
          <template #perm><strong>EXEC_DEVICE</strong></template>
          <template #root><strong>root</strong></template>
          <template #system><strong>SYSTEM</strong></template>
          <template #user><strong>{{ t('mh.settings.exec.signedInUser') }}</strong></template>
        </i18n-t>
      </v-alert>

      <v-switch
        :model-value="agentStore.orgExecEnabled === true"
        :loading="saving"
        :disabled="saving || agentStore.orgExecEnabled === null"
        color="primary"
        density="compact"
        hide-details
        :label="t('mh.settings.exec.allow')"
        @update:model-value="onToggle"
      />
      <div class="text-caption text-medium-emphasis mt-1">
        <i18n-t keypath="mh.settings.offDeviceGate" tag="span" scope="global">
          <template #setting><code>exec_enabled</code></template>
        </i18n-t>
      </div>

      <v-alert v-if="error" type="error" variant="tonal" density="compact" class="mt-3">
        {{ error }}
      </v-alert>

      <!-- FR-94 — absent on a server from before it (`null`), so hidden
           rather than shown as a switch that cannot be read. -->
      <template v-if="agentStore.orgExecRequireSystem !== null">
        <v-switch
          :model-value="agentStore.orgExecRequireSystem === true"
          :loading="savingRequire"
          :disabled="savingRequire || agentStore.orgExecEnabled === null"
          color="primary"
          density="compact"
          hide-details
          class="mt-4"
          :label="t('mh.settings.exec.requireSystem')"
          data-testid="exec-require-system"
          @update:model-value="onToggleRequireSystem"
        />
        <div class="text-caption text-medium-emphasis mt-1">
          <i18n-t keypath="mh.settings.exec.requireSystemHint" tag="span" scope="global">
            <template #cmd><code>meshharbord anchor create</code></template>
          </i18n-t>
        </div>
        <v-alert
          v-if="requireError"
          type="error"
          variant="tonal"
          density="compact"
          class="mt-3"
        >
          {{ requireError }}
        </v-alert>
      </template>
    </SettingsGate>

    <!-- MeshHarbor SSH gate 1. A SEPARATE card from remote execution above, and
         a separate switch server-side: allowing bounded diagnostic commands
         is not the same decision as allowing interactive sessions, and one
         control must never read as the other. -->
    <SettingsGate
      :title="t('mh.settings.ssh.title')"
      icon="mdi-console-network-outline"
      :summary="onOff(agentStore.orgSshEnabled)"
    >
      <v-alert
        type="warning"
        variant="tonal"
        density="compact"
        class="mb-4"
        icon="mdi-shield-alert-outline"
      >
        <i18n-t keypath="mh.settings.ssh.warn" tag="span" scope="global">
          <template #perm><strong>SSH_DEVICE</strong></template>
        </i18n-t>
      </v-alert>

      <v-switch
        :model-value="agentStore.orgSshEnabled === true"
        :loading="savingSsh"
        :disabled="savingSsh || agentStore.orgSshEnabled === null"
        color="primary"
        density="compact"
        hide-details
        :label="t('mh.settings.ssh.allow')"
        @update:model-value="onToggleSsh"
      />
      <div class="text-caption text-medium-emphasis mt-1">
        <i18n-t keypath="mh.settings.offDeviceGate" tag="span" scope="global">
          <template #setting><code>ssh_enabled</code></template>
        </i18n-t>
      </div>

      <v-alert v-if="sshError" type="error" variant="tonal" density="compact" class="mt-3">
        {{ sshError }}
      </v-alert>
    </SettingsGate>

    <!-- FR-52 gate 1. A THIRD card, and a third server-side switch, for a
         reason stronger than the one separating the two above: those decide
         what a MEMBER of this organization may do, and this one decides
         whether someone who is not a member may do anything at all. -->
    <SettingsGate
      :title="t('mh.settings.ext.title')"
      icon="mdi-account-arrow-right-outline"
      :summary="onOff(agentStore.orgExternalAccessEnabled)"
    >
      <v-alert
        type="warning"
        variant="tonal"
        density="compact"
        class="mb-4"
        icon="mdi-shield-account-outline"
      >
        <i18n-t keypath="mh.settings.ext.warn" tag="span" scope="global">
          <template #outside><strong>{{ t('mh.settings.ext.outside') }}</strong></template>
          <template #onDevice><strong>{{ t('mh.settings.ext.onDevice') }}</strong></template>
        </i18n-t>
      </v-alert>

      <v-switch
        :model-value="agentStore.orgExternalAccessEnabled === true"
        :loading="savingExternal"
        :disabled="savingExternal || agentStore.orgExternalAccessEnabled === null"
        color="primary"
        density="compact"
        hide-details
        :label="t('mh.settings.ext.allow')"
        @update:model-value="onToggleExternal"
      />
      <div class="text-caption text-medium-emphasis mt-1">
        {{ t('mh.settings.ext.hint') }}
      </div>

      <v-alert v-if="externalError" type="error" variant="tonal" density="compact" class="mt-3">
        {{ externalError }}
      </v-alert>
    </SettingsGate>

    <!-- FR-92 — keep busy. Unlike the cards above this is ON by default
         (operator decision) and the switch is the org's DENY, shown as
         "allow" so on reads as on. The device enforces it; a deny also stops
         a keep busy already running. -->
    <SettingsGate
      :title="t('mh.settings.kb.title')"
      icon="mdi-cursor-default-gesture-outline"
      :summary="keepBusySummary"
      data-testid="org-keep-busy-card"
    >
      <p class="text-body-2 mb-3">
        {{ t('mh.settings.kb.body') }}
      </p>
      <v-switch
        :model-value="agentStore.orgKeepBusyDenied === false"
        :loading="savingKeepBusy"
        :disabled="savingKeepBusy || agentStore.orgKeepBusyDenied === null"
        color="primary"
        density="compact"
        hide-details
        :label="t('mh.settings.kb.allow')"
        data-testid="org-keep-busy-switch"
        @update:model-value="onToggleKeepBusy"
      />
      <div class="text-caption text-medium-emphasis mt-1">
        <i18n-t keypath="mh.settings.kb.hint" tag="span" scope="global">
          <template #setting><code>keep_busy_enabled</code></template>
        </i18n-t>
      </div>

      <!-- FR-92 P8 — the org's default pattern. A preference, never a
           policy: it never reaches a device, and a person's own last
           choice for a device wins over it in the viewer. -->
      <v-select
        :model-value="agentStore.orgKeepBusyDefaultPattern ?? 'circle'"
        :items="patternItems"
        :label="t('keepBusy.defaultPattern.label')"
        :loading="savingKeepBusyPattern"
        :disabled="savingKeepBusyPattern || agentStore.orgKeepBusyDenied === null"
        density="compact"
        hide-details
        class="mt-4"
        style="max-width: 320px"
        data-testid="org-keep-busy-default-pattern"
        @update:model-value="onDefaultPattern"
      />
      <div class="text-caption text-medium-emphasis mt-1">
        {{ t('keepBusy.defaultPattern.hint') }}
      </div>

      <v-alert v-if="keepBusyError" type="error" variant="tonal" density="compact" class="mt-3">
        {{ keepBusyError }}
      </v-alert>

      <v-divider class="my-4" />
      <!-- FR-92 P7 — the permanent history. MANAGE_AGENTS server-side; a
           refusal shows inside the list and ends nothing. -->
      <KeepBusyHistorySection :tenant-id="tenantId" />
    </SettingsGate>

    <!-- FR-101 P2 — what a remote-desktop session in this org may carry.
         Each feature on / ask / off; the stricter of this and a device's own
         setting wins, and the device enforces it whatever the server sends.
         A change applies to sessions that start after it. -->
    <SettingsGate
      :title="t('mh.settings.rc.title')"
      icon="mdi-shield-lock-outline"
      :summary="rcFeaturesSummary"
      data-testid="org-rc-session-card"
    >
      <p class="text-body-2 mb-3">
        <i18n-t keypath="mh.settings.rc.body" tag="span" scope="global">
          <template #ask><strong>{{ t('mh.settings.rc.askWord') }}</strong></template>
        </i18n-t>
      </p>
      <v-select
        v-for="f in rcFeatureRows()"
        :key="f.key"
        :model-value="agentStore.orgRcSessionPolicy?.[f.key] ?? null"
        :items="rcPolicyItems()"
        :label="f.label"
        :loading="savingRcFeature === f.key"
        :disabled="savingRcFeature !== null || agentStore.orgRcSessionPolicy === null"
        density="compact"
        hide-details
        class="mb-3"
        style="max-width: 320px"
        :data-testid="`org-rc-session-${f.key}`"
        @update:model-value="(v: RcFeaturePolicy | null) => onRcFeature(f.key, v)"
      />
      <div class="text-caption text-medium-emphasis mt-1">
        <i18n-t keypath="mh.settings.rc.hint" tag="span" scope="global">
          <template #a><code>rc_clipboard</code></template>
          <template #b><code>rc_files</code></template>
          <template #c><code>rc_audio</code></template>
        </i18n-t>
      </div>
      <v-alert v-if="rcSessionError" type="error" variant="tonal" density="compact" class="mt-3">
        {{ rcSessionError }}
      </v-alert>
    </SettingsGate>

    <!-- FR-51 gate 1. Its own card and its own server-side switch, like the
         two above: a standing credential that mints device identities is its
         own grant, not an implication of exec or SSH. -->
    <SettingsGate
      :title="t('mh.settings.keys.title')"
      icon="mdi-clock-fast"
      :summary="onOff(agentStore.orgEphemeralKeysEnabled)"
    >
      <v-alert
        type="warning"
        variant="tonal"
        density="compact"
        class="mb-4"
        icon="mdi-shield-alert-outline"
      >
        <i18n-t keypath="mh.settings.keys.warn" tag="span" scope="global">
          <template #reusable><strong>{{ t('mh.settings.keys.reusable') }}</strong></template>
          <template #selfRemoving><strong>{{ t('mh.settings.keys.selfRemoving') }}</strong></template>
        </i18n-t>
      </v-alert>

      <v-switch
        :model-value="agentStore.orgEphemeralKeysEnabled === true"
        :loading="savingKeys"
        :disabled="savingKeys || agentStore.orgEphemeralKeysEnabled === null"
        color="primary"
        density="compact"
        hide-details
        :label="t('mh.settings.keys.allow')"
        @update:model-value="onToggleKeys"
      />
      <div class="text-caption text-medium-emphasis mt-1">
        {{ t('mh.settings.keys.hint') }}
      </div>

      <v-alert v-if="keysError" type="error" variant="tonal" density="compact" class="mt-3">
        {{ keysError }}
      </v-alert>
    </SettingsGate>

    <!-- FR-101 P4b — how long a remote-desktop session in this org may last.
         The hub ends a session that reaches it (the viewer is told which limit
         it was). Off for existing organizations (operator decision). -->
    <SettingsGate
      :title="t('mh.settings.lim.title')"
      icon="mdi-timer-sand"
      :summary="limitsSummary"
      data-testid="org-rc-limits-card"
    >
      <v-select
        :model-value="agentStore.orgRcMaxSessionSecs === undefined ? null : agentStore.orgRcMaxSessionSecs ?? 0"
        :items="maxSessionOptions()"
        :label="t('mh.settings.lim.max')"
        :loading="savingMaxSession"
        :disabled="savingMaxSession || agentStore.orgRcMaxSessionSecs === undefined"
        density="compact"
        hide-details
        style="max-width: 320px"
        data-testid="org-rc-max-session"
        @update:model-value="onMaxSession"
      />
      <div class="text-caption text-medium-emphasis mt-1">
        {{ t('mh.settings.lim.maxHint') }}
      </div>
      <v-alert v-if="maxSessionError" type="error" variant="tonal" density="compact" class="mt-3">
        {{ maxSessionError }}
      </v-alert>
      <!-- FR-101 P4b-2 — the idle limit. The DEVICE keeps it (only it sees
           both the input and the screen), so devices too old to advertise
           it ignore it; a device's own setting may shorten it. -->
      <v-select
        :model-value="agentStore.orgRcIdleSecs === undefined ? null : agentStore.orgRcIdleSecs ?? 0"
        :items="idleOptions()"
        :label="t('mh.settings.lim.idle')"
        :loading="savingIdle"
        :disabled="savingIdle || agentStore.orgRcIdleSecs === undefined"
        density="compact"
        hide-details
        class="mt-4"
        style="max-width: 320px"
        data-testid="org-rc-idle"
        @update:model-value="onIdle"
      />
      <div class="text-caption text-medium-emphasis mt-1">
        {{ t('mh.settings.lim.idleHint') }}
      </div>
      <v-alert v-if="idleError" type="error" variant="tonal" density="compact" class="mt-3">
        {{ idleError }}
      </v-alert>
    </SettingsGate>

    <!-- The exec/SSH audit + activity sections moved to /tenant/{id}/audit
         (2026-08-26) — history review is its own nav destination now. -->
  </component>
</template>

<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { useDisplay } from 'vuetify'
import { VExpansionPanels } from 'vuetify/components'
import { useTenantStore } from '@/stores/tenant'
import { useAgentStore, type RcFeaturePolicy, type RcSessionPolicy } from '@/stores/agents'
import { KEEP_BUSY_PATTERNS } from '@/composables/keepBusy'
import KeepBusyHistorySection from '@/components/admin/KeepBusyHistorySection.vue'
import SettingsGate from '@/components/admin/SettingsGate.vue'

const props = defineProps<{ tenantId: string }>()
const { t } = useI18n()
const tenantStore = useTenantStore()
const agentStore = useAgentStore()
const { xs } = useDisplay()

const saving = ref(false)
const error = ref<string | null>(null)

// Tracked separately from the exec pair on purpose: a failure to flip one
// switch must not render as an error under the other.
const savingSsh = ref(false)
const sshError = ref<string | null>(null)

async function onToggle(v: boolean | null) {
  saving.value = true
  error.value = null
  try {
    await agentStore.setOrgExecEnabled(props.tenantId, v === true)
  } catch (e) {
    error.value = (e as Error).message
  } finally {
    saving.value = false
  }
}

// FR-94 — its own pair, so a failure here never renders under the switch above.
const savingRequire = ref(false)
const requireError = ref<string | null>(null)

async function onToggleRequireSystem(v: boolean | null) {
  savingRequire.value = true
  requireError.value = null
  try {
    await agentStore.setOrgExecRequireSystem(props.tenantId, v === true)
  } catch (e) {
    requireError.value = (e as Error).message
  } finally {
    savingRequire.value = false
  }
}

async function onToggleSsh(v: boolean | null) {
  savingSsh.value = true
  sshError.value = null
  try {
    await agentStore.setOrgSshEnabled(props.tenantId, v === true)
  } catch (e) {
    sshError.value = (e as Error).message
  } finally {
    savingSsh.value = false
  }
}

// FR-52 — its own pair too. A failure to flip the external-access switch
// must never render as an error under exec or SSH.
const savingExternal = ref(false)
const externalError = ref<string | null>(null)

async function onToggleExternal(v: boolean | null) {
  savingExternal.value = true
  externalError.value = null
  try {
    await agentStore.setOrgExternalAccessEnabled(props.tenantId, v === true)
  } catch (e) {
    externalError.value = (e as Error).message
  } finally {
    savingExternal.value = false
  }
}

// FR-92 — its own pair too. The switch shows "allow"; the server stores
// the deny.
const savingKeepBusy = ref(false)
const keepBusyError = ref<string | null>(null)

async function onToggleKeepBusy(allow: boolean | null) {
  savingKeepBusy.value = true
  keepBusyError.value = null
  try {
    await agentStore.setOrgKeepBusyDenied(props.tenantId, allow !== true)
  } catch (e) {
    keepBusyError.value = (e as Error).message
  } finally {
    savingKeepBusy.value = false
  }
}

// FR-92 P8 — the default pattern, its own saving flag so a failed pattern
// change never greys out the switch. The labels are the viewer's own.
const patternItems = KEEP_BUSY_PATTERNS.map((p) => ({ title: p.label, value: p.id }))
const savingKeepBusyPattern = ref(false)

async function onDefaultPattern(pattern: string | null) {
  if (!pattern) return
  savingKeepBusyPattern.value = true
  keepBusyError.value = null
  try {
    await agentStore.setOrgKeepBusyDefaultPattern(props.tenantId, pattern)
  } catch (e) {
    keepBusyError.value = (e as Error).message
  } finally {
    savingKeepBusyPattern.value = false
  }
}

// FR-101 P2 — the org's session policy, one select per feature. Its own error,
// and the feature being saved, so a failure never renders under another card.
const rcFeatureRows = (): { key: keyof RcSessionPolicy; label: string; short: string }[] => [
  { key: 'clipboard', label: t('mh.settings.rc.clipboard'), short: t('mh.settings.rc.clipboard') },
  { key: 'files', label: t('mh.settings.rc.fileTransfer'), short: t('mh.settings.rc.files') },
  { key: 'audio', label: t('mh.settings.rc.audio'), short: t('mh.settings.rc.audioShort') },
]
const rcPolicyItems = (): { title: string; value: RcFeaturePolicy }[] => [
  { title: t('mh.settings.rc.on'), value: 'on' },
  { title: t('mh.settings.rc.ask'), value: 'ask' },
  { title: t('mh.settings.rc.off'), value: 'off' },
]
const savingRcFeature = ref<keyof RcSessionPolicy | null>(null)
const rcSessionError = ref<string | null>(null)

async function onRcFeature(key: keyof RcSessionPolicy, value: RcFeaturePolicy | null) {
  if (!value) return
  savingRcFeature.value = key
  rcSessionError.value = null
  try {
    await agentStore.setOrgRcSessionPolicy(props.tenantId, { [key]: value })
  } catch (e) {
    rcSessionError.value = (e as Error).message
  } finally {
    savingRcFeature.value = null
  }
}

// FR-51 — its own pair, same isolation rule as exec vs SSH above.
const savingKeys = ref(false)
const keysError = ref<string | null>(null)

async function onToggleKeys(v: boolean | null) {
  savingKeys.value = true
  keysError.value = null
  try {
    await agentStore.setOrgEphemeralKeysEnabled(props.tenantId, v === true)
  } catch (e) {
    keysError.value = (e as Error).message
  } finally {
    savingKeys.value = false
  }
}

// FR-101 P4b — the maximum session length. `0` in the select is "no limit"
// (sent as `null`); the stored value is seconds.
/** A preset duration's label, in the interface language. */
function durationLabel(secs: number): string {
  if (secs === 0) return t('mh.settings.lim.none')
  if (secs === 60 * 60) return t('mh.settings.lim.hour')
  if (secs % 3600 === 0) return t('mh.settings.lim.hours', { n: secs / 3600 })
  return t('mh.settings.lim.minutes', { n: Math.round(secs / 60) })
}
const presets = (values: number[]): { title: string; value: number }[] =>
  values.map((value) => ({ title: durationLabel(value), value }))
const maxSessionItems = (): { title: string; value: number }[] =>
  presets([0, 30 * 60, 60 * 60, 2 * 60 * 60, 4 * 60 * 60, 8 * 60 * 60, 24 * 60 * 60])
/** The presets, plus the stored value when it is none of them (set through
 *  the API), so the select never shows blank for a limit that is in force. */
function maxSessionOptions(): { title: string; value: number }[] {
  const cur = agentStore.orgRcMaxSessionSecs
  const items = maxSessionItems()
  if (typeof cur === 'number' && cur > 0 && !items.some((i) => i.value === cur)) {
    return [...items, { title: t('mh.settings.lim.minutes', { n: Math.round(cur / 60) }), value: cur }]
  }
  return items
}
const savingMaxSession = ref(false)
const maxSessionError = ref<string | null>(null)

async function onMaxSession(secs: number | null) {
  if (secs === null) return
  savingMaxSession.value = true
  maxSessionError.value = null
  try {
    await agentStore.setOrgRcMaxSessionSecs(props.tenantId, secs === 0 ? null : secs)
  } catch (e) {
    maxSessionError.value = (e as Error).message
  } finally {
    savingMaxSession.value = false
  }
}

// FR-101 P4b-2 — the idle limit, the same way: `0` is "no limit".
const idleItems = (): { title: string; value: number }[] =>
  presets([0, 5 * 60, 15 * 60, 30 * 60, 60 * 60, 2 * 60 * 60])
function idleOptions(): { title: string; value: number }[] {
  const cur = agentStore.orgRcIdleSecs
  const items = idleItems()
  if (typeof cur === 'number' && cur > 0 && !items.some((i) => i.value === cur)) {
    return [...items, { title: t('mh.settings.lim.minutes', { n: Math.round(cur / 60) }), value: cur }]
  }
  return items
}
const savingIdle = ref(false)
const idleError = ref<string | null>(null)

async function onIdle(secs: number | null) {
  if (secs === null) return
  savingIdle.value = true
  idleError.value = null
  try {
    await agentStore.setOrgRcIdleSecs(props.tenantId, secs === 0 ? null : secs)
  } catch (e) {
    idleError.value = (e as Error).message
  } finally {
    savingIdle.value = false
  }
}

// FR-116 — each gate's state, for its collapsed panel on a phone. Empty while
// it is unknown: not loaded yet, or not readable with the caller's rights.
function onOff(v: boolean | null): string {
  return v === null ? '' : v ? t('mh.settings.rc.on') : t('mh.settings.rc.off')
}
/** A multi-part summary wraps only between parts ("Files: ask · Audio: off"),
 *  never inside one. */
function joinParts(parts: string[]): string {
  return parts.map((p) => p.replace(/ /g, ' ')).join(' · ')
}
const keepBusySummary = computed(() =>
  agentStore.orgKeepBusyDenied === null ? '' : agentStore.orgKeepBusyDenied ? t('mh.settings.kb.notAllowed') : t('mh.settings.kb.allowed'),
)
const rcFeaturesSummary = computed(() => {
  const p = agentStore.orgRcSessionPolicy
  if (!p) return ''
  const limited = rcFeatureRows()
    .filter((f) => p[f.key] === 'ask' || p[f.key] === 'off')
    .map((f) => `${f.short}: ${t(`mh.settings.rc.pol.${p[f.key]}`)}`)
  return limited.length ? joinParts(limited) : t('mh.settings.rc.allOn')
})
const limitsSummary = computed(() => {
  const max = agentStore.orgRcMaxSessionSecs
  const idle = agentStore.orgRcIdleSecs
  if (max === undefined && idle === undefined) return ''
  const parts: string[] = []
  if (typeof max === 'number' && max > 0) {
    parts.push(t('mh.settings.lim.maxPart', { d: maxSessionOptions().find((i) => i.value === max)?.title }))
  }
  if (typeof idle === 'number' && idle > 0) {
    parts.push(t('mh.settings.lim.idlePart', { d: idleOptions().find((i) => i.value === idle)?.title }))
  }
  return parts.length ? joinParts(parts) : t('mh.settings.lim.noLimits')
})

onMounted(() => {
  void agentStore.fetchOrgRcSessionLimits(props.tenantId)
  void agentStore.fetchOrgExecEnabled(props.tenantId)
  void agentStore.fetchOrgSshEnabled(props.tenantId)
  void agentStore.fetchOrgKeepBusyDenied(props.tenantId)
  void agentStore.fetchOrgRcSessionPolicy(props.tenantId)
  void agentStore.fetchOrgEphemeralKeysEnabled(props.tenantId)
  void agentStore.fetchExternalAccess(props.tenantId)
})
</script>
