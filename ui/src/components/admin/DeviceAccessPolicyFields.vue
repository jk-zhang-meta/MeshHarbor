<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 G ROX EOOD -->
<template>
  <!-- A device's access-policy controls — ONE copy for the desktop grid's
       Consent cell (`plain`: values only, stacked in the cell) and the phone
       card's Access panel (`outlined`: labelled fields). Every control writes
       on change; the parent owns the request and the busy state. -->
  <div :class="['device-policy-fields', `device-policy-fields--${variant}`]">
    <v-select
      :model-value="agent.access_policy.consent_mode ?? 'prompt'"
      :items="consentModeItems()"
      :label="labelled ? t('mh.policy.label.consent') : undefined"
      density="compact"
      :variant="variant"
      hide-details
      :disabled="busy"
      :loading="busy"
      class="consent-select"
      :aria-label="t('mh.policy.aria.consent', { name: deviceName })"
      @update:model-value="(m) => emit('consent', m as ConsentMode)"
    />
    <!-- FR-27 — the owner shortcut, made visible. Controlling your OWN device
         auto-consents server-side BEFORE this mode is read, so on a fleet
         where one person owns everything the select above had no observable
         effect and nothing said so. Shown only on devices YOU own; for
         everyone else the mode already applies and the row would be noise. -->
    <v-checkbox
      v-if="ownedByMe"
      :model-value="agent.access_policy.prompt_owner ?? false"
      density="compact"
      hide-details
      :disabled="busy"
      :label="ownerPromptLabel(agent.access_policy)"
      :aria-label="t('mh.policy.aria.owner', { name: deviceName })"
      class="consent-owner-toggle"
      @update:model-value="(v) => emit('prompt-owner', v === true)"
    />
    <!-- P6 — multi-user input mode (free-for-all | exclusive). -->
    <v-select
      :model-value="agent.access_policy.input_mode ?? 'free'"
      :items="inputModeItems()"
      :label="labelled ? t('mh.policy.label.input') : undefined"
      density="compact"
      :variant="variant"
      hide-details
      :disabled="busy"
      class="consent-select"
      :aria-label="t('mh.policy.aria.input', { name: deviceName })"
      @update:model-value="(m) => emit('input-mode', m as 'free' | 'exclusive')"
    />
    <!-- FR-101 P4b-2b — this device's own idle limit. The shorter of it and
         the organization's applies, so it can tighten the org's but never
         loosen it; the device keeps it. -->
    <v-select
      :model-value="agent.access_policy.auto_terminate_idle_minutes ?? 0"
      :items="idleMinuteItems(agent.access_policy.auto_terminate_idle_minutes)"
      :label="labelled ? t('mh.policy.label.idle') : undefined"
      density="compact"
      :variant="variant"
      hide-details
      :disabled="busy"
      class="consent-select"
      :title="idleLimitHint()"
      :aria-label="t('mh.policy.aria.idle', { name: deviceName })"
      @update:model-value="(m) => emit('idle-minutes', m as number)"
    />
    <!-- FR-99 P3b — ask this device to lock its screen when the last remote
         session ends. The device takes the stricter of this and its owner's
         own setting, so it can only tighten it. -->
    <v-select
      :model-value="agent.access_policy.lock_on_end ?? 'never'"
      :items="lockOnEndItems()"
      :label="labelled ? t('mh.policy.label.lock') : undefined"
      density="compact"
      :variant="variant"
      hide-details
      :disabled="busy"
      class="consent-select"
      :title="lockOnEndHint()"
      :aria-label="t('mh.policy.aria.lock', { name: deviceName })"
      @update:model-value="(m) => emit('lock-on-end', m as LockOnEnd)"
    />
    <!-- #1882 — may a session to this device ride the mesh? Off by default:
         the agent keeps overlay addresses out of its ICE. -->
    <v-checkbox
      :model-value="agent.access_policy.rc_overlay ?? false"
      density="compact"
      hide-details
      :disabled="busy"
      :label="t('mh.policy.label.rcOverlay')"
      :title="rcOverlayHint()"
      :aria-label="t('mh.policy.aria.rcOverlay', { name: deviceName })"
      class="consent-owner-toggle"
      @update:model-value="(v) => emit('rc-overlay', v === true)"
    />
    <!-- The hints above live in `title`, which a touch screen never shows.
         The labelled (phone) layout spells them out instead, on demand. -->
    <div v-if="labelled" class="text-caption text-medium-emphasis mt-1">
      <a
        href="#"
        class="text-primary"
        :aria-expanded="showHints"
        @click.prevent="showHints = !showHints"
      >
        {{ showHints ? t('mh.policy.hideHints') : t('mh.policy.showHints') }}
      </a>
      <ul v-if="showHints" class="ps-4 mt-1">
        <li class="mb-1"><strong>{{ t('mh.policy.label.idle') }}</strong> — {{ idleLimitHint() }}</li>
        <li class="mb-1"><strong>{{ t('mh.policy.label.lock') }}</strong> — {{ lockOnEndHint() }}</li>
        <li><strong>{{ t('mh.policy.label.rcOverlay') }}</strong> — {{ rcOverlayHint() }}</li>
      </ul>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import type { Agent, ConsentMode, LockOnEnd } from '@/stores/agents'
import {
  consentModeItems,
  idleLimitHint,
  idleMinuteItems,
  inputModeItems,
  lockOnEndHint,
  lockOnEndItems,
  ownerPromptLabel,
  rcOverlayHint,
} from './devicePolicy'

const { t } = useI18n()

const props = withDefaults(
  defineProps<{
    agent: Agent
    /** A write for this device is in flight: every control waits. */
    busy?: boolean
    /** The caller owns the device — only then does the owner toggle exist. */
    ownedByMe?: boolean
    /** `plain` for the grid cell (values only), `outlined` for the phone
     *  card (labelled fields). */
    variant?: 'plain' | 'outlined'
  }>(),
  { busy: false, ownedByMe: false, variant: 'plain' },
)

const emit = defineEmits<{
  consent: [mode: ConsentMode]
  'prompt-owner': [on: boolean]
  'input-mode': [mode: 'free' | 'exclusive']
  'idle-minutes': [minutes: number]
  'lock-on-end': [lock: LockOnEnd]
  'rc-overlay': [on: boolean]
}>()

const labelled = computed(() => props.variant === 'outlined')
const deviceName = computed(() => props.agent.display_name || props.agent.name)
const showHints = ref(false)
</script>

<style scoped>
.device-policy-fields--outlined {
  display: flex;
  flex-direction: column;
  gap: 8px;
}
</style>
