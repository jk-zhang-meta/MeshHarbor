<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 G ROX EOOD -->
<template>
  <!-- FR-129 — the one place a person types a two-factor code: the remote
       desktop prompt, the web console and the admin dialog. A phone keypad by
       default (six digits); a recovery code, when allowed, is a deliberate
       switch, because it is spent for good. -->
  <div>
    <v-text-field
      ref="field"
      v-model="raw"
      :label="recovery ? t('mh.tfa.code.recoveryLabel') : t('mh.tfa.code.label')"
      :placeholder="recovery ? 'abcd-efgh' : '123456'"
      :inputmode="recovery ? 'text' : 'numeric'"
      :maxlength="recovery ? 9 : 6"
      autocomplete="one-time-code"
      autocapitalize="off"
      spellcheck="false"
      :autofocus="autofocus"
      :disabled="disabled"
      :error-messages="errorMessages"
      :hide-details="!errorMessages"
      variant="outlined"
      density="comfortable"
      class="tfa-code"
      data-testid="tfa-code-input"
      @keydown.enter.prevent="onEnter"
    />
    <v-btn
      v-if="allowRecovery"
      variant="text"
      size="small"
      class="px-1 mt-1"
      :disabled="disabled"
      data-testid="tfa-code-mode"
      @click="toggle"
    >
      {{ recovery ? t('mh.tfa.code.useApp') : t('mh.tfa.code.useRecovery') }}
    </v-btn>
  </div>
</template>

<script setup lang="ts">
import { nextTick, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { codeForWire } from '@/utils/twoFactor'

const props = withDefaults(
  defineProps<{
    modelValue: string
    /** Offer a recovery code too (sessions and switching off; never the
     *  confirm step, which proves the app was set up). */
    allowRecovery?: boolean
    autofocus?: boolean
    disabled?: boolean
    errorMessages?: string
  }>(),
  { allowRecovery: true, autofocus: false, disabled: false, errorMessages: undefined },
)

const emit = defineEmits<{
  (e: 'update:modelValue', v: string): void
  /** Enter on a well-formed code. */
  (e: 'submit'): void
}>()

const { t } = useI18n()
const field = ref<{ focus: () => void } | null>(null)
const recovery = ref(false)
const raw = ref(props.modelValue)

/** Six digits only in app mode, so a pasted "123 456" still reads right. */
function clean(v: string): string {
  return recovery.value ? v.slice(0, 9) : v.replace(/\D/g, '').slice(0, 6)
}

watch(raw, (v) => {
  const c = clean(v ?? '')
  // Writing the cleaned value back is what makes a rejected key vanish from
  // the field: an unchanged model would leave it on screen.
  if (c !== v) {
    raw.value = c
    return
  }
  if (c !== props.modelValue) emit('update:modelValue', c)
})

watch(
  () => props.modelValue,
  (v) => {
    if (v !== raw.value) raw.value = v
  },
)

function toggle() {
  recovery.value = !recovery.value
  raw.value = ''
  void nextTick(() => field.value?.focus())
}

function onEnter() {
  if (codeForWire(raw.value, props.allowRecovery)) emit('submit')
}

function focus() {
  field.value?.focus()
}

defineExpose({ focus })
</script>

<style scoped>
.tfa-code :deep(input) {
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  font-size: 1.25rem;
  letter-spacing: 0.25em;
}
</style>
