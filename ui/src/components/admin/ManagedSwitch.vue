<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 G ROX EOOD -->
<template>
  <!-- The toggle keeps its width and the label wraps under it on a narrow
       screen. In a no-wrap row the toggle (a v-btn-group, which scrolls inside
       itself) shrank instead, and its third button — On — was hidden: a key
       that was On looked exactly like Leave alone. -->
  <div class="d-flex flex-wrap align-center ga-2 ga-sm-3">
    <v-btn-toggle
      :model-value="choice"
      :disabled="disabled"
      color="primary"
      density="compact"
      variant="outlined"
      divided
      mandatory
      class="flex-shrink-0"
      @update:model-value="pick"
    >
      <v-btn value="unmanaged" size="small">{{ t('mh.managed.leave') }}</v-btn>
      <v-btn value="off" size="small">{{ t('mh.managed.off') }}</v-btn>
      <v-btn value="on" size="small">{{ t('mh.managed.on') }}</v-btn>
    </v-btn-toggle>
    <span class="text-body-2">{{ label }}</span>
  </div>
</template>

<script setup lang="ts">
/**
 * Three states, because the wire has three and a switch has two.
 *
 * `undefined` = NOT MANAGED: the device keeps whatever it has locally. That is
 * a different thing from `false`, which actively asserts "off" and will turn
 * the key off on a device that had it on. A two-state control cannot express
 * the difference, so an operator toggling one key would silently assert a
 * value for every other key on the surface — which is exactly why
 * `DesiredConfig`'s fields are all `Option` on the server.
 */
import { computed } from 'vue'
import { useI18n } from 'vue-i18n'

const props = defineProps<{
  modelValue: boolean | undefined
  label: string
  disabled?: boolean
}>()

const emit = defineEmits<{
  (e: 'update:modelValue', v: boolean | undefined): void
}>()

const { t } = useI18n()

type Choice = 'unmanaged' | 'off' | 'on'

const choice = computed<Choice>(() =>
  props.modelValue === undefined ? 'unmanaged' : props.modelValue ? 'on' : 'off',
)

function pick(v: unknown) {
  // `mandatory` keeps one button always selected, so `v` is never null in
  // practice — but a stray value must not be read as `false`, which would
  // silently turn a key OFF on the device.
  if (v !== 'unmanaged' && v !== 'off' && v !== 'on') return
  emit('update:modelValue', v === 'unmanaged' ? undefined : v === 'on')
}
</script>
