<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 G ROX EOOD -->
<!--
  FR-39 — the fallback for a visitor who is interested but not ready to create
  an account. Without it, everyone who does not convert on the spot is
  unreachable forever, and every burst of traffic is a spike rather than an
  audience.

  The server answers 202 for every outcome — new address, known address,
  previously unsubscribed — so this component deliberately shows ONE message and
  cannot report "you are already subscribed". That is the point: telling them
  apart here would leak list membership for an address the visitor may not own.

  FR-58: `variant` — the original styling assumed the teal CTA parent ("dark");
  "light" makes it reusable on white/pale surfaces (footer, the deferred
  prompt). Emits `subscribed` on the one success path so a host surface can
  latch "never ask again".
-->
<template>
  <div class="stay-in-touch" :class="variant === 'light' ? 'stay-light' : 'stay-dark'">
    <p v-if="!hideLede" class="text-body-2 mb-3 stay-sub">
      {{ t('mh.nl.lede') }}
    </p>

    <v-form v-if="!done" class="d-flex flex-wrap ga-2 justify-center" @submit.prevent="submit">
      <v-text-field
        v-model="email"
        type="email"
        name="email"
        autocomplete="email"
        placeholder="you@example.com"
        density="compact"
        variant="solo"
        hide-details
        single-line
        :disabled="busy"
        class="stay-field"
        :aria-label="t('mh.nl.yourEmail')"
      />
      <v-btn
        type="submit"
        :color="variant === 'light' ? 'primary' : 'white'"
        variant="flat"
        :class="variant === 'light' ? '' : 'text-primary'"
        :loading="busy"
        :disabled="!email.trim()"
      >
        {{ t('mh.nl.keepPosted') }}
      </v-btn>
    </v-form>

    <p v-else class="text-body-2 stay-done" role="status">
      {{ t('mh.nl.thanks') }}
    </p>

    <p class="text-caption mt-3 stay-fine">
      {{ t('mh.nl.fine') }}
      <router-link to="/privacy" class="stay-link">{{ t('mh.nl.privacy') }}</router-link>
    </p>
  </div>
</template>

<script setup lang="ts">
import { ref } from 'vue'
import { api } from '@/api/client'
import { useSnackbar } from '@/composables/useSnackbar'
import { newsletterSource, queryOf } from '@/utils/attribution'
import { trackGoal } from '@/utils/goals'
import { useI18n } from 'vue-i18n'

const { t } = useI18n()

const props = withDefaults(
  defineProps<{ source?: string; variant?: 'dark' | 'light'; hideLede?: boolean }>(),
  {
    source: 'landing',
    variant: 'dark',
    hideLede: false,
  },
)
const emit = defineEmits<{ subscribed: [] }>()

const email = ref('')
const busy = ref(false)
const done = ref(false)
const { showError } = useSnackbar()

async function submit() {
  if (busy.value || !email.value.trim()) return
  busy.value = true
  try {
    // ⚠️ Path is relative to the client's BASE_URL, which is already '/api' —
    // this line once said '/api/subscribe', the wire request was
    // POST /api/api/subscribe, and every submission 404'd (FR-58 evidence 1).
    // FR-88 §3a: a campaign on this page's URL stands in for the form's own
    // source. Read at submit time from the URL; nothing is stored.
    const source = newsletterSource(queryOf(window.location.search), props.source)
    await api.post('/subscribe', { email: email.value.trim(), source })
    // Success is the ONLY branch, by design — see the comment at the top of
    // this file. The server does not tell us which outcome occurred.
    done.value = true
    email.value = ''
    emit('subscribed')
    trackGoal('subscribe')
  } catch {
    // Only a transport or server failure lands here; a rejected address does
    // not, because the endpoint accepts everything that parses.
    showError(t('mh.nl.serverFailed'))
  } finally {
    busy.value = false
  }
}
</script>

<style scoped>
.stay-in-touch {
  max-width: 520px;
  margin: 0 auto;
}
.stay-field {
  flex: 1 1 240px;
  min-width: 0;
}
/* The original look: white-on-teal, for the landing CTA parent. */
.stay-dark .stay-sub,
.stay-dark .stay-done {
  color: rgba(255, 255, 255, 0.86);
}
.stay-dark .stay-fine {
  color: rgba(255, 255, 255, 0.68);
  line-height: 1.5;
}
.stay-dark .stay-link {
  color: rgba(255, 255, 255, 0.92);
  text-underline-offset: 2px;
}
/* Light surfaces: footer, the deferred prompt card. */
.stay-light .stay-sub,
.stay-light .stay-done {
  color: rgba(26, 26, 46, 0.78);
}
.stay-light .stay-fine {
  color: rgba(26, 26, 46, 0.6);
  line-height: 1.5;
}
.stay-light .stay-link {
  color: #00796b;
  text-underline-offset: 2px;
}
.stay-light .stay-field :deep(.v-field) {
  border: 1px solid rgba(0, 150, 136, 0.35);
  box-shadow: none;
}
</style>
