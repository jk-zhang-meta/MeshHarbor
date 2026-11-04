<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 G ROX EOOD -->
<template>
  <v-card>
    <v-card-title>MagicDNS</v-card-title>

    <v-card-text>
      <v-alert
        v-if="error"
        type="error"
        variant="tonal"
        closable
        @click:close="error = null"
        class="mb-4"
      >
        {{ error }}
      </v-alert>

      <v-alert
        v-if="saved"
        type="success"
        variant="tonal"
        closable
        @click:close="saved = false"
        class="mb-4"
      >
        {{ $t('mh.dns.saved') }}
      </v-alert>

      <p class="text-medium-emphasis mb-4">
        {{ $t('mh.dns.intro1') }}
        (<code>&lt;node&gt;.&lt;domain&gt;</code>){{ $t('mh.dns.intro2') }}
      </p>

      <v-text-field
        v-model="domain"
        :label="$t('mh.dns.domain')"
        placeholder="myorg.roomler.net"
        :hint="$t('mh.dns.domainHint')"
        persistent-hint
        class="mb-4"
      />

      <v-text-field
        v-model="nameserversText"
        :label="$t('mh.dns.upstream')"
        placeholder="1.1.1.1, 8.8.8.8"
        :hint="$t('mh.dns.upstreamHint')"
        persistent-hint
        class="mb-4"
      />

      <v-btn color="primary" variant="flat" :loading="loading" @click="save">
        {{ $t('common.save') }}
      </v-btn>
    </v-card-text>
  </v-card>
</template>

<script setup lang="ts">
import { ref } from 'vue'
import { useOverlayRoutesStore } from '@/stores/overlayRoutes'

const props = defineProps<{ tenantId: string }>()
const store = useOverlayRoutesStore()

const domain = ref('')
const nameserversText = ref('')
const loading = ref(false)
const saved = ref(false)
const error = ref<string | null>(null)

async function load() {
  try {
    const s = await store.fetchMagicDns(props.tenantId)
    domain.value = s.magic_dns_domain ?? ''
    nameserversText.value = s.magic_dns_nameservers.join(', ')
  } catch (e) {
    error.value = (e as Error).message
  }
}

async function save() {
  loading.value = true
  error.value = null
  saved.value = false
  try {
    const nameservers = nameserversText.value
      .split(',')
      .map((s) => s.trim())
      .filter((s) => s.length > 0)
    const trimmed = domain.value.trim()
    const s = await store.saveMagicDns(props.tenantId, {
      magic_dns_domain: trimmed.length > 0 ? trimmed : null,
      magic_dns_nameservers: nameservers,
    })
    domain.value = s.magic_dns_domain ?? ''
    nameserversText.value = s.magic_dns_nameservers.join(', ')
    saved.value = true
  } catch (e) {
    error.value = (e as Error).message
  } finally {
    loading.value = false
  }
}

load()
</script>
