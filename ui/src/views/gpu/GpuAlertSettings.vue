<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 G ROX EOOD -->
<template>
  <v-row dense>
    <!-- Personal Alert Rules -->
    <v-col cols="12" lg="5">
      <v-card variant="outlined">
        <v-card-title>{{ t('mh.gpu.alerts.rulesTitle') }}</v-card-title>
        <v-card-text>
          <p class="text-body-2 text-medium-emphasis mb-3">{{ t('mh.gpu.alerts.rulesIntro') }}</p>
          <v-switch
            v-model="ruleForm.enabled"
            color="primary"
            :label="t('mh.gpu.alerts.enable')"
            density="compact"
            hide-details
            class="mb-3"
          />
          <div class="d-flex flex-wrap ga-2 mb-2">
            <v-text-field
              v-model.number="ruleForm.free_gpus_min"
              type="number"
              min="1"
              density="compact"
              variant="outlined"
              :label="t('mh.gpu.alerts.freeMin')"
              style="max-width: 180px"
            />
            <v-text-field
              v-model.number="ruleForm.free_min_mem_gb"
              type="number"
              min="0"
              density="compact"
              variant="outlined"
              :label="t('mh.gpu.alerts.minMemGb')"
              style="max-width: 180px"
            />
          </div>
          <v-checkbox v-model="ruleForm.held_idle_alert" density="compact" hide-details :label="t('mh.gpu.alerts.heldIdle')" />
          <v-checkbox v-model="ruleForm.fault_alert" density="compact" hide-details :label="t('mh.gpu.alerts.fault')" />
          <v-checkbox v-model="ruleForm.machine_alert" density="compact" hide-details :label="t('mh.gpu.alerts.offline')" />
          <v-select
            v-model="ruleForm.lang"
            :items="langChoices"
            density="compact"
            variant="outlined"
            :label="t('mh.gpu.alerts.lang')"
            class="mt-3"
            style="max-width: 220px"
          />
          <v-alert v-if="ruleSaved" type="success" variant="tonal" density="compact" class="mt-2">
            {{ t('mh.gpu.alerts.saved') }}
          </v-alert>
          <v-alert v-if="ruleError" type="error" variant="tonal" density="compact" class="mt-2">
            {{ ruleError }}
          </v-alert>
          <v-btn color="primary" class="mt-3" :loading="savingRule" @click="saveRules">
            {{ t('common.save') }}
          </v-btn>
        </v-card-text>
      </v-card>
    </v-col>

    <!-- Personal Bot Channels -->
    <v-col cols="12" lg="7">
      <v-card variant="outlined">
        <v-card-title class="d-flex align-center">
          <span>{{ t('mh.gpu.bots.title') }}</span>
          <v-spacer />
          <v-btn color="primary" size="small" prepend-icon="mdi-plus" @click="openAddChannel">
            {{ t('mh.gpu.bots.add') }}
          </v-btn>
        </v-card-title>
        <v-card-text>
          <p class="text-body-2 text-medium-emphasis mb-3">{{ t('mh.gpu.bots.intro') }}</p>
          <v-progress-linear v-if="gpuStore.alertsLoading" indeterminate class="mb-2" />
          <v-alert v-if="botFeedback" :type="botFeedback.ok ? 'success' : 'error'" variant="tonal" density="compact" class="mb-2">
            {{ botFeedback.msg }}
          </v-alert>

          <v-table v-if="gpuStore.channels.length" density="compact" class="table-stack-xs">
            <thead>
              <tr>
                <th>{{ t('mh.gpu.bots.col.name') }}</th>
                <th>{{ t('mh.gpu.bots.col.provider') }}</th>
                <th>{{ t('mh.gpu.bots.col.url') }}</th>
                <th>{{ t('mh.gpu.bots.col.enabled') }}</th>
                <th class="text-right">{{ t('mh.gpu.bots.col.actions') }}</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="ch in gpuStore.channels" :key="ch.id">
                <td>
                  <div class="font-weight-medium">{{ ch.name }}</div>
                  <v-chip v-if="ch.last_error" size="x-small" color="error" variant="tonal" class="mt-1">
                    {{ ch.last_error }}
                  </v-chip>
                </td>
                <td><v-chip size="x-small" variant="tonal">{{ ch.kind }}</v-chip></td>
                <td class="text-caption text-mono">{{ ch.masked_url }}</td>
                <td>
                  <v-switch
                    :model-value="ch.enabled"
                    density="compact"
                    hide-details
                    color="primary"
                    @update:model-value="(v) => toggleChannel(ch, Boolean(v))"
                  />
                </td>
                <td class="text-right text-no-wrap">
                  <v-btn
                    size="x-small"
                    variant="tonal"
                    :loading="testingId === ch.id"
                    @click="testChannel(ch)"
                  >
                    {{ t('mh.gpu.bots.test') }}
                  </v-btn>
                  <v-btn
                    size="x-small"
                    variant="text"
                    color="error"
                    icon="mdi-delete-outline"
                    class="ml-1"
                    @click="remove(ch)"
                  />
                </td>
              </tr>
            </tbody>
          </v-table>
          <div v-else-if="!gpuStore.alertsLoading" class="text-center pa-4 text-medium-emphasis">
            {{ t('mh.gpu.bots.empty') }}
          </div>
        </v-card-text>
      </v-card>
    </v-col>
  </v-row>

  <!-- Add Channel Dialog -->
  <v-dialog v-model="addOpen" max-width="520">
    <v-card>
      <v-card-title>{{ t('mh.gpu.bots.addTitle') }}</v-card-title>
      <v-card-text>
        <v-select
          v-model="chForm.kind"
          :items="providerChoices"
          density="compact"
          variant="outlined"
          :label="t('mh.gpu.bots.col.provider')"
          class="mb-2"
        />
        <v-text-field
          v-model="chForm.name"
          density="compact"
          variant="outlined"
          :label="t('mh.gpu.bots.col.name')"
          class="mb-2"
        />
        <v-text-field
          v-model="chForm.url"
          density="compact"
          variant="outlined"
          :label="t('mh.gpu.bots.webhookUrl')"
          placeholder="https://..."
          class="mb-2"
        />
        <v-text-field
          v-if="chForm.kind === 'feishu' || chForm.kind === 'dingtalk'"
          v-model="chForm.secret"
          type="password"
          density="compact"
          variant="outlined"
          :label="t('mh.gpu.bots.secret')"
          class="mb-2"
        />
        <v-text-field
          v-if="chForm.kind === 'telegram'"
          v-model="chForm.chat_id"
          density="compact"
          variant="outlined"
          :label="t('mh.gpu.bots.chatId')"
          class="mb-2"
        />
        <v-checkbox
          v-model="chForm.include_users"
          density="compact"
          hide-details
          :label="t('mh.gpu.bots.includeUsers')"
        />
        <v-select
          v-model="chForm.lang"
          :items="langChoices"
          density="compact"
          variant="outlined"
          :label="t('mh.gpu.alerts.lang')"
          class="mt-2"
        />
        <v-alert v-if="addError" type="error" variant="tonal" density="compact" class="mt-2">
          {{ addError }}
        </v-alert>
      </v-card-text>
      <v-card-actions>
        <v-spacer />
        <v-btn variant="text" @click="addOpen = false">{{ t('common.cancel') }}</v-btn>
        <v-btn color="primary" :loading="adding" @click="submitAdd">{{ t('common.save') }}</v-btn>
      </v-card-actions>
    </v-card>
  </v-dialog>
</template>

<script setup lang="ts">
import { reactive, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { useGpuStore } from '@/stores/gpu'
import type { GpuAlertChannel, GpuBotKind } from '@/api/gpu'

const props = defineProps<{ tenantId: string }>()
const { t } = useI18n()
const gpuStore = useGpuStore()

const ruleForm = reactive({
  enabled: false,
  free_gpus_min: 1 as number | null,
  free_min_mem_gb: null as number | null,
  held_idle_alert: true,
  fault_alert: true,
  machine_alert: true,
  lang: 'zh' as string | null,
})

const savingRule = ref(false)
const ruleSaved = ref(false)
const ruleError = ref<string | null>(null)

const langChoices = [
  { value: 'zh', title: '中文 (zh)' },
  { value: 'en', title: 'English (en)' },
]

const providerChoices: Array<{ value: GpuBotKind; title: string }> = [
  { value: 'feishu', title: 'Feishu / Lark (飞书)' },
  { value: 'dingtalk', title: 'DingTalk (钉钉)' },
  { value: 'wecom', title: 'WeCom (企业微信)' },
  { value: 'slack', title: 'Slack' },
  { value: 'discord', title: 'Discord' },
  { value: 'telegram', title: 'Telegram' },
  { value: 'generic', title: 'Generic HTTPS Webhook' },
]

watch(
  () => gpuStore.alertRule,
  (r) => {
    ruleForm.enabled = r.enabled
    ruleForm.free_gpus_min = r.free_gpus_min ?? 1
    ruleForm.free_min_mem_gb = r.free_min_mem_gb ?? null
    ruleForm.held_idle_alert = r.held_idle_alert
    ruleForm.fault_alert = r.fault_alert
    ruleForm.machine_alert = r.machine_alert
    ruleForm.lang = r.lang ?? 'zh'
  },
  { immediate: true, deep: true },
)

async function saveRules() {
  savingRule.value = true
  ruleSaved.value = false
  ruleError.value = null
  try {
    await gpuStore.updateAlertRule(props.tenantId, {
      enabled: ruleForm.enabled,
      free_gpus_min: ruleForm.free_gpus_min || null,
      free_min_mem_gb: ruleForm.free_min_mem_gb || null,
      held_idle_alert: ruleForm.held_idle_alert,
      fault_alert: ruleForm.fault_alert,
      machine_alert: ruleForm.machine_alert,
      lang: ruleForm.lang || null,
    })
    ruleSaved.value = true
  } catch (e) {
    ruleError.value = (e as Error).message
  } finally {
    savingRule.value = false
  }
}

const addOpen = ref(false)
const adding = ref(false)
const addError = ref<string | null>(null)
const testingId = ref<string | null>(null)
const botFeedback = ref<{ ok: boolean; msg: string } | null>(null)

const chForm = reactive({
  kind: 'feishu' as GpuBotKind,
  name: '',
  url: '',
  secret: '',
  chat_id: '',
  include_users: false,
  lang: 'zh',
})

function openAddChannel() {
  addError.value = null
  chForm.kind = 'feishu'
  chForm.name = ''
  chForm.url = ''
  chForm.secret = ''
  chForm.chat_id = ''
  chForm.include_users = false
  chForm.lang = 'zh'
  addOpen.value = true
}

async function submitAdd() {
  adding.value = true
  addError.value = null
  try {
    await gpuStore.addChannel(props.tenantId, {
      kind: chForm.kind,
      name: chForm.name.trim(),
      url: chForm.url.trim(),
      secret: chForm.secret.trim() || undefined,
      chat_id: chForm.chat_id.trim() || undefined,
      include_users: chForm.include_users,
      lang: chForm.lang,
    })
    addOpen.value = false
  } catch (e) {
    addError.value = (e as Error).message
  } finally {
    adding.value = false
  }
}

async function toggleChannel(ch: GpuAlertChannel, enabled: boolean) {
  try {
    await gpuStore.updateChannel(props.tenantId, ch.id, { enabled })
  } catch (e) {
    botFeedback.value = { ok: false, msg: (e as Error).message }
  }
}

async function testChannel(ch: GpuAlertChannel) {
  testingId.value = ch.id
  botFeedback.value = null
  try {
    const res = await gpuStore.sendTestChannel(props.tenantId, ch.id)
    botFeedback.value = res.ok
      ? { ok: true, msg: t('mh.gpu.bots.testOk', { name: ch.name }) }
      : { ok: false, msg: res.error || t('mh.gpu.bots.testFail') }
  } catch (e) {
    botFeedback.value = { ok: false, msg: (e as Error).message }
  } finally {
    testingId.value = null
  }
}

async function remove(ch: GpuAlertChannel) {
  try {
    await gpuStore.removeChannel(props.tenantId, ch.id)
  } catch (e) {
    botFeedback.value = { ok: false, msg: (e as Error).message }
  }
}
</script>

<style scoped>
.text-mono {
  font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
}
</style>
