<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 G ROX EOOD -->
<!--
  FR-90 P2j-5 — an ended terminal session made a managed one, from its room
  (P2f-4b): the same record, its conversation resumed on the device that
  adopted it, from its terminal's own history. Offered to its owner where the
  server copies sessions (the route is the replicaset's), on an adopted
  session its terminal ended; one stopped from MeshHarbor, whose terminal went
  on after it, or ended any other way, is not offered it. The answer is a
  start's, in the server's words.
-->
<template>
  <v-chip v-if="becoming && !shown" size="small" variant="tonal" color="info" data-testid="hive-manage-in-progress">
    {{ $t('hive.manage.inProgress') }}
  </v-chip>
  <v-dialog v-if="offered || shown" v-model="shown" max-width="520">
    <template #activator="{ props: activator }">
      <v-btn v-bind="activator" size="small" variant="text" prepend-icon="mdi-robot-outline" data-testid="hive-manage-open">
        {{ $t('hive.manage.button') }}
      </v-btn>
    </template>
    <v-card>
      <v-card-title>{{ $t('hive.manage.title') }}</v-card-title>
      <v-card-text>
        <p class="text-body-2 mb-3" data-testid="hive-manage-explain">
          {{ $t('hive.manage.explain', { device: deviceName }) }}
        </p>
        <v-alert
          v-if="lastRefused"
          type="warning"
          variant="tonal"
          density="compact"
          class="mb-3"
          data-testid="hive-manage-last-refused"
        >
          {{ $t('hive.manage.lastRefused', { why: lastRefused }) }}
        </v-alert>
        <v-text-field
          v-model="folder"
          :label="$t('hive.manage.folder', { device: deviceName })"
          :hint="$t('hive.manage.folderHint')"
          persistent-hint
          :disabled="done"
          density="compact"
          data-testid="hive-manage-folder"
        />
        <v-alert
          v-if="outcome"
          :type="outcome.kind"
          variant="tonal"
          density="compact"
          class="mt-3"
          data-testid="hive-manage-outcome"
        >
          {{ outcome.text }}
        </v-alert>
      </v-card-text>
      <v-card-actions>
        <v-spacer />
        <v-btn variant="text" data-testid="hive-manage-close" @click="shown = false">{{ $t('common.close') }}</v-btn>
        <v-btn
          color="primary"
          variant="flat"
          :loading="asking"
          :disabled="asking || done || !folder.trim()"
          data-testid="hive-manage-submit"
          @click="manageNow"
        >
          {{ $t('hive.manage.submit') }}
        </v-btn>
      </v-card-actions>
    </v-card>
  </v-dialog>
</template>

<script setup lang="ts">
import { computed, onMounted, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { isBecomingManaged, mayBecomeManaged, useHiveStore, type HiveSession } from '@/stores/hive'
import { useAuthStore } from '@/stores/auth'
import { useNodeLabel } from '@/composables/useNodeLabel'

const props = defineProps<{ tenantId: string; sessionId: string }>()
const hive = useHiveStore()
const auth = useAuthStore()
const { t } = useI18n()

const shown = ref(false)
const folder = ref('')
const asking = ref(false)
/** Asked, and the asking taken: nothing to ask again from this dialog. */
const done = ref(false)
const outcome = ref<{ kind: 'success' | 'info' | 'warning' | 'error'; text: string } | null>(null)

const session = computed<HiveSession | null>(() => hive.sessions.find((s) => s.id === props.sessionId) ?? null)
// FR-116 AC4 — the device by the name the Devices page shows; the session's
// kept machine name only for a device this org no longer lists.
const { agentLabel } = useNodeLabel()
const deviceName = computed(() => agentLabel(session.value?.device_id, session.value?.device_name ?? ''))
/** Only its owner makes it managed; the server answers anyone else 404. */
const isOwner = computed(() => !!session.value && !!auth.user && session.value.owner_id === auth.user.id)
/** The route is the replicaset's: where the server copies nothing, it is not there. */
const copied = computed(() => hive.copied[props.tenantId] === true)
const offered = computed(() => copied.value && isOwner.value && mayBecomeManaged(session.value))
const becoming = computed(() => isBecomingManaged(session.value))
/** The word its device refused the last asking with: the record is the
 *  adopted session it was again, and may be asked once more. */
const lastRefused = computed(() => (offered.value ? (session.value?.from_terminal?.refused ?? null) : null))

watch(shown, (open) => {
  if (!open) return
  folder.value = session.value?.folder ?? ''
  outcome.value = null
  done.value = false
})

async function manageNow(): Promise<void> {
  const s = session.value
  if (!s || asking.value || done.value) return
  const typed = folder.value.trim()
  asking.value = true
  outcome.value = null
  try {
    const res = await hive.manage(props.tenantId, s.id, typed !== s.folder ? typed : undefined)
    if (res.outcome === 'accepted') {
      outcome.value = { kind: 'success', text: t('hive.manage.accepted', { device: agentLabel(s.device_id, s.device_name) }) }
    } else if (res.outcome === 'pending') {
      outcome.value = { kind: 'info', text: t('hive.manage.pending') }
    } else {
      // The server's words: each names its own next step.
      outcome.value = { kind: 'warning', text: t('hive.manage.refused', { why: res.message ?? res.reason ?? '' }) }
    }
    done.value = res.outcome !== 'refused'
  } catch (e) {
    outcome.value = { kind: 'error', text: (e as Error).message }
  } finally {
    asking.value = false
  }
}

onMounted(() => {
  void hive.checkServed(props.tenantId)
})
</script>
