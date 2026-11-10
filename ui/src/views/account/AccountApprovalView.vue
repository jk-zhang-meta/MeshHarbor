<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<template>
  <v-container fluid class="pa-2 pa-md-4 pa-xl-6">
    <div class="d-flex flex-wrap align-center justify-space-between ga-2 mb-3">
      <h1 class="text-h5">{{ $t('mh.approval.title') }}</h1>
      <v-btn variant="outlined" prepend-icon="mdi-refresh" :loading="approval.accessLoading || approval.loading" :disabled="approval.reviewing" @click="refresh">{{ $t('common.refresh') }}</v-btn>
    </div>
    <p class="text-body-2 mb-4">{{ $t('mh.approval.intro') }}</p>
    <v-alert v-if="approval.error" type="error" variant="tonal" class="mb-3" role="alert">{{ approval.error }}</v-alert>
    <v-progress-linear v-if="approval.accessLoading" indeterminate :aria-label="$t('mh.approval.checking')" />
    <v-alert v-else-if="!approval.isOwner" type="warning" variant="tonal" data-testid="approval-access-denied">
      {{ approval.access?.enabled === false ? $t('mh.approval.notEnabled') : $t('mh.approval.ownerOnly') }}
    </v-alert>
    <template v-else>
      <v-tabs :model-value="approval.tab" :disabled="approval.reviewing" @update:model-value="changeTab">
        <v-tab value="pending">{{ $t('mh.approval.tab.pending') }}</v-tab>
        <v-tab value="approved">{{ $t('mh.approval.tab.approved') }}</v-tab>
        <v-tab value="rejected">{{ $t('mh.approval.tab.rejected') }}</v-tab>
        <v-tab value="suspended">{{ $t('mh.approval.tab.suspended') }}</v-tab>
      </v-tabs>
      <div class="text-caption my-2">{{ $t('mh.approval.summary', { total: approval.total, perPage: approval.perPage }) }}<span v-if="approval.tab === 'pending'">{{ $t('mh.approval.includesLegacy') }}</span></div>
      <v-progress-linear v-if="approval.loading" indeterminate :aria-label="$t('mh.approval.loading')" />
      <v-table>
        <thead><tr><th>{{ $t('mh.approval.col.account') }}</th><th>{{ $t('mh.approval.col.email') }}</th><th>{{ $t('mh.approval.col.status') }}</th><th>{{ $t('mh.approval.col.emailVerified') }}</th><th>{{ $t('mh.approval.col.revision') }}</th><th>{{ $t('mh.approval.col.review') }}</th></tr></thead>
        <tbody>
          <tr v-for="account in approval.items" :key="account.user_id" :data-testid="`approval-row-${account.user_id}`">
            <td>{{ account.username }}</td><td>{{ account.email }}</td>
            <td>{{ stateLabel(account.state) }}</td>
            <td>{{ account.email_verified ? $t('common.yes') : $t('common.no') }}</td><td>{{ account.revision }}</td>
            <td class="py-2">
              <div class="d-flex flex-wrap ga-1">
                <v-btn v-if="account.state !== 'approved'" size="small" color="success" variant="tonal" :disabled="approval.loading || approval.reviewing" data-testid="approve-account" @click="askReview(account, 'approved')">{{ $t('mh.approval.approve') }}</v-btn>
                <v-btn v-if="account.state !== 'rejected'" size="small" color="error" variant="tonal" :disabled="approval.loading || approval.reviewing" data-testid="reject-account" @click="askReview(account, 'rejected')">{{ $t('mh.approval.reject') }}</v-btn>
                <v-btn v-if="account.state === 'approved'" size="small" color="warning" variant="tonal" :disabled="approval.loading || approval.reviewing" data-testid="suspend-account" @click="askReview(account, 'suspended')">{{ $t('mh.approval.suspend') }}</v-btn>
              </div>
            </td>
          </tr>
          <tr v-if="!approval.loading && !approval.items.length"><td colspan="6" class="text-center py-5">{{ $t('mh.approval.empty') }}</td></tr>
        </tbody>
      </v-table>
      <v-pagination :model-value="approval.page" :length="approval.pageCount" :disabled="approval.loading || approval.reviewing" :total-visible="5" class="mt-3" @update:model-value="approval.setPage" />
    </template>
    <v-dialog v-model="confirmOpen" max-width="520" :persistent="approval.reviewing">
      <v-card v-if="pending">
        <v-card-title>{{ $t('mh.approval.confirmTitle', { action: decisionLabel(pending.state) }) }}</v-card-title>
        <v-card-text>
          <p>{{ pending.account.username }} · {{ pending.account.email }}</p>
          <p class="mt-2">{{ $t('mh.approval.revisionNote', { revision: pending.account.revision }) }}</p>
          <v-alert v-if="pending.state !== 'approved'" type="warning" variant="tonal" class="mt-3">{{ $t('mh.approval.revokeWarning') }}</v-alert>
          <v-alert v-if="approval.error" type="error" variant="tonal" class="mt-3">{{ approval.error }}</v-alert>
        </v-card-text>
        <v-card-actions><v-spacer /><v-btn :disabled="approval.reviewing" @click="confirmOpen = false">{{ $t('common.cancel') }}</v-btn><v-btn color="primary" :loading="approval.reviewing" data-testid="confirm-account-review" @click="confirmReview">{{ $t('mh.approval.confirmAction', { action: decisionLabel(pending.state).toLowerCase() }) }}</v-btn></v-card-actions>
      </v-card>
    </v-dialog>
  </v-container>
</template>
<script setup lang="ts">
import { ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { useAuthStore } from '@/stores/auth'
import { useAccountApprovalStore, type ApprovalAccount, type ApprovalDecision, type ApprovalTab } from '@/stores/accountApproval'
const auth = useAuthStore()
const approval = useAccountApprovalStore()
const confirmOpen = ref(false)
const pending = ref<{ account: ApprovalAccount; state: ApprovalDecision } | null>(null)
const { t, te } = useI18n()
const decisionLabel = (state: ApprovalDecision) => ({ approved: t('mh.approval.approve'), rejected: t('mh.approval.reject'), suspended: t('mh.approval.suspend') })[state]
const stateLabel = (state: string) => (te(`mh.approval.state.${state}`) ? t(`mh.approval.state.${state}`) : state)
async function refresh() {
  confirmOpen.value = false
  pending.value = null
  if (await approval.loadAccess(auth.user?.id ?? null)) await approval.loadQueue()
}
function changeTab(value: unknown) {
  if (['pending', 'approved', 'rejected', 'suspended'].includes(String(value))) {
    confirmOpen.value = false
    pending.value = null
    void approval.selectTab(value as ApprovalTab)
  }
}
function askReview(account: ApprovalAccount, state: ApprovalDecision) {
  pending.value = { account: { ...account }, state }
  confirmOpen.value = true
}
async function confirmReview() {
  if (!pending.value || !approval.isOwner) return
  const result = await approval.review(pending.value.account, pending.value.state)
  if (result !== 'failed') { confirmOpen.value = false; pending.value = null }
}
watch(() => approval.isOwner, (allowed) => { if (!allowed) { confirmOpen.value = false; pending.value = null } })
watch(() => auth.user?.id ?? null, () => { void refresh() }, { immediate: true })
</script>
