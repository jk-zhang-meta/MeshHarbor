<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<template>
  <v-container fluid class="pa-2 pa-md-4 pa-xl-6">
    <div class="d-flex flex-wrap align-center justify-space-between ga-2 mb-3">
      <h1 class="text-h5">Account approvals</h1>
      <v-btn variant="outlined" prepend-icon="mdi-refresh" :loading="approval.accessLoading || approval.loading" :disabled="approval.reviewing" @click="refresh">Refresh</v-btn>
    </div>
    <p class="text-body-2 mb-4">Central account admission. Organization roles, device enrollment and operating-system permissions are separate.</p>
    <v-alert v-if="approval.error" type="error" variant="tonal" class="mb-3" role="alert">{{ approval.error }}</v-alert>
    <v-progress-linear v-if="approval.accessLoading" indeterminate aria-label="Checking approval access" />
    <v-alert v-else-if="!approval.isOwner" type="warning" variant="tonal" data-testid="approval-access-denied">
      {{ approval.access?.enabled === false ? 'Account approval is not enabled on this server.' : 'Only the central approval owner can access this console.' }}
    </v-alert>
    <template v-else>
      <v-tabs :model-value="approval.tab" :disabled="approval.reviewing" @update:model-value="changeTab">
        <v-tab value="pending">Pending review</v-tab>
        <v-tab value="approved">Approved</v-tab>
        <v-tab value="rejected">Rejected</v-tab>
        <v-tab value="suspended">Suspended</v-tab>
      </v-tabs>
      <div class="text-caption my-2">{{ approval.total }} accounts · {{ approval.perPage }} per page<span v-if="approval.tab === 'pending'"> · Includes existing unreviewed accounts</span></div>
      <v-progress-linear v-if="approval.loading" indeterminate aria-label="Loading accounts" />
      <v-table>
        <thead><tr><th>Account</th><th>Email</th><th>Status</th><th>Email verified</th><th>Revision</th><th>Review</th></tr></thead>
        <tbody>
          <tr v-for="account in approval.items" :key="account.user_id" :data-testid="`approval-row-${account.user_id}`">
            <td>{{ account.username }}</td><td>{{ account.email }}</td>
            <td>{{ account.state === 'legacy_unreviewed' ? 'Existing — unreviewed' : account.state }}</td>
            <td>{{ account.email_verified ? 'Yes' : 'No' }}</td><td>{{ account.revision }}</td>
            <td class="py-2">
              <div class="d-flex flex-wrap ga-1">
                <v-btn v-if="account.state !== 'approved'" size="small" color="success" variant="tonal" :disabled="approval.loading || approval.reviewing" data-testid="approve-account" @click="askReview(account, 'approved')">Approve</v-btn>
                <v-btn v-if="account.state !== 'rejected'" size="small" color="error" variant="tonal" :disabled="approval.loading || approval.reviewing" data-testid="reject-account" @click="askReview(account, 'rejected')">Reject</v-btn>
                <v-btn v-if="account.state === 'approved'" size="small" color="warning" variant="tonal" :disabled="approval.loading || approval.reviewing" data-testid="suspend-account" @click="askReview(account, 'suspended')">Suspend</v-btn>
              </div>
            </td>
          </tr>
          <tr v-if="!approval.loading && !approval.items.length"><td colspan="6" class="text-center py-5">No accounts in this view.</td></tr>
        </tbody>
      </v-table>
      <v-pagination :model-value="approval.page" :length="approval.pageCount" :disabled="approval.loading || approval.reviewing" :total-visible="5" class="mt-3" @update:model-value="approval.setPage" />
    </template>
    <v-dialog v-model="confirmOpen" max-width="520" :persistent="approval.reviewing">
      <v-card v-if="pending">
        <v-card-title>{{ decisionLabel(pending.state) }} account?</v-card-title>
        <v-card-text>
          <p>{{ pending.account.username }} · {{ pending.account.email }}</p>
          <p class="mt-2">The server must accept revision {{ pending.account.revision }} before any status changes.</p>
          <v-alert v-if="pending.state !== 'approved'" type="warning" variant="tonal" class="mt-3">This revokes account admission. Existing network and device sessions have their own revocation rules.</v-alert>
          <v-alert v-if="approval.error" type="error" variant="tonal" class="mt-3">{{ approval.error }}</v-alert>
        </v-card-text>
        <v-card-actions><v-spacer /><v-btn :disabled="approval.reviewing" @click="confirmOpen = false">Cancel</v-btn><v-btn color="primary" :loading="approval.reviewing" data-testid="confirm-account-review" @click="confirmReview">Confirm {{ decisionLabel(pending.state).toLowerCase() }}</v-btn></v-card-actions>
      </v-card>
    </v-dialog>
  </v-container>
</template>
<script setup lang="ts">
import { ref, watch } from 'vue'
import { useAuthStore } from '@/stores/auth'
import { useAccountApprovalStore, type ApprovalAccount, type ApprovalDecision, type ApprovalTab } from '@/stores/accountApproval'
const auth = useAuthStore()
const approval = useAccountApprovalStore()
const confirmOpen = ref(false)
const pending = ref<{ account: ApprovalAccount; state: ApprovalDecision } | null>(null)
const decisionLabel = (state: ApprovalDecision) => ({ approved: 'Approve', rejected: 'Reject', suspended: 'Suspend' })[state]
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
