<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 G ROX EOOD -->
<template>
  <v-theme-provider theme="light">
    <div class="legal-page">
      <v-container class="legal-container py-6 py-md-12 px-4 px-md-6">
        <router-link to="/landing" class="text-body-2 text-primary text-decoration-none d-inline-flex align-center mb-6">
          <v-icon size="small" class="mr-1">mdi-arrow-left</v-icon>
          Back to home
        </router-link>

        <h1 class="text-h4 text-md-h3 font-weight-bold mb-2">Imprint</h1>
        <p class="text-body-2 legal-muted mb-8">Last updated: August 2026</p>

        <section class="mb-8">
          <h2 class="text-h5 font-weight-bold mb-3">1. Operator</h2>
          <p class="text-body-1 legal-muted">
            MeshHarbor is operated by <strong>G ROX EOOD</strong>, a single-member limited liability company
            (ЕООД) registered in the Bulgarian Commercial Register.
          </p>
          <p class="text-body-1 legal-muted mt-2">
            The company is recorded in the register in Cyrillic as <strong>„Г РОКС" ЕООД</strong>, with
            <strong>G ROX</strong> entered as its registered Latin spelling. "G ROX EOOD" is the Latin form of
            that same legal entity.
          </p>
        </section>

        <section class="mb-8">
          <h2 class="text-h5 font-weight-bold mb-3">2. Registered Office</h2>
          <p class="text-body-1 legal-muted">
            Plovdivska 110<br>
            4400 Pazardzhik<br>
            Bulgaria
          </p>
        </section>

        <section class="mb-8">
          <h2 class="text-h5 font-weight-bold mb-3">3. Registration and VAT</h2>
          <p class="text-body-1 legal-muted">
            <strong>Unified Identification Code (UIC/EIK):</strong> 205174895<br>
            <strong>Register:</strong> Commercial Register and Register of Non-Profit Legal Entities,
            Registry Agency of the Republic of Bulgaria<br>
            <strong>VAT identification number:</strong> BG205174895
          </p>
        </section>

        <section class="mb-8">
          <h2 class="text-h5 font-weight-bold mb-3">4. Represented By</h2>
          <p class="text-body-1 legal-muted">
            <strong>Goran Jovanov</strong> — Manager, and sole owner of the company's capital. He is authorised
            to represent and bind G ROX EOOD.
          </p>
        </section>

        <section class="mb-8">
          <h2 class="text-h5 font-weight-bold mb-3">5. Contact</h2>
          <p class="text-body-1 legal-muted">
            <strong>Email:</strong> <a href="mailto:legal@meshharbor.itachi.fans" class="text-primary">legal@meshharbor.itachi.fans</a><br>
            <strong>Privacy and data protection:</strong>
            <a href="mailto:privacy@meshharbor.itachi.fans" class="text-primary">privacy@meshharbor.itachi.fans</a><br>
            <strong>Telephone:</strong> <a href="tel:+359877118883" class="text-primary">+359 87 711 8883</a>
          </p>
        </section>

        <section class="mb-8">
          <h2 class="text-h5 font-weight-bold mb-3">6. Websites Operated by G ROX EOOD</h2>
          <p class="text-body-1 legal-muted">
            <a href="https://meshharbor.itachi.fans" class="text-primary">meshharbor.itachi.fans</a> and
            <a href="https://meshharbor.itachi.fans" class="text-primary">meshharbor.itachi.fans</a> are both owned and operated by
            G ROX EOOD, and email addresses on either domain belong to the company.
          </p>
        </section>

        <section class="mb-8">
          <h2 class="text-h5 font-weight-bold mb-3">7. Responsibility for Content</h2>
          <p class="text-body-1 legal-muted">
            G ROX EOOD is responsible for the content it publishes on these websites. Content created and
            shared by users of the platform remains the responsibility of those users, as set out in our
            <router-link to="/terms" class="text-primary">Terms of Service</router-link>. How we handle
            personal data is described in our
            <router-link to="/privacy" class="text-primary">Privacy Policy</router-link>.
          </p>
        </section>

        <!--
          Deliberately no EU "Online Dispute Resolution platform" link here.
          Regulation (EU) 2024/3228 repealed Regulation (EU) No 524/2013 and
          the ODR platform ceased operating on 20 July 2025, so the link that
          still appears in most imprint boilerplate is dead. Do not re-add it.
        -->
        <section class="mb-8">
          <h2 class="text-h5 font-weight-bold mb-3">8. Consumer Disputes</h2>
          <p class="text-body-1 legal-muted">
            We are neither obliged nor willing to participate in dispute resolution proceedings before a
            consumer arbitration board. We would much rather resolve any concern directly — please write to
            <a href="mailto:legal@meshharbor.itachi.fans" class="text-primary">legal@meshharbor.itachi.fans</a> and we will respond.
          </p>
        </section>
      </v-container>
    </div>
  </v-theme-provider>
</template>

<script setup>
</script>

<style scoped>
.legal-page {
  background: #ffffff;
  color: #1a1a2e;
  min-height: 100vh;
}

.legal-container {
  max-width: 800px;
}

.legal-muted {
  color: rgba(26, 26, 46, 0.75) !important;
  line-height: 1.7;
}
</style>
