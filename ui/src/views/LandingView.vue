<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 G ROX EOOD -->
<template>
  <v-theme-provider theme="light">
  <div class="landing-page">
    <!-- Navbar -->
    <!-- FR-116: below 960 px the section links live in a ☰ menu (with Log In,
         on a phone) — they were hidden there with no other way to reach them,
         and the bar still squeezed the wordmark to "Roo". From 960 px up the
         bar is unchanged. -->
    <v-app-bar flat color="transparent" class="landing-nav">
      <v-toolbar-title class="font-weight-bold text-h5 flex-0-0">
        <img :src="BRAND_LOGO_LIGHT" alt="MeshHarbor · 织港" width="180" height="36" class="landing-brand-logo" />
      </v-toolbar-title>
      <v-spacer />
      <v-btn variant="text" href="#features" class="d-none d-md-inline-flex">Features</v-btn>
      <v-btn variant="text" href="#download" class="d-none d-md-inline-flex">Download</v-btn>
      <v-btn variant="text" href="#pricing" class="d-none d-md-inline-flex">Pricing</v-btn>
      <!-- FR-60: `href`, not `:to` — /docs is statically generated HTML served
           by nginx, not a route in this SPA's router. A router-link would
           resolve to the 404 view. -->
      <v-btn variant="text" :href="appPath('/docs/')" class="d-none d-md-inline-flex">Docs</v-btn>
      <v-btn variant="outlined" color="primary" :to="{ name: 'login' }" class="mx-2 d-none d-sm-inline-flex">Log In</v-btn>
      <v-btn color="primary" :to="{ name: 'register' }" class="d-none d-sm-inline-flex">Get Started Free</v-btn>
      <v-btn color="primary" :to="{ name: 'register' }" class="d-sm-none" size="small">Sign Up</v-btn>
      <v-menu location="bottom end">
        <template #activator="{ props: menuProps }">
          <v-btn
            v-bind="menuProps"
            icon="mdi-menu"
            variant="text"
            class="d-md-none ml-1"
            aria-label="Menu"
            data-testid="landing-menu"
          />
        </template>
        <v-list density="comfortable" min-width="200">
          <v-list-item href="#features" title="Features" />
          <v-list-item href="#download" title="Download" />
          <v-list-item href="#pricing" title="Pricing" />
          <v-list-item :href="appPath('/docs/')" title="Docs" />
          <template v-if="xs">
            <v-divider class="my-1" />
            <v-list-item :to="{ name: 'login' }" title="Log In" prepend-icon="mdi-login" />
          </template>
        </v-list>
      </v-menu>
    </v-app-bar>

    <!-- Hero -->
    <section class="hero-section">
      <v-container>
        <v-row align="center" justify="center">
          <v-col cols="12" md="6" lg="5" class="text-center text-md-left hero-copy">
            <h1 class="text-h4 text-md-h2 font-weight-bold mb-4">{{ HERO.titleLead }}<br/><span class="text-primary">{{ HERO.titleAccent }}</span></h1>
            <p class="text-body-1 text-md-h6 landing-muted mb-6 mb-md-8">{{ HERO.lead }}</p>
            <div class="d-flex flex-wrap justify-center justify-md-start ga-3">
              <v-btn color="primary" size="large" :to="{ name: 'register' }" class="px-6">Start Free</v-btn>
              <v-btn variant="outlined" size="large" href="#download" class="px-6">Download</v-btn>
            </div>
          </v-col>
          <v-col cols="12" md="6" lg="6" class="mt-8 mt-md-0 hero-graphic">
            <ArchitectureGraphic />
          </v-col>
        </v-row>
      </v-container>
    </section>

    <!-- Capability strip (honest, no fabricated stats) -->
    <section class="trust-section py-4 py-md-6">
      <v-container>
        <div class="d-flex flex-wrap justify-center ga-2">
          <v-chip v-for="c in capabilities" :key="c" variant="tonal" color="primary" size="small">{{ c }}</v-chip>
        </div>
      </v-container>
    </section>

    <!-- FR-88 P3: the video tour, as on the static homepage. -->
    <section id="video" class="py-8 py-md-12">
      <v-container style="max-width: 920px">
        <h2 class="text-h4 text-md-h3 text-center font-weight-bold mb-2">{{ VIDEO_TOUR.title }}</h2>
        <p class="text-center text-body-1 landing-muted mb-6">{{ VIDEO_TOUR.lead }}</p>
        <VideoFacade :video-id="FEATURED_VIDEO_ID" :poster="videoTourPoster" />
      </v-container>
    </section>

    <!-- Pillars -->
    <section id="features" class="features-section py-8 py-md-16">
      <v-container>
        <div v-for="(pillar, pi) in pillars" :key="pillar.title" :class="pi > 0 ? 'mt-10 mt-md-16' : ''">
          <h2 class="text-h4 text-md-h3 text-center font-weight-bold mb-2">{{ pillar.title }}</h2>
          <p class="text-center text-body-1 landing-muted mb-6 mb-md-10">{{ pillar.subtitle }}</p>
          <v-row>
            <v-col v-for="feature in pillar.features" :key="feature.title" cols="12" sm="6" md="4">
              <v-card variant="outlined" class="feature-card pa-4 pa-md-6 h-100" rounded="lg">
                <v-icon :color="feature.color" size="48" class="mb-4">{{ feature.icon }}</v-icon>
                <h3 class="text-h6 font-weight-bold mb-2">{{ feature.title }}</h3>
                <p class="text-body-2 landing-muted">{{ feature.description }}</p>
              </v-card>
            </v-col>
          </v-row>
        </div>
      </v-container>
    </section>

    <!-- Download / install -->
    <section id="download" class="download-section py-8 py-md-16">
      <v-container>
        <h2 class="text-h4 text-md-h3 text-center font-weight-bold mb-2">{{ DOWNLOAD.title }}</h2>
        <p class="text-center text-body-1 landing-muted mb-6 mb-md-12">{{ DOWNLOAD.lead }}</p>
        <v-row justify="center">
          <v-col v-for="os in downloads" :key="os.os" cols="12" md="4">
            <v-card variant="outlined" class="pa-4 pa-md-6 h-100 d-flex flex-column" rounded="lg">
              <div class="d-flex align-center mb-3">
                <v-icon size="32" class="mr-2" color="primary">{{ os.icon }}</v-icon>
                <h3 class="text-h6 font-weight-bold">{{ os.title }}</h3>
              </div>
              <v-btn
                v-if="os.wizardUrl"
                :href="os.wizardUrl"
                color="primary"
                variant="tonal"
                prepend-icon="mdi-download"
                class="mb-4 align-self-start"
              >
                Roomler Setup
              </v-btn>
              <p class="text-body-2 landing-muted mb-1">
                {{ os.wizardUrl ? 'Or from a terminal:' : 'From a terminal:' }}
              </p>
              <pre class="install-cmd text-caption pa-2 rounded flex-grow-1">{{ os.command }}</pre>
            </v-card>
          </v-col>
        </v-row>
      </v-container>
    </section>

    <!-- Pricing -->
    <section id="pricing" class="pricing-section py-8 py-md-16">
      <v-container>
        <h2 class="text-h4 text-md-h3 text-center font-weight-bold mb-2">{{ PRICING.title }}</h2>
        <p class="text-center text-body-1 landing-muted mb-6 mb-md-12">{{ PRICING.lead }}</p>
        <v-row justify="center">
          <v-col v-for="plan in plans" :key="plan.id" cols="12" sm="6" md="4">
            <v-card
              :variant="plan.id === 'pro' ? 'elevated' : 'outlined'"
              :elevation="plan.id === 'pro' ? 8 : 0"
              class="pa-4 pa-md-6 h-100 d-flex flex-column"
              rounded="lg"
              :class="{ 'border-primary': plan.id === 'pro' }"
            >
              <v-chip v-if="plan.id === 'pro'" color="primary" size="small" class="mb-4 align-self-start">Most Popular</v-chip>
              <h3 class="text-h5 font-weight-bold">{{ plan.name }}</h3>
              <v-chip
                v-if="plan.id === 'free' && plan.commercial_use !== false"
                color="success"
                size="small"
                variant="tonal"
                class="mt-2 align-self-start"
                data-testid="landing-commercial-use"
              >
                Free for commercial use
              </v-chip>
              <div class="my-4">
                <span class="text-h3 font-weight-bold">${{ plan.price_cents / 100 }}</span>
                <span v-if="plan.price_cents > 0" class="text-body-2 landing-muted">
                  <!-- FR-115 — the euro figure only once EUR is on sale (`stripe.currencies`) -->
                  <template v-if="(plan.prices || []).some((p) => p.currency === 'eur')">/ €{{ plan.price_cents / 100 }} </template>per user / month
                </span>
                <span v-else class="text-body-2 landing-muted">forever</span>
                <div v-if="annualLine(plan)" class="text-body-2 landing-muted">{{ annualLine(plan) }}</div>
              </div>
              <v-divider class="mb-4" />
              <v-list density="compact" class="flex-grow-1 bg-transparent">
                <v-list-item v-for="f in plan.features" :key="f" :title="f" prepend-icon="mdi-check" />
              </v-list>
              <v-btn
                :color="plan.id === 'pro' ? 'primary' : undefined"
                :variant="plan.id === 'pro' ? 'flat' : 'outlined'"
                block
                size="large"
                :to="{ name: 'register' }"
                class="mt-4"
              >
                {{ plan.price_cents === 0 ? 'Get Started Free' : 'Start Now' }}
              </v-btn>
            </v-card>
          </v-col>
        </v-row>
      </v-container>
    </section>

    <!-- Final CTA -->
    <section class="cta-section py-8 py-md-16">
      <v-container>
        <v-row justify="center">
          <v-col cols="12" md="8" class="text-center">
            <h2 class="text-h4 text-md-h3 font-weight-bold mb-4 text-white">{{ CTA.title }}</h2>
            <p class="text-body-1 cta-subtitle mb-6 mb-md-8">{{ CTA.lead }}</p>
            <v-btn color="white" size="large" :to="{ name: 'register' }" class="px-6 text-primary">{{ CTA.button }}</v-btn>

            <v-divider class="my-8 cta-divider" />
            <StayInTouch source="landing" />
          </v-col>
        </v-row>
      </v-container>
    </section>

    <!-- Footer -->
    <v-footer class="landing-footer py-4 py-md-8">
      <v-container>
        <v-row>
          <v-col cols="12" sm="3">
            <div class="text-h6 font-weight-bold mb-2">MeshHarbor · 织港</div>
            <p class="text-body-2 landing-muted">Remote access, private networking, and collaboration for your devices and your team.</p>
          </v-col>
          <v-col cols="6" sm="2">
            <div class="text-subtitle-2 font-weight-bold mb-2">Product</div>
            <a href="#features" class="text-body-2 landing-muted mb-1 d-block text-decoration-none">Features</a>
            <a href="#download" class="text-body-2 landing-muted mb-1 d-block text-decoration-none">Download</a>
            <a href="#pricing" class="text-body-2 landing-muted mb-1 d-block text-decoration-none">Pricing</a>
            <a :href="appPath('/docs/')" class="text-body-2 landing-muted mb-1 d-block text-decoration-none">Documentation</a>
          </v-col>
          <v-col cols="6" sm="2">
            <div class="text-subtitle-2 font-weight-bold mb-2">Install</div>
            <a :href="appPath('/docs/start/install/windows/')" class="text-body-2 landing-muted mb-1 d-block text-decoration-none">Windows</a>
            <a :href="appPath('/docs/start/install/macos/')" class="text-body-2 landing-muted mb-1 d-block text-decoration-none">macOS</a>
            <a :href="appPath('/docs/start/install/linux/')" class="text-body-2 landing-muted mb-1 d-block text-decoration-none">Linux</a>
            <a :href="appPath('/docs/start/self-hosting/')" class="text-body-2 landing-muted mb-1 d-block text-decoration-none">Self-hosting</a>
          </v-col>
          <v-col cols="6" sm="2">
            <div class="text-subtitle-2 font-weight-bold mb-2">Legal</div>
            <router-link to="/privacy" class="text-body-2 landing-muted mb-1 d-block text-decoration-none">Privacy Policy</router-link>
            <router-link to="/terms" class="text-body-2 landing-muted mb-1 d-block text-decoration-none">Terms of Service</router-link>
            <router-link to="/imprint" class="text-body-2 landing-muted mb-1 d-block text-decoration-none">Imprint</router-link>
          </v-col>
          <v-col cols="12" sm="3">
            <!-- FR-58: the footer door into the same list — light variant,
                 its own source tag. -->
            <div class="text-subtitle-2 font-weight-bold mb-2">Stay in touch</div>
            <StayInTouch variant="light" source="landing-footer" />
          </v-col>
        </v-row>
        <v-divider class="my-4" />
        <div class="text-body-2 landing-muted text-center">&copy; {{ new Date().getFullYear() }} G ROX EOOD &mdash; Roomler. All rights reserved. MeshHarbor · 织港 is based on Roomler.</div>
      </v-container>
    </v-footer>

    <!-- FR-58: the deferred auto-ask — once ever, after real engagement,
         never a blocking modal. -->
    <NewsletterPrompt />
  </div>
  </v-theme-provider>
</template>

<script setup lang="ts">
import { appOrigin } from '@/utils/deployment'
import { appPath } from '@/utils/deployment'
import { onMounted, ref } from 'vue'
import { useRoute } from 'vue-router'
import { useDisplay } from 'vuetify'
import ArchitectureGraphic from '@/components/landing/ArchitectureGraphic.vue'
import NewsletterPrompt from '@/components/landing/NewsletterPrompt.vue'
import StayInTouch from '@/components/landing/StayInTouch.vue'
import { BRAND_LOGO_LIGHT } from '@/composables/useBrand'
import { installCards } from '@/utils/enrollCommands'
import { CAPABILITIES, CTA, DOWNLOAD, FALLBACK_PLANS, HERO, PILLARS, PRICING, VIDEO_TOUR, annualLine, type Plan } from '@/utils/landing'
import { FEATURED_VIDEO_ID } from '@/utils/videos'
import VideoFacade from '@/components/common/VideoFacade.vue'
import videoTourPoster from '@/assets/tutorial/video-C1YdfmhbAKM.jpg'

const route = useRoute()
// FR-116 — on a phone Log In moves into the ☰ menu, leaving the bar the
// wordmark, Sign Up and the menu.
const { xs } = useDisplay()

// FR-87: the copy and the plan table live in `@/utils/landing`, shared with
// the static homepage the docs generator writes for `/`.
const capabilities = CAPABILITIES
const pillars = PILLARS

// One-line installs — same vitest-locked template source the in-app
// enrollment dialog uses (token placeholder until they have one), and the
// wizard only where it installs the agent (FR-97 D5).
const osIcon: Record<string, string> = {
  windows: 'mdi-microsoft-windows',
  linux: 'mdi-linux',
  macos: 'mdi-apple',
}
const downloads = installCards(appOrigin(window.location.origin)).map((card) => ({
  ...card,
  icon: osIcon[card.os]!,
}))

// The fallback until /api/stripe/plans (the single source of truth) answers.
const plans = ref<Plan[]>(FALLBACK_PLANS.map((p) => ({ ...p, features: [...p.features] })))

// FR-58: the old `?subscribe=<outcome>` snackbar that lived here was dead
// code — the API's redirect target (`/?subscribe=…`) is auth-gated, so this
// view never received the query. Outcomes now render on the public
// `/newsletter/confirmed` + `/newsletter/unsubscribed` pages.

onMounted(async () => {
  try {
    const resp = await fetch(appPath('/api/stripe/plans'))
    if (resp.ok) {
      const live = (await resp.json()) as Plan[]
      if (Array.isArray(live) && live.length > 0) plans.value = live
    }
  } catch {
    // fallback copy stays
  }
  // The /pricing route renders this same view — land on the plans.
  if (route.name === 'pricing') {
    document.getElementById('pricing')?.scrollIntoView({ behavior: 'auto' })
  }
})
</script>

<style scoped>
.landing-page {
  background: linear-gradient(180deg, #f5faf9 0%, #ffffff 40%);
  color: #1a1a2e;
}
/* The page forces the light theme, so the light lockup always fits. */
.landing-brand-logo {
  display: block;
  height: 36px;
  width: auto;
}

.landing-nav {
  position: fixed !important;
  z-index: 100;
  backdrop-filter: blur(12px);
  background: rgba(255, 255, 255, 0.92) !important;
  border-bottom: 1px solid rgba(0, 150, 136, 0.1);
  color: #1a1a2e !important;
}

.hero-section {
  padding-top: 96px;
  padding-bottom: 48px;
  background: linear-gradient(135deg, #e0f2f1 0%, #e8f5e9 50%, #e0f7fa 100%);
  position: relative;
  overflow: hidden;
}
@media (min-width: 960px) {
  .hero-section {
    padding-top: 140px;
    padding-bottom: 80px;
  }
}

.hero-section::before {
  content: '';
  position: absolute;
  top: -50%;
  left: -50%;
  width: 200%;
  height: 200%;
  background: radial-gradient(circle at 30% 70%, rgba(0, 150, 136, 0.06) 0%, transparent 50%),
              radial-gradient(circle at 70% 30%, rgba(239, 83, 80, 0.06) 0%, transparent 50%);
  animation: float 20s ease-in-out infinite;
  pointer-events: none;
}

/* Keep the hero content (and its interactive legend) above the ambient
   ::before layer. */
.hero-copy,
.hero-graphic {
  position: relative;
  z-index: 1;
}

@keyframes float {
  0%, 100% { transform: translate(0, 0); }
  50% { transform: translate(-2%, 2%); }
}

.trust-section {
  background: #fafafa;
  border-top: 1px solid rgba(0, 0, 0, 0.06);
  border-bottom: 1px solid rgba(0, 0, 0, 0.06);
}

.features-section {
  background: #ffffff;
}

.download-section {
  background: linear-gradient(180deg, #ffffff 0%, #f5faf9 100%);
}

.install-cmd {
  background: #1a1a2e;
  color: #e0f2f1;
  font-family: monospace;
  white-space: pre-wrap;
  word-break: break-all;
  margin: 0;
}

.feature-card {
  transition: transform 0.2s ease, box-shadow 0.2s ease;
  border-color: rgba(0, 0, 0, 0.08) !important;
}

.feature-card:hover {
  transform: translateY(-4px);
  box-shadow: 0 12px 40px rgba(0, 150, 136, 0.12) !important;
}

.pricing-section {
  background: linear-gradient(180deg, #f5f5f5 0%, #fafafa 100%);
}

.border-primary {
  border: 2px solid #009688 !important;
}

.cta-section {
  background: linear-gradient(135deg, #009688 0%, #00796B 100%);
  position: relative;
  overflow: hidden;
}

.cta-section::before {
  content: '';
  position: absolute;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  background: radial-gradient(circle at 20% 80%, rgba(255, 255, 255, 0.1) 0%, transparent 50%),
              radial-gradient(circle at 80% 20%, rgba(255, 255, 255, 0.08) 0%, transparent 50%);
}

.cta-subtitle {
  color: rgba(255, 255, 255, 0.85);
}

/* Separates the primary CTA from the lower-commitment one below it, without
   reading as a second section — the email capture is a fallback, not a rival. */
.cta-divider {
  border-color: rgba(255, 255, 255, 0.22) !important;
  max-width: 520px;
  margin-inline: auto;
}

.landing-footer {
  background: #fafafa !important;
  border-top: 1px solid rgba(0, 0, 0, 0.06);
}

.landing-muted {
  color: rgba(26, 26, 46, 0.7) !important;
}

.landing-page :deep(.v-card) {
  background-color: #ffffff !important;
  color: #1a1a2e !important;
}

.landing-page :deep(.v-list) {
  color: #1a1a2e !important;
}

.landing-page :deep(.v-footer) {
  color: #1a1a2e !important;
}
</style>
