<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 G ROX EOOD -->
<template>
  <v-theme-provider theme="light">
  <div class="landing-page">
    <!-- Navbar -->
    <v-app-bar flat color="transparent" class="landing-nav">
      <v-toolbar-title class="font-weight-bold text-h5 flex-0-0">
        <img :src="BRAND_LOGO_LIGHT" alt="MeshHarbor · 织港" width="180" height="36" class="landing-brand-logo" />
      </v-toolbar-title>
      <v-spacer />
      <v-btn variant="text" href="#features" class="d-none d-md-inline-flex">{{ t('landing.nav.features') }}</v-btn>
      <v-btn variant="text" href="#download" class="d-none d-md-inline-flex">{{ t('landing.nav.download') }}</v-btn>
      <!-- FR-60: `href`, not `:to` — /docs is statically generated HTML served
           by nginx, not a route in this SPA's router. -->
      <v-btn variant="text" :href="appPath('/docs/')" class="d-none d-md-inline-flex">{{ t('landing.nav.docs') }}</v-btn>
      <v-btn
        variant="text"
        :lang="otherLocale.code"
        :aria-label="t('landing.nav.language')"
        data-testid="landing-locale"
        class="landing-locale"
        @click="setLocale(otherLocale.code)"
      >
        {{ otherLocale.short }}
      </v-btn>
      <v-btn variant="outlined" color="primary" :to="{ name: 'login' }" class="mx-2 d-none d-sm-inline-flex">{{ t('landing.nav.login') }}</v-btn>
      <v-btn color="primary" variant="flat" :to="{ name: 'register' }" class="d-none d-sm-inline-flex me-md-2">{{ t('landing.nav.getStarted') }}</v-btn>
      <v-btn color="primary" variant="flat" :to="{ name: 'register' }" class="d-sm-none" size="small">{{ t('landing.nav.signUp') }}</v-btn>
      <v-menu location="bottom end">
        <template #activator="{ props: menuProps }">
          <v-btn
            v-bind="menuProps"
            icon="mdi-menu"
            variant="text"
            class="d-md-none ml-1"
            :aria-label="t('landing.nav.menu')"
            data-testid="landing-menu"
          />
        </template>
        <v-list density="comfortable" min-width="200">
          <v-list-item href="#features" :title="t('landing.nav.features')" />
          <v-list-item href="#download" :title="t('landing.nav.download')" />
          <v-list-item :href="appPath('/docs/')" :title="t('landing.nav.docs')" />
          <template v-if="xs">
            <v-divider class="my-1" />
            <v-list-item :to="{ name: 'login' }" :title="t('landing.nav.login')" prepend-icon="mdi-login" />
          </template>
        </v-list>
      </v-menu>
    </v-app-bar>

    <!-- Hero -->
    <section class="hero-section">
      <v-container>
        <v-row align="center" justify="center">
          <v-col cols="12" md="6" lg="5" class="text-center text-md-left hero-copy">
            <h1 class="text-h4 text-md-h2 font-weight-bold mb-4">{{ copy.HERO.titleLead }}<br/><span class="text-primary">{{ copy.HERO.titleAccent }}</span></h1>
            <p class="text-body-1 text-md-h6 landing-muted mb-6 mb-md-8">{{ copy.HERO.lead }}</p>
            <div class="d-flex flex-wrap justify-center justify-md-start ga-3">
              <v-btn color="primary" size="large" :to="{ name: 'register' }" class="px-6">{{ t('landing.hero.start') }}</v-btn>
              <v-btn variant="outlined" size="large" href="#download" class="px-6">{{ t('landing.nav.download') }}</v-btn>
            </div>
          </v-col>
          <v-col cols="12" md="6" lg="6" class="mt-8 mt-md-0 hero-graphic">
            <ArchitectureGraphic />
          </v-col>
        </v-row>
      </v-container>
    </section>

    <!-- Capability strip -->
    <section class="trust-section py-4 py-md-6">
      <v-container>
        <div class="d-flex flex-wrap justify-center ga-2">
          <v-chip v-for="c in copy.CAPABILITIES" :key="c" variant="tonal" color="primary" size="small">{{ c }}</v-chip>
        </div>
      </v-container>
    </section>

    <!-- FR-88 P3: the video tour, as on the static homepage. -->
    <section id="video" class="py-8 py-md-12">
      <v-container style="max-width: 920px">
        <h2 class="text-h4 text-md-h3 text-center font-weight-bold mb-2">{{ copy.VIDEO_TOUR.title }}</h2>
        <p class="text-center text-body-1 landing-muted mb-6">{{ copy.VIDEO_TOUR.lead }}</p>
        <VideoFacade
          :video-id="FEATURED_VIDEO_ID"
          :poster="videoTourPoster"
          :caption="locale.startsWith('zh') ? t('landing.video.caption') : undefined"
        />
      </v-container>
    </section>

    <!-- Pillars -->
    <section id="features" class="features-section py-8 py-md-16">
      <v-container>
        <div v-for="(pillar, pi) in copy.PILLARS" :key="pillar.title" :class="pi > 0 ? 'mt-10 mt-md-16' : ''">
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
        <h2 class="text-h4 text-md-h3 text-center font-weight-bold mb-2">{{ copy.DOWNLOAD.title }}</h2>
        <p class="text-center text-body-1 landing-muted mb-6 mb-md-12">{{ copy.DOWNLOAD.lead }}</p>
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
                {{ t('landing.download.wizard') }}
              </v-btn>
              <p class="text-body-2 landing-muted mb-1">
                {{ os.wizardUrl ? t('landing.download.orTerminal') : t('landing.download.terminal') }}
              </p>
              <pre class="install-cmd text-caption pa-2 rounded flex-grow-1">{{ os.command }}</pre>
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
            <h2 class="text-h4 text-md-h3 font-weight-bold mb-4 text-white">{{ copy.CTA.title }}</h2>
            <p class="text-body-1 cta-subtitle mb-6 mb-md-8">{{ copy.CTA.lead }}</p>
            <v-btn color="white" size="large" :to="{ name: 'register' }" class="px-6 text-primary">{{ copy.CTA.button }}</v-btn>
          </v-col>
        </v-row>
      </v-container>
    </section>

    <!-- Footer -->
    <v-footer class="landing-footer py-4 py-md-8">
      <v-container>
        <v-row>
          <v-col cols="12" sm="4">
            <div class="text-h6 font-weight-bold mb-2">MeshHarbor · 织港</div>
            <p class="text-body-2 landing-muted">{{ t('landing.footer.tagline') }}</p>
          </v-col>
          <v-col cols="6" sm="3">
            <div class="text-subtitle-2 font-weight-bold mb-2">{{ t('landing.footer.product') }}</div>
            <a href="#features" class="text-body-2 landing-muted mb-1 d-block text-decoration-none">{{ t('landing.nav.features') }}</a>
            <a href="#download" class="text-body-2 landing-muted mb-1 d-block text-decoration-none">{{ t('landing.nav.download') }}</a>
            <a :href="appPath('/docs/')" class="text-body-2 landing-muted mb-1 d-block text-decoration-none">{{ t('landing.footer.docs') }}</a>
          </v-col>
          <v-col cols="6" sm="3">
            <div class="text-subtitle-2 font-weight-bold mb-2">{{ t('landing.footer.install') }}</div>
            <a :href="appPath('/docs/start/install/windows/')" class="text-body-2 landing-muted mb-1 d-block text-decoration-none">Windows</a>
            <a :href="appPath('/docs/start/install/macos/')" class="text-body-2 landing-muted mb-1 d-block text-decoration-none">macOS</a>
            <a :href="appPath('/docs/start/install/linux/')" class="text-body-2 landing-muted mb-1 d-block text-decoration-none">Linux</a>
            <a :href="appPath('/docs/start/self-hosting/')" class="text-body-2 landing-muted mb-1 d-block text-decoration-none">{{ t('landing.footer.selfHosting') }}</a>
          </v-col>
          <v-col cols="6" sm="2">
            <div class="text-subtitle-2 font-weight-bold mb-2">{{ t('landing.footer.legal') }}</div>
            <router-link to="/privacy" class="text-body-2 landing-muted mb-1 d-block text-decoration-none">{{ t('landing.footer.privacy') }}</router-link>
            <router-link to="/terms" class="text-body-2 landing-muted mb-1 d-block text-decoration-none">{{ t('landing.footer.terms') }}</router-link>
            <router-link to="/imprint" class="text-body-2 landing-muted mb-1 d-block text-decoration-none">{{ t('landing.footer.imprint') }}</router-link>
          </v-col>
        </v-row>
        <v-divider class="my-4" />
        <div class="text-body-2 landing-muted text-center">{{ t('landing.footer.copyright', { year: new Date().getFullYear() }) }}</div>
      </v-container>
    </v-footer>
  </div>
  </v-theme-provider>
</template>

<script setup lang="ts">
import { appOrigin, appPath } from '@/utils/deployment'
import { computed } from 'vue'
import { useI18n } from 'vue-i18n'
import { useDisplay } from 'vuetify'
import ArchitectureGraphic from '@/components/landing/ArchitectureGraphic.vue'
import { BRAND_LOGO_LIGHT } from '@/composables/useBrand'
import { installCards } from '@/utils/enrollCommands'
import { landingCopy } from '@/utils/landing'
import { LOCALES, setLocale } from '@/plugins/i18n'
import { FEATURED_VIDEO_ID } from '@/utils/videos'
import VideoFacade from '@/components/common/VideoFacade.vue'
import videoTourPoster from '@/assets/tutorial/video-C1YdfmhbAKM.jpg'

const { xs } = useDisplay()

const { t, locale } = useI18n()
const copy = computed(() => landingCopy(locale.value))
const SHORT_LABEL: Record<string, string> = { en: 'English', 'zh-CN': '中文' }
const otherLocale = computed(() => {
  const l = LOCALES.find((x) => x.code !== locale.value) ?? LOCALES[0]
  return { code: l.code, short: SHORT_LABEL[l.code] ?? l.label }
})

const osIcon: Record<string, string> = {
  windows: 'mdi-microsoft-windows',
  linux: 'mdi-linux',
  macos: 'mdi-apple',
}
const downloads = installCards(appOrigin(window.location.origin)).map((card) => ({
  ...card,
  icon: osIcon[card.os]!,
}))
</script>

<style scoped>
.landing-page {
  background: linear-gradient(180deg, #f5faf9 0%, #ffffff 40%);
  color: #1a1a2e;
}
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

.hero-copy,
.hero-graphic {
  position: relative;
  z-index: 1;
}
.hero-copy h1 {
  text-wrap: balance;
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
