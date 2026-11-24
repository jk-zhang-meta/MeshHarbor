<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 G ROX EOOD -->
<!--
  The sign-in and sign-up frame (flat theme, 2026-11-23): what the product is on
  the left, the form on the right. The left panel is the brand's one bold moment:
  harbor ink with the mark's hexagon woven across it (织港, "a woven harbour").
  Below md the panel folds away and the form stands alone.
-->
<template>
  <div class="mh-auth page-no-sideways">
    <aside class="mh-auth__brand">
      <svg class="mh-auth__weave" aria-hidden="true" focusable="false">
        <defs>
          <pattern id="mh-weave" width="84" height="72" patternUnits="userSpaceOnUse">
            <path d="M21 0h42l21 36-21 36H21L0 36Z" />
            <path d="M0 36h21M63 36h21M42 0v18M42 54v18" />
            <circle cx="21" cy="0" r="2" />
            <circle cx="63" cy="0" r="2" />
            <circle cx="0" cy="36" r="2" />
            <circle cx="84" cy="36" r="2" />
            <circle cx="21" cy="72" r="2" />
            <circle cx="63" cy="72" r="2" />
          </pattern>
        </defs>
        <rect width="100%" height="100%" fill="url(#mh-weave)" />
      </svg>
      <div class="mh-auth__brand-inner">
        <div class="mh-auth__lockup">
          <img :src="markOnInk" alt="" width="34" height="36" />
          <span>{{ PRODUCT_TITLE }}</span>
        </div>
        <h1 class="mh-auth__headline">{{ t('mh.authShell.headline') }}</h1>
        <p class="mh-auth__lede">{{ t('mh.authShell.lede') }}</p>
        <ul class="mh-auth__facts">
          <li v-for="f in facts" :key="f.key">
            <v-icon size="18">{{ f.icon }}</v-icon>
            <span>{{ t(`mh.authShell.${f.key}`) }}</span>
          </li>
        </ul>
      </div>
    </aside>
    <section class="mh-auth__form">
      <div class="mh-auth__form-inner">
        <slot />
      </div>
    </section>
  </div>
</template>

<script setup lang="ts">
import { useI18n } from 'vue-i18n'
import markOnInk from '@/assets/brand/meshharbor-mark-dark.svg'
import { PRODUCT_TITLE } from '@/utils/product'

const { t } = useI18n()
const facts = [
  { key: 'factRemote', icon: 'mdi-monitor-share' },
  { key: 'factMesh', icon: 'mdi-lan-connect' },
  { key: 'factTeam', icon: 'mdi-account-group-outline' },
]
</script>

<style scoped>
.mh-auth {
  display: grid;
  grid-template-columns: minmax(0, 1fr) minmax(360px, 520px);
  min-height: 100vh;
  min-height: 100dvh;
  width: 100%;
  background: rgb(var(--v-theme-background));
}
.mh-auth__brand {
  position: relative;
  overflow: hidden;
  display: flex;
  align-items: center;
  padding: clamp(32px, 6vw, 88px);
  background: #10212b;
  color: #eef6f8;
}
.v-theme--dark .mh-auth__brand {
  background: #0a1216;
  border-inline-end: 1px solid var(--mh-hairline);
}
.mh-auth__weave {
  position: absolute;
  inset: 0;
  width: 100%;
  height: 100%;
}
.mh-auth__weave path {
  fill: none;
  stroke: #59ded2;
  stroke-width: 1;
  opacity: 0.14;
}
.mh-auth__weave circle {
  fill: #59ded2;
  opacity: 0.22;
}
/* The weave fades out behind the words, so they never sit on a line. */
.mh-auth__brand::after {
  content: '';
  position: absolute;
  inset: 0;
  background: linear-gradient(90deg, rgba(16, 33, 43, 0.96) 0%, rgba(16, 33, 43, 0.82) 48%, rgba(16, 33, 43, 0.2) 100%);
}
.v-theme--dark .mh-auth__brand::after {
  background: linear-gradient(90deg, rgba(10, 18, 22, 0.96) 0%, rgba(10, 18, 22, 0.82) 48%, rgba(10, 18, 22, 0.2) 100%);
}
.mh-auth__brand-inner {
  position: relative;
  z-index: 1;
  max-width: 520px;
}
.mh-auth__lockup {
  display: flex;
  align-items: center;
  gap: 12px;
  font-size: 1.0625rem;
  font-weight: 600;
  letter-spacing: 0.01em;
  margin-bottom: 40px;
}
.mh-auth__headline {
  font-size: clamp(1.75rem, 1.2rem + 1.6vw, 2.5rem);
  line-height: 1.2;
  font-weight: 600;
  letter-spacing: -0.02em;
  margin: 0 0 16px;
  text-wrap: balance;
}
.mh-auth__lede {
  font-size: 1rem;
  line-height: 1.7;
  text-wrap: pretty;
  color: rgba(238, 246, 248, 0.72);
  margin: 0 0 32px;
}
.mh-auth__facts {
  list-style: none;
  padding: 0;
  margin: 0;
  display: grid;
  gap: 14px;
}
.mh-auth__facts li {
  display: flex;
  align-items: flex-start;
  gap: 12px;
  font-size: 0.9375rem;
  line-height: 1.5;
  color: rgba(238, 246, 248, 0.88);
}
.mh-auth__facts .v-icon {
  color: #59ded2;
  margin-top: 2px;
}
.mh-auth__form {
  display: flex;
  align-items: center;
  justify-content: center;
  padding: clamp(24px, 4vw, 56px);
  background: rgb(var(--v-theme-surface));
}
.mh-auth__form-inner {
  width: 100%;
  max-width: 380px;
}
@media (max-width: 959.98px) {
  .mh-auth {
    grid-template-columns: 1fr;
  }
  .mh-auth__brand {
    display: none;
  }
  .mh-auth__form {
    background: rgb(var(--v-theme-background));
    padding: 32px 16px;
  }
}
</style>
