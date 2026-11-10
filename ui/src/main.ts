// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
import { createApp } from 'vue'
import i18n from '@/plugins/i18n'
import vuetify from '@/plugins/vuetify'
// After Vuetify's own styles: the phone-width utilities (FR-116).
import '@/styles/responsive.css'
import pinia from '@/plugins/pinia'
import router from '@/plugins/router'
import App from '@/App.vue'
import { clearLegacyTokens } from '@/api/session'
import { loadAnalytics } from '@/utils/analytics'
import { installStaleBuildRecovery } from '@/utils/staleBuild'
import { useCapabilitiesStore } from '@/stores/capabilities'

// Delete the tokens earlier versions kept in localStorage — an access token
// (7 days) and, worse, a refresh token (30 days) that re-mints access tokens.
// They are cookies now, but shipping that fix only stops NEW ones being
// written: a user who never signs out again would otherwise carry the old pair
// until they expire. Runs before anything can read them.
clearLegacyTokens()

// FR-102 (#2127) — the analytics tracker, on the hosted site only. It was a
// static tag in index.html, so every self-hosted install and every localhost
// run reported to purestat.ai as meshharbor.itachi.fans. A no-op on any other host, and
// under a WebDriver, so the e2e suite never loads it either.
loadAnalytics()

const app = createApp(App)

// Plugin order matters: i18n FIRST, vuetify SECOND
app.use(i18n)
app.use(vuetify)
app.use(pinia)
// FR-69 P9 — ask the server what it is composed of, once, before the first
// navigation resolves: the router's module guard awaits this same request,
// and the navigation hides the pillars the server does not mount. Never
// blocks the mount and never throws — an unanswered server fails OPEN.
void useCapabilitiesStore().load()
app.use(router)
// A tab left open across a promote asks for chunks the new image no longer
// has: load the page the server serves now, once (utils/staleBuild.ts).
installStaleBuildRecovery(window, router)

app.mount('#app')
