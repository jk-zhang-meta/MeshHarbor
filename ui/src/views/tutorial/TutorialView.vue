<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 G ROX EOOD -->
<template>
  <v-container fluid class="pa-2 pa-md-4 pa-xl-6">
    <div class="d-flex align-center flex-wrap ga-2 mb-2 mb-md-4">
      <h1 class="text-h5 text-md-h4">{{ $t('nav.tutorial') }}</h1>
      <v-chip size="small" variant="tonal" color="primary" class="ml-1 font-weight-medium">
        {{ t('mh.tut.done', { done: doneCount, total: chapters.length }) }}
      </v-chip>
      <v-spacer />
      <v-btn
        v-if="doneCount > 0"
        size="small"
        variant="text"
        prepend-icon="mdi-restore"
        @click="reset"
      >
        {{ t('mh.tut.reset') }}
      </v-btn>
    </div>

    <v-row>
      <!-- Chapter rail -->
      <v-col cols="12" md="3" lg="3">
        <v-card variant="outlined" class="tutorial-rail" rounded="lg">
          <!-- Plain click + :active rather than v-list selection: the rail
               must track the URL hash (which back/forward and deep links
               also drive), not v-list's own selection state. -->
          <v-list density="compact" nav>
            <v-list-item
              v-for="c in chapters"
              :key="c.id"
              :active="c.id === activeId"
              color="primary"
              :prepend-icon="c.icon"
              :title="c.title"
              :subtitle="c.blurb"
              @click="go(c.id)"
            >
              <template #append>
                <v-icon v-if="isDone(c.id)" size="small" color="success">
                  mdi-check-circle
                </v-icon>
              </template>
            </v-list-item>
          </v-list>
        </v-card>
      </v-col>

      <v-col cols="12" md="9" lg="9">
        <v-card variant="outlined" class="pa-4 pa-md-6" rounded="lg">
          <div class="d-flex align-center ga-2 mb-3">
            <v-avatar size="36" color="primary" variant="tonal">
              <v-icon :icon="active.icon" />
            </v-avatar>
            <h2 class="text-h6 text-md-h5 font-weight-bold">{{ active.title }}</h2>
          </div>

          <!-- Landing-page headline treatment (chapter 0). -->
          <template v-if="active.tagline">
            <h3 class="text-h5 text-md-h4 font-weight-bold mb-2 tutorial-headline">
              {{ active.tagline.headline }}<br />
              <span class="text-primary">{{ active.tagline.accent }}</span>
            </h3>
            <p class="text-body-1 text-md-h6 text-medium-emphasis font-weight-regular mb-4">
              {{ active.tagline.sub }}
            </p>
          </template>

          <!-- Capability strip, straight off the landing page. -->
          <div v-if="active.chips" class="d-flex flex-wrap ga-2 mb-4">
            <v-chip
              v-for="chip in active.chips"
              :key="chip"
              size="small"
              variant="tonal"
              color="primary"
            >
              {{ chip }}
            </v-chip>
          </div>

          <!-- FR-88 P3: the video tour, loaded from YouTube only on a click. -->
          <VideoFacade
            v-if="active.video"
            class="mb-5"
            :video-id="active.video.id"
            :poster="active.video.poster"
            :caption="active.video.caption"
          />

          <!-- The heroes are the README's own illustrations: a light
               palette on transparent. They are painted on a fixed light
               panel in BOTH themes — recolouring them per theme would mean
               forking every artwork. -->
          <div v-if="active.hero" class="tutorial-hero mb-5">
            <img :src="active.hero" :alt="active.heroAlt || active.title" />
          </div>

          <!-- Decorated promise bullets. -->
          <v-row v-if="active.badges" class="mb-2">
            <v-col v-for="b in active.badges" :key="b.title" cols="12" sm="6" md="4">
              <div class="tutorial-badge h-100">
                <v-avatar size="34" :color="b.color" variant="tonal" class="mb-2">
                  <v-icon :icon="b.icon" :color="b.color" size="20" />
                </v-avatar>
                <div class="text-subtitle-2 font-weight-bold mb-1">{{ b.title }}</div>
                <div class="text-body-2 text-medium-emphasis">{{ b.text }}</div>
              </div>
            </v-col>
          </v-row>

          <p class="text-body-1 mb-5">
            <template v-for="(seg, i) in richSegments(active.lead)" :key="i">
              <strong v-if="seg.bold">{{ seg.text }}</strong>
              <template v-else>{{ seg.text }}</template>
            </template>
          </p>

          <div class="d-flex align-center ga-2 mb-3">
            <v-icon icon="mdi-play-circle-outline" color="primary" size="20" />
            <h3 class="text-subtitle-1 font-weight-bold">{{ t('mh.tut.tryIt') }}</h3>
          </div>
          <div class="tutorial-steps mb-5">
            <div v-for="(s, i) in active.steps" :key="i" class="tutorial-step">
              <div class="d-flex align-start ga-3">
                <v-avatar size="30" color="primary" variant="tonal" class="flex-shrink-0">
                  <v-icon v-if="s.icon" :icon="s.icon" size="17" />
                  <span v-else class="text-caption font-weight-bold">{{ i + 1 }}</span>
                </v-avatar>
                <div class="flex-grow-1">
                  <div class="text-body-2">
                    <template v-for="(seg, j) in richSegments(s.text)" :key="j">
                      <strong v-if="seg.bold">{{ seg.text }}</strong>
                      <template v-else>{{ seg.text }}</template>
                    </template>
                  </div>
                  <div v-if="s.code" class="tutorial-code mt-2">
                    <code>{{ s.code }}</code>
                    <v-btn
                      icon="mdi-content-copy"
                      size="x-small"
                      variant="text"
                      :aria-label="t('mh.tut.copy', { code: s.code })"
                      @click="copy(s.code)"
                    />
                  </div>
                  <div v-if="s.to" class="mt-2">
                    <v-btn
                      size="small"
                      variant="tonal"
                      color="primary"
                      append-icon="mdi-arrow-right"
                      :to="linkFor(s)"
                    >
                      {{ s.linkLabel || t('mh.tut.open') }}
                    </v-btn>
                  </div>
                  <div v-if="s.graphic" class="tutorial-step-graphic mt-3">
                    <img :src="s.graphic" :alt="s.graphicAlt || ''" />
                  </div>
                </div>
              </div>
            </div>
          </div>

          <!-- Landing pillar "gems" as cards. -->
          <template v-if="active.highlights">
            <div class="d-flex align-center ga-2 mb-3">
              <v-icon icon="mdi-star-four-points-outline" color="primary" size="20" />
              <h3 class="text-subtitle-1 font-weight-bold">{{ t('mh.tut.holdsUp') }}</h3>
            </div>
            <v-row class="mb-3">
              <v-col v-for="h in active.highlights" :key="h.title" cols="12" sm="6" md="4">
                <v-card variant="outlined" rounded="lg" class="pa-4 h-100">
                  <v-icon :icon="h.icon" :color="h.color" size="30" class="mb-2" />
                  <div class="text-subtitle-2 font-weight-bold mb-1">{{ h.title }}</div>
                  <div class="text-body-2 text-medium-emphasis">{{ h.text }}</div>
                </v-card>
              </v-col>
            </v-row>
          </template>

          <div class="d-flex align-center ga-2 mb-2">
            <v-icon icon="mdi-information-outline" color="primary" size="20" />
            <h3 class="text-subtitle-1 font-weight-bold">{{ t('mh.tut.inDetail') }}</h3>
          </div>
          <v-table density="compact" class="tutorial-detail mb-5">
            <tbody>
              <tr v-for="(d, i) in active.detail" :key="i">
                <th class="font-weight-bold">{{ d.label }}</th>
                <td>{{ d.text }}</td>
              </tr>
            </tbody>
          </v-table>

          <!-- FR-12 P2 — take the reader to the real control, spotlighted.
               Only rendered for chapters that declare a tour. -->
          <div v-if="active.tour" class="mb-4">
            <v-btn
              color="primary"
              variant="tonal"
              size="small"
              prepend-icon="mdi-target"
              @click="startTour(active.tour)"
            >
              {{ active.tour.label }}
            </v-btn>
          </div>

          <v-divider class="mb-4" />

          <div class="d-flex align-center flex-wrap ga-2">
            <v-btn
              :color="isDone(active.id) ? 'success' : 'primary'"
              :variant="isDone(active.id) ? 'tonal' : 'flat'"
              :prepend-icon="isDone(active.id) ? 'mdi-check-circle' : 'mdi-check'"
              size="small"
              @click="toggle(active.id)"
            >
              {{ isDone(active.id) ? t('mh.tut.doneBtn') : t('mh.tut.markDone') }}
            </v-btn>
            <v-spacer />
            <v-btn
              v-if="prevChapter"
              size="small"
              variant="text"
              prepend-icon="mdi-chevron-left"
              @click="go(prevChapter.id)"
            >
              {{ prevChapter.title }}
            </v-btn>
            <v-btn
              v-if="nextChapter"
              size="small"
              variant="tonal"
              color="primary"
              append-icon="mdi-chevron-right"
              @click="go(nextChapter.id)"
            >
              {{ nextChapter.title }}
            </v-btn>
          </div>
        </v-card>
      </v-col>
    </v-row>
  </v-container>
</template>

<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useAuthStore } from '@/stores/auth'
import { useSnackbar } from '@/composables/useSnackbar'
import { useTutorialProgress } from '@/composables/useTutorialProgress'
import VideoFacade from '@/components/common/VideoFacade.vue'
import {
  TUTORIAL_CHAPTERS,
  chapterById,
  richSegments,
  type TutorialStep,
} from './tutorialChapters'
import { useI18n } from 'vue-i18n'

const { t } = useI18n()

const route = useRoute()
const router = useRouter()

// FR-12 P2 — hand off to the live page. The tour id travels as a query param
// because the overlay is mounted by the LAYOUT, not by this view: by the time
// the tour runs, this component is gone.
function startTour(tour: { id: string; routeName: string }) {
  router.push({
    name: tour.routeName,
    params: { tenantId: route.params.tenantId },
    query: { tour: tour.id },
  })
}
const auth = useAuthStore()
const { showSuccess } = useSnackbar()

const chapters = TUTORIAL_CHAPTERS
const tenantId = computed(() => route.params.tenantId as string)

// The URL hash IS the chapter: /tutorial#devices deep-links from the
// devices empty state, and back/forward moves between chapters.
const activeId = ref(chapterById(route.hash.replace('#', ''))?.id ?? chapters[0].id)
watch(
  () => route.hash,
  (h) => {
    const c = chapterById(h.replace('#', ''))
    if (c) activeId.value = c.id
  },
)

const active = computed(() => chapterById(activeId.value) ?? chapters[0])
const activeIndex = computed(() => chapters.findIndex((c) => c.id === active.value.id))
const prevChapter = computed(() => chapters[activeIndex.value - 1])
const nextChapter = computed(() => chapters[activeIndex.value + 1])

const { doneCount, isDone, toggle, reset } = useTutorialProgress(() => auth.user?.id)

function go(id: string) {
  activeId.value = id
  router.replace({ hash: `#${id}` })
  globalThis.scrollTo?.({ top: 0, behavior: 'smooth' })
}

/** Steps name a route; the tenant id comes from where the reader already
 *  is, so a link can never land on someone else's org. */
function linkFor(s: TutorialStep) {
  return { name: s.to!.name, params: { tenantId: tenantId.value }, query: s.to!.query }
}

async function copy(text: string) {
  try {
    await navigator.clipboard.writeText(text)
    showSuccess(t('mh.tut.copied'))
  } catch {
    /* clipboard blocked (permissions / insecure context) — the command is
       visible and selectable either way, so this is not worth an error. */
  }
}
</script>

<style scoped>
.tutorial-rail {
  position: sticky;
  top: 76px;
}

.tutorial-headline {
  line-height: 1.2;
}

/* The heroes are light-palette artwork (README parity). Give them a fixed
   pale panel so the dark theme doesn't put dark ink on a dark surface —
   one artwork, legible in both themes. Height is deliberately generous:
   at half this size the labels inside the diagrams are unreadable. */
.tutorial-hero {
  background: #f5f7fa;
  border: 1px solid rgba(0, 150, 136, 0.18);
  border-radius: 10px;
  padding: 16px;
  text-align: center;
}
.tutorial-hero img {
  max-width: 100%;
  height: auto;
  max-height: 680px;
}

.tutorial-badge {
  border-left: 3px solid rgb(var(--v-theme-primary));
  padding: 2px 0 2px 12px;
}

.tutorial-step + .tutorial-step {
  margin-top: 18px;
  padding-top: 18px;
  border-top: 1px solid rgba(var(--v-theme-on-surface), 0.08);
}

/* Per-step diagrams: same pale panel, and wide enough to read their own
   labels (they carry text). */
.tutorial-step-graphic {
  background: #f5f7fa;
  border: 1px solid rgba(0, 150, 136, 0.18);
  border-radius: 8px;
  padding: 10px;
  max-width: 560px;
}
.tutorial-step-graphic img {
  display: block;
  width: 100%;
  height: auto;
}

.tutorial-code {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  background: rgba(var(--v-theme-on-surface), 0.06);
  border-radius: 6px;
  padding: 4px 4px 4px 10px;
  max-width: 100%;
  overflow-x: auto;
}
.tutorial-code code {
  font-size: 0.8125rem;
  white-space: nowrap;
}

.tutorial-detail th {
  width: 30%;
  min-width: 140px;
  vertical-align: top;
  text-align: left;
}
.tutorial-detail td {
  white-space: normal;
  padding-top: 8px;
  padding-bottom: 8px;
}
</style>
