<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 G ROX EOOD -->
<!--
  FR-88 (#1790) P3 — a click-to-load YouTube video, the app's twin of the static
  site's facade (ui/docs/theme/video.ts). Our own poster under a play button; the
  youtube-nocookie.com player replaces it only when someone presses play, so the
  page loads nothing from YouTube before that.
-->
<template>
  <figure v-if="video" class="video-facade">
    <iframe
      v-if="playing"
      class="video-facade__frame"
      :src="embedUrl(video.id)"
      :title="video.title"
      allow="autoplay; encrypted-media; picture-in-picture; fullscreen"
      allowfullscreen
    />
    <button
      v-else
      type="button"
      class="video-facade__button"
      :aria-label="label"
      @click="playing = true"
    >
      <img class="video-facade__poster" :src="poster" alt="" loading="lazy" decoding="async" />
      <span class="video-facade__play">
        <v-icon icon="mdi-play" size="40" />
      </span>
      <span class="video-facade__time">{{ clockOf(video.duration) }}</span>
    </button>
    <figcaption class="text-body-2 text-medium-emphasis mt-2">
      {{ caption || video.title }}
      <span class="d-block text-caption">{{ t('mh.video.fromYoutube') }}</span>
    </figcaption>
  </figure>
</template>

<script setup lang="ts">
import { computed, ref } from 'vue'
import { clockOf, embedUrl, minutesOf, videoById } from '@/utils/videos'
import { useI18n } from 'vue-i18n'

const { t } = useI18n()

const props = defineProps<{
  /** A YouTube id from `ui/src/utils/videos.ts`; anything else renders nothing. */
  videoId: string
  /** The poster's URL (an imported asset). */
  poster: string
  caption?: string
}>()

const video = computed(() => videoById(props.videoId))
const label = computed(() =>
  video.value
    ? t('mh.video.play', { title: video.value.title, n: minutesOf(video.value.duration) })
    : '',
)
const playing = ref(false)
</script>

<style scoped>
.video-facade {
  margin: 0;
}
.video-facade__button,
.video-facade__frame {
  position: relative;
  display: block;
  width: 100%;
  aspect-ratio: 16 / 9;
  border: 0;
  padding: 0;
  border-radius: 12px;
  overflow: hidden;
  background: #1a1a2e;
  cursor: pointer;
}
.video-facade__poster {
  display: block;
  width: 100%;
  height: 100%;
  object-fit: cover;
}
.video-facade__play {
  position: absolute;
  left: 50%;
  top: 50%;
  width: 76px;
  height: 76px;
  margin: -38px 0 0 -38px;
  display: flex;
  align-items: center;
  justify-content: center;
  border-radius: 50%;
  background: rgb(var(--v-theme-primary));
  color: #fff;
  box-shadow: 0 8px 28px rgba(26, 26, 46, 0.35);
  transition: transform 0.15s ease;
}
.video-facade__button:hover .video-facade__play,
.video-facade__button:focus-visible .video-facade__play {
  transform: scale(1.08);
}
.video-facade__button:focus-visible {
  outline: 3px solid rgb(var(--v-theme-primary));
  outline-offset: 3px;
}
.video-facade__time {
  position: absolute;
  right: 12px;
  bottom: 12px;
  padding: 2px 8px;
  border-radius: 6px;
  background: rgba(0, 0, 0, 0.78);
  color: #fff;
  font-size: 0.8rem;
  font-weight: 600;
  font-variant-numeric: tabular-nums;
}
@media (prefers-reduced-motion: reduce) {
  .video-facade__play {
    transition: none;
  }
}
</style>
