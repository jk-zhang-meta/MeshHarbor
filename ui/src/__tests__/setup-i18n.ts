// SPDX-License-Identifier: AGPL-3.0-only
// Components render `$t(...)` like the app does; tests mount them with the app's i18n
// (English by default), so English assertions keep their meaning.
import { config } from '@vue/test-utils'
import i18n from '@/plugins/i18n'

config.global.plugins = [...(config.global.plugins ?? []), i18n]
