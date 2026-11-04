/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 G ROX EOOD
 *
 * FR-60 (#1165) — the ONLY render-blocking script on a docs page, and it
 * is ~300 bytes.
 *
 * OS tabs are CSS-only (radio + :checked), so the first panel in DOM order
 * — Windows — is what renders before any JavaScript runs. On a Getting
 * Started page the install command is above the fold, so a macOS reader
 * with a stored preference would watch the wrong OS paint and then swap.
 *
 * This sets `data-os` on <html> BEFORE first paint; `docs.css` honours it
 * with a small override block, and `docs.js` removes the attribute once it
 * has checked the real radios, handing control back to the CSS-only
 * mechanism. Net effect: no flash, and the tabs still work with JS off
 * (no attribute is ever set, so the radios decide, exactly as they do now).
 *
 * ⚠️ Must stay dependency-free and synchronous. Wrapped in try/catch
 * because localStorage THROWS (not returns null) in a browser configured
 * to block site data, and an exception here would abort head parsing.
 */
(function () {
  try {
    var os = localStorage.getItem('meshharbor-docs-os')
    if (os === 'windows' || os === 'macos' || os === 'linux') {
      document.documentElement.setAttribute('data-os', os)
    }
  } catch (e) {
    /* storage unavailable — fall through to the CSS default */
  }
})()
