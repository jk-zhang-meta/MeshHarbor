// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//
// Headless i18n parity, key coverage, and local-font / zero-CDN verification
// for both meshharbor-desktop and meshharbor-setup front-ends.
'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const REPO_ROOT = path.resolve(__dirname, '..', '..', '..');
const DESKTOP_FRONT = path.join(REPO_ROOT, 'agents', 'meshharbor-desktop', 'src', 'front');
const SETUP_FRONT = path.join(REPO_ROOT, 'agents', 'meshharbor-setup', 'src', 'front');

const desktopI18n = require(path.join(DESKTOP_FRONT, 'i18n.js'));
const setupI18n = require(path.join(SETUP_FRONT, 'i18n.js'));

function placeholdersOf(str) {
  const found = new Set();
  for (const m of String(str).matchAll(/\{([a-zA-Z0-9_]+)\}/g)) {
    found.add(m[1]);
  }
  return [...found].sort();
}

function checkDictionaryParity(label, i18n) {
  assert.ok(i18n && i18n.MESSAGES, `${label}: missing MESSAGES export`);
  const en = i18n.MESSAGES.en;
  const zh = i18n.MESSAGES['zh-CN'];
  assert.ok(en && typeof en === 'object', `${label}: missing en table`);
  assert.ok(zh && typeof zh === 'object', `${label}: missing zh-CN table`);

  const enKeys = Object.keys(en).sort();
  const zhKeys = Object.keys(zh).sort();
  assert.ok(enKeys.length > 0, `${label}: en table is empty`);

  const missingInZh = enKeys.filter((k) => !Object.prototype.hasOwnProperty.call(zh, k));
  const extraInZh = zhKeys.filter((k) => !Object.prototype.hasOwnProperty.call(en, k));
  assert.deepEqual(missingInZh, [], `${label}: keys missing in zh-CN`);
  assert.deepEqual(extraInZh, [], `${label}: extra keys in zh-CN not present in en`);

  for (const k of enKeys) {
    assert.equal(typeof en[k], 'string', `${label}: en['${k}'] is not a string`);
    assert.equal(typeof zh[k], 'string', `${label}: zh-CN['${k}'] is not a string`);
    assert.ok(en[k].trim().length > 0, `${label}: en['${k}'] is empty`);
    assert.ok(zh[k].trim().length > 0, `${label}: zh-CN['${k}'] is empty`);
    assert.deepEqual(
      placeholdersOf(zh[k]),
      placeholdersOf(en[k]),
      `${label}: placeholder mismatch for key '${k}' (en=${JSON.stringify(en[k])}, zh-CN=${JSON.stringify(zh[k])})`,
    );
  }

  // Saved-choice validator (only exact saved values `'en'` or `'zh-CN'`, else null -> OS fallback).
  assert.equal(i18n.normalizeLang('en'), 'en');
  assert.equal(i18n.normalizeLang('EN'), 'en');
  assert.equal(i18n.normalizeLang('zh-CN'), 'zh-CN');
  assert.equal(i18n.normalizeLang('zh_cn'), 'zh-CN');
  assert.equal(i18n.normalizeLang(''), null);
  assert.equal(i18n.normalizeLang('fr-FR'), null);
  assert.equal(i18n.normalizeLang(null), null);

  // OS locale fallback rules must match Web UI (`zh*` -> `zh-CN`, else `en`).
  assert.equal(i18n.detectOsLang('zh'), 'zh-CN');
  assert.equal(i18n.detectOsLang('zh-CN'), 'zh-CN');
  assert.equal(i18n.detectOsLang('zh-Hans'), 'zh-CN');
  assert.equal(i18n.detectOsLang('zh-TW'), 'zh-CN');
  assert.equal(i18n.detectOsLang('zh_HK.UTF-8'), 'zh-CN');
  assert.equal(i18n.detectOsLang(['en-US', 'zh-Hans-CN']), 'zh-CN');
  assert.equal(i18n.detectOsLang('en'), 'en');
  assert.equal(i18n.detectOsLang('en-US'), 'en');
  assert.equal(i18n.detectOsLang('de-DE'), 'en');
  assert.equal(i18n.detectOsLang(''), 'en');

  // Language switching smoke check.
  i18n.setLang('en', { syncNative: false });
  assert.equal(i18n.getLang(), 'en');
  i18n.setLang('zh-CN', { syncNative: false });
  assert.equal(i18n.getLang(), 'zh-CN');
  i18n.setLang('en', { syncNative: false });

  return enKeys.length;
}

function checkFrontCoverageAndHygiene(label, frontDir, i18n) {
  const en = i18n.MESSAGES.en;
  const entries = fs.readdirSync(frontDir);

  // 1. HTML data-i18n* attribute references & zero external CDN URLs.
  const htmlFiles = entries.filter((f) => f.endsWith('.html'));
  assert.ok(htmlFiles.length > 0, `${label}: no HTML files found`);
  for (const file of htmlFiles) {
    const src = fs.readFileSync(path.join(frontDir, file), 'utf8');
    for (const m of src.matchAll(/data-i18n(?:-[a-z-]+)?="([^"]+)"/g)) {
      const key = m[1];
      assert.ok(
        Object.prototype.hasOwnProperty.call(en, key),
        `${label}/${file}: unknown data-i18n key '${key}'`,
      );
    }
    assert.equal(
      /<(?:link|script)\b[^>]*\b(?:href|src)\s*=\s*["']https?:\/\//i.test(src),
      false,
      `${label}/${file}: external HTTP(S) <link> or <script> detected`,
    );
  }

  // 2. JS t('literal.key', ...) references must all exist in dictionary.
  const jsFiles = entries.filter((f) => f.endsWith('.js') && f !== 'i18n.js' && f !== 'mesh-util.js');
  for (const file of jsFiles) {
    const src = fs.readFileSync(path.join(frontDir, file), 'utf8');
    for (const m of src.matchAll(/(?:^|[^\w$])t\(\s*'([a-zA-Z0-9_.-]+)'\s*(?:,|\))/g)) {
      const key = m[1];
      assert.ok(
        Object.prototype.hasOwnProperty.call(en, key),
        `${label}/${file}: unknown t('${key}') reference`,
      );
    }
  }

  // 3. CSS bundled local fonts & zero external URLs / @import CDN.
  const cssFiles = entries.filter((f) => f.endsWith('.css'));
  assert.ok(cssFiles.length > 0, `${label}: no CSS files found`);
  let fontFaceRefs = 0;
  for (const file of cssFiles) {
    const src = fs.readFileSync(path.join(frontDir, file), 'utf8');
    assert.equal(
      /url\(\s*['"]?https?:\/\//i.test(src),
      false,
      `${label}/${file}: external HTTP(S) url() detected in CSS`,
    );
    assert.equal(
      /@import\s+(?:url\()?\s*['"]?https?:\/\//i.test(src),
      false,
      `${label}/${file}: external HTTP(S) @import detected in CSS`,
    );
    for (const m of src.matchAll(/url\(\s*['"](\.\/fonts\/[^'"]+\.woff2)['"]\s*\)/g)) {
      fontFaceRefs += 1;
      const fontPath = path.join(frontDir, m[1]);
      assert.ok(fs.existsSync(fontPath), `${label}/${file}: missing bundled font ${m[1]}`);
      assert.ok(fs.statSync(fontPath).size > 1000, `${label}/${file}: bundled font ${m[1]} looks truncated`);
    }
  }
  assert.ok(fontFaceRefs >= 6, `${label}: expected >= 6 bundled IBM Plex @font-face rules, got ${fontFaceRefs}`);
}

const desktopCount = checkDictionaryParity('meshharbor-desktop', desktopI18n);
const setupCount = checkDictionaryParity('meshharbor-setup', setupI18n);

checkFrontCoverageAndHygiene('meshharbor-desktop', DESKTOP_FRONT, desktopI18n);
checkFrontCoverageAndHygiene('meshharbor-setup', SETUP_FRONT, setupI18n);

// Check dynamic-prefix key tables in desktop JS match desktop i18n dictionary.
const recSrc = fs.readFileSync(path.join(DESKTOP_FRONT, 'recordings.js'), 'utf8');
const endingsBlock = recSrc.match(/const ENDINGS = \{([\s\S]*?)\};/);
assert.ok(endingsBlock, 'recordings.js: ENDINGS table not found');
for (const m of endingsBlock[1].matchAll(/^\s+([a-z0-9_]+):/gm)) {
  assert.ok(
    Object.prototype.hasOwnProperty.call(desktopI18n.MESSAGES.en, 'rec.end.' + m[1]),
    `recordings.js: missing rec.end.${m[1]} in desktop i18n`,
  );
}

const edSrc = fs.readFileSync(path.join(DESKTOP_FRONT, 'editor.js'), 'utf8');
const refusalsBlock = edSrc.match(/const REFUSALS = \{([\s\S]*?)\};/);
assert.ok(refusalsBlock, 'editor.js: REFUSALS table not found');
for (const m of refusalsBlock[1].matchAll(/^\s+([a-z0-9_]+):/gm)) {
  assert.ok(
    Object.prototype.hasOwnProperty.call(desktopI18n.MESSAGES.en, 'ed.refusal.' + m[1]),
    `editor.js: missing ed.refusal.${m[1]} in desktop i18n`,
  );
}
const soundBlock = edSrc.match(/const SOUND = \{([\s\S]*?)\};/);
assert.ok(soundBlock, 'editor.js: SOUND table not found');
for (const m of soundBlock[1].matchAll(/^\s+([a-z0-9_]+):/gm)) {
  assert.ok(
    Object.prototype.hasOwnProperty.call(desktopI18n.MESSAGES.en, 'ed.sound.' + m[1]),
    `editor.js: missing ed.sound.${m[1]} in desktop i18n`,
  );
}

const obSrc = fs.readFileSync(path.join(DESKTOP_FRONT, 'onboarding.js'), 'utf8');
const featBlock = obSrc.match(/const featureLabels = \[([\s\S]*?)\];/);
assert.ok(featBlock, 'onboarding.js: featureLabels table not found');
for (const m of featBlock[1].matchAll(/\['([a-z0-9_]+)',/g)) {
  assert.ok(
    Object.prototype.hasOwnProperty.call(desktopI18n.MESSAGES.en, 'ob.feat.' + m[1]),
    `onboarding.js: missing ob.feat.${m[1]} in desktop i18n`,
  );
}

console.log(
  `i18n parity & zero-CDN passed: desktop=${desktopCount} keys, setup=${setupCount} keys (100% en/zh-CN parity + placeholders + bundled IBM Plex fonts)`,
);
