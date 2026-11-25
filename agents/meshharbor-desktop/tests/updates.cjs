// Headless: no browser, Tauri window, daemon, OS input or private config.
// Covers the Overview self-update state machine (`describeUpdate`, `fmtBytes`,
// `stripAgentTag`) in both en and zh-CN.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');

const i18nSrc = fs.readFileSync(path.join(__dirname, '../src/front/i18n.js'), 'utf8');
const overviewSrc = fs.readFileSync(path.join(__dirname, '../src/front/overview.js'), 'utf8');

function loadRealm(lang) {
  const realm = {
    window: {
      MeshHarbor: {
        $: () => null,
        invoke: async () => ({ stage: 'idle', current: '0.4.216' }),
        show() {},
        hide() {},
        setText() {},
        on() {},
        get: () => null,
        navigate() {},
        currentView: () => 'overview',
      },
      localStorage: {
        _m: { 'meshharbor.lang': lang },
        getItem(k) { return this._m[k] || null; },
        setItem(k, v) { this._m[k] = String(v); },
      },
      addEventListener() {},
    },
    document: {
      documentElement: { lang: '' },
      addEventListener() {},
      querySelectorAll: () => [],
      querySelector: () => null,
    },
    navigator: { language: lang },
    localStorage: {
      _m: { 'meshharbor.lang': lang },
      getItem(k) { return this._m[k] || null; },
      setItem(k, v) { this._m[k] = String(v); },
    },
    setTimeout,
    clearTimeout,
  };
  vm.runInNewContext(i18nSrc, realm);
  if (realm.window.MeshHarborI18n && realm.window.MeshHarborI18n.setLang) {
    realm.window.MeshHarborI18n.setLang(lang);
  }
  vm.runInNewContext(overviewSrc, realm);
  return realm.window.MeshHarborOverview;
}

const en = loadRealm('en');
const zh = loadRealm('zh-CN');

// Helpers
assert.equal(en.stripAgentTag('agent-v0.4.217'), '0.4.217');
assert.equal(en.stripAgentTag('0.4.217'), '0.4.217');
assert.equal(en.fmtBytes(512), '512 B');
assert.equal(en.fmtBytes(1536), '1.5 KB');
assert.equal(en.fmtBytes(33 * 1024 * 1024), '33.0 MB');

// Downloading with byte progress
const dl = en.describeUpdate({
  current: '0.4.216',
  latest: 'agent-v0.4.217',
  stage: 'downloading',
  update_available: true,
  downloaded_bytes: 16 * 1024 * 1024,
  total_bytes: 32 * 1024 * 1024,
});
assert.equal(dl.active, true);
assert.equal(dl.showProgress, true);
assert.equal(dl.indeterminate, false);
assert.equal(dl.pct, 50);
assert.match(dl.text, /16\.0 MB.*32\.0 MB.*50%/);
assert.equal(dl.showInstall, false);

// Pre-downloaded ready & deferred for user_active
const readyIdle = zh.describeUpdate({
  current: '0.4.216',
  latest: 'agent-v0.4.217',
  stage: 'ready',
  update_available: true,
  staged_ready: true,
  defer_reason: 'user_active',
});
assert.equal(readyIdle.active, false);
assert.equal(readyIdle.showBanner, true);
assert.equal(readyIdle.showInstall, true);
assert.equal(readyIdle.installLabelKey, 'ov.updates.installNow');
assert.match(readyIdle.bannerTitle, /0\.4\.217/);
assert.match(readyIdle.bannerSub, /空闲|锁屏/);

// Pre-downloaded ready & deferred for active_session
const readySess = en.describeUpdate({
  current: '0.4.216',
  latest: 'agent-v0.4.217',
  stage: 'ready',
  update_available: true,
  staged_ready: true,
  defer_reason: 'active_session',
});
assert.match(readySess.bannerSub, /active sessions/i);

// Restarting stays active + indeterminate bar
const rst = en.describeUpdate({
  current: '0.4.216',
  latest: 'agent-v0.4.217',
  stage: 'restarting',
  update_available: true,
});
assert.equal(rst.active, true);
assert.equal(rst.showProgress, true);
assert.equal(rst.indeterminate, true);

// Failure surfaces real error and enables retry button
const fail = zh.describeUpdate({
  current: '0.4.216',
  latest: 'agent-v0.4.217',
  stage: 'failed',
  update_available: true,
  message: 'signature mismatch',
});
assert.equal(fail.active, false);
assert.equal(fail.tone, 'error');
assert.equal(fail.showInstall, true);
assert.equal(fail.installLabelKey, 'ov.updates.retry');
assert.match(fail.text, /signature mismatch/);

// Up-to-date & succeeded
const ok = en.describeUpdate({
  current: '0.4.217',
  latest: 'agent-v0.4.217',
  stage: 'up_to_date',
});
assert.equal(ok.tone, 'ok');
assert.equal(ok.showBanner, false);
assert.equal(ok.showInstall, false);

const done = zh.describeUpdate({
  current: '0.4.217',
  latest: '0.4.217',
  stage: 'succeeded',
});
assert.equal(done.tone, 'ok');
assert.match(done.text, /0\.4\.217/);

console.log('updates: ok');
