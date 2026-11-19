// Headless: no browser, Tauri window, daemon, OS input or private config.
// What the Devices page says after Connect, by what `cmd_open_remote` answered
// (`WebSurface` in commands.rs, spelled snake_case).
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');

const realm = {
  window: {
    MeshHarbor: {
      $: () => null,
      invoke: async () => ({}),
      show() {},
      hide() {},
      fmtRelative: () => '',
      on() {},
      get: () => null,
      currentView: () => 'overview',
    },
    addEventListener() {},
  },
  document: {
    addEventListener() {},
    querySelectorAll: () => [],
    visibilityState: 'hidden',
  },
  navigator: {},
  setTimeout,
  clearTimeout,
};

const source = fs.readFileSync(path.join(__dirname, '../src/front/devices.js'), 'utf8');
vm.runInNewContext(source, realm);
const { viewerNoteFor } = realm.window.MeshHarborDevices;

// A window of its own needs no explanation, on any platform.
assert.equal(viewerNoteFor('window'), null);
assert.equal(viewerNoteFor('app_window'), null);
// An older companion backend answered nothing at all.
assert.equal(viewerNoteFor(undefined), null);
assert.equal(viewerNoteFor(null), null);

// A browser tab says so, and names what would give the window.
const note = viewerNoteFor('browser_tab');
assert.match(note, /default browser/);
for (const name of ['Chrome', 'Edge', 'Chromium', 'Brave']) assert.ok(note.includes(name), name);

// The page reads the note it was given, and the handler shows it.
assert.ok(source.includes("await invoke('cmd_open_remote'"));
assert.ok(source.includes('st.viewerNote = viewerNoteFor(where);'));
console.log('devices-viewer-note: ok');
