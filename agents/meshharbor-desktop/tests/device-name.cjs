// Headless: no browser, Tauri window, daemon, OS input or private config.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');
const nodes = new Map();
function el(id) {
  if (!nodes.has(id)) nodes.set(id, { value: '', textContent: '', hidden: false,
    matches: () => false, addEventListener() {}, classList: { toggle() {} } });
  return nodes.get(id);
}
const realm = { window: { MeshHarbor: { $: el,
  setText: (id, value) => { el(id).textContent = value; }, show() {}, hide() {} } },
  document: { addEventListener() {}, querySelectorAll() { return []; } } };
const source = fs.readFileSync(path.join(__dirname, '../src/front/settings.js'), 'utf8');
assert(source.includes('  function paintStatus(s) {'));
vm.runInNewContext(source.replace('  function paintStatus(s) {',
  '  window.paintNameStatus = paintStatus;\n  function paintStatus(s) {'), realm);
const paint = value => realm.window.paintNameStatus({ device_name: 'server-name', ...value });
paint({ name_sync: { state: 'pending', proposed_name: 'offline-choice' } });
assert.equal(el('rename-input').value, 'offline-choice');
assert.match(el('rename-sync-state').textContent, /queued.*server-name/);
paint({ name_sync: { state: 'failed', proposed_name: 'offline-choice', error: 'name_revision_conflict' } });
assert.match(el('rename-sync-state').textContent, /name_revision_conflict/);
paint({ device_name: 'new-web-name', name_sync: { state: 'synced' } });
assert.equal(el('rename-input').value, 'new-web-name');
assert.match(el('rename-sync-state').textContent, /synchronized/);
el('rename-input').matches = () => true;
el('rename-input').value = 'unsent editing';
paint({ name_sync: { state: 'synced' } });
assert.equal(el('rename-input').value, 'unsent editing');
paint({ name_sync: null });
assert.match(el('rename-sync-state').textContent, /compatible daemon/);
paint({ name_sync: { state: 'unsupported', proposed_name: 'kept' } });
assert.match(el('rename-sync-state').textContent, /Server does not support/);
assert(!source.includes('Device name updated to'));
console.log('6 name UI states passed: pending, conflict, canonical refresh, focused input, legacy, unsupported server');
