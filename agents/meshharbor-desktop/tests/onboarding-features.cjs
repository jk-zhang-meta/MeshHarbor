// SPDX-License-Identifier: MPL-2.0
// No browser or desktop interaction: exercise the real native picker with a tiny DOM.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');
class Element {
  constructor(tag) { this.tag = tag; this.children = []; this.style = {}; this.events = {}; }
  append(...children) { this.children.push(...children); }
  appendChild(child) { this.append(child); }
  addEventListener(name, callback) { this.events[name] = callback; }
}
const context = { window: { MeshHarbor: {} }, document: {
  createElement: tag => new Element(tag), createTextNode: text => ({ text }),
  addEventListener() {},
}};
// Expose only the existing closure-private picker in the isolated test realm.
const source = fs.readFileSync(path.join(__dirname, '../src/front/onboarding.js'), 'utf8');
assert(source.includes('  async function refreshInvitations()'));
vm.runInNewContext(source.replace('  async function refreshInvitations()',
  '  window.testPicker = featurePicker;\n  async function refreshInvitations()'), context);
function picker(initial) {
  const parent = new Element('div');
  const selected = context.window.testPicker(parent, initial);
  const inputs = parent.children[0].children.slice(1).map(row => row.children[0]);
  return { selected, inputs };
}
const fresh = picker(null);
assert.equal(fresh.selected(), 'desktop_view,desktop_control,clipboard,files,ssh,exec,rdp,network');
fresh.inputs[0].checked = false;
fresh.inputs[0].events.change();
assert.equal(fresh.selected(), 'files,ssh,exec,rdp,network');
assert(fresh.inputs[1].disabled && fresh.inputs[2].disabled);
assert.equal(picker({}).selected(), 'none', 'legacy unknown scope must never default all');
assert.equal(picker({ ssh: true }).selected(), 'ssh', 'existing selection is exact');
console.log('native invitation picker: defaults, exact legacy scope, and dependent permissions passed');
