// Headless unit test for meshharbor-desktop location deduplication & logical zone badge formatting.
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

const { dedupeLocationParts, formatDeviceLocation, formatDeviceZone } =
  realm.window.MeshHarborDevices;

assert.equal(dedupeLocationParts(['中国', '广东省', '深圳市']).join(' · '), '中国 · 广东省 · 深圳市');
assert.equal(dedupeLocationParts(['新加坡', '新加坡', '新加坡']).join(' · '), '新加坡');
assert.equal(dedupeLocationParts(['中国香港', '香港', '香港']).join(' · '), '中国香港');
assert.equal(dedupeLocationParts(['中国', '北京', '北京市']).join(' · '), '中国 · 北京市');
assert.equal(dedupeLocationParts(['中国', '吉林省', '吉林市']).join(' · '), '中国 · 吉林省 · 吉林市');

const sz = formatDeviceLocation({
  public_ip: '203.0.113.45',
  country_code: 'cn',
  country: '中国',
  region: '广东省',
  city: '深圳市',
});
assert.deepEqual(JSON.parse(JSON.stringify(sz)), {
  locationText: '中国 · 广东省 · 深圳市',
  countryCode: 'CN',
  publicIp: '203.0.113.45',
  physicalIp: '',
  physicalSeenAt: '',
  defaultRouteVpn: false,
  hasAny: true,
});

const vpnPhysical = formatDeviceLocation({
  public_ip: '198.51.100.20',
  physical_public_ip: '203.0.113.45',
  physical_seen_at: '2026-11-24T12:00:00Z',
  default_route_vpn: true,
  country_code: 'CN',
  country: '中国',
  region: '广东省',
  city: '深圳市',
});
assert.deepEqual(JSON.parse(JSON.stringify(vpnPhysical)), {
  locationText: '中国 · 广东省 · 深圳市',
  countryCode: 'CN',
  publicIp: '198.51.100.20',
  physicalIp: '203.0.113.45',
  physicalSeenAt: '2026-11-24T12:00:00Z',
  defaultRouteVpn: true,
  hasAny: true,
});

const empty = formatDeviceLocation({ public_ip: null, country: null });
assert.deepEqual(JSON.parse(JSON.stringify(empty)), {
  locationText: '',
  countryCode: '',
  publicIp: '',
  physicalIp: '',
  physicalSeenAt: '',
  defaultRouteVpn: false,
  hasAny: false,
});

const autoZone = formatDeviceZone({
  pinned_zone_id: null,
  effective_zone_id: 'non-cn',
  effective_zone_name: '非 CN 区',
});
assert.deepEqual(JSON.parse(JSON.stringify(autoZone)), {
  zoneId: 'non-cn',
  zoneLabel: '非 CN 区',
  badgeText: '非 CN 区',
  pinned: false,
  hasZone: true,
  zoneSource: '',
});

const vpnHeldZone = formatDeviceZone({
  pinned_zone_id: null,
  effective_zone_id: 'cn',
  effective_zone_name: 'CN 区',
  zone_source: 'auto_vpn_held',
});
assert.deepEqual(JSON.parse(JSON.stringify(vpnHeldZone)), {
  zoneId: 'cn',
  zoneLabel: 'CN 区',
  badgeText: 'CN 区',
  pinned: false,
  hasZone: true,
  zoneSource: 'auto_vpn_held',
});

const pinnedZone = formatDeviceZone({
  pinned_zone_id: 'cn',
  effective_zone_id: 'cn',
  effective_zone_name: 'CN 区',
});
assert.deepEqual(JSON.parse(JSON.stringify(pinnedZone)), {
  zoneId: 'cn',
  zoneLabel: 'CN 区',
  badgeText: 'CN 区',
  pinned: true,
  hasZone: true,
  zoneSource: '',
});

const noZone = formatDeviceZone({
  pinned_zone_id: null,
  effective_zone_id: null,
  effective_zone_name: null,
});
assert.deepEqual(JSON.parse(JSON.stringify(noZone)), {
  zoneId: '',
  zoneLabel: '',
  badgeText: '',
  pinned: false,
  hasZone: false,
  zoneSource: '',
});

console.log('desktop devices-geo checks passed');
