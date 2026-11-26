// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
'use strict';

const assert = require('assert');
const fs = require('fs');
const path = require('path');

const frontDir = path.join(__dirname, '../src/front');
const gpuSrc = fs.readFileSync(path.join(frontDir, 'gpu.js'), 'utf8');
const htmlSrc = fs.readFileSync(path.join(frontDir, 'index.html'), 'utf8');
const appSrc = fs.readFileSync(path.join(frontDir, 'app.js'), 'utf8');
const gpuMod = require(path.join(frontDir, 'gpu.js'));

// 1. Zero innerHTML / outerHTML / insertAdjacentHTML in gpu.js.
assert.ok(!/\.innerHTML\b/.test(gpuSrc), 'gpu.js must never use innerHTML');
assert.ok(!/\.outerHTML\b/.test(gpuSrc), 'gpu.js must never use outerHTML');
assert.ok(!/insertAdjacentHTML/.test(gpuSrc), 'gpu.js must never use insertAdjacentHTML');
assert.ok(gpuSrc.includes('waitMs:'), 'gpu.js must pass camelCase waitMs to cmd_gpu_fleet');
assert.ok(!gpuSrc.includes('wait_ms:'), 'gpu.js must not pass snake_case wait_ms to Tauri command');

// 2. Router & HTML wiring present.
assert.ok(appSrc.includes("'gpu'"), 'app.js VIEWS must include gpu');
assert.ok(htmlSrc.includes('data-view="gpu"'), 'index.html nav must include GPU Servers link');
assert.ok(htmlSrc.includes('id="view-gpu"'), 'index.html must define #view-gpu section');
assert.ok(htmlSrc.includes('<script src="gpu.js"></script>'), 'index.html must load gpu.js');

// 3. UUID validation + shell-safe CUDA / Ascend / TPU export.
assert.strictEqual(gpuMod.isValidGpuUuid('GPU-1234-abcd_0:1.2'), true);
assert.strictEqual(gpuMod.isValidGpuUuid('GPU-1; rm -rf /'), false);
assert.strictEqual(gpuMod.isValidGpuUuid('GPU-1$(id)'), false);

const cmd = gpuMod.buildFreeExportCommand({
  is_online: true,
  freshness: 'fresh',
  status: 'ok',
  gpus: [
    { uuid: 'GPU-aaa', state: 'free', lost: false },
    { uuid: 'GPU-bad;id', state: 'free', lost: false },
    { uuid: 'GPU-fault', state: 'free', ecc_uncorrected: 2 },
    { uuid: 'GPU-bbb', state: 'free', lost: false },
    { uuid: 'GPU-busy', state: 'busy', lost: false },
  ],
});
assert.strictEqual(cmd, "export CUDA_DEVICE_ORDER=PCI_BUS_ID CUDA_VISIBLE_DEVICES='GPU-aaa,GPU-bbb'");

// Ascend uses vendor_index (not renumbered display idx).
const npuCmd = gpuMod.buildFreeExportCommand({
  is_online: true,
  freshness: 'fresh',
  status: 'ok',
  backend: 'ascend',
  gpus: [
    { idx: 4, vendor_index: 0, uuid: 'ASCEND-0-deadbeef', state: 'free', lost: false },
    { idx: 5, vendor_index: 1, uuid: 'ASCEND-1-cafebabe', state: 'busy', lost: false },
    { idx: 6, vendor_index: 2, uuid: 'ASCEND-2-feedface', state: 'free', lost: false },
  ],
});
assert.strictEqual(npuCmd, "export ASCEND_RT_VISIBLE_DEVICES='0,2'");

// Stale / lagging hosts and TPU / PCI-only cards must NEVER produce a free export command.
assert.strictEqual(
  gpuMod.buildFreeExportCommand({
    is_online: true,
    freshness: 'stale',
    status: 'ok',
    gpus: [{ idx: 0, uuid: 'GPU-aaa', state: 'free' }],
  }),
  null,
);
assert.strictEqual(
  gpuMod.buildFreeExportCommand({
    is_online: true,
    freshness: 'fresh',
    lagging: true,
    status: 'ok',
    gpus: [{ idx: 0, uuid: 'GPU-aaa', state: 'free' }],
  }),
  null,
);
assert.strictEqual(
  gpuMod.buildFreeExportCommand({
    is_online: true,
    freshness: 'fresh',
    status: 'limited',
    backend: 'tpu',
    gpus: [{ idx: 0, uuid: 'TPU-0000:00:04.0', backend: 'tpu', state: 'free' }],
  }),
  null,
);

// 4. Canonical fault classification: power_cap is NEVER a fault; thermal is warning, not critical.
assert.strictEqual(gpuMod.cardHasFault({ throttle: ['power_cap'] }), false);
assert.strictEqual(gpuMod.cardHasWarning({ throttle: ['power_cap'] }), false);
assert.strictEqual(gpuMod.cardHasFault({ throttle: ['thermal'] }), false);
assert.strictEqual(gpuMod.cardHasWarning({ throttle: ['thermal'] }), true);
assert.strictEqual(gpuMod.cardHasFault({ xid_errors: [31] }), false);
assert.strictEqual(gpuMod.cardHasWarning({ xid_errors: [31] }), true);
assert.strictEqual(gpuMod.cardHasFault({ xid_errors: [79] }), true);
assert.strictEqual(gpuMod.cardHasFault({ remap_pending: true }), true);

// 5. Filter behavior covers host-level faults (driver_missing), warnings, free, offline, and search.
const sampleHosts = [
  {
    agent_id: 'a1',
    name: 'gpu-box-01',
    is_online: true,
    freshness: 'fresh',
    status: 'ok',
    free_count: 1,
    total_count: 2,
    gpus: [
      { idx: 0, name: 'RTX 4090', uuid: 'GPU-1', state: 'free', procs: [] },
      { idx: 1, name: 'RTX 4090', uuid: 'GPU-2', state: 'busy', throttle: ['thermal'], procs: [{ pid: 10, user: 'alice', name: 'python3' }] },
    ],
  },
  {
    agent_id: 'a2',
    name: 'gpu-box-02',
    is_online: true,
    freshness: 'fresh',
    status: 'ok',
    free_count: 0,
    total_count: 1,
    gpus: [{ idx: 0, name: 'H100', uuid: 'GPU-3', state: 'unknown', lost: true }],
  },
  {
    agent_id: 'a3',
    name: 'gpu-box-03',
    is_online: true,
    freshness: 'fresh',
    status: 'driver_missing',
    host_fault_severity: 'critical',
    status_detail: 'Detected 2 NVIDIA GPUs via PCIe without driver',
    free_count: 0,
    total_count: 2,
    gpus: [],
  },
];
assert.strictEqual(gpuMod.filterHosts(sampleHosts, 'free', '').length, 1);
assert.strictEqual(gpuMod.filterHosts(sampleHosts, 'fault', '').length, 2, 'fault filter must include both card faults and driver_missing hosts');
assert.strictEqual(gpuMod.filterHosts(sampleHosts, 'warning', '').length, 1);
assert.strictEqual(gpuMod.filterHosts(sampleHosts, 'all', 'alice').length, 1);
assert.strictEqual(gpuMod.filterHosts(sampleHosts, 'all', 'h100').length, 1);
assert.strictEqual(gpuMod.filterHosts(sampleHosts, 'all', 'driver_missing').length, 1);

console.log('gpu-view.cjs: all assertions passed');
