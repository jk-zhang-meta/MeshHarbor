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

// 2. Router & HTML wiring present.
assert.ok(appSrc.includes("'gpu'"), 'app.js VIEWS must include gpu');
assert.ok(htmlSrc.includes('data-view="gpu"'), 'index.html nav must include GPU Servers link');
assert.ok(htmlSrc.includes('id="view-gpu"'), 'index.html must define #view-gpu section');
assert.ok(htmlSrc.includes('<script src="gpu.js"></script>'), 'index.html must load gpu.js');

// 3. UUID validation + shell-safe CUDA_VISIBLE_DEVICES export.
assert.strictEqual(gpuMod.isValidGpuUuid('GPU-1234-abcd_0:1.2'), true);
assert.strictEqual(gpuMod.isValidGpuUuid('GPU-1; rm -rf /'), false);
assert.strictEqual(gpuMod.isValidGpuUuid('GPU-1$(id)'), false);

const cmd = gpuMod.buildFreeExportCommand({
  gpus: [
    { uuid: 'GPU-aaa', state: 'free', lost: false },
    { uuid: 'GPU-bad;id', state: 'free', lost: false },
    { uuid: 'GPU-fault', state: 'free', ecc_uncorrected: 2 },
    { uuid: 'GPU-bbb', state: 'free', lost: false },
    { uuid: 'GPU-busy', state: 'busy', lost: false },
  ],
});
assert.strictEqual(cmd, "export CUDA_VISIBLE_DEVICES='GPU-aaa,GPU-bbb'");

// 4. Filter behavior covers fault, free, offline, and process user search.
const sampleHosts = [
  {
    agent_id: 'a1',
    name: 'gpu-box-01',
    is_online: true,
    freshness: 'fresh',
    free_count: 1,
    total_count: 2,
    gpus: [
      { idx: 0, name: 'RTX 4090', uuid: 'GPU-1', state: 'free', procs: [] },
      { idx: 1, name: 'RTX 4090', uuid: 'GPU-2', state: 'busy', procs: [{ pid: 10, user: 'alice', name: 'python3' }] },
    ],
  },
  {
    agent_id: 'a2',
    name: 'gpu-box-02',
    is_online: true,
    freshness: 'fresh',
    free_count: 0,
    total_count: 1,
    gpus: [{ idx: 0, name: 'H100', uuid: 'GPU-3', state: 'unknown', lost: true }],
  },
];
assert.strictEqual(gpuMod.filterHosts(sampleHosts, 'free', '').length, 1);
assert.strictEqual(gpuMod.filterHosts(sampleHosts, 'fault', '').length, 1);
assert.strictEqual(gpuMod.filterHosts(sampleHosts, 'all', 'alice').length, 1);
assert.strictEqual(gpuMod.filterHosts(sampleHosts, 'all', 'h100').length, 1);

console.log('gpu-view.cjs: all assertions passed');
