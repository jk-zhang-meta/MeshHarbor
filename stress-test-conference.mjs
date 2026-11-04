#!/usr/bin/env node
/**
 * Conference stress test — measures max participants on current hardware.
 *
 * Flow per participant:
 *   1. Register user (REST)
 *   2. Add as tenant member (direct MongoDB — no invite API yet)
 *   3. Join conference (REST)
 *   4. Connect WebSocket
 *   5. Send media:join → receive router_capabilities + transport_created
 *   6. Send media:connect_transport (send + recv)
 *
 * Ramps up in batches, measuring latency and failures at each level.
 * Stops when failure rate exceeds threshold or hard limit reached.
 */
import WebSocket from 'ws';
import { MongoClient, ObjectId } from 'mongodb';
import { execSync } from 'child_process';
import { writeFileSync } from 'fs';

const API = process.env.API_URL || 'http://localhost:5001';
const WS_BASE = process.env.WS_URL || 'ws://localhost:5001/ws';
const MONGO_URL = process.env.MONGO_URL || 'mongodb://localhost:27019';
const DB_NAME = process.env.DB_NAME || 'roomler-ai';
const RESULTS_FILE = process.env.RESULTS_FILE || `${process.env.HOME ?? '.'}/roomler-ai/stress-test-results.txt`;

// Tuning
const BATCH_SIZE = 10;
const MAX_PARTICIPANTS = 500;
const SIGNALING_TIMEOUT_MS = 15000;
const FAILURE_RATE_THRESHOLD = 0.3;
const SETTLE_MS = 500;

let mongo;
let db;

// ─── Helpers ──────────────────────────────────────────────────────────────────

async function api(method, path, token, body) {
  const headers = { 'Content-Type': 'application/json' };
  if (token) headers['Authorization'] = `Bearer ${token}`;
  const opts = { method, headers };
  if (body) opts.body = JSON.stringify(body);
  const resp = await fetch(`${API}${path}`, opts);
  if (!resp.ok) {
    const text = await resp.text();
    throw new Error(`${method} ${path} ${resp.status}: ${text.slice(0, 200)}`);
  }
  return resp.json();
}

async function addTenantMember(tenantIdStr, userIdStr) {
  const tenantOid = ObjectId.createFromHexString(tenantIdStr);
  const userOid = ObjectId.createFromHexString(userIdStr);

  // Find the "member" role for this tenant
  const role = await db.collection('roles').findOne({
    tenant_id: tenantOid,
    name: 'member',
  });
  if (!role) throw new Error(`Member role not found for tenant ${tenantIdStr}`);

  const now = new Date();
  await db.collection('tenant_members').insertOne({
    tenant_id: tenantOid,
    user_id: userOid,
    nickname: null,
    role_ids: [role._id],
    joined_at: now,
    is_pending: false,
    is_muted: false,
    notification_override: null,
    invited_by: null,
    last_seen_at: null,
    created_at: now,
    updated_at: now,
  });
}

function waitForWsMessage(ws, type, timeoutMs = SIGNALING_TIMEOUT_MS) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      ws.removeListener('message', handler);
      reject(new Error(`Timeout waiting for ${type}`));
    }, timeoutMs);
    function handler(raw) {
      const msg = JSON.parse(raw.toString());
      if (msg.type === type) {
        clearTimeout(timer);
        ws.removeListener('message', handler);
        resolve(msg);
      }
    }
    ws.on('message', handler);
  });
}

function connectWs(token) {
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(`${WS_BASE}?token=${token}`);
    const timer = setTimeout(() => {
      ws.close();
      reject(new Error('WS connect timeout'));
    }, 10000);
    ws.on('open', () => {});
    ws.on('message', (raw) => {
      const msg = JSON.parse(raw.toString());
      if (msg.type === 'connected') {
        clearTimeout(timer);
        resolve(ws);
      }
    });
    ws.on('error', (err) => {
      clearTimeout(timer);
      reject(err);
    });
  });
}

function getSystemStats() {
  try {
    const memRaw = execSync("free -m | awk '/Mem:/ {print $2,$3,$4}'").toString().trim();
    const [total, used, free] = memRaw.split(' ').map(Number);

    let apiRssMb = 0;
    try {
      const pid = execSync("pgrep -x meshharbor-api").toString().trim().split('\n')[0];
      if (pid) {
        const rssKb = execSync(`ps -o rss= -p ${pid}`).toString().trim();
        apiRssMb = Math.round(parseInt(rssKb) / 1024);
      }
    } catch {}

    const loadAvg = execSync("cat /proc/loadavg").toString().trim().split(' ').slice(0, 3).join(' ');
    return { memTotal: total, memUsed: used, memFree: free, apiRssMb, loadAvg };
  } catch {
    return { memTotal: 0, memUsed: 0, memFree: 0, apiRssMb: 0, loadAvg: 'N/A' };
  }
}

// ─── Participant lifecycle ────────────────────────────────────────────────────

async function joinParticipant(index, tenantId, confId) {
  const t0 = Date.now();
  const phases = {};

  // 1. Register
  const username = `stress_${Date.now()}_${index}`;
  const user = await api('POST', '/api/auth/register', null, {
    username,
    email: `${username}@stress.test`,
    password: 'StressTest1234',
    display_name: `User ${index}`,
  });
  const token = user.access_token;
  const userId = user.user.id;
  phases.register = Date.now() - t0;

  // 2. Add as tenant member via MongoDB
  const t1 = Date.now();
  await addTenantMember(tenantId, userId);
  phases.addMember = Date.now() - t1;

  // 3. REST join conference
  const t2 = Date.now();
  await api('POST', `/api/tenant/${tenantId}/conference/${confId}/join`, token);
  phases.restJoin = Date.now() - t2;

  // 4. WS connect
  const t3 = Date.now();
  const ws = await connectWs(token);
  phases.wsConnect = Date.now() - t3;

  // 5. media:join signaling
  const t4 = Date.now();
  const capsPromise = waitForWsMessage(ws, 'media:router_capabilities');
  const transportPromise = waitForWsMessage(ws, 'media:transport_created');

  ws.send(JSON.stringify({ type: 'media:join', data: { conference_id: confId } }));

  const [, transportMsg] = await Promise.all([capsPromise, transportPromise]);
  phases.mediaJoin = Date.now() - t4;

  // 6. Connect both transports
  const t5 = Date.now();
  const fakeDtls = {
    role: 'client',
    fingerprints: [{
      algorithm: 'sha-256',
      value: 'AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99',
    }],
  };

  ws.send(JSON.stringify({
    type: 'media:connect_transport',
    data: {
      conference_id: confId,
      transport_id: transportMsg.data.send_transport.id,
      dtls_parameters: fakeDtls,
    },
  }));
  ws.send(JSON.stringify({
    type: 'media:connect_transport',
    data: {
      conference_id: confId,
      transport_id: transportMsg.data.recv_transport.id,
      dtls_parameters: fakeDtls,
    },
  }));
  await new Promise(r => setTimeout(r, 50));
  phases.connectTransport = Date.now() - t5;

  phases.total = Date.now() - t0;
  return { ws, token, phases, index };
}

// ─── Main ─────────────────────────────────────────────────────────────────────

async function main() {
  const lines = [];
  const log = (msg) => { console.log(msg); lines.push(msg); };

  // Connect to MongoDB
  mongo = new MongoClient(MONGO_URL);
  await mongo.connect();
  db = mongo.db(DB_NAME);

  log('╔══════════════════════════════════════════════════════════════╗');
  log('║       CONFERENCE STRESS TEST — Max Participants             ║');
  log('╚══════════════════════════════════════════════════════════════╝');
  log('');

  const sysStart = getSystemStats();
  log(`System: ${sysStart.memTotal}MB RAM, load: ${sysStart.loadAvg}`);
  log(`API RSS at start: ${sysStart.apiRssMb}MB`);
  log(`Config: batch=${BATCH_SIZE}, max=${MAX_PARTICIPANTS}, timeout=${SIGNALING_TIMEOUT_MS}ms`);
  log('');

  // Setup: create organizer, tenant, conference
  log('── Setup ──');
  const orgUser = `org_${Date.now()}`;
  const org = await api('POST', '/api/auth/register', null, {
    username: orgUser,
    email: `${orgUser}@stress.test`,
    password: 'StressTest1234',
    display_name: 'Organizer',
  });
  const orgToken = org.access_token;

  const tenant = await api('POST', '/api/tenant', orgToken, {
    name: 'Stress Org',
    slug: `stress-${Date.now()}`,
  });
  const tenantId = tenant.id;

  const conf = await api('POST', `/api/tenant/${tenantId}/conference`, orgToken, {
    subject: 'Stress Test Conference',
  });
  const confId = conf.id;

  const startResp = await api('POST', `/api/tenant/${tenantId}/conference/${confId}/start`, orgToken);
  log(`Conference: ${confId} (codecs: ${startResp.rtp_capabilities?.codecs?.length})`);
  log('');

  // Organizer joins
  await api('POST', `/api/tenant/${tenantId}/conference/${confId}/join`, orgToken);
  const orgWs = await connectWs(orgToken);
  const capP = waitForWsMessage(orgWs, 'media:router_capabilities');
  const tpP = waitForWsMessage(orgWs, 'media:transport_created');
  orgWs.send(JSON.stringify({ type: 'media:join', data: { conference_id: confId } }));
  await Promise.all([capP, tpP]);
  log('Organizer joined (participant #1)');

  const allWs = [orgWs];
  const batchResults = [];

  let totalJoined = 1;
  let totalFailed = 0;
  let stopped = false;
  let stopReason = '';

  log('');
  log('── Ramping up participants ──');
  log('');
  log('Batch | Joined | Failed | Avg(ms) | P50(ms) | P95(ms) | RSS(MB) | Load');
  log('──────┼────────┼────────┼─────────┼─────────┼─────────┼─────────┼─────────');

  for (let batch = 0; !stopped && totalJoined < MAX_PARTICIPANTS; batch++) {
    const count = Math.min(BATCH_SIZE, MAX_PARTICIPANTS - totalJoined);
    const batchPromises = [];

    for (let i = 0; i < count; i++) {
      const idx = totalJoined + i + 1;
      batchPromises.push(
        joinParticipant(idx, tenantId, confId)
          .then((result) => ({ ok: true, ...result }))
          .catch((err) => ({ ok: false, error: err.message, index: totalJoined + i + 1 }))
      );
    }

    const results = await Promise.all(batchPromises);
    const succeeded = results.filter(r => r.ok);
    const failed = results.filter(r => !r.ok);

    for (const r of succeeded) allWs.push(r.ws);

    totalJoined += succeeded.length;
    totalFailed += failed.length;

    const joinTimes = succeeded.map(r => r.phases.total).sort((a, b) => a - b);
    const avg = joinTimes.length ? Math.round(joinTimes.reduce((a, b) => a + b, 0) / joinTimes.length) : 0;
    const p50 = joinTimes.length ? joinTimes[Math.floor(joinTimes.length * 0.5)] : 0;
    const p95 = joinTimes.length ? joinTimes[Math.floor(joinTimes.length * 0.95)] : 0;

    const sys = getSystemStats();

    log(`  ${String(batch + 1).padStart(3)}  |  ${String(succeeded.length).padStart(4)}  |  ${String(failed.length).padStart(4)}  | ${String(avg).padStart(7)} | ${String(p50).padStart(7)} | ${String(p95).padStart(7)} | ${String(sys.apiRssMb).padStart(7)} | ${sys.loadAvg}`);

    batchResults.push({
      batch: batch + 1,
      succeeded: succeeded.length,
      failed: failed.length,
      totalJoined,
      avgMs: avg,
      p50Ms: p50,
      p95Ms: p95,
      apiRssMb: sys.apiRssMb,
      loadAvg: sys.loadAvg,
      failErrors: failed.map(f => f.error),
    });

    if (failed.length > 0) {
      const unique = [...new Set(failed.map(f => f.error.split(':')[0]))];
      log(`       └─ errors: ${unique.join(', ')}`);
    }

    const failureRate = failed.length / count;
    if (failureRate > FAILURE_RATE_THRESHOLD) {
      stopped = true;
      stopReason = `Failure rate ${(failureRate * 100).toFixed(0)}% exceeded ${(FAILURE_RATE_THRESHOLD * 100).toFixed(0)}% threshold`;
    }
    if (totalJoined >= MAX_PARTICIPANTS) {
      stopped = true;
      stopReason = `Reached max participants limit (${MAX_PARTICIPANTS})`;
    }

    if (!stopped) await new Promise(r => setTimeout(r, SETTLE_MS));
  }

  // ── Final report ──
  const sysEnd = getSystemStats();
  log('');
  log('════════════════════════════════════════════════════════════════');
  log('                        RESULTS');
  log('════════════════════════════════════════════════════════════════');
  log('');
  log(`  Max participants joined:    ${totalJoined}`);
  log(`  Total failed:               ${totalFailed}`);
  log(`  Stop reason:                ${stopReason}`);
  log('');
  log(`  API RSS (start → end):      ${sysStart.apiRssMb}MB → ${sysEnd.apiRssMb}MB (+${sysEnd.apiRssMb - sysStart.apiRssMb}MB)`);
  log(`  System load:                ${sysEnd.loadAvg}`);
  log(`  System memory:              ${sysEnd.memUsed}/${sysEnd.memTotal}MB used`);

  const lastGood = batchResults.filter(b => b.succeeded > 0).pop();
  if (lastGood) {
    log('');
    log(`  Last successful batch (#${lastGood.batch}):`);
    log(`    Avg join time:  ${lastGood.avgMs}ms`);
    log(`    P50:            ${lastGood.p50Ms}ms`);
    log(`    P95:            ${lastGood.p95Ms}ms`);
  }

  log('');
  log('── Latency trend ──');
  log('');
  log('  Total | Avg(ms) | P95(ms) | RSS(MB)');
  log('  ──────┼─────────┼─────────┼────────');
  let running = 1;
  for (const b of batchResults) {
    running += b.succeeded;
    log(`  ${String(running).padStart(5)} | ${String(b.avgMs).padStart(7)} | ${String(b.p95Ms).padStart(7)} | ${String(b.apiRssMb).padStart(7)}`);
  }

  // Cleanup
  log('');
  log('Cleaning up...');
  const closePromises = allWs.map(ws => new Promise(r => {
    ws.on('close', r);
    ws.close();
  }));
  await Promise.race([
    Promise.all(closePromises),
    new Promise(r => setTimeout(r, 5000)),
  ]);
  await mongo.close();
  log('Done.');

  writeFileSync(RESULTS_FILE, lines.join('\n') + '\n');
  log(`\nResults written to: ${RESULTS_FILE}`);
}

main().catch((err) => {
  console.error('Stress test crashed:', err);
  if (mongo) mongo.close().catch(() => {});
  process.exit(1);
});
