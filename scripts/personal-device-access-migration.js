// SPDX-License-Identifier: AGPL-3.0-only
// mongosh input. The caller supplies ACTION, SPEC, and (except snapshot) SNAPSHOT.
// Rehearse against an isolated DB first. Apply/rollback require the application
// to be stopped: the invitation check and agent update span two collections.
// No tokens, machine IDs, connection endpoints or unrelated fields are copied.
(() => {
  'use strict';
  const assert = (ok, why) => { if (!ok) throw new Error(why); };
  assert(['snapshot', 'apply', 'verify', 'rollback'].includes(ACTION), 'invalid action');
  assert(SPEC && SPEC.database && SPEC.owner_id && SPEC.tenant_id, 'missing exact scope');
  assert(Array.isArray(SPEC.agent_ids) && SPEC.agent_ids.length > 0, 'explicit agent IDs required');
  assert(new Set(SPEC.agent_ids).size === SPEC.agent_ids.length, 'duplicate agent ID');
  const d = db.getSiblingDB(SPEC.database);
  const owner = ObjectId(SPEC.owner_id), tenant = ObjectId(SPEC.tenant_id);
  const ids = SPEC.agent_ids.map(x => ObjectId(x));
  const fields = ['personal_access_owner_id', 'ssh_policy', 'exec_policy'];
  const own = (row, key) => Object.prototype.hasOwnProperty.call(row, key);
  const encode = value => EJSON.stringify(value, null, 0, {relaxed: false});
  const clone = value => EJSON.parse(encode(value), {relaxed: false});
  const projection = {_id: 1, tenant_id: 1, owner_user_id: 1, deleted_at: 1, ephemeral: 1};
  fields.forEach(key => { projection[key] = 1; });
  const identity = id => ({_id: id, tenant_id: tenant, owner_user_id: owner,
    deleted_at: null, ephemeral: {$ne: true}});
  const invitationCount = () => d.device_invites.countDocuments({
    agent_id: {$in: ids}, $or: [{state: {$in: ['enrolled', 'redeemed']}}, {removal_pending: true}]
  });
  const scoped = () => {
    assert(invitationCount() === 0, 'invited or removal-pending device in personal scope');
    const rows = ids.map(id => d.agents.findOne(identity(id), projection));
    assert(rows.every(Boolean), 'missing, deleted, ephemeral, or wrong-owner device');
    return rows;
  };
  if (ACTION === 'snapshot') {
    print(encode({schema: 1, spec: SPEC, records: scoped()}));
    return;
  }
  assert(SNAPSHOT && Number(SNAPSHOT.schema) === 1 && encode(SNAPSHOT.spec) === encode(SPEC), 'snapshot scope mismatch');
  const before = SNAPSHOT.records;
  assert(before.length === ids.length, 'snapshot count mismatch');
  before.forEach((row, i) => {
    assert(row._id.equals(ids[i]) && row.tenant_id.equals(tenant) && row.owner_user_id.equals(owner), 'snapshot identity mismatch');
    assert(!row.deleted_at && row.ephemeral !== true, 'snapshot contains ineligible device');
  });
  const desired = row => ({
    personal_access_owner_id: owner,
    ssh_policy: {...clone(row.ssh_policy || {}), mode: 'on', can_originate: true,
      allowed_user_ids: [owner], allowed_role_ids: [], consent_mode: 'auto'},
    exec_policy: {...clone(row.exec_policy || {}), mode: 'on', can_originate: true,
      allowed_user_ids: [owner], allowed_role_ids: [], consent_mode: 'auto'},
  });
  const expectedFilter = (id, row) => {
    const f = identity(id);
    for (const key of fields) f[key] = own(row, key) ? {$eq: row[key], $exists: true} : {$exists: false};
    return f;
  };
  if (ACTION === 'verify') {
    scoped();
    before.forEach(row => assert(d.agents.countDocuments(expectedFilter(row._id, desired(row))) === 1, 'modified profile mismatch'));
    print(JSON.stringify({action: ACTION, database: SPEC.database, count: before.length, result: 'verified'}));
    return;
  }
  assert(typeof QUIESCED !== 'undefined' && QUIESCED === true, 'application must be verifiably quiesced before mutation');
  scoped();
  // Preflight EVERY row before the first write. Per-document CAS prevents a
  // stale snapshot from overwriting changes even if the operator missed a writer.
  before.forEach(row => {
    const pristine = d.agents.countDocuments(expectedFilter(row._id, row)) === 1;
    const modified = d.agents.countDocuments(expectedFilter(row._id, desired(row))) === 1;
    assert(ACTION === 'apply' ? pristine : pristine || modified, 'profile drift: no changes applied');
  });
  let changed = 0;
  for (const row of before) {
    // A failed apply may have changed only a prefix. Recovery accepts already
    // pristine rows, but never overwrites an unrelated third state.
    if (ACTION === 'rollback' && d.agents.countDocuments(expectedFilter(row._id, row)) === 1) continue;
    const next = ACTION === 'apply' ? desired(row) : row;
    const set = {}, unset = {};
    for (const key of fields) {
      if (own(next, key)) set[key] = next[key];
      else unset[key] = '';
    }
    const update = {};
    if (Object.keys(set).length) update.$set = set;
    if (Object.keys(unset).length) update.$unset = unset;
    const r = d.agents.updateOne(expectedFilter(row._id, ACTION === 'apply' ? row : desired(row)), update);
    assert(r.matchedCount === 1, `concurrent change after ${changed} writes; preserve snapshot and inspect before recovery`);
    changed++;
  }
  before.forEach(row => assert(d.agents.countDocuments(expectedFilter(row._id,
    ACTION === 'apply' ? desired(row) : row)) === 1, 'post-write verification failed'));
  print(JSON.stringify({action: ACTION, database: SPEC.database, count: changed, result: 'verified'}));
})();
