'use strict';
/* Self-test: node --no-warnings test.js  — starts the server and checks auth, pairing, sync, paging, conflicts, audit protection, multi-tenancy, contract duration, permissions and admin portal. */
const assert = require('assert'), { spawn } = require('child_process'), fs = require('fs'), os = require('os'), path = require('path');
const PORT = 18920, ADMIN = 'adm-test', dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mxc-'));
const srv = spawn(process.execPath, ['--no-warnings', 'server.js'], { cwd: __dirname, env: { ...process.env, PORT, ADMIN_KEY: ADMIN, DATA_DIR: dir }, stdio: 'ignore' });
const call = async (p, o = {}) => {
  const r = await fetch('http://127.0.0.1:' + PORT + p, { ...o, headers: { 'content-type': 'application/json', ...(o.headers || {}) } });
  const text = await r.text();
  let j = {};
  try { j = JSON.parse(text); } catch (_) { j = { _raw: text }; }
  return { s: r.status, j };
};
const sleep = ms => new Promise(r => setTimeout(r, ms));
let n = 0;
const ok = m => { n++; console.log('ok ' + m); };

(async () => {
  try {
    for (let i = 0; i < 40; i++) {
      try { if ((await call('/health')).s === 200) break; } catch (e) { }
      await sleep(100);
    }
    const A = { authorization: 'Bearer ' + ADMIN };

    // 1. Wrong Admin Key rejected
    assert.strictEqual((await call('/admin/tenants', { headers: { authorization: 'Bearer x' } })).s, 401);

    // 2. Create Tenant with contract duration (365 days) and permissions
    const c = await call('/admin/tenants', {
      method: 'POST',
      headers: A,
      body: JSON.stringify({
        name: 'Shop',
        ownerName: 'Ali',
        phone: '01012345678',
        plan: 'standard',
        contractDurationDays: 365,
        maxDevices: 2,
        permissions: { pos: true, inventory: true, aiVoice: true }
      })
    });
    assert.strictEqual(c.s, 201);
    assert.ok(c.j.expiresAt);
    assert.strictEqual(c.j.maxDevices, 2);
    assert.strictEqual(c.j.permissions.pos, true);
    const H = { authorization: 'Bearer ' + c.j.key };
    ok('tenant created with contract duration and permissions, wrong admin key rejected');

    // 3. Sync needs business key & paired device
    assert.strictEqual((await call('/v1/sync', { method: 'POST', body: '{}' })).s, 401);
    assert.strictEqual((await call('/v1/sync', { method: 'POST', headers: H, body: '{}' })).s, 403);
    ok('sync needs a business key and a paired device');

    // 4. Device Pairing (PC & Phone)
    const pa = (await call('/v1/pair', { method: 'POST', headers: H, body: JSON.stringify({ name: 'PC' }) })).j;
    const pb = (await call('/v1/pair', { method: 'POST', headers: H, body: JSON.stringify({ name: 'Phone' }) })).j;
    assert.ok(pa.empty);
    assert.deepStrictEqual([pa.code, pb.code], ['A', 'B']);
    assert.ok(pa.subscription && pa.subscription.daysRemaining > 300);
    ok('devices paired, given codes (A, B) and subscription info returned');

    // 5. Max Devices limit check (maxDevices was set to 2)
    const pExceed = await call('/v1/pair', { method: 'POST', headers: H, body: JSON.stringify({ name: 'Tablet' }) });
    assert.strictEqual(pExceed.s, 403);
    assert.strictEqual(pExceed.j.error, 'max_devices_exceeded');
    ok('max devices limit strictly enforced by server');

    // 6. Tenant Info endpoint
    const tInfo = await call('/v1/tenant/info', { headers: H });
    assert.strictEqual(tInfo.s, 200);
    assert.strictEqual(tInfo.j.status, 'active');
    assert.strictEqual(tInfo.j.devicesCount, 2);
    ok('tenant info endpoint returns subscription status and linked devices');

    const sync = async (dev, since, changes) => (await call('/v1/sync', {
      method: 'POST',
      headers: { ...H, 'x-device': dev.device },
      body: JSON.stringify({ since, changes })
    })).j;
    const rec = (t, id, o, bs = 0) => ({ t, id, json: JSON.stringify(o), bs });

    // 7. 1200 records from A in three batches
    let r;
    for (let b = 0; b < 3; b++) {
      r = await sync(pa, 0, Array.from({ length: 400 }, (_, i) => rec('items', 'i' + (b * 400 + i), { id: 'i' + (b * 400 + i), name: 'x' })));
    }
    assert.strictEqual(r.applied.length, 400);
    ok('A pushed 1200 records');

    // 8. B pulls in pages
    let cur = 0, got = [];
    for (let g = 0; g < 10; g++) {
      const p = await sync(pb, cur, []);
      got.push(...p.changes);
      cur = p.cursor;
      if (!p.more) break;
    }
    assert.strictEqual(got.length, 1200);
    assert.strictEqual(new Set(got.map(x => x.id)).size, 1200);
    ok('B pulled all 1200 records in pages, none missed or duplicated');

    // 9. Conflict handling
    const i0 = got.find(x => x.id === 'i0');
    const a1 = await sync(pa, cur, [rec('items', 'i0', { id: 'i0', name: 'A edit' }, i0.seq)]);
    assert.strictEqual(a1.applied.length, 1);
    const seqA = a1.applied[0].seq;
    const b1 = await sync(pb, cur, [rec('items', 'i0', { id: 'i0', name: 'B edit' }, i0.seq)]);
    assert.strictEqual(b1.rejected.length, 1);
    assert.strictEqual(b1.rejected[0].reason, 'conflict');
    assert.strictEqual(JSON.parse(b1.rejected[0].server.json).name, 'A edit');
    ok('second concurrent edit of the same record is rejected and gets the winning version');

    // 10. Edit after winning version
    const b2 = await sync(pb, cur, [rec('items', 'i0', { id: 'i0', name: 'B edit' }, seqA)]);
    assert.strictEqual(b2.applied.length, 1);
    ok('after seeing the latest version, B can edit it');

    // 11. Idempotency on retry
    const retry = await sync(pa, 0, [rec('items', 'new1', { id: 'new1' })]);
    const retry2 = await sync(pa, 0, [rec('items', 'new1', { id: 'new1' })]);
    assert.strictEqual(retry2.applied.length, 1);
    assert.strictEqual(retry2.applied[0].seq, retry.applied[0].seq);
    ok('re-sending the same change after a network failure is harmless (idempotent)');

    // 12. Audit append-only protection
    const au = await sync(pa, 0, [rec('audit', 'a1', { id: 'a1', ev: 'inv_void' })]);
    assert.strictEqual(au.applied.length, 1);
    const au2 = await sync(pb, 0, [rec('audit', 'a1', { id: 'a1', ev: 'tampered' }, 1), { t: 'audit', id: 'a1', del: true, bs: 1 }]);
    assert.strictEqual(au2.rejected.length, 2);
    assert.ok(au2.rejected.every(x => x.reason === 'append_only'));
    ok('audit entries cannot be edited or deleted by any device');

    // 13. Deletions propagate
    const d = await sync(pa, 0, [{ t: 'items', id: 'new1', del: true, bs: retry.applied[0].seq }]);
    assert.strictEqual(d.applied.length, 1);
    const pull = await sync(pb, cur, []);
    assert.ok(pull.changes.some(x => x.id === 'new1' && x.del));
    ok('deletions propagate to other devices');

    // 14. Unknown tables rejected
    assert.strictEqual((await sync(pa, 0, [{ t: 'nope', id: 'x', json: '{}' }])).rejected[0].reason, 'bad_record');
    ok('unknown tables are rejected');

    // 15. Devices list
    const list = await call('/v1/devices', { headers: H });
    assert.strictEqual(list.j.length, 2);
    ok('device list available to the owner');

    // 16. Disabling tenant locks them out
    await call('/admin/tenants/' + c.j.id, { method: 'PATCH', headers: A, body: JSON.stringify({ enabled: false }) });
    assert.strictEqual((await call('/v1/pair', { method: 'POST', headers: H, body: '{}' })).s, 403);
    ok('a disabled business is locked out');

    // Reactivate tenant
    await call('/admin/tenants/' + c.j.id, { method: 'PATCH', headers: A, body: JSON.stringify({ enabled: true }) });

    // 17. Contract Expiration test: set expiresAt to yesterday
    const yesterday = new Date(Date.now() - 86400000).toISOString();
    await call('/admin/tenants/' + c.j.id, { method: 'PATCH', headers: A, body: JSON.stringify({ expiresAt: yesterday }) });
    const expSync = await call('/v1/sync', { method: 'POST', headers: { ...H, 'x-device': pa.device }, body: '{}' });
    assert.strictEqual(expSync.s, 403);
    assert.strictEqual(expSync.j.error, 'tenant_expired');
    ok('contract expiration locks out sync and pairing with tenant_expired error');

    // 18. Contract Renewal endpoint
    const renRes = await call('/admin/tenants/' + c.j.id + '/renew', { method: 'POST', headers: A, body: JSON.stringify({ days: 90 }) });
    assert.strictEqual(renRes.s, 200);
    assert.ok(renRes.j.daysRemaining >= 89);
    const renSync = await call('/v1/sync', { method: 'POST', headers: { ...H, 'x-device': pa.device }, body: '{}' });
    assert.strictEqual(renSync.s, 200);
    ok('contract renewal successfully restores sync access and extends contract duration');

    // 19. Public Self-Registration endpoint
    const regRes = await call('/v1/register', {
      method: 'POST',
      body: JSON.stringify({ name: 'Auto Parts Al-Wafaa', ownerName: 'Karim', phone: '01122334455', plan: 'trial', contractDays: 30 })
    });
    assert.strictEqual(regRes.s, 201);
    assert.ok(regRes.j.key && regRes.j.key.startsWith('mxc_'));
    ok('public self-registration successfully creates tenant with trial license');

    // 20. Admin Web Dashboard
    const dashRes = await call('/admin');
    assert.strictEqual(dashRes.s, 200);
    assert.ok(dashRes.j._raw.includes('لوحة تحكم خادم المنشآت'));
    ok('admin web dashboard HTML is served correctly');

    console.log(`\nALL ${n} CLOUD & TENANT TESTS PASSED`);
  } catch (e) {
    console.error('TEST FAILED:', e.message);
    process.exitCode = 1;
  }
  srv.kill();
})();
