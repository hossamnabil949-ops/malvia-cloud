'use strict';
/* MALVIA Nexus — Cloud sync server with Multi-Tenancy, Contract Duration & Permissions Control.
   One SQLite database file PER BUSINESS (tenant): complete isolation, trivial per-customer backup/export.
   Sync = record-level with a global sequence number (seq) per tenant:
     - devices push the records they changed, with the seq they last saw ("bs");
     - the server accepts a change only if nobody changed that record since (else it returns the server's version);
     - append-only data (audit) can never be changed or deleted;
     - devices pull everything newer than their cursor.
   Driver: better-sqlite3 with automatic fallback to node:sqlite on Node >= 22. */
const http = require('http'), fs = require('fs'), path = require('path'), crypto = require('crypto');

const env = (k, d) => (process.env[k] !== undefined && process.env[k] !== '' ? process.env[k] : d);
const CFG = {
  port: +env('PORT', 8788),
  adminKey: env('ADMIN_KEY', ''),
  dataDir: env('DATA_DIR', path.join(__dirname, 'data')),
  origins: env('ALLOWED_ORIGINS', '').split(',').map(s => s.trim()).filter(Boolean),
  pageSize: 500,
  maxChanges: 500,
  maxRec: 2 * 1024 * 1024
};

const TABLES = new Set(['items', 'invoices', 'purchases', 'customers', 'vendors', 'users', 'partners', 'expenses', 'distributions', 'audit', 'collections', 'vpayments', 'pmoves', 'adjustments', 'kv']);
const APPEND_ONLY = new Set(['audit']);

const DEFAULT_PERMISSIONS = {
  pos: true,          // نقاط البيع POS
  inventory: true,    // إدارة المخازن والأصناف
  purchases: true,    // فواتير المشتريات
  suppliers: true,    // الموردين وحساباتهم
  customers: true,    // العملاء وحساباتهم
  finance: true,      // الخزينة والأرباح والمصروفات
  reports: true,      // التقارير والحركات المالية
  aiVoice: true,      // المساعد الصوتي الذكي
  multiDevice: true   // دعم تعدد الأجهزة
};

fs.mkdirSync(path.join(CFG.dataDir, 'tenants'), { recursive: true });
const sha = s => crypto.createHash('sha256').update(s).digest('hex');
const eqSafe = (a, b) => {
  if (!a || !b) return false;
  const A = Buffer.from(String(a)), B = Buffer.from(String(b));
  return A.length === B.length && crypto.timingSafeEqual(A, B);
};

function openDriver(file) {
  try {
    const B = require('better-sqlite3');
    const db = new B(file);
    return { kind: 'better-sqlite3', exec: s => db.exec(s), prepare: s => db.prepare(s), close: () => db.close() };
  } catch (e) { /* fall back */ }
  const { DatabaseSync } = require('node:sqlite');
  const db = new DatabaseSync(file);
  return { kind: 'node:sqlite', exec: s => db.exec(s), prepare: s => db.prepare(s), close: () => db.close() };
}

/* ---------- registry of tenants (JSON file) ---------- */
const REG = path.join(CFG.dataDir, 'tenants.json');
let reg = { tenants: [] };
try { reg = JSON.parse(fs.readFileSync(REG, 'utf8')); } catch (e) { /* first run */ }
const saveReg = () => {
  fs.writeFileSync(REG + '.tmp', JSON.stringify(reg, null, 2));
  fs.renameSync(REG + '.tmp', REG);
};

/* ---------- per-tenant database ---------- */
const open = new Map();
function tdb(t) {
  if (open.has(t.id)) return open.get(t.id);
  const db = openDriver(path.join(CFG.dataDir, 'tenants', t.id + '.db'));
  db.exec('PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;');
  db.exec('CREATE TABLE IF NOT EXISTS recs (tbl TEXT NOT NULL, id TEXT NOT NULL, json TEXT NOT NULL, seq INTEGER NOT NULL, del INTEGER NOT NULL DEFAULT 0, dev TEXT, ts TEXT NOT NULL, PRIMARY KEY(tbl,id));');
  db.exec('CREATE INDEX IF NOT EXISTS recs_seq ON recs(seq);');
  db.exec('CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT NOT NULL);');
  db.exec('CREATE TABLE IF NOT EXISTS devices (id TEXT PRIMARY KEY, name TEXT, code TEXT NOT NULL, created TEXT NOT NULL, last_seen TEXT);');
  db.exec("INSERT OR IGNORE INTO meta(k,v) VALUES('seq','0');");
  db.exec("CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON recs WHEN OLD.tbl='audit' BEGIN SELECT RAISE(ABORT,'audit is append-only'); END;");
  db.exec("CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON recs WHEN OLD.tbl='audit' BEGIN SELECT RAISE(ABORT,'audit is append-only'); END;");
  open.set(t.id, db);
  return db;
}
const curSeq = db => +db.prepare("SELECT v FROM meta WHERE k='seq'").get().v;

/* ---------- tenant contract & subscription evaluation ---------- */
function evaluateTenant(t) {
  if (!t) return { valid: false, error: 'unauthorized', code: 401 };
  if (!t.enabled) {
    return {
      valid: false,
      error: 'tenant_disabled',
      code: 403,
      message: 'تم إيقاف هذه المنشأة من قبل الإدارة. يرجى التواصل مع إدارة النظام.'
    };
  }

  const now = Date.now();
  const exp = t.expiresAt ? new Date(t.expiresAt).getTime() : Infinity;
  const isExpired = now > exp;
  const daysRemaining = t.expiresAt ? Math.max(0, Math.ceil((exp - now) / 86400000)) : 9999;

  if (isExpired) {
    return {
      valid: false,
      error: 'tenant_expired',
      code: 403,
      message: 'انتهت مدة التعاقد / اشتراك المنشأة السحابي. يرجى التجديد للاستمرار بالمزامنة.',
      expiresAt: t.expiresAt,
      daysRemaining: 0
    };
  }

  return {
    valid: true,
    plan: t.plan || 'standard',
    status: 'active',
    expiresAt: t.expiresAt || null,
    daysRemaining,
    maxDevices: t.maxDevices || 10,
    permissions: t.permissions || DEFAULT_PERMISSIONS
  };
}

/* ---------- http helpers ---------- */
function cors(req, res) {
  const o = req.headers.origin;
  if (!CFG.origins.length) res.setHeader('Access-Control-Allow-Origin', '*');
  else if (o && CFG.origins.includes(o)) {
    res.setHeader('Access-Control-Allow-Origin', o);
    res.setHeader('Vary', 'Origin');
  }
  res.setHeader('Access-Control-Allow-Headers', 'authorization,content-type,x-device,x-admin-key');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PATCH,PUT,DELETE,OPTIONS');
}

const send = (res, c, o) => {
  res.writeHead(c, { 'content-type': 'application/json; charset=utf-8' });
  res.end(JSON.stringify(o));
};

const sendHtml = (res, c, html) => {
  res.writeHead(c, { 'content-type': 'text/html; charset=utf-8' });
  res.end(html);
};

const body = (req, lim = 8 * 1024 * 1024) => new Promise((ok, no) => {
  let n = 0;
  const c = [];
  req.on('data', d => {
    n += d.length;
    if (n > lim) {
      no(Object.assign(new Error('too_large'), { code: 413 }));
      req.destroy();
    } else c.push(d);
  });
  req.on('end', () => {
    try {
      ok(c.length ? JSON.parse(Buffer.concat(c).toString('utf8')) : {});
    } catch (e) {
      no(Object.assign(new Error('bad_json'), { code: 400 }));
    }
  });
  req.on('error', no);
});

const bearer = req => {
  const h = req.headers.authorization || '';
  return h.startsWith('Bearer ') ? h.slice(7).trim() : '';
};

const tenantOf = req => {
  const k = bearer(req);
  if (!k) return null;
  const h = sha(k);
  return reg.tenants.find(t => eqSafe(t.keyHash, h)) || null;
};

const isAdmin = req => {
  if (!CFG.adminKey) return false;
  const b = bearer(req) || String(req.headers['x-admin-key'] || '').trim();
  return eqSafe(b, CFG.adminKey);
};

const buckets = new Map();
const rateOk = (id, max) => {
  const now = Date.now(), w = (buckets.get(id) || []).filter(t => now - t < 60000);
  if (w.length >= max) { buckets.set(id, w); return false; }
  w.push(now);
  buckets.set(id, w);
  return true;
};

/* ---------- core: apply a batch of client changes, then return what is newer ---------- */
function sync(t, device, since, changes) {
  const db = tdb(t), now = new Date().toISOString();
  const applied = [], rejected = [], mine = new Set();
  db.exec('BEGIN IMMEDIATE');
  try {
    let seq = curSeq(db);
    const get = db.prepare('SELECT json, seq, del FROM recs WHERE tbl=? AND id=?');
    const up = db.prepare('INSERT INTO recs(tbl,id,json,seq,del,dev,ts) VALUES(?,?,?,?,?,?,?) ON CONFLICT(tbl,id) DO UPDATE SET json=excluded.json, seq=excluded.seq, del=excluded.del, dev=excluded.dev, ts=excluded.ts');
    for (const c of changes) {
      if (!c || !TABLES.has(c.t) || typeof c.id !== 'string' || !c.id || c.id.length > 200) {
        rejected.push({ t: c && c.t, id: c && c.id, reason: 'bad_record' });
        continue;
      }
      const isDel = !!c.del, json = isDel ? '' : String(c.json || '');
      if (!isDel && (json.length > CFG.maxRec || !json.startsWith('{') && !json.startsWith('['))) {
        rejected.push({ t: c.t, id: c.id, reason: 'bad_record' });
        continue;
      }
      const row = get.get(c.t, c.id), bs = +c.bs || 0;
      if (APPEND_ONLY.has(c.t) && row) {
        if (!isDel && row.json === json) {
          applied.push({ t: c.t, id: c.id, seq: row.seq });
          mine.add(c.t + '\u0000' + c.id);
        } else {
          rejected.push({ t: c.t, id: c.id, reason: 'append_only', server: { json: row.json, seq: row.seq, del: !!row.del } });
        }
        continue;
      }
      if (APPEND_ONLY.has(c.t) && isDel) {
        rejected.push({ t: c.t, id: c.id, reason: 'append_only' });
        continue;
      }
      if (row && row.seq > bs) {
        if (!isDel && !row.del && row.json === json) {
          applied.push({ t: c.t, id: c.id, seq: row.seq });
          mine.add(c.t + '\u0000' + c.id);
          continue;
        }
        rejected.push({ t: c.t, id: c.id, reason: 'conflict', server: { json: row.json, seq: row.seq, del: !!row.del } });
        continue;
      }
      seq++;
      up.run(c.t, c.id, json, seq, isDel ? 1 : 0, device.id, now);
      applied.push({ t: c.t, id: c.id, seq });
      mine.add(c.t + '\u0000' + c.id);
    }
    db.prepare("UPDATE meta SET v=? WHERE k='seq'").run(String(seq));
    db.prepare('UPDATE devices SET last_seen=? WHERE id=?').run(now, device.id);
    db.exec('COMMIT');
  } catch (e) {
    try { db.exec('ROLLBACK'); } catch (_) { /* ignore */ }
    throw e;
  }
  const rows = db.prepare('SELECT tbl, id, json, seq, del FROM recs WHERE seq>? ORDER BY seq ASC LIMIT ?').all(+since || 0, CFG.pageSize + 1);
  const more = rows.length > CFG.pageSize;
  const page = more ? rows.slice(0, CFG.pageSize) : rows;
  const out = page.filter(r => !mine.has(r.tbl + '\u0000' + r.id)).map(r => ({ t: r.tbl, id: r.id, json: r.json, seq: r.seq, del: !!r.del }));
  const cursor = more ? page[page.length - 1].seq : curSeq(db);
  return { applied, rejected, changes: out, cursor, more };
}

/* ---------- HTML Web Admin Portal ---------- */
function renderAdminHtml() {
  return `<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>لوحة تحكم خادم المنشآت | MALVIA Cloud Admin</title>
<link href="https://fonts.googleapis.com/css2?family=Cairo:wght@400;600;700;800&display=swap" rel="stylesheet">
<style>
:root {
  --bg: #0B1120; --card: #1E293B; --card2: #334155; --border: #334155;
  --text: #F8FAFC; --muted: #94A3B8; --primary: #38BDF8; --primary-dark: #0284C7;
  --success: #34D399; --warning: #FBBF24; --danger: #F87171;
}
* { box-sizing: border-box; margin: 0; padding: 0; font-family: 'Cairo', sans-serif; }
body { background: var(--bg); color: var(--text); padding: 24px; min-height: 100vh; }
.container { max-width: 1200px; margin: 0 auto; }
header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 24px; padding-bottom: 16px; border-bottom: 1px solid var(--border); }
.brand { display: flex; align-items: center; gap: 12px; }
.logo-badge { background: linear-gradient(135deg, var(--primary), var(--primary-dark)); width: 44px; height: 44px; border-radius: 12px; display: grid; place-items: center; font-weight: 800; font-size: 20px; color: #fff; }
h1 { font-size: 22px; font-weight: 800; }
.stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 16px; margin-bottom: 24px; }
.stat-card { background: var(--card); border: 1px solid var(--border); border-radius: 16px; padding: 20px; }
.stat-card .num { font-size: 32px; font-weight: 800; color: var(--primary); margin-top: 4px; }
.stat-card .lbl { color: var(--muted); font-size: 14px; font-weight: 600; }
.card { background: var(--card); border: 1px solid var(--border); border-radius: 16px; padding: 24px; margin-bottom: 24px; }
.card-hdr { display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px; }
.btn { display: inline-flex; align-items: center; gap: 8px; background: var(--primary); color: #0f172a; padding: 10px 18px; border-radius: 10px; font-weight: 700; border: none; cursor: pointer; transition: 0.2s; }
.btn:hover { background: #7dd3fc; }
.btn-sm { padding: 6px 12px; font-size: 13px; border-radius: 8px; }
.btn-sec { background: var(--card2); color: var(--text); }
.btn-sec:hover { background: #475569; }
.btn-danger { background: rgba(248,113,113,0.15); color: var(--danger); border: 1px solid rgba(248,113,113,0.3); }
.btn-danger:hover { background: rgba(248,113,113,0.3); }
.btn-success { background: rgba(52,211,153,0.15); color: var(--success); border: 1px solid rgba(52,211,153,0.3); }
.table-wrap { overflow-x: auto; }
table { width: 100%; border-collapse: collapse; text-align: right; }
th, td { padding: 14px 16px; border-bottom: 1px solid var(--border); font-size: 14px; }
th { color: var(--muted); font-weight: 700; background: rgba(15,23,42,0.4); }
tr:hover td { background: rgba(255,255,255,0.02); }
.badge { display: inline-flex; align-items: center; gap: 4px; padding: 4px 10px; border-radius: 99px; font-size: 12px; font-weight: 700; }
.badge-active { background: rgba(52,211,153,0.15); color: var(--success); }
.badge-expired { background: rgba(248,113,113,0.15); color: var(--danger); }
.badge-disabled { background: rgba(148,163,184,0.15); color: var(--muted); }
.modal-overlay { position: fixed; inset: 0; background: rgba(0,0,0,0.75); backdrop-filter: blur(4px); display: none; place-items: center; padding: 20px; z-index: 99; }
.modal { background: var(--card); border: 1px solid var(--border); border-radius: 20px; width: 100%; max-width: 580px; padding: 24px; max-height: 90vh; overflow-y: auto; }
.fld { margin-bottom: 16px; }
.fld label { display: block; font-size: 13px; font-weight: 700; color: var(--muted); margin-bottom: 6px; }
.fld input, .fld select, .fld textarea { width: 100%; background: #0f172a; border: 1px solid var(--border); border-radius: 10px; padding: 10px 14px; color: #fff; font-size: 14px; }
.grid-2 { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }
.perm-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 8px; margin-top: 8px; }
.perm-lbl { display: flex; align-items: center; gap: 8px; font-size: 13px; background: rgba(15,23,42,0.5); padding: 8px 12px; border-radius: 8px; cursor: pointer; }
.key-box { background: #0f172a; border: 1px dashed var(--primary); padding: 12px; border-radius: 10px; font-family: monospace; font-size: 13px; color: var(--primary); word-break: break-all; margin: 12px 0; }
</style>
</head>
<body>
<div class="container">
  <header>
    <div class="brand">
      <div class="logo-badge">M</div>
      <div>
        <h1>سحابة مالفيا — إدارة المنشآت والتعاقدات (Multi-Tenancy)</h1>
        <small style="color:var(--muted)">خادم المزامنة اللامركزي وإدارة التراخيص</small>
      </div>
    </div>
    <div style="display:flex; gap:10px; align-items:center;">
      <input type="password" id="adminKeyInput" placeholder="أدخل ADMIN_KEY" style="background:#0f172a; border:1px solid var(--border); border-radius:8px; padding:8px 12px; color:#fff; font-size:13px; width:180px;">
      <button class="btn btn-sm" onclick="saveKeyAndRefresh()">دخول</button>
      <button class="btn btn-sm btn-sec" onclick="openCreateModal()">+ منشأة جديدة</button>
    </div>
  </header>

  <div class="stats">
    <div class="stat-card">
      <div class="lbl">إجمالي المنشآت المسجلة</div>
      <div class="num" id="sTotal">0</div>
    </div>
    <div class="stat-card">
      <div class="lbl">المنشآت النشطة (سارية التعاقد)</div>
      <div class="num" id="sActive" style="color:var(--success)">0</div>
    </div>
    <div class="stat-card">
      <div class="lbl">المنشآت المنتهية أو الموقوفة</div>
      <div class="num" id="sExpired" style="color:var(--danger)">0</div>
    </div>
    <div class="stat-card">
      <div class="lbl">إجمالي الأجهزة المرتبطة</div>
      <div class="num" id="sDevices" style="color:var(--warning)">0</div>
    </div>
  </div>

  <div class="card">
    <div class="card-hdr">
      <h2>قائمة المنشآت (Tenants) والتراخيص</h2>
      <button class="btn btn-sm btn-sec" onclick="loadTenants()">تحديث البيانات</button>
    </div>
    <div class="table-wrap">
      <table>
        <thead>
          <tr>
            <th>المنشأة</th>
            <th>الخطة</th>
            <th>الحالة</th>
            <th>نهاية التعاقد</th>
            <th>الأيام المتبقية</th>
            <th>الأجهزة</th>
            <th>السجلات</th>
            <th>إجراءات الإدارة</th>
          </tr>
        </thead>
        <tbody id="tenantRows">
          <tr><td colspan="8" style="text-align:center; color:var(--muted); padding:30px;">جاري تحميل المنشآت...</td></tr>
        </tbody>
      </table>
    </div>
  </div>
</div>

<!-- Modal Create Tenant -->
<div class="modal-overlay" id="createModal">
  <div class="modal">
    <h3 style="margin-bottom:16px;">تسجيل منشأة جديدة (New Tenant)</h3>
    <div class="fld">
      <label>اسم المنشأة أو المحل التجاري *</label>
      <input id="tName" placeholder="مثال: شركة الأمل لقطع الغيار">
    </div>
    <div class="grid-2">
      <div class="fld">
        <label>اسم المالك / المدير</label>
        <input id="tOwner" placeholder="أحمد محمد">
      </div>
      <div class="fld">
        <label>رقم الهاتف للتواصل</label>
        <input id="tPhone" placeholder="010XXXXXXXX">
      </div>
    </div>
    <div class="grid-2">
      <div class="fld">
        <label>باقة الاشتراك (Plan)</label>
        <select id="tPlan">
          <option value="trial">تجريبي (Trial - 14 يوم)</option>
          <option value="basic">أساسي (Basic - 3 أجهزة)</option>
          <option value="standard" selected>قياسي (Standard - 10 أجهزة)</option>
          <option value="enterprise">مؤسسات (Enterprise - غير محدود)</option>
        </select>
      </div>
      <div class="fld">
        <label>مدة التعاقد (بالأيام)</label>
        <input id="tDays" type="number" value="365">
      </div>
    </div>
    <div class="fld">
      <label>الحد الأقصى للأجهزة المسموح بها</label>
      <input id="tMaxDev" type="number" value="10">
    </div>
    <div class="fld">
      <label>الصلاحيات الممنوحة للمنشأة:</label>
      <div class="perm-grid">
        <label class="perm-lbl"><input type="checkbox" id="p_pos" checked> نقاط البيع (POS)</label>
        <label class="perm-lbl"><input type="checkbox" id="p_inv" checked> المخازن والجرد</label>
        <label class="perm-lbl"><input type="checkbox" id="p_pur" checked> فواتير المشتريات</label>
        <label class="perm-lbl"><input type="checkbox" id="p_fin" checked> الخزينة والأرباح</label>
        <label class="perm-lbl"><input type="checkbox" id="p_rep" checked> التقارير المتقدمة</label>
        <label class="perm-lbl"><input type="checkbox" id="p_ai" checked> المساعد الصوتي AI</label>
      </div>
    </div>
    <div style="display:flex; justify-content:flex-end; gap:10px; margin-top:20px;">
      <button class="btn btn-sec" onclick="closeCreateModal()">إلغاء</button>
      <button class="btn" onclick="submitCreateTenant()">حفظ وإنشاء المنشأة</button>
    </div>
  </div>
</div>

<!-- Modal Key Notice -->
<div class="modal-overlay" id="keyModal">
  <div class="modal">
    <h3 style="color:var(--success); margin-bottom:12px;">تم إنشاء المنشأة بنجاح!</h3>
    <p style="font-size:14px; color:var(--muted); line-height:1.6;">
      انسخ هذا المفتاح السحابي وقم بتسليمه للعميل. يتم عرضه <b>مرة واحدة فقط</b> ولن يظهر مجدداً لأسباب أمنية:
    </p>
    <div class="key-box" id="newKeyBox"></div>
    <button class="btn" style="width:100%; margin-top:10px;" onclick="navigator.clipboard.writeText(document.getElementById('newKeyBox').innerText); alert('تم نسخ المفتاح'); closeKeyModal();">نسخ المفتاح وإغلاق</button>
  </div>
</div>

<script>
let adminKey = localStorage.getItem('malvia_admin_key') || '';
document.getElementById('adminKeyInput').value = adminKey;

function saveKeyAndRefresh() {
  adminKey = document.getElementById('adminKeyInput').value.trim();
  localStorage.setItem('malvia_admin_key', adminKey);
  loadTenants();
}

function openCreateModal() { document.getElementById('createModal').style.display = 'grid'; }
function closeCreateModal() { document.getElementById('createModal').style.display = 'none'; }
function closeKeyModal() { document.getElementById('keyModal').style.display = 'none'; loadTenants(); }

async function api(path, opts = {}) {
  const headers = { 'content-type': 'application/json', ...(opts.headers || {}) };
  if (adminKey) headers['authorization'] = 'Bearer ' + adminKey;
  const r = await fetch(path, { ...opts, headers });
  if (r.status === 401) { alert('المفتاح السري للإدارة غير صحيح أو لم يتم إدخاله.'); throw new Error('unauthorized'); }
  return r.json();
}

async function loadTenants() {
  try {
    const list = await api('/admin/tenants');
    let total = list.length, active = 0, expired = 0, devs = 0;
    const tbody = document.getElementById('tenantRows');
    if (!list.length) {
      tbody.innerHTML = '<tr><td colspan="8" style="text-align:center; padding:30px; color:var(--muted);">لا توجد أي منشآت مسجلة بعد. انقر على "+ منشأة جديدة" لإضافة أول عميل.</td></tr>';
      return;
    }
    tbody.innerHTML = list.map(t => {
      devs += t.devices || 0;
      const isExp = t.status === 'expired' || (t.daysRemaining != null && t.daysRemaining <= 0);
      const isDis = !t.enabled;
      if (isDis || isExp) expired++; else active++;
      const badgeCls = isDis ? 'badge-disabled' : isExp ? 'badge-expired' : 'badge-active';
      const statusTxt = isDis ? 'موقوف' : isExp ? 'منتهي التعاقد' : 'نشط';
      const expDate = t.expiresAt ? new Date(t.expiresAt).toLocaleDateString('ar-EG') : 'دائم';
      const days = t.daysRemaining != null ? (t.daysRemaining + ' يوم') : '—';
      
      return \`<tr>
        <td>
          <b>\${t.name}</b>
          <div style="font-size:11px; color:var(--muted);">\${t.id} \${t.ownerName ? '· ' + t.ownerName : ''} \${t.phone ? '· ' + t.phone : ''}</div>
        </td>
        <td><span class="badge" style="background:#0f172a; border:1px solid var(--border);">\${t.plan || 'standard'}</span></td>
        <td><span class="badge \${badgeCls}">\${statusTxt}</span></td>
        <td>\${expDate}</td>
        <td>\${days}</td>
        <td>\${t.devices || 0} / \${t.maxDevices || 10}</td>
        <td>\${t.records || 0}</td>
        <td>
          <div style="display:flex; gap:6px;">
            <button class="btn btn-sm btn-sec" title="تجديد شهر (+30 يوم)" onclick="renewTenant('\${t.id}', 30)">+30 يوم</button>
            <button class="btn btn-sm btn-sec" title="تجديد سنة (+365 يوم)" onclick="renewTenant('\${t.id}', 365)">+سنة</button>
            <button class="btn btn-sm \${t.enabled ? 'btn-danger' : 'btn-success'}" onclick="toggleTenant('\${t.id}', \${!t.enabled})">\${t.enabled ? 'إيقاف' : 'تفعيل'}</button>
          </div>
        </td>
      </tr>\`;
    }).join('');
    document.getElementById('sTotal').innerText = total;
    document.getElementById('sActive').innerText = active;
    document.getElementById('sExpired').innerText = expired;
    document.getElementById('sDevices').innerText = devs;
  } catch (e) {
    console.error(e);
  }
}

async function submitCreateTenant() {
  const name = document.getElementById('tName').value.trim();
  if (!name) return alert('يرجى إدخال اسم المنشأة');
  const payload = {
    name,
    ownerName: document.getElementById('tOwner').value.trim(),
    phone: document.getElementById('tPhone').value.trim(),
    plan: document.getElementById('tPlan').value,
    contractDurationDays: +document.getElementById('tDays').value || 365,
    maxDevices: +document.getElementById('tMaxDev').value || 10,
    permissions: {
      pos: document.getElementById('p_pos').checked,
      inventory: document.getElementById('p_inv').checked,
      purchases: document.getElementById('p_pur').checked,
      finance: document.getElementById('p_fin').checked,
      reports: document.getElementById('p_rep').checked,
      aiVoice: document.getElementById('p_ai').checked,
      multiDevice: true
    }
  };
  try {
    const res = await api('/admin/tenants', { method: 'POST', body: JSON.stringify(payload) });
    closeCreateModal();
    document.getElementById('newKeyBox').innerText = res.key;
    document.getElementById('keyModal').style.display = 'grid';
  } catch (e) {
    alert('حدث خطأ أثناء الإنشاء: ' + e.message);
  }
}

async function renewTenant(id, days) {
  if (!confirm(\`هل أنت متأكد من تمديد تعاقد المنشأة بمقدار \${days} يوماً؟\`)) return;
  try {
    await api(\`/admin/tenants/\${id}/renew\`, { method: 'POST', body: JSON.stringify({ days }) });
    loadTenants();
  } catch (e) { alert(e.message); }
}

async function toggleTenant(id, enabled) {
  try {
    await api(\`/admin/tenants/\${id}\`, { method: 'PATCH', body: JSON.stringify({ enabled }) });
    loadTenants();
  } catch (e) { alert(e.message); }
}

if (adminKey) loadTenants();
</script>
</body>
</html>`;
}

/* ---------- routes ---------- */
async function handle(req, res) {
  cors(req, res);
  if (req.method === 'OPTIONS') { res.writeHead(204); return res.end(); }
  const url = new URL(req.url, 'http://x');
  const p = url.pathname;

  if (p === '/health') {
    return send(res, 200, { ok: true, version: '1.0.0', time: new Date().toISOString() });
  }

  // Built-in Admin Dashboard Web UI
  if (p === '/admin' || p === '/admin/' || p === '/admin/dashboard') {
    return sendHtml(res, 200, renderAdminHtml());
  }

  // Public / Client Tenant Registration
  if (p === '/v1/register' && req.method === 'POST') {
    if (!rateOk('reg:pub', 15)) return send(res, 429, { error: 'rate_limited' });
    let b; try { b = await body(req, 64 * 1024); } catch (e) { return send(res, e.code || 400, { error: e.message }); }
    const name = String(b.name || '').trim();
    if (!name) return send(res, 400, { error: 'name_required', message: 'اسم المنشأة مطلوب' });

    const key = 'mxc_' + crypto.randomBytes(24).toString('hex');
    const now = new Date();
    const contractDays = Number(b.contractDays) || (b.plan === 'trial' ? 14 : 30);
    const expiresAt = new Date(now.getTime() + contractDays * 86400000).toISOString();
    const maxDevices = Number(b.maxDevices) || (b.plan === 'trial' ? 2 : 5);

    const t = {
      id: 't_' + crypto.randomBytes(5).toString('hex'),
      name,
      ownerName: String(b.ownerName || '').trim(),
      phone: String(b.phone || '').trim(),
      email: String(b.email || '').trim(),
      keyHash: sha(key),
      enabled: true,
      plan: b.plan || 'trial',
      contractDurationDays: contractDays,
      createdAt: now.toISOString(),
      startDate: now.toISOString(),
      expiresAt: expiresAt,
      maxDevices: maxDevices,
      permissions: { ...DEFAULT_PERMISSIONS, ...(b.permissions || {}) },
      notes: String(b.notes || '').trim()
    };
    reg.tenants.push(t);
    saveReg();
    tdb(t);
    return send(res, 201, {
      ok: true,
      id: t.id,
      name: t.name,
      key, // shown once
      licenseKey: key,
      tenant: { id: t.id, name: t.name, plan: t.plan, expiresAt: t.expiresAt },
      plan: t.plan,
      expiresAt: t.expiresAt,
      maxDevices: t.maxDevices,
      message: 'تم تسجيل المنشأة بنجاح'
    });
  }

  // Tenant Pairing with Device
  if (p === '/v1/pair' && req.method === 'POST') {
    const t = tenantOf(req);
    if (!t) return send(res, 401, { error: 'unauthorized', message: 'مفتاح المنشأة غير صحيح' });
    
    const evalRes = evaluateTenant(t);
    if (!evalRes.valid) return send(res, evalRes.code, evalRes);

    if (!rateOk('pair:' + t.id, 30)) return send(res, 429, { error: 'rate_limited' });
    let b; try { b = await body(req, 64 * 1024); } catch (e) { return send(res, e.code || 400, { error: e.message }); }
    
    const db = tdb(t);
    const currentDevices = db.prepare('SELECT COUNT(*) AS n FROM devices').get().n;
    if (currentDevices >= evalRes.maxDevices) {
      return send(res, 403, {
        error: 'max_devices_exceeded',
        message: `تم الوصول للحد الأقصى للأجهزة المسموح بها لهذه المنشأة (${evalRes.maxDevices} جهاز). يرجى الترقية لإضافة أجهزة جديدة.`
      });
    }

    const n = currentDevices;
    const code = String.fromCharCode(65 + (n % 26)) + (n >= 26 ? Math.floor(n / 26) : '');
    const id = 'd_' + crypto.randomBytes(6).toString('hex');
    db.prepare('INSERT INTO devices(id,name,code,created) VALUES(?,?,?,?)').run(id, String(b.name || 'device').slice(0, 60), code, new Date().toISOString());

    return send(res, 200, {
      device: id,
      code,
      tenant: t.name,
      empty: curSeq(db) === 0,
      subscription: {
        plan: evalRes.plan,
        status: 'active',
        expiresAt: evalRes.expiresAt,
        daysRemaining: evalRes.daysRemaining,
        maxDevices: evalRes.maxDevices,
        permissions: evalRes.permissions
      }
    });
  }

  // Sync Endpoint
  if (p === '/v1/sync' && req.method === 'POST') {
    const t = tenantOf(req);
    if (!t) return send(res, 401, { error: 'unauthorized', message: 'مفتاح المنشأة غير صحيح' });

    const evalRes = evaluateTenant(t);
    if (!evalRes.valid) return send(res, evalRes.code, evalRes);

    if (!rateOk('sync:' + t.id, 300)) return send(res, 429, { error: 'rate_limited' });
    const dv = String(req.headers['x-device'] || '');
    const dev = dv && tdb(t).prepare('SELECT id, code FROM devices WHERE id=?').get(dv);
    if (!dev) return send(res, 403, { error: 'unknown_device', message: 'جهاز غير معروف أو تم فك ربطه' });

    let b; try { b = await body(req); } catch (e) { return send(res, e.code || 400, { error: e.message }); }
    if (b.changes !== undefined && (!Array.isArray(b.changes) || b.changes.length > CFG.maxChanges)) {
      return send(res, 400, { error: 'bad_changes' });
    }

    try {
      const resData = sync(t, dev, b.since, b.changes || []);
      resData.subscription = {
        plan: evalRes.plan,
        status: 'active',
        expiresAt: evalRes.expiresAt,
        daysRemaining: evalRes.daysRemaining,
        permissions: evalRes.permissions
      };
      return send(res, 200, resData);
    } catch (e) {
      console.error(e);
      return send(res, 500, { error: 'server_error' });
    }
  }

  // Tenant Information & Subscription Status
  if (p === '/v1/tenant/info' && req.method === 'GET') {
    const t = tenantOf(req);
    if (!t) return send(res, 401, { error: 'unauthorized' });
    const evalRes = evaluateTenant(t);
    const db = tdb(t);
    const devices = db.prepare('SELECT id, name, code, created, last_seen FROM devices ORDER BY created').all();
    const records = db.prepare('SELECT COUNT(*) AS n FROM recs').get().n;

    return send(res, 200, {
      id: t.id,
      name: t.name,
      ownerName: t.ownerName || '',
      phone: t.phone || '',
      enabled: t.enabled,
      status: evalRes.valid ? 'active' : evalRes.error,
      plan: evalRes.plan,
      expiresAt: evalRes.expiresAt,
      daysRemaining: evalRes.daysRemaining,
      maxDevices: evalRes.maxDevices,
      permissions: evalRes.permissions,
      devicesCount: devices.length,
      devices,
      records
    });
  }

  // Devices List for tenant
  if (p === '/v1/devices' && req.method === 'GET') {
    const t = tenantOf(req);
    if (!t) return send(res, 401, { error: 'unauthorized' });
    return send(res, 200, tdb(t).prepare('SELECT id, name, code, created, last_seen FROM devices ORDER BY created').all());
  }

  /* ---------- Admin Endpoints ---------- */
  if (p.startsWith('/admin/')) {
    if (!isAdmin(req)) return send(res, 401, { error: 'unauthorized' });

    // Create Tenant via Admin
    if (p === '/admin/tenants' && req.method === 'POST') {
      let b; try { b = await body(req, 64 * 1024); } catch (e) { return send(res, e.code || 400, { error: e.message }); }
      if (!String(b.name || '').trim()) return send(res, 400, { error: 'name_required' });

      const key = 'mxc_' + crypto.randomBytes(24).toString('hex');
      const now = new Date();
      const contractDays = Number(b.contractDurationDays) || Number(b.contractDays) || (b.plan === 'trial' ? 14 : 365);
      const expiresAt = b.expiresAt ? new Date(b.expiresAt).toISOString() : new Date(now.getTime() + contractDays * 86400000).toISOString();

      const t = {
        id: 't_' + crypto.randomBytes(5).toString('hex'),
        name: String(b.name).trim(),
        ownerName: String(b.ownerName || '').trim(),
        phone: String(b.phone || '').trim(),
        email: String(b.email || '').trim(),
        keyHash: sha(key),
        enabled: b.enabled !== undefined ? !!b.enabled : true,
        plan: b.plan || 'standard',
        contractDurationDays: contractDays,
        createdAt: now.toISOString(),
        startDate: now.toISOString(),
        expiresAt: expiresAt,
        maxDevices: Number(b.maxDevices) || (b.plan === 'trial' ? 2 : 10),
        permissions: { ...DEFAULT_PERMISSIONS, ...(b.permissions || {}) },
        notes: String(b.notes || '').trim()
      };
      reg.tenants.push(t);
      saveReg();
      tdb(t);
      return send(res, 201, {
        id: t.id,
        name: t.name,
        key, // shown ONCE
        plan: t.plan,
        expiresAt: t.expiresAt,
        maxDevices: t.maxDevices,
        permissions: t.permissions
      });
    }

    // List All Tenants
    if (p === '/admin/tenants' && req.method === 'GET') {
      return send(res, 200, reg.tenants.map(t => {
        const db = tdb(t);
        const evalRes = evaluateTenant(t);
        return {
          id: t.id,
          name: t.name,
          ownerName: t.ownerName || '',
          phone: t.phone || '',
          enabled: t.enabled,
          plan: t.plan || 'standard',
          status: evalRes.valid ? 'active' : evalRes.error,
          expiresAt: t.expiresAt || null,
          daysRemaining: evalRes.daysRemaining,
          maxDevices: t.maxDevices || 10,
          permissions: t.permissions || DEFAULT_PERMISSIONS,
          records: db.prepare('SELECT COUNT(*) AS n FROM recs').get().n,
          seq: curSeq(db),
          devices: db.prepare('SELECT COUNT(*) AS n FROM devices').get().n
        };
      }));
    }

    // Renew Tenant Contract Endpoint: /admin/tenants/:id/renew
    const mRenew = p.match(/^\/admin\/tenants\/(\w+)\/renew$/);
    if (mRenew && req.method === 'POST') {
      const t = reg.tenants.find(x => x.id === mRenew[1]);
      if (!t) return send(res, 404, { error: 'not_found' });
      let b; try { b = await body(req, 64 * 1024); } catch (e) { return send(res, e.code || 400, { error: e.message }); }
      
      const addDays = Number(b.days) || Number(b.addDays) || 30;
      if (b.plan) t.plan = b.plan;
      const baseDate = t.expiresAt && new Date(t.expiresAt) > new Date() ? new Date(t.expiresAt) : new Date();
      t.expiresAt = new Date(baseDate.getTime() + addDays * 86400000).toISOString();
      t.enabled = true; // reactivate if disabled
      saveReg();
      return send(res, 200, {
        id: t.id,
        name: t.name,
        plan: t.plan,
        expiresAt: t.expiresAt,
        daysRemaining: Math.ceil((new Date(t.expiresAt) - Date.now()) / 86400000),
        message: `تم تمديد التعاقد بنجاح بمقدار ${addDays} يوماً`
      });
    }

    // Update Tenant (Toggle Enabled, Change Plan, Expiration, Permissions)
    const mPatch = p.match(/^\/admin\/tenants\/(\w+)$/);
    if (mPatch && req.method === 'PATCH') {
      const t = reg.tenants.find(x => x.id === mPatch[1]);
      if (!t) return send(res, 404, { error: 'not_found' });
      let b; try { b = await body(req, 64 * 1024); } catch (e) { return send(res, e.code || 400, { error: e.message }); }

      if (typeof b.enabled === 'boolean') t.enabled = b.enabled;
      if (b.name) t.name = String(b.name).trim();
      if (b.ownerName !== undefined) t.ownerName = String(b.ownerName).trim();
      if (b.phone !== undefined) t.phone = String(b.phone).trim();
      if (b.plan) t.plan = String(b.plan);
      if (b.maxDevices) t.maxDevices = Number(b.maxDevices);
      if (b.expiresAt) t.expiresAt = new Date(b.expiresAt).toISOString();
      if (b.permissions && typeof b.permissions === 'object') {
        t.permissions = { ...(t.permissions || DEFAULT_PERMISSIONS), ...b.permissions };
      }
      saveReg();
      return send(res, 200, { id: t.id, enabled: t.enabled, plan: t.plan, expiresAt: t.expiresAt });
    }
  }

  return send(res, 404, { error: 'not_found' });
}

/* ---------- daily consistent backup of every tenant database (keeps 14) ---------- */
function backupAll() {
  const day = new Date().toISOString().slice(0, 10);
  for (const t of reg.tenants) {
    try {
      const dir = path.join(CFG.dataDir, 'backups', t.id);
      fs.mkdirSync(dir, { recursive: true });
      const f = path.join(dir, `${day}.db`);
      if (!fs.existsSync(f)) tdb(t).exec(`VACUUM INTO '${f.replace(/'/g, "''")}'`);
      const l = fs.readdirSync(dir).filter(n => /^\d{4}-\d{2}-\d{2}\.db$/.test(n)).sort();
      while (l.length > 14) fs.unlinkSync(path.join(dir, l.shift()));
    } catch (e) {
      console.error('backup failed for', t.id, e.message);
    }
  }
}

const server = http.createServer((req, res) => handle(req, res).catch(e => {
  console.error(e);
  if (!res.headersSent) send(res, 500, { error: 'server_error' });
}));

if (require.main === module) {
  if (!CFG.adminKey) console.warn('WARNING: ADMIN_KEY is not set; tenant admin is disabled.');
  backupAll();
  setInterval(backupAll, 6 * 3600 * 1000);
  server.listen(CFG.port, () => {
    console.log('=====================================================================');
    console.log('   MALVIA Cloud Sync Server & Multi-Tenant Management');
    console.log('   سيرفر مالفيا السحابي وإدارة التينانت والاشتراكات');
    console.log('=====================================================================');
    console.log(`   - Server URL:         http://localhost:${CFG.port}`);
    console.log(`   - Admin Dashboard:    http://localhost:${CFG.port}/admin`);
    console.log(`   - Super Admin Key:    ${CFG.adminKey}`);
    console.log('=====================================================================');
    console.log('   Endpoints:');
    console.log(`   * Public Register:    POST http://localhost:${CFG.port}/v1/register`);
    console.log(`   * Device Pairing:     POST http://localhost:${CFG.port}/v1/pair`);
    console.log(`   * Realtime Sync:      POST http://localhost:${CFG.port}/v1/sync`);
    console.log(`   * License Info:       GET  http://localhost:${CFG.port}/v1/tenant/info`);
    console.log('=====================================================================');
    console.log('Server is running. Press Ctrl+C to stop.');
  });
}

module.exports = { server, CFG, reg, DEFAULT_PERMISSIONS };
