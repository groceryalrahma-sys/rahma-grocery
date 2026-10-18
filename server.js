'use strict';
// نظام بقالة الرحمة - الخادم (بدون أي مكتبات خارجية)
const http = require('http'), fs = require('fs'), path = require('path'), crypto = require('crypto');
const PORT = +process.env.PORT || 3000, HOST = process.env.HOST || '0.0.0.0';
const TRUST_PROXY = process.env.TRUST_PROXY === '1';
const DIR = path.join(__dirname, 'data'), BK = path.join(DIR, 'backups'), AUD = path.join(DIR, 'audio'), FILE = path.join(DIR, 'db.json');
[DIR, BK, AUD].forEach(d => fs.mkdirSync(d, { recursive: true }));

const COLS = ['customers', 'ledger', 'installments', 'expenses', 'cards', 'cardSales', 'cardStock', 'overnight', 'notices'];
const emptyDb = () => {
  const d = {
    admin: null, instAdmin: null, setupCode: crypto.randomBytes(4).toString('hex'), audio: [],
    settings: { shopName: 'بقالة الرحمة', owner: 'أبو مالك', city: 'Amman', country: 'Jordan', method: 23,
      iqama: { Fajr: 25, Dhuhr: 20, Asr: 20, Maghrib: 10, Isha: 20 }, activeAdhan: '', activeFajr: '', activeIqama: '' }
  };
  COLS.forEach(c => d[c] = []);
  return d;
};
let db;
try { db = JSON.parse(fs.readFileSync(FILE, 'utf8')); } catch { db = emptyDb(); }
const base = emptyDb();
for (const k in base) if (!(k in db)) db[k] = base[k];
db.settings = { ...base.settings, ...db.settings };

const pad = n => String(n).padStart(2, '0');
const today = () => { const d = new Date(); return d.getFullYear() + '-' + pad(d.getMonth() + 1) + '-' + pad(d.getDate()); };
function save() {
  const t = FILE + '.tmp';
  fs.writeFileSync(t, JSON.stringify(db));
  fs.renameSync(t, FILE);
  // نسخة احتياطية تلقائية لكل يوم (تُحدَّث مع كل تعديل) ونحتفظ بآخر 60 يوم
  fs.copyFileSync(FILE, path.join(BK, 'auto-' + today() + '.json'));
  const l = fs.readdirSync(BK).filter(x => x.startsWith('auto-')).sort();
  while (l.length > 60) fs.unlinkSync(path.join(BK, l.shift()));
}
if (!fs.existsSync(FILE)) save();

// ---------- تشفير ----------
const scrypt = (pw, salt) => crypto.scryptSync(String(pw), salt, 64).toString('hex');
const mkHash = pw => { const s = crypto.randomBytes(16).toString('hex'); return s + ':' + scrypt(pw, s); };
const chk = (pw, st) => {
  if (!st) return false;
  const [s, h] = st.split(':');
  const a = Buffer.from(scrypt(pw, s), 'hex'), b = Buffer.from(h, 'hex');
  return a.length === b.length && crypto.timingSafeEqual(a, b);
};
const uid = () => crypto.randomBytes(6).toString('hex');

// ---------- جلسات وحماية من التخمين ----------
const sessions = new Map();
const fails = new Map();
const ipOf = req => (TRUST_PROXY && req.headers['x-forwarded-for']) ? String(req.headers['x-forwarded-for']).split(',')[0].trim() : req.socket.remoteAddress;
const locked = ip => { const f = fails.get(ip); return f && f.until > Date.now(); };
const addFail = ip => { const f = fails.get(ip) || { n: 0, until: 0 }; f.n++; if (f.n >= 5) { f.until = Date.now() + 15 * 60000; f.n = 0; } fails.set(ip, f); };
const getSess = req => {
  const m = /(?:^|;\s*)sid=([a-f0-9]{64})/.exec(req.headers.cookie || '');
  if (!m) return null;
  const s = sessions.get(m[1]);
  if (!s || s.exp < Date.now()) { sessions.delete(m[1]); return null; }
  s.exp = Date.now() + 12 * 3600e3;
  return { ...s, token: m[1] };
};
const startSess = (req, res, role, cid) => {
  const t = crypto.randomBytes(32).toString('hex');
  sessions.set(t, { role, cid, exp: Date.now() + 12 * 3600e3 });
  const secure = (req.headers['x-forwarded-proto'] === 'https' || req.socket.encrypted) ? '; Secure' : '';
  res.setHeader('Set-Cookie', `sid=${t}; HttpOnly; SameSite=Strict; Path=/; Max-Age=43200${secure}`);
};

// ---------- أدوات ----------
const bad = (m, s = 400) => Object.assign(new Error(m), { status: s });
const json = (res, s, o) => { res.writeHead(s, { 'Content-Type': 'application/json; charset=utf-8' }); res.end(JSON.stringify(o)); };
const readBody = (req, max = 1e6) => new Promise((ok, no) => {
  const ch = []; let n = 0;
  req.on('data', c => { n += c.length; if (n > max) { no(bad('الملف أو الطلب كبير جدًا', 413)); req.destroy(); } else ch.push(c); });
  req.on('end', () => ok(Buffer.concat(ch)));
  req.on('error', no);
});
const readJson = async req => { try { return JSON.parse((await readBody(req)).toString() || '{}'); } catch (e) { if (e.status) throw e; throw bad('بيانات غير صالحة'); } };
const pub = c => { const { pinHash, ...r } = c; return r; };
const clean = o => { const r = {}; for (const k of Object.keys(o || {})) if (!['id', 'pinHash', '__proto__', 'constructor', 'prototype'].includes(k)) r[k] = o[k]; return r; };
const bal = (cid, acc) => db.ledger.filter(e => e.customerId === cid && e.account === acc && !e.settled).reduce((s, e) => s + e.delta, 0);

function meData(c) {
  const insts = db.installments.filter(i => i.customerId === c.id);
  const daily = bal(c.id, 'daily'), monthly = bal(c.id, 'monthly');
  const hasDebt = daily !== 0 || monthly !== 0;
  const hasInst = insts.some(i => i.total - (i.payments || []).reduce((s, p) => s + p.amount, 0) > 0.0001);
  return {
    name: c.name, code: c.code, shop: db.settings.shopName, daily, monthly,
    entries: db.ledger.filter(e => e.customerId === c.id).sort((a, b) => b.ts - a.ts).slice(0, 400)
      .map(e => ({ account: e.account, delta: e.delta, note: e.note, ts: e.ts, settled: !!e.settled })),
    installments: insts,
    notices: db.notices.filter(n => n.scope === 'all' || (n.scope === 'debts' && hasDebt) || (n.scope === 'installments' && hasInst) || (n.scope === 'customer' && n.customerId === c.id))
      .sort((a, b) => b.ts - a.ts).slice(0, 50).map(n => ({ text: n.text, ts: n.ts, scope: n.scope }))
  };
}
const newCode = () => { let c; do { c = String(crypto.randomInt(10000, 100000)); } while (db.customers.some(x => x.code === c)); return c; };

const SETTING_KEYS = ['shopName', 'owner', 'city', 'country', 'method', 'iqama', 'activeAdhan', 'activeFajr', 'activeIqama'];
const INDEX = path.join(__dirname, 'public', 'index.html');

async function route(req, res) {
  const u = new URL(req.url, 'http://x'), p = u.pathname, m = req.method;
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; connect-src 'self' https://api.aladhan.com; media-src 'self' blob:; img-src 'self' data:; frame-ancestors 'none'");
  if (m === 'GET' && (p === '/' || p === '/index.html')) {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' });
    return res.end(fs.readFileSync(INDEX));
  }
  if (!p.startsWith('/api/')) return json(res, 404, { error: 'غير موجود' });
  res.setHeader('Cache-Control', 'no-store');
  if (m !== 'GET' && req.headers['x-requested-with'] !== 'fetch') throw bad('طلب مرفوض', 403);
  const ip = ipOf(req), sess = getSess(req);

  // ----- عام -----
  if (p === '/api/status' && m === 'GET') return json(res, 200, { setup: !!db.admin, shop: db.settings.shopName, role: sess ? sess.role : null });
  if (p === '/api/setup' && m === 'POST') {
    if (db.admin) throw bad('تم الإعداد مسبقًا', 403);
    if (locked(ip)) throw bad('محاولات كثيرة، انتظر 15 دقيقة', 429);
    const b = await readJson(req);
    if (String(b.code || '').trim() !== db.setupCode) { addFail(ip); throw bad('رمز الإعداد غير صحيح (يظهر في شاشة تشغيل الخادم)', 403); }
    if (!b.user || String(b.password || '').length < 8) throw bad('اسم المستخدم مطلوب وكلمة السر 8 أحرف على الأقل');
    db.admin = { user: String(b.user).trim(), hash: mkHash(b.password) };
    save();
    startSess(req, res, 'admin');
    return json(res, 200, { ok: true });
  }
  if (p === '/api/login' && m === 'POST') {
    if (locked(ip)) throw bad('محاولات خاطئة كثيرة، انتظر 15 دقيقة', 429);
    const b = await readJson(req);
    if (b.role === 'admin') {
      if (db.admin && String(b.user) === db.admin.user && chk(b.password, db.admin.hash)) { startSess(req, res, 'admin'); return json(res, 200, { ok: true, role: 'admin' }); }
    } else if (b.role === 'inst') {
      if (db.instAdmin && String(b.user) === db.instAdmin.user && chk(b.password, db.instAdmin.hash)) { startSess(req, res, 'inst'); return json(res, 200, { ok: true, role: 'inst' }); }
    } else {
      const c = db.customers.find(x => x.code === String(b.user).trim());
      if (c && chk(b.password, c.pinHash)) { startSess(req, res, 'customer', c.id); return json(res, 200, { ok: true, role: 'customer' }); }
    }
    addFail(ip);
    throw bad('بيانات الدخول غير صحيحة', 401);
  }
  if (p === '/api/logout' && m === 'POST') { if (sess) sessions.delete(sess.token); res.setHeader('Set-Cookie', 'sid=; HttpOnly; Path=/; Max-Age=0'); return json(res, 200, { ok: true }); }

  // ----- الزبون: قراءة فقط -----
  if (p === '/api/me' && m === 'GET') {
    if (!sess || sess.role !== 'customer') throw bad('غير مصرح', 401);
    const c = db.customers.find(x => x.id === sess.cid);
    if (!c) throw bad('الحساب غير موجود', 404);
    return json(res, 200, meData(c));
  }

  // ----- المدير فقط من هنا -----
  // مسؤول الأقساط: مسموح له فقط بهذه المسارات، وأي شيء آخر مرفوض
  const instOk = sess && sess.role === 'inst' && (
    (p === '/api/inst-all' && m === 'GET') ||
    /^\/api\/c\/installments(\/\w+)?$/.test(p) ||
    /^\/api\/installments\/\w+\/pay$/.test(p) ||
    (p === '/api/c/customers' && m === 'POST'));
  if (!sess || (sess.role !== 'admin' && !instOk)) throw bad('غير مصرح', 401);

  if (p === '/api/inst-all' && m === 'GET') {
    return json(res, 200, {
      settings: { shopName: db.settings.shopName, owner: db.settings.owner },
      customers: db.customers.map(c => ({ id: c.id, name: c.name, phone: c.phone, bannedInstall: !!c.bannedInstall, banReason: c.banReason })),
      installments: db.installments
    });
  }

  if (p === '/api/all' && m === 'GET') {
    const o = { ...db }; delete o.admin; delete o.setupCode; delete o.instAdmin;
    o.customers = db.customers.map(pub);
    o.adminUser = db.admin.user;
    o.instAdminUser = db.instAdmin ? db.instAdmin.user : null;
    return json(res, 200, o);
  }

  let mm;
  if ((mm = /^\/api\/c\/(\w+)(?:\/(\w+))?$/.exec(p)) && COLS.includes(mm[1])) {
    const name = mm[1], id = mm[2], arr = db[name];
    if (m === 'POST' && !id) {
      const b = clean(await readJson(req));
      if (name === 'customers') {
        const nm = String(b.name || '').trim();
        if (!nm) throw bad('الاسم مطلوب');
        const pin = String(crypto.randomInt(100000, 1000000));
        const item = { id: uid(), code: newCode(), pinHash: mkHash(pin), name: nm, phone: String(b.phone || ''), note: String(b.note || ''), bannedDebt: false, bannedInstall: false, banReason: '', ts: Date.now() };
        arr.push(item); save();
        return json(res, 200, { item: pub(item), pin });
      }
      const item = { ...b, id: uid(), ts: Date.now() };
      arr.push(item); save();
      return json(res, 200, { item });
    }
    if (m === 'PUT' && id) {
      const it = arr.find(x => x.id === id);
      if (!it) throw bad('غير موجود', 404);
      const b = clean(await readJson(req));
      if (name === 'customers') { const ok = ['name', 'phone', 'note', 'bannedDebt', 'bannedInstall', 'banReason']; for (const k of Object.keys(b)) if (!ok.includes(k)) delete b[k]; }
      Object.assign(it, b); save();
      return json(res, 200, { item: name === 'customers' ? pub(it) : it });
    }
    if (m === 'DELETE' && id) {
      const i = arr.findIndex(x => x.id === id);
      if (i < 0) throw bad('غير موجود', 404);
      arr.splice(i, 1); save();
      return json(res, 200, { ok: true });
    }
  }

  if ((mm = /^\/api\/customers\/(\w+)\/pin$/.exec(p)) && m === 'POST') {
    const c = db.customers.find(x => x.id === mm[1]);
    if (!c) throw bad('غير موجود', 404);
    const pin = String(crypto.randomInt(100000, 1000000));
    c.pinHash = mkHash(pin); save();
    for (const [t, s] of sessions) if (s.cid === c.id) sessions.delete(t);
    return json(res, 200, { pin, code: c.code });
  }
  if ((mm = /^\/api\/installments\/(\w+)\/pay$/.exec(p)) && m === 'POST') {
    const it = db.installments.find(x => x.id === mm[1]);
    if (!it) throw bad('غير موجود', 404);
    const b = await readJson(req), amt = +b.amount;
    if (!(amt > 0)) throw bad('المبلغ غير صحيح');
    it.payments = it.payments || [];
    it.payments.push({ id: uid(), amount: amt, note: String(b.note || ''), ts: Date.now() });
    save();
    return json(res, 200, { item: it });
  }
  if (p === '/api/settle' && m === 'POST') {
    const b = await readJson(req);
    let n = 0;
    db.ledger.forEach(e => { if (e.customerId === b.customerId && e.account === b.account && !e.settled) { e.settled = true; e.settledAt = Date.now(); n++; } });
    save();
    return json(res, 200, { settled: n });
  }
  if (p === '/api/settings' && m === 'PUT') {
    const b = await readJson(req);
    for (const k of SETTING_KEYS) if (k in b) {
      if (k === 'iqama') { for (const pr of ['Fajr', 'Dhuhr', 'Asr', 'Maghrib', 'Isha']) if (b.iqama && b.iqama[pr] != null) db.settings.iqama[pr] = Math.max(0, +b.iqama[pr] || 0); }
      else if (k === 'method') db.settings.method = +b.method || 23;
      else db.settings[k] = String(b[k]).slice(0, 100);
    }
    save();
    return json(res, 200, { settings: db.settings });
  }
  if (p === '/api/password' && m === 'POST') {
    const b = await readJson(req);
    if (!chk(b.old, db.admin.hash)) throw bad('كلمة السر الحالية غير صحيحة', 403);
    if (String(b.password || '').length < 8) throw bad('كلمة السر الجديدة 8 أحرف على الأقل');
    if (b.user && db.instAdmin && String(b.user).trim() === db.instAdmin.user) throw bad('الاسم مستخدم لمسؤول الأقساط، اختر اسمًا آخر');
    db.admin.hash = mkHash(b.password);
    if (b.user) db.admin.user = String(b.user).trim();
    save();
    return json(res, 200, { ok: true });
  }
  if (p === '/api/inst-admin' && sess.role === 'admin' && m === 'POST') {
    const b = await readJson(req), user = String(b.user || '').trim();
    if (!user) throw bad('اسم المستخدم مطلوب');
    if (user === db.admin.user) throw bad('اختر اسمًا مختلفًا عن اسم المدير');
    if (String(b.password || '').length < 8) throw bad('كلمة السر 8 أحرف على الأقل');
    db.instAdmin = { user, hash: mkHash(b.password) };
    save();
    for (const [t, s] of sessions) if (s.role === 'inst') sessions.delete(t);
    return json(res, 200, { ok: true });
  }
  if (p === '/api/inst-admin' && sess.role === 'admin' && m === 'DELETE') {
    db.instAdmin = null; save();
    for (const [t, s] of sessions) if (s.role === 'inst') sessions.delete(t);
    return json(res, 200, { ok: true });
  }

  // ----- النسخ الاحتياطي -----
  if (p === '/api/backup' && m === 'GET') {
    const o = { ...db }; delete o.admin; delete o.setupCode; delete o.instAdmin;
    o.audio = [];
    res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8', 'Content-Disposition': `attachment; filename="rahma-backup-${today()}.json"` });
    return res.end(JSON.stringify(o));
  }
  if (p === '/api/backup/save' && m === 'POST') {
    const f = 'manual-' + today() + '-' + Date.now() + '.json';
    fs.copyFileSync(FILE, path.join(BK, f));
    const l = fs.readdirSync(BK).filter(x => x.startsWith('manual-')).sort();
    while (l.length > 30) fs.unlinkSync(path.join(BK, l.shift()));
    return json(res, 200, { file: f });
  }
  if (p === '/api/backups' && m === 'GET') return json(res, 200, { files: fs.readdirSync(BK).sort().reverse().slice(0, 40) });
  if (p === '/api/restore' && m === 'POST') {
    const b = JSON.parse((await readBody(req, 30e6)).toString() || '{}');
    if (!COLS.every(c => Array.isArray(b[c]))) throw bad('ملف النسخة الاحتياطية غير صالح');
    fs.copyFileSync(FILE, path.join(BK, 'before-restore-' + Date.now() + '.json'));
    const keep = { admin: db.admin, instAdmin: db.instAdmin, setupCode: db.setupCode, audio: db.audio };
    db = { ...emptyDb(), ...b, ...keep };
    db.settings = { ...base.settings, ...(b.settings || {}) };
    save();
    return json(res, 200, { ok: true });
  }

  // ----- الأصوات (أذان / إقامة) -----
  if (p === '/api/audio' && m === 'POST') {
    const kind = u.searchParams.get('kind'), nm = (u.searchParams.get('name') || 'مؤذن').slice(0, 60);
    if (!['adhan', 'iqama'].includes(kind)) throw bad('نوع غير صحيح');
    const mime = String(req.headers['content-type'] || '');
    if (!mime.startsWith('audio/')) throw bad('الملف يجب أن يكون صوتيًا');
    const buf = await readBody(req, 15e6);
    const id = uid();
    fs.writeFileSync(path.join(AUD, id), buf);
    db.audio.push({ id, kind, name: nm, mime }); save();
    return json(res, 200, { id });
  }
  if ((mm = /^\/api\/audio\/(\w+)$/.exec(p))) {
    const a = db.audio.find(x => x.id === mm[1]);
    if (!a) throw bad('غير موجود', 404);
    if (m === 'GET') { res.writeHead(200, { 'Content-Type': a.mime, 'Cache-Control': 'private, max-age=86400' }); return res.end(fs.readFileSync(path.join(AUD, a.id))); }
    if (m === 'DELETE') {
      db.audio = db.audio.filter(x => x.id !== a.id);
      try { fs.unlinkSync(path.join(AUD, a.id)); } catch { }
      ['activeAdhan', 'activeFajr', 'activeIqama'].forEach(k => { if (db.settings[k] === a.id) db.settings[k] = ''; });
      save();
      return json(res, 200, { ok: true });
    }
  }
  throw bad('غير موجود', 404);
}

http.createServer(async (req, res) => {
  try { await route(req, res); }
  catch (e) {
    if (!e.status) console.error(e);
    if (!res.headersSent) json(res, e.status || 500, { error: e.status ? e.message : 'خطأ في الخادم' });
    else res.end();
  }
}).listen(PORT, HOST, () => {
  console.log(`\nبقالة الرحمة تعمل على: http://localhost:${PORT}`);
  if (!db.admin) console.log(`رمز الإعداد الأول (أدخله في الصفحة لإنشاء حساب المدير): ${db.setupCode}\n`);
});
