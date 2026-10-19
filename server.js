'use strict';
// نظام بقالة الرحمة - الخادم (متصل بقاعدة بيانات MongoDB سحابية دائمة)
const http = require('http'), fs = require('fs'), path = require('path'), crypto = require('crypto');
const { MongoClient } = require('mongodb');

const PORT = +process.env.PORT || 3000, HOST = process.env.HOST || '0.0.0.0';
const TRUST_PROXY = process.env.TRUST_PROXY === '1';
const MONGO_URI = process.env.MONGODB_URI; // رابط قاعدة البيانات السحابية

if (!MONGO_URI) {
  console.error("خطأ حرج: يجب توفير متغير البيئة MONGODB_URI لرابط قاعدة البيانات!");
}

const AUD = path.join(__dirname, 'data', 'audio');
fs.mkdirSync(AUD, { recursive: true });

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

let db = emptyDb();
let dbCollection;

// الاتصال بـ MongoDB ومزامنة البيانات عند بدء التشغيل
async function initDatabase() {
  const client = new MongoClient(MONGO_URI);
  await client.connect();
  const database = client.db('rahma_grocery');
  dbCollection = database.collection('main_data');
  
  let doc = await dbCollection.findOne({ _id: 'store_data' });
  if (!doc) {
    db = emptyDb();
    await dbCollection.insertOne({ _id: 'store_data', ...db });
  } else {
    db = doc;
    const base = emptyDb();
    for (const k in base) if (!(k in db)) db[k] = base[k];
    db.settings = { ...base.settings, ...db.settings };
  }
  console.log("تم الاتصال بقاعدة البيانات السحابية بنجاح وتأمين البيانات!");
}

async function save() {
  if (dbCollection) {
    await dbCollection.replaceOne({ _id: 'store_data' }, { _id: 'store_data', ...db });
  }
}

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
const MIN = 60000, DAY = 24 * 3600e3;
const lockLeft = key => { const f = fails.get(key); return f && f.until > Date.now() ? f.until - Date.now() : 0; };
const locked = key => lockLeft(key) > 0;
const addFail = (key, first = 5, firstMin = 15, next = 5, nextMin = 15) => {
  const now = Date.now(), f = fails.get(key) || { n: 0, until: 0, last: now, locks: 0 };
  if (f.until <= now && now - f.last > DAY) { f.n = 0; f.locks = 0; }
  else if (f.until <= now && now - f.last > 15 * MIN) f.n = 0;
  f.last = now; f.n++;
  const lim = f.locks === 0 ? first : next;
  if (f.n >= lim) { f.until = now + (f.locks === 0 ? firstMin : nextMin) * MIN; f.locks++; f.n = 0; }
  fails.set(key, f);
};
setInterval(() => { const n = Date.now(); for (const [k, f] of fails) if (f.until <= n && n - f.last > DAY) fails.delete(k); }, 30 * MIN).unref();
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

  if (p === '/api/status' && m === 'GET') return json(res, 200, { setup: !!db.admin, shop: db.settings.shopName, role: sess ? sess.role : null });
  if (p === '/api/setup' && m === 'POST') {
    if (db.admin) throw bad('تم الإعداد مسبقًا', 403);
    if (locked(ip)) throw bad('محاولات كثيرة، انتظر 15 دقيقة', 429);
    const b = await readJson(req);
    if (String(b.code || '').trim() !== db.setupCode) { addFail(ip); throw bad('رمز الإعداد غير صحيح', 403); }
    if (!b.user || String(b.password || '').length < 8) throw bad('اسم المستخدم مطلوب وكلمة السر 8 أحرف على الأقل');
    db.admin = { user: String(b.user).trim(), hash: mkHash(b.password) };
    await save();
    startSess(req, res, 'admin');
    return json(res, 200, { ok: true });
  }
  if (p === '/api/login' && m === 'POST') {
    const b = await readJson(req);
    const uname = String(b.user || '').trim().toLowerCase().slice(0, 60);
    const rl = b.role === 'customer' ? 'customer' : 'staff';
    const kUser = 'u|' + ip + '|' + rl + '|' + uname, kIp = 'i|' + ip, kAcc = 'a|' + rl + '|' + uname;
    const left = Math.max(lockLeft(kUser), lockLeft(kIp), lockLeft(kAcc));
    if (left > 0) throw bad('محاولات خاطئة كثيرة، انتظر دقيقة ثم حاول مرة أخرى', 429);
    if (rl === 'staff') {
      if (db.admin && uname === db.admin.user.toLowerCase() && chk(b.password, db.admin.hash)) { fails.delete(kUser); fails.delete(kAcc); startSess(req, res, 'admin'); return json(res, 200, { ok: true, role: 'admin' }); }
      if (db.instAdmin && uname === db.instAdmin.user.toLowerCase() && chk(b.password, db.instAdmin.hash)) { fails.delete(kUser); fails.delete(kAcc); startSess(req, res, 'inst'); return json(res, 200, { ok: true, role: 'inst' }); }
    } else {
      const c = db.customers.find(x => x.code === String(b.user).trim());
      if (c && chk(b.password, c.pinHash)) { fails.delete(kUser); fails.delete(kAcc); startSess(req, res, 'customer', c.id); return json(res, 200, { ok: true, role: 'customer' }); }
    }
    addFail(kUser, 10, 15, 5, 20); addFail(kAcc, 20, 15, 20, 15); addFail(kIp, 40, 15, 40, 15);
    throw bad('بيانات الدخول غير صحيحة', 401);
  }
  if (p === '/api/logout' && m === 'POST') { if (sess) sessions.delete(sess.token); res.setHeader('Set-Cookie', 'sid=; HttpOnly; Path=/; Max-Age=0'); return json(res, 200, { ok: true }); }

  if (p === '/api/me' && m === 'GET') {
    if (!sess || sess.role !== 'customer') throw bad('غير مصرح', 401);
    const c = db.customers.find(x => x.id === sess.cid);
    if (!c) throw bad('الحساب غير موجود', 404);
    return json(res, 200, meData(c));
  }

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
    const o = { ...db }; delete o.admin; delete o.setupCode; delete o.instAdmin; delete o._id;
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
        arr.push(item); await save();
        return json(res, 200, { item: pub(item), pin });
      }
      const item = { ...b, id: uid(), ts: Date.now() };
      arr.push(item); await save();
      return json(res, 200, { item });
    }
    if (m === 'PUT' && id) {
      const it = arr.find(x => x.id === id);
      if (!it) throw bad('غير موجود', 404);
      const b = clean(await readJson(req));
      if (name === 'customers') { const ok = ['name', 'phone', 'note', 'bannedDebt', 'bannedInstall', 'banReason']; for (const k of Object.keys(b)) if (!ok.includes(k)) delete b[k]; }
      Object.assign(it, b); await save();
      return json(res, 200, { item: name === 'customers' ? pub(it) : it });
    }
    if (m === 'DELETE' && id) {
      const i = arr.findIndex(x => x.id === id);
      if (i < 0) throw bad('غير موجود', 404);
      arr.splice(i, 1); await save();
      return json(res, 200, { ok: true });
    }
  }

  if ((mm = /^\/api\/customers\/(\w+)\/pin$/.exec(p)) && m === 'POST') {
    const c = db.customers.find(x => x.id === mm[1]);
    if (!c) throw bad('غير موجود', 404);
    const pin = String(crypto.randomInt(100000, 1000000));
    c.pinHash = mkHash(pin); await save();
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
    await save();
    return json(res, 200, { item: it });
  }
  if (p === '/api/settle' && m === 'POST') {
    const b = await readJson(req);
    let n = 0;
    db.ledger.forEach(e => { if (e.customerId === b.customerId && e.account === b.account && !e.settled) { e.settled = true; e.settledAt = Date.now(); n++; } });
    await save();
    return json(res, 200, { settled: n });
  }
  if (p === '/api/settings' && m === 'PUT') {
    const b = await readJson(req);
    for (const k of SETTING_KEYS) if (k in b) {
      if (k === 'iqama') { for (const pr of ['Fajr', 'Dhuhr', 'Asr', 'Maghrib', 'Isha']) if (b.iqama && b.iqama[pr] != null) db.settings.iqama[pr] = Math.max(0, +b.iqama[pr] || 0); }
      else if (k === 'method') db.settings.method = +b.method || 23;
      else db.settings[k] = String(b[k]).slice(0, 100);
    }
    await save();
    return json(res, 200, { settings: db.settings });
  }
  if (p === '/api/password' && m === 'POST') {
    const b = await readJson(req);
    if (!chk(b.old, db.admin.hash)) throw bad('كلمة السر الحالية غير صحيحة', 403);
    if (String(b.password || '').length < 8) throw bad('كلمة السر الجديدة 8 أحرف على الأقل');
    if (b.user && db.instAdmin && String(b.user).trim().toLowerCase() === db.instAdmin.user.toLowerCase()) throw bad('الاسم مستخدم لمسؤول الأقساط');
    db.admin.hash = mkHash(b.password);
    if (b.user) db.admin.user = String(b.user).trim();
    await save();
    return json(res, 200, { ok: true });
  }
  if (p === '/api/inst-admin' && sess.role === 'admin' && m === 'POST') {
    const b = await readJson(req), user = String(b.user || '').trim();
    if (!user) throw bad('اسم المستخدم مطلوب');
    if (user.toLowerCase() === db.admin.user.toLowerCase()) throw bad('اختر اسمًا مختلفًا');
    if (String(b.password || '').length < 8) throw bad('كلمة السر 8 أحرف على الأقل');
    db.instAdmin = { user, hash: mkHash(b.password) };
    await save();
    for (const [t, s] of sessions) if (s.role === 'inst') sessions.delete(t);
    return json(res, 200, { ok: true });
  }
  if (p === '/api/inst-admin' && sess.role === 'admin' && m === 'DELETE') {
    db.instAdmin = null; await save();
    for (const [t, s] of sessions) if (s.role === 'inst') sessions.delete(t);
    return json(res, 200, { ok: true });
  }
  throw bad('غير موجود', 404);
}

// بدء التشغيل بعد الاتصال بقاعدة البيانات السحابية
initDatabase().then(() => {
  http.createServer(async (req, res) => {
    try { await route(req, res); }
    catch (e) {
      if (!e.status) console.error(e);
      if (!res.headersSent) json(res, e.status || 500, { error: e.status ? e.message : 'خطأ في الخادم' });
      else res.end();
    }
  }).listen(PORT, HOST, () => {
    console.log(`\nبقالة الرحمة تعمل سحابياً على: http://localhost:${PORT}`);
    if (!db.admin) console.log(`رمز الإعداد الأول: ${db.setupCode}\n`);
  });
}).catch(err => {
  console.error("فشل الاتصال بقاعدة البيانات السحابية:", err);
});