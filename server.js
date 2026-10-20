'use strict';
// خادم دليل الأرقام: مصادقة + تخزين + مزامنة فورية + جهاز واحد لكل مستخدم (بلا مكتبات خارجية)
const http = require('http'), fs = require('fs'), path = require('path'), crypto = require('crypto'), zlib = require('zlib');
const DIR = __dirname, DATA = process.env.DATA_DIR || DIR;
const DBF = path.join(DATA, 'db.json'), SEED = path.join(DIR, 'seed.json'), HTMLF = path.join(DIR, 'index.html');
const MAXU = 300, PS = ' › ', DAY = 864e5;
let DB, LOG = [], LOGMIN = 0;
const hashPw = (p, k, salt) => crypto.scryptSync(String(p) + '\u0000' + String(k), salt, 32).toString('hex');
function mkUser(u, name, p, k, role, hc) { const salt = crypto.randomBytes(16).toString('hex'); return { u: u.toLowerCase(), name, role, salt, h: hashPw(p, k, salt), hc: hc || [] }; }
let saveT = null;
function save(now) {
  const w = () => { try { fs.mkdirSync(DATA, { recursive: true }); const tmp = DBF + '.tmp'; fs.writeFileSync(tmp, JSON.stringify(DB)); fs.renameSync(tmp, DBF); } catch (e) { console.error('save failed', e.message); } };
  clearTimeout(saveT); if (now) w(); else saveT = setTimeout(w, 250);
}
function init() {
  try { DB = JSON.parse(fs.readFileSync(DBF, 'utf8')); }
  catch (e) {
    const s = JSON.parse(fs.readFileSync(SEED, 'utf8'));
    DB = { v: 1, next: 1, contacts: [], users: [], hc: [], ord: s.ord, fav: {}, sessions: {} };
    s.contacts.forEach(c => DB.contacts.push({ i: DB.next++, n: c.n, t: c.t || '', p: c.p || '', w: c.w || '', c: c.c, h: c.h ? 1 : 0 }));
    DB.users.push(process.env.ADMIN_PASS && process.env.ADMIN_CODE ? mkUser(process.env.ADMIN_USER || 'admin', 'المدير', process.env.ADMIN_PASS, process.env.ADMIN_CODE, 'admin') : s.admin);
    save(true);
  }
  if (process.env.CLEAR_SESSIONS) { DB.sessions = {}; save(true); }
  LOGMIN = DB.v;
}
init();
const parentOf = k => k.includes(PS) ? k.split(PS)[0] : k;
const hid = (k, l) => l.includes(k) || l.includes(parentOf(k));
const visible = (c, u) => !c.h && !hid(c.c, DB.hc) && !hid(c.c, u.hc || []);
const pub = (c, adm) => adm && c.h ? { i: c.i, n: c.n, t: c.t, p: c.p, w: c.w, c: c.c, h: 1 } : { i: c.i, n: c.n, t: c.t, p: c.p, w: c.w, c: c.c };
const fmt = raw => {
  let t = String(raw || '').replace(/[\u200b-\u200f\u202a-\u202e]/g, '').trim(); if (!t) return { p: '', w: '' };
  if (t.startsWith('+') && !t.startsWith('+964')) { const d = t.replace(/\D/g, ''); return d.length < 7 ? null : { p: t, w: '+' + d }; }
  let d = t.replace(/\D/g, ''); if (d.startsWith('00')) d = d.slice(2); if (d.startsWith('964')) d = d.slice(3); d = d.replace(/^0+/, '');
  if (d.length == 10 && d[0] == '7') return { p: `0${d.slice(0, 3)} ${d.slice(3, 6)} ${d.slice(6)}`, w: '+964' + d };
  return d.length < 7 ? null : { p: t, w: '' };
};
const str = (v, n) => String(v == null ? '' : v).trim().slice(0, n);
function clean(q) {
  const n = str(q.n, 200), t = str(q.t, 200), c = str(q.c, 120); if (!n && !t) return 'name'; if (!c) return 'cat';
  const f = fmt(q.p); if (!f) return 'phone';
  return { n: n || t, t: n ? t : '', p: f.p, w: f.w, c, h: q.h ? 1 : 0 };
}
// ---- sessions & live clients
const streams = new Map();
const sessOf = u => Object.entries(DB.sessions).find(([, s]) => s.u === u && s.exp > Date.now());
function kill(sid, kick) { delete DB.sessions[sid]; const r = streams.get(sid); if (r) { try { if (kick) r.write('event: kick\ndata: 1\n\n'); r.end(); } catch (e) {} streams.delete(sid); } }
const killUser = u => { for (const [sid, s] of Object.entries(DB.sessions)) if (s.u === u) kill(sid, true); save(); };
function bump(entry) {
  DB.v++; if (entry) { entry.v = DB.v; LOG.push(entry); if (LOG.length > 300) { LOG.shift(); LOGMIN = LOG[0].v - 1; } } else { LOG.push({ v: DB.v, t: 'r' }); }
  save(); for (const r of streams.values()) { try { r.write(`data: {"v":${DB.v}}\n\n`); } catch (e) {} }
}
setInterval(() => { for (const r of streams.values()) { try { r.write(': ping\n\n'); } catch (e) {} } const n = Date.now(); let ch = 0; for (const [sid, s] of Object.entries(DB.sessions)) if (s.exp < n) { kill(sid, true); ch++; } if (ch) save(); }, 25000);
const cookies = req => Object.fromEntries((req.headers.cookie || '').split(';').map(x => x.trim().split('=')).filter(x => x[0] && x[1]));
function auth(req) {
  const sid = cookies(req).sid, s = sid && DB.sessions[sid]; if (!s) return null;
  if (s.exp < Date.now()) { kill(sid, true); save(); return null; }
  const u = DB.users.find(x => x.u === s.u); if (!u) { kill(sid, true); return null; }
  return { sid, s, u };
}
// ---- http helpers
function send(req, res, code, obj, extra) {
  const s = JSON.stringify(obj), h = { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', ...(extra || {}) };
  if (s.length > 1024 && /gzip/.test(req.headers['accept-encoding'] || '')) { h['Content-Encoding'] = 'gzip'; res.writeHead(code, h); res.end(zlib.gzipSync(s)); } else { res.writeHead(code, h); res.end(s); }
}
const readBody = (req, lim) => new Promise(r => { let b = '', big = false; req.on('data', d => { b += d; if (b.length > lim) { big = true; req.destroy(); } }); req.on('end', () => { if (big) return r(null); try { r(b ? JSON.parse(b) : {}); } catch (e) { r(null); } }); req.on('error', () => r(null)); });
const hits = new Map(), fails = new Map();
const limited = ip => { const n = Date.now(), h = (hits.get(ip) || []).filter(x => n - x < 60000); h.push(n); hits.set(ip, h); return h.length > 400; };
function lockWait(k) { const f = fails.get(k); if (!f || f.n < 5) return 0; const w = Math.min(900, 30 * 2 ** (f.n - 5)) * 1000 - (Date.now() - f.t); return w > 0 ? Math.ceil(w / 1000) : 0; }
const addFail = k => { const f = fails.get(k) || { n: 0 }; fails.set(k, { n: f.n + 1, t: Date.now() }); };
function fullData(a) {
  const u = a.u, adm = u.role === 'admin', cs = [];
  for (const c of DB.contacts) if (adm || visible(c, u)) cs.push(pub(c, adm));
  const d = { role: u.role, name: u.name, u: u.u, v: DB.v, ord: DB.ord, contacts: cs, fav: DB.fav[u.u] || [], max: MAXU, rem: (a.s.exp - a.s.t) > 2 * DAY };
  if (adm) d.hc = DB.hc;
  return d;
}
const usersList = () => DB.users.filter(x => x.role !== 'admin').map(x => { const s = sessOf(x.u); return { u: x.u, name: x.name, hc: x.hc || [], bound: !!s, since: s ? s[1].t : 0 }; });
const validPw = (p, k) => typeof p === 'string' && typeof k === 'string' && p.length >= 8 && k.length >= 4;
const validU = u => /^[a-z0-9._-]{3,32}$/.test(u);
// ---- server
http.createServer(async (req, res) => {
  const P = new URL(req.url, 'http://x').pathname, M = req.method;
  const sec = { 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer', 'X-Frame-Options': 'DENY' };
  if (M === 'GET' && (P === '/' || P === '/index.html')) { try { res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store', ...sec }); return res.end(fs.readFileSync(HTMLF)); } catch (e) { res.writeHead(500); return res.end('index.html missing'); } }
  if (P === '/healthz') { res.writeHead(200); return res.end('ok'); }
  if (!P.startsWith('/api/')) { res.writeHead(404); return res.end('Not found'); }
  const ip = String(req.headers['x-forwarded-for'] || req.socket.remoteAddress).split(',')[0].trim();
  if (limited(ip)) return send(req, res, 429, { err: 'rate' });
  const url = new URL(req.url, 'http://x'), parts = P.split('/').filter(Boolean).slice(1), A = parts[0];
  try {
    if (A === 'login' && M === 'POST') {
      const q = await readBody(req, 2000); if (!q) return send(req, res, 400, {});
      const u = str(q.u, 64).toLowerCase(), w = Math.max(lockWait('ip:' + ip), lockWait('u:' + u));
      if (w) return send(req, res, 429, { err: 'locked', wait: w });
      const usr = DB.users.find(x => x.u === u), salt = usr ? usr.salt : '00'.repeat(16);
      const h = hashPw(q.p || '', q.k || '', salt), ok = usr && h.length === usr.h.length && crypto.timingSafeEqual(Buffer.from(h), Buffer.from(usr.h));
      if (!ok) { addFail('ip:' + ip); addFail('u:' + u); return send(req, res, 401, { err: 'bad' }); }
      fails.delete('ip:' + ip); fails.delete('u:' + u);
      const dev = str(q.dev, 64), ex = sessOf(u);
      if (ex && ex[1].dev !== dev) return send(req, res, 409, { err: 'bound' });
      if (ex) kill(ex[0], false);
      const sid = crypto.randomBytes(32).toString('hex'), now = Date.now(), rem = !!q.remember;
      DB.sessions[sid] = { u, dev, t: now, exp: now + (rem ? 365 * DAY : 12 * 3600e3) }; save();
      const secure = (req.headers['x-forwarded-proto'] || '') === 'https' ? '; Secure' : '';
      return send(req, res, 200, { ok: true }, { 'Set-Cookie': `sid=${sid}; HttpOnly; SameSite=Strict; Path=/${rem ? '; Max-Age=31536000' : ''}${secure}` });
    }
    const a = auth(req); if (!a) return send(req, res, 401, { err: 'auth' });
    const adm = a.u.role === 'admin';
    if (A === 'logout' && M === 'POST') { kill(a.sid, false); save(); return send(req, res, 200, { ok: true }, { 'Set-Cookie': 'sid=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0' }); }
    if (A === 'events' && M === 'GET') {
      res.writeHead(200, { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache', Connection: 'keep-alive', 'X-Accel-Buffering': 'no' });
      res.write('retry: 4000\n\n'); const old = streams.get(a.sid); if (old) { try { old.end(); } catch (e) {} }
      streams.set(a.sid, res); req.on('close', () => { if (streams.get(a.sid) === res) streams.delete(a.sid); }); return;
    }
    if (A === 'data' && M === 'GET') {
      const since = parseInt(url.searchParams.get('since') || '0', 10);
      if (since && since === DB.v) return send(req, res, 200, { same: true, v: DB.v });
      if (since && since > DB.v) return send(req, res, 200, fullData(a));
      if (since && since >= LOGMIN) {
        const es = LOG.filter(e => e.v > since);
        if (!es.some(e => e.t === 'r')) return send(req, res, 200, { delta: true, v: DB.v, ops: es.map(e => ({ id: e.id, c: e.c && (adm || visible(e.c, a.u)) ? pub(e.c, adm) : null })) });
      }
      return send(req, res, 200, fullData(a));
    }
    if (A === 'fav' && M === 'POST') {
      const q = await readBody(req, 1000); if (!q) return send(req, res, 400, {});
      const l = new Set(DB.fav[a.u.u] || []); if (q.on) l.add(+q.id); else l.delete(+q.id); DB.fav[a.u.u] = [...l]; save(); return send(req, res, 200, { ok: true });
    }
    if (!adm) return send(req, res, 403, { err: 'admin' });
    if (A === 'contact') {
      if (M === 'POST') { const q = await readBody(req, 5000), c = q && clean(q); if (!q || typeof c === 'string') return send(req, res, 400, { err: c || 'bad' }); const o = { i: DB.next++, ...c }; DB.contacts.push(o); bump({ t: 'c', id: o.i, c: o }); return send(req, res, 200, { ok: true, v: DB.v, id: o.i }); }
      const id = +parts[1], k = DB.contacts.findIndex(x => x.i === id); if (k < 0) return send(req, res, 404, {});
      if (M === 'PUT') { const q = await readBody(req, 5000), c = q && clean(q); if (!q || typeof c === 'string') return send(req, res, 400, { err: c || 'bad' }); DB.contacts[k] = { i: id, ...c }; bump({ t: 'c', id, c: DB.contacts[k] }); return send(req, res, 200, { ok: true, v: DB.v }); }
      if (M === 'DELETE') { DB.contacts.splice(k, 1); bump({ t: 'c', id, c: null }); return send(req, res, 200, { ok: true, v: DB.v }); }
    }
    if (A === 'import' && M === 'POST') {
      const q = await readBody(req, 8e6); if (!q || !Array.isArray(q.contacts)) return send(req, res, 400, {});
      const key = c => c.w ? c.w + '|' + c.c : c.n + '|' + c.p + '|' + c.c, have = new Set(DB.contacts.map(key));
      let add = 0, dup = 0, bad = 0;
      for (const x of q.contacts.slice(0, 30000)) { const c = clean(x); if (typeof c === 'string') { bad++; continue; } if (have.has(key(c))) { dup++; continue; } have.add(key(c)); DB.contacts.push({ i: DB.next++, ...c }); add++; }
      if (add) bump(); return send(req, res, 200, { ok: true, added: add, dup, bad, v: DB.v });
    }
    if (A === 'users' && M === 'GET') return send(req, res, 200, { users: usersList(), max: MAXU });
    if (A === 'user') {
      if (M === 'POST') {
        const q = await readBody(req, 3000); if (!q) return send(req, res, 400, {}); const u = str(q.u, 32).toLowerCase(), name = str(q.name, 80);
        if (!name || !validU(u)) return send(req, res, 400, { err: 'fields' }); if (!validPw(q.p, q.k)) return send(req, res, 400, { err: 'weak' });
        if (DB.users.some(x => x.u === u)) return send(req, res, 409, { err: 'exists' }); if (DB.users.filter(x => x.role !== 'admin').length >= MAXU) return send(req, res, 409, { err: 'max' });
        DB.users.push(mkUser(u, name, q.p, q.k, 'user', Array.isArray(q.hc) ? q.hc.map(x => str(x, 120)) : [])); bump(); return send(req, res, 200, { ok: true });
      }
      const x = DB.users.find(z => z.u === String(parts[1] || '').toLowerCase() && z.role !== 'admin'); if (!x) return send(req, res, 404, {});
      if (M === 'PUT') {
        const q = await readBody(req, 3000); if (!q) return send(req, res, 400, {}); if (q.name !== undefined) x.name = str(q.name, 80) || x.name; if (Array.isArray(q.hc)) x.hc = q.hc.map(z => str(z, 120));
        if (q.p || q.k) { if (!validPw(q.p, q.k)) return send(req, res, 400, { err: 'weak' }); x.salt = crypto.randomBytes(16).toString('hex'); x.h = hashPw(q.p, q.k, x.salt); }
        killUser(x.u); bump(); return send(req, res, 200, { ok: true });
      }
      if (M === 'DELETE') { killUser(x.u); DB.users = DB.users.filter(z => z !== x); delete DB.fav[x.u]; bump(); return send(req, res, 200, { ok: true }); }
    }
    if (A === 'unbind' && M === 'POST') { const q = await readBody(req, 500); if (!q) return send(req, res, 400, {}); const u = str(q.u, 32).toLowerCase(); if (u === a.u.u) return send(req, res, 400, {}); killUser(u); return send(req, res, 200, { ok: true }); }
    if (A === 'hc' && M === 'PUT') { const q = await readBody(req, 20000); if (!q || !Array.isArray(q.hc)) return send(req, res, 400, {}); DB.hc = q.hc.map(x => str(x, 120)); bump(); return send(req, res, 200, { ok: true }); }
    if (A === 'account' && M === 'PUT') {
      const q = await readBody(req, 1000), u = q && str(q.u, 32).toLowerCase(); if (!q || !validU(u) || !validPw(q.p, q.k)) return send(req, res, 400, { err: 'weak' });
      if (u !== a.u.u && DB.users.some(x => x.u === u)) return send(req, res, 409, { err: 'exists' });
      for (const s of Object.values(DB.sessions)) if (s.u === a.u.u) s.u = u; delete DB.fav[a.u.u]; a.u.u = u; a.u.salt = crypto.randomBytes(16).toString('hex'); a.u.h = hashPw(q.p, q.k, a.u.salt); save(); return send(req, res, 200, { ok: true });
    }
    if (A === 'backup' && M === 'GET') { const { sessions, ...rest } = DB; return send(req, res, 200, rest, { 'Content-Disposition': 'attachment; filename="phonebook-backup.json"' }); }
    if (A === 'restore' && M === 'POST') {
      const q = await readBody(req, 30e6), d = q && q.db; if (!d || !Array.isArray(d.contacts) || !Array.isArray(d.users) || !d.users.some(x => x.role === 'admin')) return send(req, res, 400, { err: 'shape' });
      DB = { ...d, sessions: DB.sessions, fav: d.fav || {}, hc: d.hc || [], ord: d.ord || [], next: Math.max(d.next || 1, ...d.contacts.map(c => c.i + 1), 1), v: Math.max(DB.v, d.v || 1) + 1 };
      for (const [sid, s] of Object.entries(DB.sessions)) if (!DB.users.some(x => x.u === s.u)) kill(sid, true);
      bump(); return send(req, res, 200, { ok: true });
    }
    return send(req, res, 404, {});
  } catch (e) { console.error(e); try { send(req, res, 500, { err: 'server' }); } catch (_) {} }
}).listen(process.env.PORT || 3000, () => console.log('listening'));
