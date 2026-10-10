// خادم خفيف بلا مكتبات خارجية: يقدّم index.html ويفرض "جهاز واحد لكل مستخدم"
const http = require('http'), fs = require('fs'), path = require('path'), crypto = require('crypto');
const DIR = __dirname, HTML = path.join(DIR, 'index.html');
const DB = path.join(process.env.DATA_DIR || DIR, 'bindings.json');
const sha = t => crypto.createHash('sha256').update(t).digest('hex');
let cache = { m: 0, html: '', V: { vaults: {} } };
function load() {
  const m = fs.statSync(HTML).mtimeMs;
  if (m !== cache.m) {
    const html = fs.readFileSync(HTML, 'utf8');
    const mt = html.match(/<script id="vaults"[^>]*>([\s\S]*?)<\/script>/);
    let V = { vaults: {} }; try { V = JSON.parse(mt[1]); } catch (e) {}
    cache = { m, html, V };
  }
  return cache;
}
let B = {}; try { B = JSON.parse(fs.readFileSync(DB, 'utf8')); } catch (e) {}
let t = null; const save = () => { clearTimeout(t); t = setTimeout(() => { try { fs.writeFileSync(DB, JSON.stringify(B)); } catch (e) {} }, 300); };
function verify(id, tok) {
  const v = load().V.vaults[id]; if (!v || !v.a || typeof tok !== 'string') return null;
  const a = Buffer.from(sha('v|' + tok)), b = Buffer.from(v.a);
  return a.length === b.length && crypto.timingSafeEqual(a, b) ? v : null;
}
const hits = new Map();
const limited = ip => { const n = Date.now(), h = (hits.get(ip) || []).filter(x => n - x < 60000); h.push(n); hits.set(ip, h); return h.length > 120; };
const send = (res, code, obj) => { res.writeHead(code, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' }); res.end(JSON.stringify(obj)); };
http.createServer((req, res) => {
  const sec = { 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer', 'X-Frame-Options': 'DENY' };
  if (req.method === 'GET' && (req.url === '/' || req.url.startsWith('/index.html'))) {
    try { res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store', ...sec }); res.end(load().html); }
    catch (e) { res.writeHead(500); res.end('index.html غير موجود'); }
    return;
  }
  if (req.method === 'GET' && req.url === '/healthz') { res.writeHead(200); return res.end('ok'); }
  if (req.method === 'POST' && req.url.startsWith('/api/')) {
    const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
    if (limited(String(ip))) return send(res, 429, { ok: false });
    let body = ''; req.on('data', d => { body += d; if (body.length > 5000) req.destroy(); });
    req.on('end', () => {
      let q; try { q = JSON.parse(body); } catch (e) { return send(res, 400, { ok: false }); }
      const act = req.url.slice(5), v = verify(q.id, q.tok), dev = String(q.dev || '').slice(0, 64), now = Date.now();
      if (!v || !dev) return send(res, 401, { ok: false });
      if (act === 'bind') {
        const b = B[q.id];
        if (b && b.d !== dev) return send(res, 409, { ok: false, err: 'bound' });
        B[q.id] = { d: dev, t: b ? b.t : now, l: now }; save(); return send(res, 200, { ok: true });
      }
      if (act === 'release') { if (B[q.id] && B[q.id].d === dev) { delete B[q.id]; save(); } return send(res, 200, { ok: true }); }
      if (act === 'admin/list' || act === 'admin/unbind') {
        if (!v.ad) return send(res, 403, { ok: false });
        if (act === 'admin/list') { const o = {}; for (const k in B) o[k] = { t: B[k].t, l: B[k].l }; return send(res, 200, { ok: true, b: o }); }
        delete B[String(q.target)]; save(); return send(res, 200, { ok: true });
      }
      send(res, 404, { ok: false });
    });
    return;
  }
  res.writeHead(404); res.end('Not found');
}).listen(process.env.PORT || 3000, () => console.log('listening'));
