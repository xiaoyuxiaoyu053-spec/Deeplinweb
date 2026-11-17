'use strict';
/**
 * DeepLine server — zero dependencies.
 *  - serves ./public (the web app and /admin)
 *  - accounts: register / login (username + password only), 金币 balance, redeem codes, settings backup
 *  - /api/free-ai : the developer's free AI (key lives in env FREE_API_KEY, never sent to clients), 3 金币 per reply
 *  - /api/ai      : stateless relay for users' own API keys (login required)
 *  - /api/admin/* : admin-only backend (online users, redeem codes, ban/unban, coins)
 */
const http = require('http');
const fs = require('fs');
const path = require('path');
const zlib = require('zlib');
const A = require('./lib/accounts');
const { db, save, audit, DATA_DIR, persistentConfigured } = require('./lib/db');

const PORT = Number(process.env.PORT) || 3000;
const PUBLIC_DIR = path.join(__dirname, 'public');
const MAX_BODY = 16 * 1024 * 1024; // own-key vision requests carry base64 images
const MAX_FREE_BODY = 3 * 1024 * 1024;
const RATE_PER_MIN = Number(process.env.RATE_LIMIT_PER_MIN) || 90;

const PROVIDERS = {
  'DeepSeek': 'https://api.deepseek.com/chat/completions',
  'Claude': 'https://api.anthropic.com/v1/messages',
  '豆包': 'https://ark.cn-beijing.volces.com/api/v3/chat/completions',
  'ChatGPT / OpenAI': 'https://api.openai.com/v1/chat/completions',
};
const DEFAULT_MODEL = { 'DeepSeek': 'deepseek-chat', 'Claude': 'claude-sonnet-5', '豆包': 'doubao-seed-2-1-pro-260915', 'ChatGPT / OpenAI': 'gpt-4.1-mini' };
const FREE = {
  provider: PROVIDERS[process.env.FREE_API_PROVIDER] ? process.env.FREE_API_PROVIDER : 'DeepSeek',
  key: process.env.FREE_API_KEY || '',
};
FREE.model = process.env.FREE_API_MODEL || DEFAULT_MODEL[FREE.provider];
const UPSTREAM_OVERRIDE = process.env.UPSTREAM_OVERRIDE || ''; // TEST ONLY: send every upstream call to a local mock
const upstreamUrl = (provider) => (UPSTREAM_OVERRIDE ? `${UPSTREAM_OVERRIDE}/${encodeURIComponent(provider)}` : PROVIDERS[provider]);
const FORWARD_HEADERS = ['authorization', 'x-api-key', 'anthropic-version'];
const SETTINGS_KEYS = new Set(['theme', 'glassUi', 'glassOpacity', 'soundEnabled', 'backgroundAlpha', 'backgroundBlur', 'bubbleColor', 'myBubbleColor', 'aiTextColor', 'myTextColor', 'bubbleShape', 'chatTheme', 'appTitle', 'inputHint', 'memoryLimit', 'multiReplyEnabled', 'multiReplyCount', 'deepThinkingEnabled', 'conversationSummaryEnabled', 'aiMomentsEnabled', 'autoAiEnabled', 'myName', 'myBio', 'directMode', 'fontChoice', 'glassOpacityMobile']);

const MIME = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.json': 'application/json; charset=utf-8', '.webmanifest': 'application/manifest+json', '.png': 'image/png', '.jpg': 'image/jpeg', '.svg': 'image/svg+xml', '.wav': 'audio/wav', '.ico': 'image/x-icon', '.txt': 'text/plain; charset=utf-8' };
const COMPRESSIBLE = new Set(['.html', '.js', '.css', '.json', '.webmanifest', '.svg', '.txt']);
const CSP = ["default-src 'self'", "script-src 'self'", "style-src 'self' 'unsafe-inline'", "img-src 'self' data: blob:", "media-src 'self' data: blob:", "font-src 'self' data:",
  "connect-src 'self' https://api.deepseek.com https://api.anthropic.com https://ark.cn-beijing.volces.com https://api.openai.com", "frame-ancestors 'none'", "base-uri 'none'", "form-action 'self'"].join('; ');

function securityHeaders(res) {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Content-Security-Policy', CSP);
  res.setHeader('Permissions-Policy', 'microphone=(self), camera=()');
}

// ───────────── rate limiting ─────────────
const buckets = new Map();
function exceeded(key, max, windowMs) {
  const now = Date.now();
  const arr = (buckets.get(key) || []).filter((t) => now - t < windowMs);
  arr.push(now); buckets.set(key, arr);
  if (buckets.size > 20000) for (const [k, v] of buckets) if (!v.length || now - v[v.length - 1] > 3600_000) buckets.delete(k);
  return arr.length > max;
}
const ipOf = (req) => String(req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim();
const failedLogins = new Map(); // username -> { n, until }

// ───────────── helpers ─────────────
function send(res, status, obj, extra) {
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', ...(extra || {}) });
  res.end(JSON.stringify(obj));
}
const fail = (res, status, message, extra) => send(res, status, { error: { message }, ...(extra || {}) });
function readBody(req, max) {
  return new Promise((resolve, reject) => {
    let size = 0, failed = false;
    const chunks = [];
    req.on('data', (c) => { if (failed) return; size += c.length; if (size > max) { failed = true; chunks.length = 0; reject(Object.assign(new Error('请求体过大'), { status: 413 })); return; } chunks.push(c); });
    req.on('end', () => { if (!failed) resolve(Buffer.concat(chunks).toString('utf8')); });
    req.on('error', (e) => { if (!failed) reject(e); });
  });
}
async function readJson(req, res, max = 256 * 1024) {
  try { return JSON.parse((await readBody(req, max)) || '{}'); }
  catch (e) {
    if (e.status === 413) { res.writeHead(413, { 'Content-Type': 'application/json; charset=utf-8', Connection: 'close' }); res.end(JSON.stringify({ error: { message: '请求体过大' } })); res.on('finish', () => req.destroy()); }
    else fail(res, 400, '请求格式错误');
    return null;
  }
}
function authed(req, res, adminOnly = false) {
  const a = A.authenticate(req);
  if (a.error) { fail(res, a.status, a.error, a.banned ? { banned: true } : undefined); return null; }
  if (adminOnly && a.user.role !== 'admin') { fail(res, 403, '需要管理员权限'); return null; }
  return a;
}

// ───────────── public + account endpoints ─────────────
function configInfo() {
  return { freeApiAvailable: !!FREE.key, freeProvider: FREE.provider, freeModel: FREE.model, costPerChat: A.COST_PER_CHAT, startCoins: A.START_COINS, currency: '金币' };
}
async function handleRegister(req, res) {
  const ip = ipOf(req);
  if (exceeded('reg:' + ip, 10, 3600_000)) return fail(res, 429, '注册过于频繁，请稍后再试');
  const body = await readJson(req, res); if (!body) return;
  const r = await A.register(String(body.username || '').trim(), body.password);
  if (r.error) return fail(res, r.status, r.error);
  send(res, 200, { token: A.newSession(r.user), user: A.publicUser(r.user) });
}
async function handleLogin(req, res) {
  const ip = ipOf(req);
  if (exceeded('login:' + ip, 30, 600_000)) return fail(res, 429, '登录尝试过于频繁，请稍后再试');
  const body = await readJson(req, res); if (!body) return;
  const key = A.keyOf(body.username);
  const lock = failedLogins.get(key);
  if (lock && lock.until > Date.now()) return fail(res, 429, '该账号登录失败次数过多，请 5 分钟后再试');
  const r = await A.login(String(body.username || ''), body.password);
  if (r.error) {
    if (r.status === 401) { const f = failedLogins.get(key) || { n: 0, until: 0 }; f.n += 1; if (f.n >= 8) { f.until = Date.now() + 300_000; f.n = 0; } failedLogins.set(key, f); }
    return fail(res, r.status, r.error);
  }
  failedLogins.delete(key);
  send(res, 200, { token: A.newSession(r.user), user: A.publicUser(r.user) });
}

async function handleFreeAi(req, res) {
  if (!FREE.key) return fail(res, 503, '管理员尚未配置免费 API');
  const a = authed(req, res); if (!a) return;
  if (exceeded('free:' + a.key, 30, 60_000)) return fail(res, 429, '请求太频繁，请稍后再试');
  const payload = await readJson(req, res, MAX_FREE_BODY); if (!payload) return;
  const body = payload.body;
  if (!body || typeof body !== 'object' || !Array.isArray(body.messages)) return fail(res, 400, '缺少请求内容');
  const user = a.user;
  if (user.coins < A.COST_PER_CHAT) return fail(res, 402, `金币不足（每次对话需要 ${A.COST_PER_CHAT} 金币），请使用兑换码充值，或改用自己的 API Key。`, { coins: user.coins });
  // pay first (atomic: single-threaded), refund if the upstream call fails
  user.coins -= A.COST_PER_CHAT; user.freeCalls = (user.freeCalls || 0) + 1; save();
  const upstreamBody = { ...body, model: FREE.model, max_tokens: Math.min(Number(body.max_tokens) || 2048, 2048) };
  delete upstreamBody.stream;
  const headers = { 'Content-Type': 'application/json' };
  if (FREE.provider === 'Claude') { headers['x-api-key'] = FREE.key; headers['anthropic-version'] = '2023-06-01'; } else headers.Authorization = 'Bearer ' + FREE.key;
  const refund = () => { user.coins += A.COST_PER_CHAT; user.freeCalls = Math.max(0, (user.freeCalls || 1) - 1); save(); };
  try {
    const up = await fetch(upstreamUrl(FREE.provider), { method: 'POST', headers, body: JSON.stringify(upstreamBody), signal: AbortSignal.timeout(120_000) });
    const text = await up.text();
    let json = null; try { json = JSON.parse(text); } catch { /* not json */ }
    if (!up.ok || !json) { refund(); return send(res, up.ok ? 502 : up.status, json ? { ...json, _coins: user.coins } : { error: { message: '免费 API 暂时不可用，已退还金币。' }, _coins: user.coins }); }
    json._coins = user.coins; json._cost = A.COST_PER_CHAT;
    send(res, 200, json);
  } catch (e) {
    refund();
    fail(res, 502, '免费 API 暂时不可用，已退还金币。', { _coins: user.coins });
  }
}

async function handleOwnKeyAi(req, res) {
  const a = authed(req, res); if (!a) return;
  if (exceeded('ai:' + ipOf(req), RATE_PER_MIN, 60_000)) return fail(res, 429, '请求太频繁，请稍后再试');
  const payload = await readJson(req, res, MAX_BODY); if (!payload) return;
  const url = PROVIDERS[payload.provider] && upstreamUrl(payload.provider);
  if (!url) return fail(res, 400, '不支持的 AI 服务商');
  if (!payload.body || typeof payload.body !== 'object') return fail(res, 400, '缺少请求内容');
  const headers = { 'Content-Type': 'application/json' };
  for (const [k, v] of Object.entries(payload.headers || {})) if (FORWARD_HEADERS.includes(String(k).toLowerCase()) && typeof v === 'string') headers[k] = v;
  try {
    const up = await fetch(url, { method: 'POST', headers, body: JSON.stringify(payload.body), signal: AbortSignal.timeout(120_000) });
    const text = await up.text();
    res.writeHead(up.status, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' }); res.end(text);
  } catch (e) { fail(res, 502, '服务器无法连接 AI 服务商：' + (e && e.name === 'TimeoutError' ? '超时' : (e && e.message) || '未知错误')); }
}

// ───────────── admin endpoints ─────────────
const adminUserView = (u) => ({ username: u.username, coins: u.coins, desk: u.desk || 0, role: u.role, banned: !!u.banned, online: A.isOnline(u), lastSeen: u.lastSeen || 0, lastLoginAt: u.lastLoginAt || 0, createdAt: u.createdAt, freeCalls: u.freeCalls || 0 });
async function handleAdmin(req, res, pathname) {
  const a = authed(req, res, true); if (!a) return;
  const who = a.user.username;
  const method = req.method;
  let m;
  if (method === 'GET' && pathname === '/api/admin/stats') {
    const users = Object.values(db.users), online = users.filter(A.isOnline);
    return send(res, 200, {
      online: online.length, onlineUsers: online.map((u) => u.username), totalUsers: users.length, bannedUsers: users.filter((u) => u.banned).length,
      codes: { total: Object.keys(db.codes).length, active: Object.values(db.codes).filter((c) => c.active && c.uses < c.maxUses).length },
      defaultAdminPassword: db.users.admin && db.users.admin.defaultPassword === true, persistentDisk: persistentConfigured, dataDir: persistentConfigured ? DATA_DIR : null,
      freeApi: { configured: !!FREE.key, provider: FREE.provider, model: FREE.model, cost: A.COST_PER_CHAT }, startCoins: A.START_COINS, serverTime: Date.now(),
    });
  }
  if (method === 'GET' && pathname === '/api/admin/users') {
    const q = (new URL(req.url, 'http://x').searchParams.get('q') || '').toLowerCase();
    const list = Object.values(db.users).filter((u) => !q || u.username.toLowerCase().includes(q)).map(adminUserView)
      .sort((x, y) => (y.online - x.online) || (y.lastSeen - x.lastSeen) || (y.createdAt - x.createdAt)).slice(0, 500);
    return send(res, 200, { users: list });
  }
  if (method === 'POST' && (m = /^\/api\/admin\/users\/([^/]+)\/ban$/.exec(pathname))) {
    const body = await readJson(req, res); if (!body) return;
    const key = A.keyOf(decodeURIComponent(m[1])), u = db.users[key];
    if (!u) return fail(res, 404, '账号不存在');
    if (key === 'admin') return fail(res, 400, '不能封禁管理员账号');
    u.banned = !!body.banned;
    audit(who, u.banned ? 'ban' : 'unban', u.username); save();
    return send(res, 200, { user: adminUserView(u) });
  }
  if (method === 'POST' && (m = /^\/api\/admin\/users\/([^/]+)\/coins$/.exec(pathname))) {
    const body = await readJson(req, res); if (!body) return;
    const u = db.users[A.keyOf(decodeURIComponent(m[1]))];
    if (!u) return fail(res, 404, '账号不存在');
    const field = body.currency === 'desk' ? 'desk' : 'coins';
    const before = u[field] || 0;
    if (Number.isFinite(Number(body.set))) u[field] = Math.min(1e9, Math.max(0, Math.trunc(Number(body.set))));
    else if (Number.isFinite(Number(body.delta))) u[field] = Math.min(1e9, Math.max(0, before + Math.trunc(Number(body.delta))));
    else return fail(res, 400, '请提供 delta 或 set');
    audit(who, 'coins', u.username, `${field === 'desk' ? '桌币' : '金币'} ${before} → ${u[field]}`); save();
    return send(res, 200, { user: adminUserView(u) });
  }
  if (method === 'GET' && pathname === '/api/admin/codes') {
    return send(res, 200, { codes: Object.values(db.codes).sort((x, y) => y.createdAt - x.createdAt).map((c) => ({ code: c.code, amount: c.amount, currency: c.currency || 'gold', maxUses: c.maxUses, uses: c.uses, active: c.active, createdAt: c.createdAt, note: c.note || '', usedBy: c.usedBy.slice(-20) })) });
  }
  if (method === 'POST' && pathname === '/api/admin/codes') {
    const body = await readJson(req, res); if (!body) return;
    const amount = Math.trunc(Number(body.amount)), maxUses = Math.trunc(Number(body.maxUses || 1));
    if (!(amount >= 1 && amount <= 10_000_000)) return fail(res, 400, '金币数量需在 1–10000000 之间');
    if (!(maxUses >= 1 && maxUses <= 1_000_000)) return fail(res, 400, '可使用次数需在 1–1000000 之间');
    let code = body.code ? A.normCode(body.code) : A.code12();
    if (!/^[A-Z0-9_-]{3,32}$/.test(code)) return fail(res, 400, '兑换码只能包含字母、数字、- 和 _（3–32 位）');
    if (db.codes[code]) return fail(res, 409, '该兑换码已存在');
    const currency = body.currency === 'desk' ? 'desk' : 'gold';
    db.codes[code] = { code, amount, currency, maxUses, uses: 0, usedBy: [], active: true, createdAt: Date.now(), createdBy: who, note: String(body.note || '').slice(0, 60) };
    audit(who, 'code-create', code, `${amount} ${currency === 'desk' ? '桌币' : '金币'} × ${maxUses}`); save();
    return send(res, 200, { code: db.codes[code] });
  }
  if ((m = /^\/api\/admin\/codes\/([^/]+)$/.exec(pathname))) {
    const code = A.normCode(decodeURIComponent(m[1]));
    if (!db.codes[code]) return fail(res, 404, '兑换码不存在');
    if (method === 'DELETE') { delete db.codes[code]; audit(who, 'code-delete', code); save(); return send(res, 200, { ok: true }); }
    if (method === 'POST') { const body = await readJson(req, res); if (!body) return; db.codes[code].active = !!body.active; audit(who, body.active ? 'code-enable' : 'code-disable', code); save(); return send(res, 200, { code: db.codes[code] }); }
  }
  if (method === 'GET' && pathname === '/api/admin/log') return send(res, 200, { log: db.log.slice(-100).reverse() });
  fail(res, 404, '未知的管理接口');
}

// ───────────── router ─────────────
async function route(req, res, pathname) {
  const method = req.method;
  if (method === 'GET' && pathname === '/healthz') return send(res, 200, { ok: true });
  if (method === 'GET' && pathname === '/api/config') return send(res, 200, configInfo());
  if (method === 'POST' && pathname === '/api/register') return handleRegister(req, res);
  if (method === 'POST' && pathname === '/api/login') return handleLogin(req, res);
  if (method === 'POST' && pathname === '/api/logout') { const a = authed(req, res); if (!a) return; delete db.sessions[a.tokenHash]; save(); return send(res, 200, { ok: true }); }
  if (method === 'GET' && pathname === '/api/me') { const a = authed(req, res); if (!a) return; return send(res, 200, { user: A.publicUser(a.user) }); }
  if (method === 'GET' && pathname === '/api/balance') { const a = authed(req, res); if (!a) return; return send(res, 200, { coins: a.user.coins, desk: a.user.desk || 0 }); }
  if (method === 'POST' && pathname === '/api/password') {
    const a = authed(req, res); if (!a) return;
    const body = await readJson(req, res); if (!body) return;
    if (!(await A.verifyPassword(a.user, String(body.oldPassword || '')))) return fail(res, 403, '当前密码不正确');
    const err = A.validateCredentials(a.user.username.length >= 3 ? a.user.username : 'abc', body.newPassword);
    if (typeof body.newPassword !== 'string' || body.newPassword.length < 6 || body.newPassword.length > 64) return fail(res, 400, '新密码需为 6–64 个字符');
    const { salt, hash } = await A.hashPassword(body.newPassword);
    a.user.salt = salt; a.user.hash = hash; a.user.defaultPassword = false;
    for (const [h, s] of Object.entries(db.sessions)) if (s.u === a.key && h !== a.tokenHash) delete db.sessions[h];
    audit(a.user.username, 'password-change', a.user.username); save();
    return send(res, 200, { ok: true });
  }
  if (method === 'POST' && pathname === '/api/redeem') {
    const a = authed(req, res); if (!a) return;
    if (exceeded('redeem:' + a.key, 10, 600_000)) return fail(res, 429, '尝试次数过多，请稍后再试');
    const body = await readJson(req, res); if (!body) return;
    const r = A.redeem(a.user, body.code);
    if (r.error) return fail(res, r.status, r.error);
    return send(res, 200, r);
  }
  if (pathname === '/api/settings') {
    const a = authed(req, res); if (!a) return;
    if (method === 'GET') return send(res, 200, { settings: a.user.settings });
    if (method === 'PUT') {
      const body = await readJson(req, res, 64 * 1024); if (!body) return;
      const clean = {};
      for (const [k, v] of Object.entries(body.settings || {})) if (SETTINGS_KEYS.has(k) && (typeof v === 'string' || typeof v === 'number' || typeof v === 'boolean') && String(v).length < 200) clean[k] = v;
      a.user.settings = { data: clean, updatedAt: Date.now() }; save();
      return send(res, 200, { settings: a.user.settings });
    }
  }
  if (method === 'POST' && pathname === '/api/free-ai') return handleFreeAi(req, res);
  if (method === 'POST' && pathname === '/api/ai') return handleOwnKeyAi(req, res);
  if (pathname.startsWith('/api/admin/')) return handleAdmin(req, res, pathname);
  if (pathname.startsWith('/api/')) return fail(res, 404, '未知接口');
  return false;
}

function serveStatic(req, res, pathname) {
  if (pathname === '/admin') pathname = '/admin.html';
  let rel = decodeURIComponent(pathname);
  if (rel.endsWith('/')) rel += 'index.html';
  const file = path.normalize(path.join(PUBLIC_DIR, rel));
  if (!file.startsWith(PUBLIC_DIR)) { res.writeHead(403); return res.end('Forbidden'); }
  fs.stat(file, (err, st) => {
    if (err || !st.isFile()) {
      if (!path.extname(rel)) return serveStatic(req, res, '/index.html');
      res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' }); return res.end('Not found');
    }
    const ext = path.extname(file).toLowerCase();
    const headers = { 'Content-Type': MIME[ext] || 'application/octet-stream', 'Cache-Control': ['.html', '.js', '.css'].includes(ext) ? 'no-cache' : 'public, max-age=604800' };
    if (COMPRESSIBLE.has(ext) && /\bgzip\b/.test(req.headers['accept-encoding'] || '')) {
      headers['Content-Encoding'] = 'gzip'; headers.Vary = 'Accept-Encoding'; res.writeHead(200, headers);
      fs.createReadStream(file).pipe(zlib.createGzip()).pipe(res);
    } else { headers['Content-Length'] = st.size; res.writeHead(200, headers); fs.createReadStream(file).pipe(res); }
  });
}

const server = http.createServer(async (req, res) => {
  securityHeaders(res);
  const { pathname } = new URL(req.url, 'http://localhost');
  try {
    if (pathname.startsWith('/api/') || pathname === '/healthz') {
      const handled = await route(req, res, pathname);
      if (handled !== false) return;
    }
    if (req.method === 'GET' || req.method === 'HEAD') return serveStatic(req, res, pathname);
    res.writeHead(405); res.end('Method Not Allowed');
  } catch (e) {
    console.error('[server] error:', e && e.stack || e);
    if (!res.headersSent) fail(res, 500, '服务器内部错误'); else res.end();
  }
});

A.ensureAdmin().then((defaultPw) => {
  server.listen(PORT, '0.0.0.0', () => {
    console.log(`DeepLine server listening on :${PORT}`);
    if (!persistentConfigured) console.warn('[warn] DATA_DIR is not set: accounts/coins/codes are stored on the ephemeral disk and will be LOST on redeploy. Attach a Render Disk and set DATA_DIR.');
    if (defaultPw) console.warn('[warn] The Admin account still uses the default password. Set ADMIN_PASSWORD in the environment, or change it in /admin.');
    if (!FREE.key) console.warn('[info] FREE_API_KEY is not set: the free API option is hidden from users.');
  });
});
