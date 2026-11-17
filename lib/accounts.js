'use strict';
const crypto = require('crypto');
const { promisify } = require('util');
const { db, save, audit } = require('./db');
const scrypt = promisify(crypto.scrypt);

const START_COINS = Number(process.env.START_COINS) || 500;
const COST_PER_CHAT = Number(process.env.COST_PER_CHAT) || 3;
const ONLINE_WINDOW_MS = 90 * 1000;
const SESSION_TTL_MS = 60 * 24 * 3600 * 1000;
const DEFAULT_ADMIN_PASSWORD = '123456AdminDeepline';

const keyOf = (name) => String(name || '').trim().toLowerCase();
const sha = (s) => crypto.createHash('sha256').update(s).digest('hex');

async function hashPassword(password, salt = crypto.randomBytes(16).toString('hex')) {
  const buf = await scrypt(password, salt, 64);
  return { salt, hash: buf.toString('hex') };
}
async function verifyPassword(user, password) {
  const { hash } = await hashPassword(password, user.salt);
  const a = Buffer.from(hash, 'hex'), b = Buffer.from(user.hash, 'hex');
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

const USERNAME_RE = /^[A-Za-z0-9_\u4e00-\u9fa5]{3,20}$/;
function validateCredentials(username, password) {
  if (!USERNAME_RE.test(username || '')) return '用户名需为 3–20 个字符：字母、数字、下划线或中文';
  if (typeof password !== 'string' || password.length < 6 || password.length > 64) return '密码需为 6–64 个字符';
  return '';
}

async function register(username, password) {
  const err = validateCredentials(username, password);
  if (err) return { error: err, status: 400 };
  const key = keyOf(username);
  if (key === 'admin') return { error: '该用户名已被保留', status: 409 };
  if (db.users[key]) return { error: '用户名已被注册', status: 409 };
  const { salt, hash } = await hashPassword(password);
  db.users[key] = { username: username.trim(), salt, hash, coins: START_COINS, desk: START_COINS, role: 'user', banned: false, createdAt: Date.now(), lastSeen: Date.now(), lastLoginAt: Date.now(), usedCodes: [], freeCalls: 0, settings: null };
  audit(username, 'register', username, `赠送 ${START_COINS} 金币 + ${START_COINS} 桌币`);
  save();
  return { user: db.users[key] };
}

/** Admin account is created automatically at startup. ADMIN_PASSWORD env overrides the default password. */
async function ensureAdmin() {
  const pw = process.env.ADMIN_PASSWORD || DEFAULT_ADMIN_PASSWORD;
  const existing = db.users.admin;
  if (!existing) {
    const { salt, hash } = await hashPassword(pw);
    db.users.admin = { username: 'Admin', salt, hash, coins: START_COINS, desk: START_COINS, role: 'admin', banned: false, createdAt: Date.now(), lastSeen: 0, lastLoginAt: 0, usedCodes: [], freeCalls: 0, settings: null, defaultPassword: pw === DEFAULT_ADMIN_PASSWORD };
    audit('system', 'create-admin', 'Admin');
  } else {
    existing.role = 'admin'; existing.banned = false;
    if (process.env.ADMIN_PASSWORD && !(await verifyPassword(existing, process.env.ADMIN_PASSWORD))) {
      const { salt, hash } = await hashPassword(process.env.ADMIN_PASSWORD);
      existing.salt = salt; existing.hash = hash; existing.defaultPassword = false;
      audit('system', 'admin-password-from-env', 'Admin');
    }
  }
  save();
  return db.users.admin.defaultPassword === true;
}

async function login(username, password) {
  const user = db.users[keyOf(username)];
  // always do the hash work so timing does not reveal whether the user exists
  const ok = user ? await verifyPassword(user, password || '') : (await hashPassword(password || '', 'deadbeefdeadbeefdeadbeefdeadbeef'), false);
  if (!user || !ok) return { error: '用户名或密码错误', status: 401 };
  if (user.banned) return { error: '该账号已被封禁，请联系管理员', status: 403 };
  user.lastLoginAt = Date.now(); user.lastSeen = Date.now();
  save();
  return { user };
}

function newSession(user) {
  const token = crypto.randomBytes(32).toString('base64url');
  db.sessions[sha(token)] = { u: keyOf(user.username), c: Date.now() };
  // prune
  const now = Date.now();
  for (const [h, s] of Object.entries(db.sessions)) if (now - s.c > SESSION_TTL_MS || !db.users[s.u]) delete db.sessions[h];
  save();
  return token;
}
function dropSessionsOf(key) { for (const [h, s] of Object.entries(db.sessions)) if (s.u === key) delete db.sessions[h]; }

function authenticate(req) {
  const m = /^Bearer (.+)$/.exec(req.headers.authorization || '');
  if (!m) return { error: '请先登录', status: 401 };
  const s = db.sessions[sha(m[1])];
  if (!s || Date.now() - s.c > SESSION_TTL_MS) return { error: '登录已过期，请重新登录', status: 401 };
  const user = db.users[s.u];
  if (!user) return { error: '账号不存在', status: 401 };
  if (typeof user.desk !== 'number') user.desk = START_COINS; // accounts created before Desk Coins
  if (user.banned) return { error: '该账号已被封禁，请联系管理员', status: 403, banned: true };
  user.lastSeen = Date.now();
  return { user, key: s.u, tokenHash: sha(m[1]) };
}

const publicUser = (u) => ({ username: u.username, coins: u.coins, desk: u.desk || 0, role: u.role, createdAt: u.createdAt });
const isOnline = (u) => Date.now() - (u.lastSeen || 0) < ONLINE_WINDOW_MS;

function code12() {
  const A = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  const b = crypto.randomBytes(12);
  let s = ''; for (let i = 0; i < 12; i++) s += A[b[i] % A.length];
  return `${s.slice(0, 4)}-${s.slice(4, 8)}-${s.slice(8)}`;
}
const normCode = (c) => String(c || '').trim().toUpperCase().replace(/\s+/g, '');

function redeem(user, rawCode) {
  const code = normCode(rawCode);
  const c = db.codes[code];
  if (!code || !c || !c.active) return { error: '兑换码无效', status: 404 };
  if (c.uses >= c.maxUses) return { error: '该兑换码已被用完', status: 410 };
  if (c.usedBy.includes(keyOf(user.username))) return { error: '你已经使用过这个兑换码', status: 409 };
  c.uses += 1; c.usedBy.push(keyOf(user.username));
  const cur = c.currency === 'desk' ? 'desk' : 'gold';
  user[cur === 'desk' ? 'desk' : 'coins'] = (user[cur === 'desk' ? 'desk' : 'coins'] || 0) + c.amount; user.usedCodes.push(code);
  audit(user.username, 'redeem', code, `+${c.amount} ${cur === 'desk' ? '桌币' : '金币'}`);
  save();
  return { added: c.amount, currency: cur, coins: user.coins, desk: user.desk || 0 };
}

module.exports = { START_COINS, COST_PER_CHAT, DEFAULT_ADMIN_PASSWORD, keyOf, hashPassword, verifyPassword, validateCredentials, register, ensureAdmin, login, newSession, dropSessionsOf, authenticate, publicUser, isOnline, code12, normCode, redeem, ONLINE_WINDOW_MS };
