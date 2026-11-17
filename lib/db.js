'use strict';
// Tiny JSON-file database (zero dependencies). Single process → all mutations are synchronous and atomic.
// IMPORTANT on Render: the default disk is EPHEMERAL (wiped on every deploy/restart). Attach a Render Disk and set DATA_DIR
// to its mount path (e.g. /var/data) or accounts, coins and codes will reset.
const fs = require('fs');
const path = require('path');

const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, '..', 'data');
const FILE = path.join(DATA_DIR, 'deepline-db.json');
const db = { users: {}, codes: {}, sessions: {}, log: [] };
let timer = null;

function load() {
  try {
    const parsed = JSON.parse(fs.readFileSync(FILE, 'utf8'));
    for (const k of Object.keys(db)) if (parsed[k] !== undefined) db[k] = parsed[k];
  } catch { /* first run */ }
}
function flush() {
  clearTimeout(timer); timer = null;
  try {
    fs.mkdirSync(DATA_DIR, { recursive: true });
    const tmp = FILE + '.tmp';
    fs.writeFileSync(tmp, JSON.stringify(db));
    fs.renameSync(tmp, FILE);
  } catch (e) { console.error('[db] save failed:', e.message); }
}
function save() { if (!timer) timer = setTimeout(flush, 400); }
function audit(who, act, target, detail) {
  db.log.push({ t: Date.now(), who, act, target: target || '', detail: detail || '' });
  if (db.log.length > 400) db.log.splice(0, db.log.length - 400);
}
for (const sig of ['SIGTERM', 'SIGINT']) process.on(sig, () => { flush(); process.exit(0); });
load();

module.exports = { db, save, flush, audit, DATA_DIR, persistentConfigured: !!process.env.DATA_DIR };
