const http = require('http');
const fs = require('fs');
const fsp = require('fs/promises');
const path = require('path');
const crypto = require('crypto');

const ROOT = __dirname;
const PORT = Number(process.env.PORT || 3000);
const AUTH_FILE = path.join(ROOT, 'dm-auth.json');
const DATA_FILE = path.join(ROOT, 'dm-data.json');
const CAMPAIGN_FILE = path.join(ROOT, 'campaign-data.json');
const SESSION_COOKIE = 'archades_dm_session';
const SESSION_TTL_MS = 1000 * 60 * 60 * 24 * 30;
const sessions = new Map();

let pinRecord = null;
let dmData = null;
let campaignStore = null;

function normalizeJoinCode(value) {
  return String(value || '').toUpperCase().replace(/[^A-Z0-9]/g, '').slice(0, 12);
}

function createDefaultDmData() {
  return {
    roster: [],
    notes: '',
    draft: { currentHp: '', currentSurges: '', tempHp: '', ongoingDamage: '', initiativeRoll: '', conditions: '' },
    encounter: { round: 1, activeId: '', notes: '', combatants: [] },
    presets: [],
    templates: []
  };
}

function normalizeDmData(value) {
  const source = value && typeof value === 'object' ? value : {};
  const base = createDefaultDmData();
  return {
    roster: Array.isArray(source.roster) ? source.roster : base.roster,
    notes: typeof source.notes === 'string' ? source.notes : base.notes,
    draft: source.draft && typeof source.draft === 'object' ? source.draft : base.draft,
    encounter: source.encounter && typeof source.encounter === 'object' ? source.encounter : base.encounter,
    presets: Array.isArray(source.presets) ? source.presets : base.presets,
    templates: Array.isArray(source.templates) ? source.templates : base.templates
  };
}

function loadDmData() {
  return normalizeDmData(safeReadJson(DATA_FILE));
}

async function saveDmData(data) {
  const payload = JSON.stringify(normalizeDmData(data), null, 2);
  return fsp.writeFile(DATA_FILE, payload + '\n', 'utf8');
}

function createDefaultCampaignRecord(code = '') {
  const now = new Date().toISOString();
  const joinCode = normalizeJoinCode(code);
  return {
    session: {
      id: `camp-${joinCode || crypto.randomBytes(4).toString('hex')}`,
      name: 'New Campaign',
      joinCode,
      createdAt: now,
      updatedAt: now,
      players: []
    },
    builder: null,
    updatedAt: now
  };
}

function normalizeCampaignRecord(value, code = '') {
  const source = value && typeof value === 'object' ? value : {};
  const fallback = createDefaultCampaignRecord(code);
  const session = source.session && typeof source.session === 'object' ? source.session : {};
  return {
    session: {
      id: String(session.id || fallback.session.id),
      name: String(session.name || fallback.session.name).trim() || fallback.session.name,
      joinCode: normalizeJoinCode(session.joinCode || code || fallback.session.joinCode) || fallback.session.joinCode,
      createdAt: String(session.createdAt || fallback.session.createdAt),
      updatedAt: String(session.updatedAt || fallback.session.updatedAt),
      players: Array.isArray(session.players) ? session.players.slice() : []
    },
    builder: source.builder && typeof source.builder === 'object' ? source.builder : null,
    updatedAt: String(source.updatedAt || fallback.updatedAt)
  };
}

function loadCampaignStore() {
  const raw = safeReadJson(CAMPAIGN_FILE);
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return {};
  return Object.entries(raw).reduce((acc, [code, record]) => {
    const normalizedCode = normalizeJoinCode(code);
    if (!normalizedCode) return acc;
    acc[normalizedCode] = normalizeCampaignRecord(record, normalizedCode);
    return acc;
  }, {});
}

async function saveCampaignStore(store) {
  const payload = JSON.stringify(store || {}, null, 2);
  return fsp.writeFile(CAMPAIGN_FILE, payload + '\n', 'utf8');
}

function getCampaignRecord(code) {
  const normalizedCode = normalizeJoinCode(code);
  if (!normalizedCode) return null;
  if (!campaignStore) campaignStore = loadCampaignStore();
  return campaignStore[normalizedCode] || null;
}

async function upsertCampaignRecord(code, patch = {}) {
  const normalizedCode = normalizeJoinCode(code);
  if (!normalizedCode) return null;
  if (!campaignStore) campaignStore = loadCampaignStore();
  const now = new Date().toISOString();
  const existing = campaignStore[normalizedCode] || createDefaultCampaignRecord(normalizedCode);
  const merged = Object.assign({}, existing, patch, { updatedAt: now, session: Object.assign({}, existing.session || {}, patch.session || {}, { updatedAt: now }) });
  const next = normalizeCampaignRecord(merged, normalizedCode);
  campaignStore[normalizedCode] = next;
  await saveCampaignStore(campaignStore);
  return next;
}

function requireDmSession(req, res) {
  const session = getSession(req);
  if (!session) {
    sendJson(res, 401, { error: 'DM authentication required.' });
    return null;
  }
  return session;
}

function normalizePin(value) {
  return String(value || '').replace(/\D/g, '').slice(0, 4);
}

function safeReadJson(filePath) {
  try {
    return JSON.parse(fs.readFileSync(filePath, 'utf8'));
  } catch {
    return null;
  }
}

function loadPinRecord() {
  const data = safeReadJson(AUTH_FILE);
  if (!data || typeof data !== 'object') return null;
  if (!data.salt || !data.hash) return null;
  return {
    salt: String(data.salt),
    hash: String(data.hash),
    createdAt: String(data.createdAt || new Date().toISOString()),
    updatedAt: String(data.updatedAt || data.createdAt || new Date().toISOString())
  };
}

function savePinRecord(record) {
  const payload = JSON.stringify(record, null, 2);
  return fsp.writeFile(AUTH_FILE, payload + '\n', 'utf8');
}

function hashPin(pin, salt = crypto.randomBytes(16).toString('hex')) {
  const normalized = normalizePin(pin);
  if (normalized.length !== 4) return null;
  const hash = crypto.scryptSync(normalized, salt, 32).toString('hex');
  return { salt, hash };
}

function verifyPin(pin, record) {
  const normalized = normalizePin(pin);
  if (normalized.length !== 4 || !record) return false;
  const expected = Buffer.from(String(record.hash), 'hex');
  const actual = crypto.scryptSync(normalized, String(record.salt), 32);
  return expected.length === actual.length && crypto.timingSafeEqual(expected, actual);
}

function parseCookies(req) {
  const header = req.headers.cookie || '';
  return header.split(';').reduce((acc, pair) => {
    const index = pair.indexOf('=');
    if (index === -1) return acc;
    const key = pair.slice(0, index).trim();
    const value = pair.slice(index + 1).trim();
    if (key) acc[key] = decodeURIComponent(value);
    return acc;
  }, {});
}

function getSessionId(req) {
  return parseCookies(req)[SESSION_COOKIE] || '';
}

function pruneSessions() {
  const now = Date.now();
  for (const [id, session] of sessions.entries()) {
    if (!session || session.expiresAt <= now) sessions.delete(id);
  }
}

function getSession(req) {
  pruneSessions();
  const id = getSessionId(req);
  if (!id) return null;
  const session = sessions.get(id);
  if (!session) return null;
  return session.expiresAt > Date.now() ? session : null;
}

function createSession() {
  const id = crypto.randomBytes(24).toString('hex');
  const session = { id, authenticatedAt: new Date().toISOString(), expiresAt: Date.now() + SESSION_TTL_MS };
  sessions.set(id, session);
  return session;
}

function clearSession(req) {
  const id = getSessionId(req);
  if (id) sessions.delete(id);
}

function setSessionCookie(headers, sessionId, expired = false) {
  const maxAge = expired ? 0 : Math.floor(SESSION_TTL_MS / 1000);
  headers['Set-Cookie'] = `${SESSION_COOKIE}=${sessionId}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${maxAge}`;
}

function sendJson(res, statusCode, payload, extraHeaders = {}) {
  const body = JSON.stringify(payload);
  res.writeHead(statusCode, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    ...extraHeaders
  });
  res.end(body);
}

async function readRequestBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on('data', chunk => {
      chunks.push(chunk);
      if (Buffer.concat(chunks).length > 1024 * 1024) {
        reject(new Error('Request body too large'));
        req.destroy();
      }
    });
    req.on('end', () => {
      if (!chunks.length) {
        resolve('');
        return;
      }
      resolve(Buffer.concat(chunks).toString('utf8'));
    });
    req.on('error', reject);
  });
}

async function readJsonBody(req) {
  const raw = await readRequestBody(req);
  if (!raw) return {};
  try {
    return JSON.parse(raw);
  } catch {
    throw new Error('Invalid JSON');
  }
}

function serveFile(res, filePath, contentType) {
  fs.readFile(filePath, (err, data) => {
    if (err) {
      res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'no-store' });
      res.end('Not found');
      return;
    }
    res.writeHead(200, {
      'Content-Type': contentType,
      'Cache-Control': 'no-store',
      'Content-Length': data.length
    });
    res.end(data);
  });
}

async function handleApi(req, res, pathname) {
  if (req.method === 'GET' && pathname === '/api/dm/session') {
    const session = getSession(req);
    sendJson(res, 200, {
      authenticated: !!session,
      pinSet: !!pinRecord
    });
    return;
  }

  if (pathname.startsWith('/api/campaign/')) {
    const code = normalizeJoinCode(pathname.split('/').pop() || '');
    if (!code) {
      sendJson(res, 400, { error: 'Missing campaign code.' });
      return;
    }
    if (req.method === 'GET') {
      const record = getCampaignRecord(code);
      if (!record) {
        sendJson(res, 404, { error: 'Campaign not found.' });
        return;
      }
      sendJson(res, 200, record);
      return;
    }
    if (req.method === 'PUT') {
      const body = await readJsonBody(req).catch(err => ({ error: err.message }));
      if (body.error) {
        sendJson(res, 400, { error: body.error });
        return;
      }
      const next = await upsertCampaignRecord(code, body || {});
      sendJson(res, 200, next);
      return;
    }
    sendJson(res, 405, { error: 'Method not allowed.' });
    return;
  }

  if (req.method === 'GET' && pathname === '/api/dm/data') {
    if (!requireDmSession(req, res)) return;
    if (!dmData) dmData = loadDmData();
    sendJson(res, 200, { data: dmData });
    return;
  }

  if (req.method === 'PUT' && pathname === '/api/dm/data') {
    if (!requireDmSession(req, res)) return;
    const body = await readJsonBody(req).catch(err => ({ error: err.message }));
    if (body.error) {
      sendJson(res, 400, { error: body.error });
      return;
    }
    dmData = normalizeDmData(body.data ?? body);
    await saveDmData(dmData);
    sendJson(res, 200, { ok: true });
    return;
  }

  if (req.method === 'POST' && pathname === '/api/dm/unlock') {
    const body = await readJsonBody(req).catch(err => ({ error: err.message }));
    if (body.error) {
      sendJson(res, 400, { error: body.error });
      return;
    }
    const pin = normalizePin(body.pin);
    if (pin.length !== 4) {
      sendJson(res, 400, { error: 'Enter a 4-digit PIN.' });
      return;
    }

    if (!pinRecord) {
      const created = hashPin(pin);
      pinRecord = {
        ...created,
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString()
      };
      await savePinRecord(pinRecord);
    } else if (!verifyPin(pin, pinRecord)) {
      sendJson(res, 401, { error: 'Wrong PIN.' });
      return;
    }

    const session = createSession();
    const headers = {};
    setSessionCookie(headers, session.id, false);
    sendJson(res, 200, {
      authenticated: true,
      pinSet: true
    }, headers);
    return;
  }

  if (req.method === 'POST' && pathname === '/api/dm/lock') {
    clearSession(req);
    const headers = {};
    setSessionCookie(headers, 'deleted', true);
    sendJson(res, 200, {
      authenticated: false,
      pinSet: !!pinRecord
    }, headers);
    return;
  }

  sendJson(res, 404, { error: 'Not found' });
}

function serveApp(req, res, pathname) {
  const indexPath = path.join(ROOT, 'index.html');
  const qrPath = path.join(ROOT, 'qrcode.js');

  if (pathname === '/' || pathname === '/index.html') {
    serveFile(res, indexPath, 'text/html; charset=utf-8');
    return;
  }

  if (pathname === '/qrcode.js') {
    serveFile(res, qrPath, 'application/javascript; charset=utf-8');
    return;
  }

  if (pathname === '/manifest.webmanifest') {
    serveFile(res, path.join(ROOT, 'manifest.webmanifest'), 'application/manifest+json; charset=utf-8');
    return;
  }

  if (pathname === '/sw.js') {
    serveFile(res, path.join(ROOT, 'sw.js'), 'application/javascript; charset=utf-8');
    return;
  }

  if (pathname === '/icon.svg') {
    serveFile(res, path.join(ROOT, 'icon.svg'), 'image/svg+xml; charset=utf-8');
    return;
  }

  serveFile(res, indexPath, 'text/html; charset=utf-8');
}

async function handler(req, res) {
  const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  if (url.pathname.startsWith('/api/')) {
    try {
      await handleApi(req, res, url.pathname);
    } catch (err) {
      sendJson(res, 500, { error: err.message || 'Server error' });
    }
    return;
  }

  serveApp(req, res, url.pathname);
}

pinRecord = loadPinRecord();
dmData = loadDmData();
campaignStore = loadCampaignStore();

const server = http.createServer((req, res) => {
  void handler(req, res);
});

server.listen(PORT, () => {
  console.log(`Archades server listening on http://localhost:${PORT}`);
});
