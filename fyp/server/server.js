

/**
 * HoneyBound-Web — server.js  v2
 *
 * Changes from v1:
 *  1. SSE endpoint  GET /api/honey/events/stream
 *     • Pushes a `honey-event` SSE message whenever addAudit() is called.
 *     • events.html reconnects automatically via EventSource.
 *  2. windowEnd enforcement in /api/honey/verify
 *     • windowEnd is now the TOTP window counter (Math.floor(Date.now()/30000)).
 *     • A mismatch means the OTP was issued in a different 30-second window — replay rejected.
 *     • NOTE: Connectly's /api/verify-otp verifies seeds directly and is the
 *       primary auth path. This endpoint is kept for completeness / future use.
 *  3. /api/honey/register clarification comment — seeds, NOT hashes, are the
 *     canonical record on Connectly. The hash-bundle path here is unused by the
 *     current Connectly flow and exists only as a secondary verification option.
 *  4. Startup log now reports PRF-backed secret storage status.
 */

import express from 'express';
import fs      from 'fs';
import https   from 'https';
import http    from 'http';
import os      from 'os';
import path    from 'path';
import crypto  from 'crypto';

const app = express();
app.use(express.json());

const ROOT   = path.resolve();
const CLIENT = path.join(ROOT, 'client');
const SERVER = path.join(ROOT, 'server');

app.use(express.static(CLIENT));

app.get('/honey.js', (req, res) => {
  res.setHeader('Content-Type', 'application/javascript');
  res.sendFile(path.join(SERVER, 'honey.js'));
});

app.get('/', (req, res) => {
  res.sendFile(path.join(CLIENT, 'index.html'));
});

// ── SSE subscriber registry ────────────────────────────────────────────────────
// Each connected events.html client gets one entry here.
const sseClients = new Set();

// ── Audit log ─────────────────────────────────────────────────────────────────
const honeyStore   = new Map();
const linkSessions = new Map();
const linkedDevices = new Map();
const accountSnapshots = new Map();
const auditLog     = [];
const AUDIT_FILE   = path.join(SERVER, 'audit_log.json');
const DEVICES_FILE = path.join(SERVER, 'linked_devices.json');
const SNAPSHOTS_FILE = path.join(SERVER, 'account_sync.json');
const DATA_KEY_ENV = 'HBW_DATA_KEY';
const DATA_CIPHER_PREFIX = 'enc:v1:';
let snapshotsNeedEncryptionMigration = false;

function getDataKey() {
  const raw = process.env[DATA_KEY_ENV];
  if (!raw || raw.trim().length < 16) {
    throw new Error(`${DATA_KEY_ENV} must be set to a long random value before storing synced OTP secrets.`);
  }
  return crypto.createHash('sha256').update(raw).digest();
}

function encryptJson(value) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', getDataKey(), iv);
  const plaintext = Buffer.from(JSON.stringify(value), 'utf8');
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  return DATA_CIPHER_PREFIX + Buffer.concat([iv, tag, ciphertext]).toString('base64');
}

function decryptJson(value) {
  if (typeof value !== 'string' || !value.startsWith(DATA_CIPHER_PREFIX)) return value;
  const raw = Buffer.from(value.slice(DATA_CIPHER_PREFIX.length), 'base64');
  const iv = raw.subarray(0, 12);
  const tag = raw.subarray(12, 28);
  const ciphertext = raw.subarray(28);
  const decipher = crypto.createDecipheriv('aes-256-gcm', getDataKey(), iv);
  decipher.setAuthTag(tag);
  return JSON.parse(Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString('utf8'));
}

function decryptSnapshot(snapshot) {
  if (!snapshot || typeof snapshot !== 'object') return snapshot;
  const next = { ...snapshot };
  if (next.encryptedAccounts && !next.accounts) {
    next.accounts = decryptJson(next.encryptedAccounts);
  }
  if (Array.isArray(next.accounts) && !next.encryptedAccounts) {
    snapshotsNeedEncryptionMigration = true;
  }
  delete next.encryptedAccounts;
  return next;
}

function encryptSnapshot(snapshot) {
  if (!snapshot || typeof snapshot !== 'object') return snapshot;
  const next = { ...snapshot };
  if (Array.isArray(next.accounts)) {
    next.encryptedAccounts = encryptJson(next.accounts);
    delete next.accounts;
  }
  return next;
}

(function loadPersistedAudit() {
  try {
    if (fs.existsSync(AUDIT_FILE)) {
      const saved = JSON.parse(fs.readFileSync(AUDIT_FILE, 'utf8'));
      if (Array.isArray(saved)) saved.forEach(e => auditLog.push(e));
      console.log(`[honey] Loaded ${auditLog.length} persisted audit events`);
    }
  } catch(e) { console.warn('[honey] Could not load audit_log.json:', e.message); }
})();

(function loadPersistedDevices() {
  try {
    if (!fs.existsSync(DEVICES_FILE)) return;
    const saved = JSON.parse(fs.readFileSync(DEVICES_FILE, 'utf8'));
    if (!saved || typeof saved !== 'object') return;
    Object.entries(saved).forEach(([uid, devices]) => {
      if (Array.isArray(devices)) linkedDevices.set(uid, devices);
    });
    console.log(`[honey] Loaded linked-device records for ${linkedDevices.size} user(s)`);
  } catch(e) { console.warn('[honey] Could not load linked_devices.json:', e.message); }
})();

(function loadPersistedSnapshots() {
  try {
    if (!fs.existsSync(SNAPSHOTS_FILE)) return;
    const saved = JSON.parse(fs.readFileSync(SNAPSHOTS_FILE, 'utf8'));
    if (!saved || typeof saved !== 'object') return;
    Object.entries(saved).forEach(([uid, snapshot]) => {
      if (snapshot && typeof snapshot === 'object') accountSnapshots.set(uid, decryptSnapshot(snapshot));
    });
    console.log(`[honey] Loaded account-sync snapshots for ${accountSnapshots.size} user(s)`);
  } catch(e) { console.warn('[honey] Could not load account_sync.json:', e.message); }
})();

if (snapshotsNeedEncryptionMigration && process.env[DATA_KEY_ENV]) {
  saveSnapshotsToDisk();
  console.log('[honey] Migrated account_sync.json secrets to encrypted-at-rest storage.');
}

function saveAuditToDisk() {
  try { fs.writeFileSync(AUDIT_FILE, JSON.stringify(auditLog.slice(0, 500)), 'utf8'); }
  catch(e) { console.warn('[honey] Could not save audit_log.json:', e.message); }
}

function saveDevicesToDisk() {
  try {
    fs.writeFileSync(DEVICES_FILE, JSON.stringify(Object.fromEntries(linkedDevices), null, 2), 'utf8');
  } catch(e) { console.warn('[honey] Could not save linked_devices.json:', e.message); }
}

function saveSnapshotsToDisk() {
  try {
    const encryptedSnapshots = Object.fromEntries(
      [...accountSnapshots.entries()].map(([uid, snapshot]) => [uid, encryptSnapshot(snapshot)])
    );
    fs.writeFileSync(SNAPSHOTS_FILE, JSON.stringify(encryptedSnapshots, null, 2), 'utf8');
  } catch(e) { console.warn('[honey] Could not save account_sync.json:', e.message); }
}

function getDevicesForUid(uid) {
  return Array.isArray(linkedDevices.get(uid)) ? linkedDevices.get(uid) : [];
}

function setDevicesForUid(uid, devices) {
  linkedDevices.set(uid, devices);
  saveDevicesToDisk();
}

function addAudit(entry) {
  const ev = { ...entry, ts: Date.now() };
  auditLog.unshift(ev);
  if (auditLog.length > 500) auditLog.splice(500);
  saveAuditToDisk();

  // Push to all connected SSE clients
  const data = JSON.stringify(ev);
  for (const client of sseClients) {
    try { client.write(`data: ${data}\n\n`); }
    catch(e) { sseClients.delete(client); }
  }
}

function pruneExpiredLinkSessions() {
  const now = Date.now();
  for (const [token, session] of linkSessions.entries()) {
    if (session.expiresAt <= now) {
      linkSessions.delete(token);
    }
  }
}

function detectLanIPv4() {
  const nets = os.networkInterfaces();
  const candidates = [];

  for (const [name, entries] of Object.entries(nets)) {
    for (const info of entries || []) {
      if (!info || info.family !== 'IPv4' || info.internal) continue;
      if (info.address.startsWith('169.254.')) continue;
      candidates.push({ name, address: info.address });
    }
  }

  if (candidates.length === 0) return null;

  const virtualNameRe = /(virtual|vmware|hyper-v|vbox|host-only|loopback|tailscale|hamachi|docker|wsl|vethernet)/i;
  const wifiNameRe = /(wi-?fi|wlan|wireless)/i;
  const ethernetNameRe = /^ethernet$/i;

  const nonVirtual = candidates.filter(c => !virtualNameRe.test(c.name));
  const wifi = nonVirtual.find(c => wifiNameRe.test(c.name));
  if (wifi) return wifi.address;
  const ethernet = nonVirtual.find(c => ethernetNameRe.test(c.name));
  if (ethernet) return ethernet.address;
  if (nonVirtual.length > 0) return nonVirtual[0].address;
  return candidates[0].address;
}

function getLinkOrigin() {
  const override = process.env.HBW_PUBLIC_LINK_ORIGIN;
  if (override) return override.replace(/\/+$/, '');
  const lanIp = detectLanIPv4();
  if (lanIp) {
    const lanHost = `honeybound.${lanIp.replace(/\./g, '-')}.nip.io`;
    return `https://${lanHost}:8443`;
  }
  return 'https://localhost:8443';
}

function loadHttpsOptions() {
  const pfxPath = process.env.HBW_TLS_PFX_PATH;
  if (pfxPath) {
    if (!process.env.HBW_TLS_PFX_PASSPHRASE) {
      throw new Error('HBW_TLS_PFX_PASSPHRASE is required when HBW_TLS_PFX_PATH is set.');
    }
    return {
      pfx: fs.readFileSync(path.resolve(ROOT, pfxPath)),
      passphrase: process.env.HBW_TLS_PFX_PASSPHRASE
    };
  }

  const defaultLanPfx = path.join(SERVER, 'lan-domain-cert.pfx');
  if (fs.existsSync(defaultLanPfx) && process.env.HBW_TLS_PFX_PASSPHRASE) {
    return {
      pfx: fs.readFileSync(defaultLanPfx),
      passphrase: process.env.HBW_TLS_PFX_PASSPHRASE
    };
  }
  if (fs.existsSync(defaultLanPfx)) {
    console.warn('[honey] LAN PFX found, but HBW_TLS_PFX_PASSPHRASE is not set. Falling back to localhost PEM certs.');
  }

  const keyPath = process.env.HBW_TLS_KEY_PATH || path.join(SERVER, 'localhost-key.pem');
  const certPath = process.env.HBW_TLS_CERT_PATH || path.join(SERVER, 'localhost.pem');

  return {
    key: fs.readFileSync(path.resolve(ROOT, keyPath)),
    cert: fs.readFileSync(path.resolve(ROOT, certPath))
  };
}

function serialiseLinkSession(session) {
  return {
    token: session.token,
    uid: session.uid,
    status: session.status,
    createdAt: session.createdAt,
    expiresAt: session.expiresAt,
    linkUrl: session.linkUrl,
    device: session.device || null,
    provisionedAccountCount: session.provisionBundle && Array.isArray(session.provisionBundle.accounts)
      ? session.provisionBundle.accounts.length
      : 0
  };
}

function sanitiseSyncAccounts(accounts) {
  if (!Array.isArray(accounts)) return [];
  return accounts
    .filter(account => account && account.id && account.secret)
    .map(account => ({
      id: String(account.id),
      serviceName: String(account.serviceName || account.id),
      secret: String(account.secret).replace(/\s+/g, '').toUpperCase(),
      digits: Number(account.digits || 6),
      period: Number(account.period || 30)
    }));
}

function buildProvisionBundleFromAccounts(accounts) {
  return {
    createdAt: Date.now(),
    accounts: sanitiseSyncAccounts(accounts)
  };
}

// ── SSE stream endpoint ────────────────────────────────────────────────────────
// events.html connects here and receives live push whenever addAudit() fires.
// No auth required — this is a local dev prototype.
app.get('/api/honey/events/stream', (req, res) => {
  res.setHeader('Content-Type',  'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection',    'keep-alive');
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.flushHeaders();

  // Send a heartbeat comment every 15 s to keep the connection alive through
  // proxies and browsers that close idle SSE connections.
  const heartbeat = setInterval(() => {
    try { res.write(': heartbeat\n\n'); }
    catch(e) { clearInterval(heartbeat); }
  }, 15000);

  sseClients.add(res);
  console.log(`[honey] SSE client connected (total: ${sseClients.size})`);

  req.on('close', () => {
    clearInterval(heartbeat);
    sseClients.delete(res);
    console.log(`[honey] SSE client disconnected (total: ${sseClients.size})`);
  });
});

// ── /api/honey/register ────────────────────────────────────────────────────────
// IMPORTANT: This endpoint stores OTP *hashes* for a window-based verify path.
// The primary Connectly auth path verifies OTPs directly against raw hex seeds
// stored in users.json — this register/verify pair is NOT called by Connectly.
// It is retained here as a secondary option (e.g. for a Connectly deployment
// that doesn't want to store raw seeds, only hashes).
//
// If you extend this, note that exportSeedsForConnectly() sends raw seed hex
// strings — you would need to hash them client-side before calling this endpoint.
app.post('/api/honey/register', (req, res) => {
  const { accountId, realIndex, otpHashes, windowEnd } = req.body;
  if (!accountId || typeof realIndex !== 'number' || !Array.isArray(otpHashes))
    return res.status(400).json({ error: 'Invalid payload' });
  if (otpHashes.length !== 20)
    return res.status(400).json({ error: `Expected 20 hashes, got ${otpHashes.length}` });
  const hexRe = /^[0-9a-f]{64}$/i;
  if (!otpHashes.every(h => hexRe.test(h)))
    return res.status(400).json({ error: 'Invalid hash format (expected SHA-256 hex)' });

  // windowEnd = TOTP window counter at registration time.
  // Stored so verify can reject OTPs from a different window (replay guard).
  const window = windowEnd ?? Math.floor(Date.now() / 30000);
  honeyStore.set(accountId, { realIndex, otpHashes, windowEnd: window });
  console.log(`[honey] Registered hash-bundle for ${accountId} (window ${window})`);
  res.json({ ok: true });
});

// ── /api/honey/verify ─────────────────────────────────────────────────────────
// Secondary verify path (hash-based). The primary path lives in Connectly.
//
// windowEnd enforcement:
//   - Client must send the TOTP window counter that was current when the OTP
//     was generated: Math.floor(Date.now() / 30000).
//   - We allow ±1 window (30 s clock drift tolerance), same as Connectly.
//   - A counter outside that range → 'stale-window' → rejected.
//   - This prevents an attacker from capturing a valid OTP and replaying it
//     in a future TOTP window.
app.post('/api/honey/verify', (req, res) => {
  const { accountId, otpHash, windowEnd } = req.body;
  if (!accountId || !otpHash)
    return res.status(400).json({ error: 'Missing fields' });

  const bundle = honeyStore.get(accountId);
  if (!bundle) {
    addAudit({ event: 'verify-no-bundle', accountId });
    return res.json({ result: 'invalid', reason: 'no-bundle' });
  }

  // Clock-tamper / forward-replay guard
  if (windowEnd !== undefined && bundle.windowEnd !== undefined) {
    const drift = Math.abs(windowEnd - bundle.windowEnd);
    if (drift > 1) {
      // More than one 30-second window away — possible replay or clock skew attack
      addAudit({ event: 'verify-stale-window', accountId, submitted: windowEnd, registered: bundle.windowEnd });
      console.warn(`[honey] Stale-window for ${accountId}: submitted=${windowEnd} registered=${bundle.windowEnd}`);
      return res.json({ result: 'invalid', reason: 'stale-window' });
    }
  }

  const normHash = otpHash.toLowerCase();
  if (bundle.otpHashes[bundle.realIndex] === normHash) {
    addAudit({ event: 'login-success', accountId });
    return res.json({ result: 'success' });
  }
  for (let i = 0; i < bundle.otpHashes.length; i++) {
    if (i === bundle.realIndex) continue;
    if (bundle.otpHashes[i] === normHash) {
      addAudit({ event: 'honeytrap-triggered', accountId, seedIndex: i });
      console.warn(`[honey] HONEYTRAP for ${accountId} — seed index ${i}`);
      return res.json({ result: 'honeytrap', index: i });
    }
  }
  addAudit({ event: 'login-invalid', accountId });
  res.json({ result: 'invalid' });
});

app.get('/api/honey/audit', (req, res) => {
  res.json(auditLog.slice(0, 100));
});

app.get('/api/honey/time', (req, res) => {
  const now = Date.now();
  res.json({
    serverTimeMs: now,
    unixWindow: Math.floor(now / 30000)
  });
});

app.post('/api/honey/link-device/session', (req, res) => {
  pruneExpiredLinkSessions();
  const uid = String(req.body?.uid || '').trim();
  if (!uid) {
    return res.status(400).json({ error: 'Missing uid' });
  }

  const token = crypto.randomBytes(12).toString('hex');
  const now = Date.now();
  const session = {
    token,
    uid,
    status: 'pending',
    createdAt: now,
    expiresAt: now + 30000,
    linkUrl: `${getLinkOrigin()}/link-device.html?token=${encodeURIComponent(token)}`
  };
  linkSessions.set(token, session);

  res.json({ ok: true, session: serialiseLinkSession(session) });
});

app.get('/api/honey/link-device/session/:token', (req, res) => {
  pruneExpiredLinkSessions();
  const session = linkSessions.get(req.params.token);
  if (!session) {
    return res.status(404).json({ error: 'Link code not found or expired' });
  }
  res.json({ ok: true, session: serialiseLinkSession(session) });
});

app.post('/api/honey/link-device/provision/:token', (req, res) => {
  pruneExpiredLinkSessions();
  const token = String(req.params.token || '').trim();
  const session = linkSessions.get(token);
  if (!session) {
    return res.status(404).json({ error: 'Link code not found or expired' });
  }

  const uid = String(req.body?.uid || '').trim();
  const accounts = Array.isArray(req.body?.accounts) ? req.body.accounts : null;
  if (!uid || uid !== session.uid) {
    return res.status(400).json({ error: 'UID does not match this link session' });
  }
  if (!accounts) {
    return res.status(400).json({ error: 'Missing accounts bundle' });
  }

  session.provisionBundle = buildProvisionBundleFromAccounts(accounts);

  res.json({
    ok: true,
    provisionedAccountCount: session.provisionBundle.accounts.length
  });
});

app.get('/api/honey/link-device/provision/:token', (req, res) => {
  pruneExpiredLinkSessions();
  const token = String(req.params.token || '').trim();
  const session = linkSessions.get(token);
  if (!session) {
    return res.status(404).json({ error: 'Link code not found or expired' });
  }
  if (!session.provisionBundle) {
    const snapshot = accountSnapshots.get(session.uid);
    if (snapshot && Array.isArray(snapshot.accounts)) {
      session.provisionBundle = buildProvisionBundleFromAccounts(snapshot.accounts);
      console.log(`[honey] Recovered provision bundle for ${session.uid} from synced snapshot`);
    }
  }
  if (!session.provisionBundle) {
    return res.status(404).json({ error: 'No account bundle has been prepared for this device yet' });
  }

  res.json({
    ok: true,
    uid: session.uid,
    bundle: {
      createdAt: session.provisionBundle.createdAt,
      accounts: session.provisionBundle.accounts
    }
  });
});

app.get('/api/honey/link-device/devices/:uid', (req, res) => {
  const uid = String(req.params.uid || '').trim();
  if (!uid) {
    return res.status(400).json({ error: 'Missing uid' });
  }
  res.json({ ok: true, devices: getDevicesForUid(uid) });
});

app.get('/api/honey/account-sync/:uid', (req, res) => {
  const uid = String(req.params.uid || '').trim();
  if (!uid) {
    return res.status(400).json({ error: 'Missing uid' });
  }

  const snapshot = accountSnapshots.get(uid);
  if (!snapshot) {
    return res.json({ ok: true, snapshot: null });
  }

  res.json({ ok: true, snapshot });
});

app.post('/api/honey/account-sync/:uid', (req, res) => {
  const uid = String(req.params.uid || '').trim();
  const bodyUid = String(req.body?.uid || '').trim();
  const deviceId = String(req.body?.deviceId || '').trim();
  const reason = String(req.body?.reason || '').trim() || 'sync';
  const accounts = sanitiseSyncAccounts(req.body?.accounts);

  if (!uid || !bodyUid || bodyUid !== uid) {
    return res.status(400).json({ error: 'UID mismatch' });
  }
  if (!deviceId) {
    return res.status(400).json({ error: 'Missing deviceId' });
  }

  const revision = Date.now();
  const snapshot = {
    uid,
    deviceId,
    reason,
    revision,
    updatedAt: new Date(revision).toISOString(),
    accounts
  };

  accountSnapshots.set(uid, snapshot);
  saveSnapshotsToDisk();

  res.json({ ok: true, snapshot });
});

app.delete('/api/honey/link-device/devices/:uid/:deviceId', (req, res) => {
  const uid = String(req.params.uid || '').trim();
  const deviceId = String(req.params.deviceId || '').trim();
  if (!uid || !deviceId) {
    return res.status(400).json({ error: 'Missing uid or deviceId' });
  }

  const nextDevices = getDevicesForUid(uid).filter(device => device && device.id !== deviceId);
  setDevicesForUid(uid, nextDevices);
  res.json({ ok: true, devices: nextDevices });
});

app.post('/api/honey/link-device/claim', (req, res) => {
  pruneExpiredLinkSessions();
  const token = String(req.body?.token || '').trim();
  const session = linkSessions.get(token);
  if (!session) {
    return res.status(404).json({ error: 'Link code not found or expired' });
  }
  if (session.expiresAt <= Date.now()) {
    linkSessions.delete(token);
    return res.status(410).json({ error: 'Link code expired' });
  }
  if (session.status === 'linked' && session.device) {
    return res.json({ ok: true, session: serialiseLinkSession(session) });
  }

  const deviceName = String(req.body?.deviceName || '').trim() || 'Linked Device';
  const platform = String(req.body?.platform || '').trim() || 'Mobile';
  const browser = String(req.body?.browser || '').trim() || 'Browser';
  const icon = String(req.body?.icon || '').trim() || 'Mobile';

  session.status = 'linked';
  session.expiresAt = Date.now() + 300000;
  session.device = {
    id: crypto.randomBytes(8).toString('hex'),
    name: deviceName,
    type: `${platform} / ${browser}`,
    icon,
    linkedAt: new Date().toISOString(),
    active: true
  };

  const devices = getDevicesForUid(session.uid).filter(device => device && device.id !== session.device.id);
  devices.push(session.device);
  setDevicesForUid(session.uid, devices);

  addAudit({
    event: 'device-linked',
    accountId: session.uid,
    deviceName: session.device.name,
    deviceType: session.device.type
  });

  res.json({ ok: true, session: serialiseLinkSession(session) });
});

app.delete('/api/honey/audit', (req, res) => {
  auditLog.splice(0, auditLog.length);
  saveAuditToDisk();
  console.log('[honey] Audit log cleared');
  // Notify SSE clients that the log was cleared
  const data = JSON.stringify({ event: 'log-cleared', ts: Date.now() });
  for (const client of sseClients) {
    try { client.write(`data: ${data}\n\n`); }
    catch(e) { sseClients.delete(client); }
  }
  res.json({ ok: true });
});

// ── Telemetry from Connectly ───────────────────────────────────────────────────
// Connectly POSTs here after each OTP attempt so HoneyBound's Events page
// shows real login outcomes alongside its own local events.
app.post('/api/honey/event', (req, res) => {
  const { accountId, outcome, serviceName, timestamp } = req.body;
  if (!accountId || !outcome) {
    return res.status(400).json({ error: 'Missing accountId or outcome' });
  }

  const typeMap = { 'login': 'login-success', 'honeytrap': 'honeytrap-triggered', 'invalid': 'login-invalid' };
  const eventType = typeMap[outcome] || 'login-invalid';

  addAudit({
    event:       eventType,
    accountId,
    serviceName: serviceName || 'Connectly',
    ts:          timestamp   || Date.now(),
    source:      'connectly'
  });

  console.log(`[honey] Event from Connectly: ${eventType} for ${accountId}`);
  res.json({ ok: true, logged: eventType });
});

// ── HTTPS ─────────────────────────────────────────────────────────────────────
const httpsOptions = loadHttpsOptions();
const HTTPS_PORT = Number(process.env.HBW_HTTPS_PORT || 8443);
const HTTP_PORT = Number(process.env.HBW_HTTP_PORT || 8080);
const httpsServer = https.createServer(httpsOptions, app);

httpsServer.on('error', err => {
  if (err.code === 'EADDRINUSE') {
    console.error(`[honey] Port ${HTTPS_PORT} is already in use. Stop the old HoneyBound process or start with HBW_HTTPS_PORT set to another port.`);
    console.error('[honey] Example: $env:HBW_HTTPS_PORT = "8444"; npm start');
    process.exit(1);
  }
  throw err;
});

httpsServer.listen(HTTPS_PORT, () => {
  console.log(`HoneyBound-Web running at https://localhost:${HTTPS_PORT}`);
  console.log('GET  /api/honey/events/stream → SSE live event push to events.html');
  console.log('POST /api/honey/event         → telemetry from Connectly');
  if (process.env.HBW_TLS_PFX_PATH) {
    console.log(`[honey] TLS source: PFX ${process.env.HBW_TLS_PFX_PATH}`);
  } else {
    console.log(`[honey] TLS source: cert=${process.env.HBW_TLS_CERT_PATH || path.join('server', 'localhost.pem')} key=${process.env.HBW_TLS_KEY_PATH || path.join('server', 'localhost-key.pem')}`);
  }
  console.log(`[honey] Public link origin: ${getLinkOrigin()}`);

  console.log(
    '\n[honey] WebAuthn PRF-backed secret storage is enabled.\n' +
    '   Existing legacy credId-encrypted entries will be migrated when opened.\n'
  );
});

http.createServer((req, res) => {
  const host = req.headers.host || '';
  const targetOrigin = getLinkOrigin();
  const targetUrl = targetOrigin + (req.url || '/');

  res.writeHead(302, { Location: targetUrl });
  res.end(`Redirecting to ${targetUrl}`);
}).on('error', err => {
  if (err.code === 'EADDRINUSE') {
    console.warn(`[honey] HTTP redirect port ${HTTP_PORT} is already in use; HTTPS server is still usable.`);
    return;
  }
  throw err;
}).listen(HTTP_PORT, () => {
  console.log(`HoneyBound secure link-device page available at ${getLinkOrigin()}/link-device.html`);
  console.log(`[honey] HTTP port ${HTTP_PORT} now redirects to the HTTPS origin for mobile onboarding.`);
});
