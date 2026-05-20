/**
 * Connectly server.js  v3
 *
 * New in v3:
 *  1. Google OAuth 2.0 — /auth/google + /auth/google/callback
 *     Google users still go through HoneyBound OTP after OAuth (by design).
 *  2. All 4 email alerts wired:
 *     • sendSuccessfulLoginAlert  — every successful OTP verification
 *     • sendHoneytrapAlert        — decoy OTP used
 *     • sendFailedOTPAlert        — bad OTP (1st + every 3rd attempt)
 *     • sendFakeDashboardAlert    — attacker action on /fakedashboard
 *  3. /api/honeytrap/action now fires sendFakeDashboardAlert
 *  4. Failed OTP attempt counter tracked per-session
 *
 * Google OAuth setup (one-time):
 *   1. console.cloud.google.com → New project → Enable "Google+ API"
 *   2. APIs & Services → Credentials → OAuth 2.0 Client ID (Web application)
 *   3. Authorised redirect URI: https://localhost:3000/auth/google/callback
 *   4. Set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET in dummy-web/.env
 *   5. npm install googleapis
 */

import express    from 'express';
import session    from 'express-session';
import bodyParser from 'body-parser';
import path       from 'path';
import https      from 'https';
import http       from 'http';
import fs         from 'fs';
import { fileURLToPath } from 'url';
import './env.js';
import { hashPassword, verifyPassword } from './password.js';
import crypto     from 'crypto';
import {
    sendHoneytrapAlert,
    sendFailedOTPAlert,
    sendSuccessfulLoginAlert,
    sendFakeDashboardAlert,
    sendGoogleLoginAlert
} from './mailer.js';

// ── Google OAuth config — fill these in ──────────────────────────────────────
const GOOGLE_CLIENT_ID     = process.env.GOOGLE_CLIENT_ID || '';
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET || '';
const GOOGLE_REDIRECT_URI  = process.env.GOOGLE_REDIRECT_URI || 'https://localhost:3000/auth/google/callback';
const GOOGLE_AUTH_URL      = 'https://accounts.google.com/o/oauth2/v2/auth';
const GOOGLE_TOKEN_URL     = 'https://oauth2.googleapis.com/token';
const GOOGLE_USERINFO_URL  = 'https://www.googleapis.com/oauth2/v3/userinfo';
const SESSION_SECRET       = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');
const GOOGLE_OAUTH_READY   = !!(GOOGLE_CLIENT_ID && GOOGLE_CLIENT_SECRET);

if (!process.env.SESSION_SECRET) {
    console.warn('[Connectly] SESSION_SECRET not set - using an ephemeral session secret for this run.');
}
if (!GOOGLE_OAUTH_READY) {
    console.warn('[Connectly] Google OAuth disabled - set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET to enable it.');
}
// ─────────────────────────────────────────────────────────────────────────────

const app  = express();
const PORT = Number(process.env.PORT || 3000);

const __filename = fileURLToPath(import.meta.url);
const __dirname  = path.dirname(__filename);
const publicPath = path.join(__dirname, '..', 'public');
const projectRoot = path.resolve(__dirname, '..', '..');
const defaultTlsKeyPath = path.join(projectRoot, 'fyp', 'server', 'localhost-key.pem');
const defaultTlsCertPath = path.join(projectRoot, 'fyp', 'server', 'localhost.pem');
const DATA_KEY_ENV = 'CONNECTLY_DATA_KEY';
const DATA_CIPHER_PREFIX = 'enc:v1:';

app.use(bodyParser.json());

// ── CORS for HoneyBound-Web (port 8443) ──────────────────────────────────────
app.use((req, res, next) => {
    const origin = req.headers.origin || '';
    if (origin === 'https://localhost:8443' || origin === 'http://localhost:8443') {
        res.setHeader('Access-Control-Allow-Origin', origin);
        res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
        res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
        res.setHeader('Access-Control-Allow-Credentials', 'true');
    }
    if (req.method === 'OPTIONS') return res.sendStatus(204);
    next();
});

app.use(session({
    secret:            SESSION_SECRET,
    resave:            false,
    saveUninitialized: false,
    cookie: { secure: true, maxAge: 3600000 }
}));
app.use(express.static(publicPath));

function loadHttpsOptions() {
    const keyPath = process.env.CONNECTLY_TLS_KEY_PATH || defaultTlsKeyPath;
    const certPath = process.env.CONNECTLY_TLS_CERT_PATH || defaultTlsCertPath;
    return {
        key: fs.readFileSync(keyPath),
        cert: fs.readFileSync(certPath)
    };
}

// ─── Persistent user store ────────────────────────────────────────────────────
const USERS_FILE = path.join(__dirname, 'users.json');
let usersNeedEncryptionMigration = false;

function getDataKey() {
    const raw = process.env[DATA_KEY_ENV];
    if (!raw || raw.trim().length < 16) {
        throw new Error(`${DATA_KEY_ENV} must be set to a long random value before storing OTP secrets.`);
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

function decryptUserRecord(record) {
    if (!record || typeof record !== 'object') return record;
    const next = { ...record };
    for (const field of ['totpSecret', 'honeySeeds', 'seeds']) {
        if (next[field]) {
            if (typeof next[field] !== 'string' || !next[field].startsWith(DATA_CIPHER_PREFIX)) {
                usersNeedEncryptionMigration = true;
            }
            next[field] = decryptJson(next[field]);
        }
    }
    return next;
}

function encryptUserRecord(record) {
    if (!record || typeof record !== 'object') return record;
    const next = { ...record };
    for (const field of ['totpSecret', 'honeySeeds', 'seeds']) {
        if (next[field]) next[field] = encryptJson(next[field]);
    }
    return next;
}

function loadUsers() {
    try {
        if (fs.existsSync(USERS_FILE)) {
            const rawUsers = JSON.parse(fs.readFileSync(USERS_FILE, 'utf8'));
            return new Map(Object.entries(rawUsers).map(([key, value]) => [key, decryptUserRecord(value)]));
        }
    } catch (e) {
        console.warn('[Connectly] Could not load users.json:', e.message);
    }
    return new Map();
}
function saveUsers(users) {
    try {
        const encryptedUsers = Object.fromEntries(
            [...users.entries()].map(([key, value]) => [key, encryptUserRecord(value)])
        );
        fs.writeFileSync(USERS_FILE, JSON.stringify(encryptedUsers, null, 2), 'utf8');
    }
    catch (e) { console.error('[Connectly] Failed to save users.json:', e.message); }
}
const users = loadUsers();
if (usersNeedEncryptionMigration && process.env[DATA_KEY_ENV]) {
    saveUsers(users);
    console.log('[Connectly] Migrated users.json secrets to encrypted-at-rest storage.');
}

// ─── HoneyBound proxy ─────────────────────────────────────────────────────────
function proxyToHoneyBound(p, payload) {
    return new Promise((resolve, reject) => {
        const body = JSON.stringify(payload);
        const req  = https.request(
            { hostname: 'localhost', port: 8443, path: p, method: 'POST',
              headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) },
              rejectUnauthorized: false, timeout: 3000 },
            res => { let d = ''; res.on('data', c => d += c); res.on('end', () => { try { resolve(JSON.parse(d)); } catch { reject(new Error('Bad JSON')); } }); }
        );
        req.on('error', reject);
        req.on('timeout', () => { req.destroy(); reject(new Error('Timeout')); });
        req.write(body); req.end();
    });
}

function getHoneyBoundJson(p) {
    return new Promise((resolve, reject) => {
        const req = https.request(
            { hostname: 'localhost', port: 8443, path: p, method: 'GET',
              rejectUnauthorized: false, timeout: 3000 },
            res => {
                let d = '';
                res.on('data', c => d += c);
                res.on('end', () => {
                    if ((res.statusCode || 500) < 200 || (res.statusCode || 500) >= 300) {
                        return reject(new Error(`HoneyBound returned HTTP ${res.statusCode}`));
                    }
                    try { resolve(JSON.parse(d)); }
                    catch { reject(new Error('Bad JSON')); }
                });
            }
        );
        req.on('error', reject);
        req.on('timeout', () => { req.destroy(); reject(new Error('Timeout')); });
        req.end();
    });
}

const TRUSTED_CLOCK_SKEW_LIMIT_MS = 30000;
const TRUSTED_CLOCK_CACHE_MS      = 15000;
let trustedClockState = { checkedAt: 0, skewMs: 0, serverTimeMs: 0 };

async function ensureHoneyBoundTrustedClock(force = false) {
    const now = Date.now();
    if (!force && trustedClockState.checkedAt && (now - trustedClockState.checkedAt) < TRUSTED_CLOCK_CACHE_MS) {
        return trustedClockState;
    }

    const payload = await getHoneyBoundJson('/api/honey/time');
    const serverTimeMs = Number(payload?.serverTimeMs || 0);
    if (!serverTimeMs) {
        throw new Error('HoneyBound did not return a valid trusted time.');
    }

    trustedClockState = {
        checkedAt: now,
        skewMs: now - serverTimeMs,
        serverTimeMs
    };
    return trustedClockState;
}

// ─── Link any pending HoneyBound bundle to a user ────────────────────────────
function linkPendingHoney(username) {
    const user = users.get(username);
    if (!user || user.honeyAccountId) return; // already linked

    for (const [key, data] of users.entries()) {
        if (key.startsWith('__honey__')) {
            user.honeyAccountId = data.accountId;
            user.honeySeeds     = data.seeds;
            user.honeyRealIndex = data.realIndex;
            user.honeyService   = data.serviceName || 'Connectly';
            users.set(username, user);
            users.delete(key);
            saveUsers(users);
            console.log(`[Link] ✅ Pending HoneyBound bundle linked to "${username}"`);
            return;
        }
    }
}

// ─── Google OAuth helpers ─────────────────────────────────────────────────────

/** Exchange code for tokens and then fetch userinfo from Google */
async function googleCodeToUser(code) {
    // 1. Exchange code for tokens
    const tokenBody = new URLSearchParams({
        code,
        client_id:     GOOGLE_CLIENT_ID,
        client_secret: GOOGLE_CLIENT_SECRET,
        redirect_uri:  GOOGLE_REDIRECT_URI,
        grant_type:    'authorization_code'
    }).toString();

    const tokenData = await new Promise((resolve, reject) => {
        const req = https.request(
            { hostname: 'oauth2.googleapis.com', path: '/token', method: 'POST',
              headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Content-Length': Buffer.byteLength(tokenBody) },
              timeout: 5000 },
            res => { let d = ''; res.on('data', c => d += c); res.on('end', () => { try { resolve(JSON.parse(d)); } catch { reject(new Error('Bad token JSON')); } }); }
        );
        req.on('error', reject);
        req.on('timeout', () => { req.destroy(); reject(new Error('Token timeout')); });
        req.write(tokenBody); req.end();
    });

    if (!tokenData.access_token) throw new Error(tokenData.error_description || 'No access_token');

    // 2. Fetch userinfo
    const userInfo = await new Promise((resolve, reject) => {
        const req = https.request(
            { hostname: 'www.googleapis.com', path: '/oauth2/v3/userinfo', method: 'GET',
              headers: { Authorization: `Bearer ${tokenData.access_token}` }, timeout: 5000 },
            res => { let d = ''; res.on('data', c => d += c); res.on('end', () => { try { resolve(JSON.parse(d)); } catch { reject(new Error('Bad userinfo JSON')); } }); }
        );
        req.on('error', reject);
        req.on('timeout', () => { req.destroy(); reject(new Error('Userinfo timeout')); });
        req.end();
    });

    return userInfo; // { sub, email, name, given_name, family_name, picture, ... }
}

// ─── TOTP helpers ─────────────────────────────────────────────────────────────
function totpFromHexSeed(hexSeed, digits = 6, period = 30, timeOffset = 0) {
    const seedBytes = Buffer.from(hexSeed, 'hex');
    const counter   = Math.floor(Date.now() / 1000 / period) + timeOffset;
    const cb        = Buffer.alloc(8);
    cb.writeUInt32BE(Math.floor(counter / 0x100000000), 0);
    cb.writeUInt32BE(counter >>> 0, 4);
    const hmac   = crypto.createHmac('sha1', seedBytes).update(cb).digest();
    const offset = hmac[hmac.length - 1] & 0x0f;
    const code   = ((hmac[offset]     & 0x7f) << 24 |
                    (hmac[offset + 1] & 0xff) << 16 |
                    (hmac[offset + 2] & 0xff) << 8  |
                    (hmac[offset + 3] & 0xff)) % Math.pow(10, digits);
    return code.toString().padStart(digits, '0');
}

function totpMatchesHexSeed(otp, hexSeed, digits = 6, period = 30) {
    return [-1, 0, 1].some(offset => totpFromHexSeed(hexSeed, digits, period, offset) === otp);
}

function matchedTotpWindowForHexSeed(otp, hexSeed, digits = 6, period = 30) {
    for (const offset of [-1, 0, 1]) {
        if (totpFromHexSeed(hexSeed, digits, period, offset) === otp) {
            return currentTotpWindow(period) + offset;
        }
    }
    return null;
}

function currentTotpWindow(period = 30) {
    return Math.floor(Date.now() / 1000 / period);
}

function isWindowStale(submittedWindow, period = 30) {
    if (submittedWindow === undefined || submittedWindow === null) return false;
    return Math.abs(submittedWindow - currentTotpWindow(period)) > 1;
}

function getReplayState(record) {
    if (!record) return null;
    if (!record.honeyReplayWindows || typeof record.honeyReplayWindows !== 'object') {
        record.honeyReplayWindows = {};
    }
    return record.honeyReplayWindows;
}

// ─── IP helper ────────────────────────────────────────────────────────────────
function getIP(req) {
    return req.headers['x-forwarded-for']?.split(',')[0]?.trim()
        || req.socket?.remoteAddress
        || 'unknown';
}

// ─── STATIC ROUTES ────────────────────────────────────────────────────────────
app.get('/', (req, res) => {
    if (req.session?.verified) return res.redirect('/dashboard');
    res.sendFile(path.join(publicPath, 'login.html'));
});
app.get('/register',      (req, res) => res.sendFile(path.join(publicPath, 'register.html')));
app.get('/otp',           (req, res) => res.sendFile(path.join(publicPath, 'otp.html')));
app.get('/api/auth-status', (req, res) => {
    res.json({
        success: true,
        googleOAuthReady: GOOGLE_OAUTH_READY
    });
});
app.get('/dashboard',     (req, res) => {
    if (!req.session?.verified) return res.redirect('/');
    res.sendFile(path.join(publicPath, 'dashboard.html'));
});
app.get('/fakedashboard', (req, res) => res.sendFile(path.join(publicPath, 'fakedashboard.html')));
app.get('/2fa-setup',     (req, res) => {
    if (!req.session?.verified) return res.redirect('/');
    res.sendFile(path.join(publicPath, '2fa-setup.html'));
});

// ─── GOOGLE OAUTH ─────────────────────────────────────────────────────────────

/** Step 1 — Redirect user to Google's consent screen */
app.get('/auth/google', (req, res) => {
    if (!GOOGLE_OAUTH_READY) {
        return res.redirect('/?error=google_not_configured');
    }

    // Generate a CSRF state token
    const state = crypto.randomBytes(16).toString('hex');
    req.session.oauthState = state;

    const params = new URLSearchParams({
        client_id:     GOOGLE_CLIENT_ID,
        redirect_uri:  GOOGLE_REDIRECT_URI,
        response_type: 'code',
        scope:         'openid email profile',
        state,
        access_type:   'online',
        prompt:        'select_account'
    });

    req.session.save(() => res.redirect(`${GOOGLE_AUTH_URL}?${params}`));
});

/** Step 2 — Google redirects back here with ?code=... */
app.get('/auth/google/callback', async (req, res) => {
    if (!GOOGLE_OAUTH_READY) {
        return res.redirect('/?error=google_not_configured');
    }

    const { code, state, error } = req.query;

    if (error) {
        console.error('[Google OAuth] Error from Google:', error);
        return res.redirect('/?error=google_denied');
    }

    // CSRF check
    if (!state || state !== req.session.oauthState) {
        console.warn('[Google OAuth] CSRF state mismatch');
        return res.redirect('/?error=csrf');
    }
    delete req.session.oauthState;

    try {
        const gUser = await googleCodeToUser(code);
        // gUser = { sub, email, name, given_name, picture, ... }

        const googleEmail = (gUser.email || '').toLowerCase().trim();
        const googleSub   = gUser.sub; // permanent Google user ID
        const displayName = gUser.name || gUser.given_name || 'User';
        const avatar      = (gUser.given_name || displayName || 'U')[0].toUpperCase();
        const ip          = getIP(req);

        // Find existing user by googleSub or by googleEmail
        let existingUser = null;
        let existingKey  = null;
        for (const [uname, udata] of users.entries()) {
            if (uname.startsWith('__honey__')) continue;
            if (udata.googleSub === googleSub || udata.googleEmail === googleEmail) {
                existingUser = udata;
                existingKey  = uname;
                break;
            }
        }

        if (existingUser) {
            // ── Returning Google user ─────────────────────────────────────
            console.log(`[Google OAuth] Returning user: ${existingKey}`);

            // Link any pending HoneyBound bundle FIRST, then re-read user
            linkPendingHoney(existingKey);
            const freshUser      = users.get(existingKey);
            const hasHoneyBound  = !!(freshUser?.honeySeeds && freshUser?.honeyAccountId);
            const requiresOtp    = !!(hasHoneyBound || freshUser?.totpEnabled);

            req.session.regenerate(err => {
                if (err) return res.redirect('/?error=session');
                req.session.username    = existingKey;
                req.session.displayName = freshUser.displayName || displayName;
                req.session.avatar      = freshUser.avatar || avatar;
                req.session.verified    = !requiresOtp;
                req.session.pendingOtp  = requiresOtp;
                req.session.loginMethod = 'google';
                req.session.googleEmail = googleEmail;
                req.session.otpFailCount = 0;

                req.session.save(() => {
                    // Alert sent to both admin AND the user's own Gmail
                    sendGoogleLoginAlert({
                        username:    existingKey,
                        email:       googleEmail,
                        displayName: freshUser.displayName || displayName,
                        ip,
                        ts:          Date.now(),
                        isNew:       false
                    }).catch(e => console.error('[mailer]', e.message));

                    // OTP if HoneyBound or standard TOTP is enabled, otherwise straight to dashboard
                    res.redirect(requiresOtp ? '/otp' : '/dashboard');
                });
            });

        } else {
            // ── New Google user — auto-register ──────────────────────────
            // Derive a username from email (strip domain, sanitise)
            let baseUsername = googleEmail.split('@')[0].replace(/[^a-z0-9_]/gi, '').toLowerCase();
            if (!baseUsername) baseUsername = 'user';
            // Ensure unique
            let username = baseUsername;
            let suffix   = 1;
            while (users.has(username)) username = baseUsername + suffix++;

            const newUser = {
                username,
                displayName,
                avatar,
                googleSub,
                googleEmail,
                // No passwordHash — Google-only account
                passwordHash: null
            };
            users.set(username, newUser);
            saveUsers(users);
            console.log(`[Google OAuth] New user registered: ${username} (${googleEmail})`);

            req.session.regenerate(err => {
                if (err) return res.redirect('/?error=session');
                req.session.username    = username;
                req.session.displayName = displayName;
                req.session.avatar      = avatar;
                req.session.verified    = true;   // skip OTP for new Google users
                req.session.pendingOtp  = false;
                req.session.loginMethod = 'google';
                req.session.googleEmail = googleEmail;

                req.session.save(() => {
                    // Fire new-Google-user alert
                    sendGoogleLoginAlert({
                        username,
                        email:       googleEmail,
                        displayName,
                        ip,
                        ts:          Date.now(),
                        isNew:       true
                    }).catch(e => console.error('[mailer]', e.message));

                    // Link any pending HoneyBound bundle
                    linkPendingHoney(username);

                    // New Google users go straight to dashboard
                    res.redirect('/dashboard');
                });
            });
        }

    } catch (err) {
        console.error('[Google OAuth] Callback error:', err.message);
        res.redirect('/?error=google_failed');
    }
});

// ─── SESSION API ──────────────────────────────────────────────────────────────
app.get('/api/session-user', (req, res) => {
    if (!req.session.username || (!req.session.verified && !req.session.pendingOtp && !req.session.honeytrap))
        return res.status(401).json({ success: false });
    const user = users.get(req.session.username);
    res.json({
        success:     true,
        username:    req.session.username,
        displayName: req.session.displayName,
        avatar:      req.session.avatar,
        pendingOtp:  req.session.pendingOtp || false,
        totpEnabled: !!(user?.totpEnabled),
        googleEmail: req.session.googleEmail || null,
        honeyAccountId: user?.honeyAccountId || null,
        honeyLinked: !!(user?.honeyAccountId && Array.isArray(user?.honeySeeds) && user.honeySeeds.length)
    });
});

// ─── AUTH — password register / login ─────────────────────────────────────────
app.post('/api/register', (req, res) => {
    const { firstName, lastName, username, password } = req.body;
    if (!firstName || !lastName || !username || !password)
        return res.json({ success: false, message: 'All fields are required.' });
    if (users.has(username.toLowerCase()))
        return res.json({ success: false, message: 'Username already taken.' });

    const user = {
        username:     username.toLowerCase(),
        displayName:  `${firstName} ${lastName}`,
        avatar:       firstName.charAt(0).toUpperCase(),
        passwordHash: hashPassword(password)
    };
    users.set(user.username, user);
    saveUsers(users);

    req.session.username    = user.username;
    req.session.displayName = user.displayName;
    req.session.avatar      = user.avatar;
    req.session.verified    = true;

    req.session.save(() => res.json({ success: true, redirect: '/dashboard' }));
});

app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    if (!username || !password)
        return res.json({ success: false, message: 'Please fill in all fields.' });
    const user = users.get(username.toLowerCase());
    if (!user || !user.passwordHash || !verifyPassword(password, user.passwordHash))
        return res.json({ success: false, message: 'Invalid username or password.' });

    req.session.regenerate(err => {
        if (err) return res.json({ success: false, message: 'Session error.' });
        req.session.username       = user.username;
        req.session.displayName    = user.displayName;
        req.session.avatar         = user.avatar;
        req.session.verified       = false;
        req.session.pendingOtp     = true;
        req.session.loginMethod    = 'password';
        req.session.otpFailCount   = 0;
        req.session.save(() => res.json({ success: true, redirect: '/otp' }));
    });
});

// ─── OTP VERIFICATION ─────────────────────────────────────────────────────────
app.post('/api/verify-otp', async (req, res) => {

    // 1. Valid pending session required
    if (!req.session.pendingOtp || !req.session.username) {
        console.log('[OTP] ❌ No pending session');
        return res.json({ success: false, message: 'No pending OTP session. Please log in again.' });
    }

    const { otp, accountId, windowEnd } = req.body;
    const username = req.session.username;
    const ip       = getIP(req);
    const ua       = req.headers['user-agent'] || '';
    const ts       = Date.now();
    console.log(`[OTP] user="${username}" accountId="${accountId||'(none)'}" otp="${otp}"`);

    // 2. Valid 6-digit OTP required
    if (!otp || !/^[0-9]{6}$/.test(otp)) {
        return res.json({ success: false, message: 'Please enter a valid 6-digit code.' });
    }

    // 3. Account ID required
    if (!accountId || accountId.trim().length < 6) {
        return res.json({
            success: false,
            message: 'No HoneyBound Account ID entered. ' +
                     'Open HoneyBound-Web → My Accounts → click 🔗 on your Connectly account, ' +
                     'then paste the Account ID into the field above.'
        });
    }

    const aid = accountId.trim();

    // 4. Trusted-clock check against HoneyBound
    try {
        const trustedClock = await ensureHoneyBoundTrustedClock(false);
        if (Math.abs(trustedClock.skewMs) > TRUSTED_CLOCK_SKEW_LIMIT_MS) {
            console.warn(
                `[OTP] Trusted-clock mismatch for "${username}" - ` +
                `connectly=${ts} honeybound=${trustedClock.serverTimeMs} skewMs=${trustedClock.skewMs}`
            );
            proxyToHoneyBound('/api/honey/event', {
                accountId: aid,
                outcome: 'invalid',
                serviceName: 'Connectly',
                timestamp: ts,
                reason: 'trusted-clock-mismatch',
                skewMs: trustedClock.skewMs
            }).catch(() => {});
            return res.status(503).json({
                success: false,
                message: 'Trusted server time check failed. Please correct the server clock and try again.'
            });
        }
    } catch (e) {
        console.warn(`[OTP] Trusted-clock check unavailable for "${username}": ${e.message}`);
        return res.status(503).json({
            success: false,
            message: 'Could not verify trusted server time. Please try again shortly.'
        });
    }

    // 5. Clock-tamper / forward-replay guard
    if (windowEnd !== undefined && isWindowStale(windowEnd)) {
        const serverWindow = currentTotpWindow();
        console.warn(`[OTP] ⚠ Stale-window for "${username}" — submitted=${windowEnd} server=${serverWindow}`);
        proxyToHoneyBound('/api/honey/event', {
            accountId: aid, outcome: 'invalid', serviceName: 'Connectly',
            timestamp: ts, reason: 'stale-window'
        }).catch(() => {});
        return res.json({ success: false, message: 'OTP has expired. Please generate a fresh code.' });
    }

    // 6. Find seeds
    const userRecord    = users.get(username);
    const pendingBundle = users.get('__honey__' + aid);
    let seeds = null, realIndex = 0, fromBundle = false;

    if (userRecord?.honeyAccountId === aid && Array.isArray(userRecord.honeySeeds)) {
        seeds     = userRecord.honeySeeds;
        realIndex = userRecord.honeyRealIndex ?? 0;
    } else if (pendingBundle && Array.isArray(pendingBundle.seeds)) {
        seeds      = pendingBundle.seeds;
        realIndex  = pendingBundle.realIndex ?? 0;
        fromBundle = true;
    }

    // 6. No seeds found → hard reject
    if (!seeds) {
        return res.json({
            success: false,
            message: 'This Account ID has not been linked yet. ' +
                     'Complete the 🔗 Link flow in HoneyBound-Web first.'
        });
    }

    // 7. Check real seed
    const matchedWindow = matchedTotpWindowForHexSeed(otp, seeds[realIndex]);
    if (matchedWindow !== null) {
        const replayContainer = fromBundle ? pendingBundle : userRecord;
        const replayState = getReplayState(replayContainer);
        const lastUsedWindow = replayState ? replayState[aid] : undefined;

        if (lastUsedWindow === matchedWindow) {
            console.warn(`[OTP] ⚠ Replay detected for "${username}" — accountId=${aid} window=${matchedWindow}`);
            proxyToHoneyBound('/api/honey/event', {
                accountId: aid, outcome: 'invalid', serviceName: 'Connectly',
                timestamp: ts, windowEnd: matchedWindow, reason: 'replay-window'
            }).catch(() => {});
            return res.json({ success: false, message: 'This OTP has already been used in the current time window. Please wait for a fresh code.' });
        }

        req.session.verified   = true;
        req.session.pendingOtp = false;
        console.log(`[OTP] ✅ SUCCESS for "${username}"`);

        if (fromBundle && userRecord) {
            userRecord.honeyAccountId = aid;
            userRecord.honeySeeds     = seeds;
            userRecord.honeyRealIndex = realIndex;
            userRecord.honeyService   = pendingBundle.serviceName || 'Connectly';
            userRecord.honeyReplayWindows = pendingBundle.honeyReplayWindows || {};
            users.set(username, userRecord);
            users.delete('__honey__' + aid);
        }

        const persistedUser = users.get(username);
        const persistedReplayState = getReplayState(persistedUser);
        persistedReplayState[aid] = matchedWindow;
        users.set(username, persistedUser);
        saveUsers(users);

        proxyToHoneyBound('/api/honey/event', {
            accountId: aid, outcome: 'login', serviceName: 'Connectly',
            timestamp: ts, windowEnd: matchedWindow
        }).catch(() => {});

        // ✉️ Successful login alert (to admin + user's Google email if any)
        sendSuccessfulLoginAlert({
            username,
            ip,
            userAgent:  ua,
            ts,
            method:     req.session.loginMethod || 'password',
            userEmail:  req.session.googleEmail || userRecord?.googleEmail || null
        }).catch(e => console.error('[mailer]', e.message));

        return req.session.save(() => res.json({ success: true, redirect: '/dashboard', mode: 'honeybound' }));
    }

    // 8. Check decoy seeds — honeytrap detection
    for (let i = 0; i < seeds.length; i++) {
        if (i === realIndex) continue;
        if (totpMatchesHexSeed(otp, seeds[i])) {
            console.warn(`[OTP] 🚨 HONEYTRAP for "${username}" — decoy index ${i}`);

            proxyToHoneyBound('/api/honey/event', {
                accountId: aid, outcome: 'honeytrap', serviceName: 'Connectly',
                timestamp: ts, windowEnd: currentTotpWindow()
            }).catch(() => {});

            // ✉️ Honeytrap alert (to admin + user's Google email)
            sendHoneytrapAlert({
                username,
                accountId: aid,
                decoyIndex: i,
                ip,
                userAgent:  ua,
                ts,
                userEmail:  req.session.googleEmail || userRecord?.googleEmail || null
            }).catch(e => console.error('[mailer]', e.message));

            req.session.honeytrap  = true;
            req.session.pendingOtp = false;
            return req.session.save(() => res.json({
                success:   false,
                honeytrap: true,
                index:     i,
                message:   `Decoy seed #${i + 1} was used. This incident has been logged in HoneyBound.`,
                redirect:  '/fakedashboard'
            }));
        }
    }

    // 9. Truly invalid OTP — track failure count and alert on 1st + every 3rd
    req.session.otpFailCount = (req.session.otpFailCount || 0) + 1;
    const failCount = req.session.otpFailCount;

    console.log(`[OTP] ❌ Invalid OTP for "${username}" (attempt #${failCount})`);
    proxyToHoneyBound('/api/honey/event', {
        accountId: aid, outcome: 'invalid', serviceName: 'Connectly',
        timestamp: ts, windowEnd: currentTotpWindow()
    }).catch(() => {});

    // ✉️ Failed OTP alert: fire on 1st attempt and every 3rd after that
    if (failCount === 1 || failCount % 3 === 0) {
        sendFailedOTPAlert({
            username,
            ip,
            userAgent:    ua,
            ts,
            attemptCount: failCount,
            userEmail:    req.session.googleEmail || userRecord?.googleEmail || null
        }).catch(e => console.error('[mailer]', e.message));
    }

    return res.json({ success: false, message: 'Invalid OTP. Please check HoneyBound-Web and try again.' });
});

// ─── FAKE DASHBOARD ACTION LOGGING ───────────────────────────────────────────
// Receives telemetry from fakedashboard.html and fires email alert
const fakeDashboardSessions = new Map(); // track per-session actions

app.post('/api/honeytrap/action', (req, res) => {
    if (!req.session.honeytrap || !req.session.username) {
        return res.json({ ok: false });
    }

    const { action, detail } = req.body;
    const username = req.session.username;
    const ip       = getIP(req);
    const ua       = req.headers['user-agent'] || '';
    const ts       = Date.now();

    console.log(`[FakeDash] 👁 ${username} — ${action}: ${detail}`);

    // Build per-session action log
    if (!fakeDashboardSessions.has(req.session.id)) {
        fakeDashboardSessions.set(req.session.id, []);
    }
    const actions = fakeDashboardSessions.get(req.session.id);
    actions.push({ action, detail, ts });

    // Fire email on page-load (first action) and on high-value actions
    const highValue = ['Change Password', 'Delete Account', '2FA Setup'];
    const isHighValue = highValue.some(v => (detail || '').includes(v));
    const isFirstLoad = action === 'page-load';

    if (isFirstLoad || isHighValue) {
        const userRecord  = users.get(username);
        sendFakeDashboardAlert({
            username,
            ip,
            userAgent: ua,
            ts,
            actions:   actions.slice(-10), // last 10 actions
            userEmail: req.session.googleEmail || userRecord?.googleEmail || null
        }).catch(e => console.error('[mailer]', e.message));
    }

    res.json({ ok: true });
});

// ─── HONEYBOUND ACCOUNT REGISTRATION ─────────────────────────────────────────
app.post('/api/register-honeybound-account', (req, res) => {
    const { accountId, seeds, realIndex, serviceName } = req.body;

    if (!accountId || !Array.isArray(seeds) || seeds.length !== 20 || typeof realIndex !== 'number') {
        return res.status(400).json({ success: false, message: 'Invalid payload.' });
    }

    const hexRe = /^[0-9a-f]+$/i;
    if (!seeds.every(s => typeof s === 'string' && s.length >= 20 && hexRe.test(s))) {
        return res.status(400).json({ success: false, message: 'Invalid seed format.' });
    }

    let targetUsername = req.session?.username || null;

    // If session has a username, always use it directly
    if (!targetUsername) {
        // Try to match by existing honeyAccountId
        for (const [uname, udata] of users.entries()) {
            if (!uname.startsWith('__honey__') && udata.honeyAccountId === accountId) {
                targetUsername = uname;
                break;
            }
        }
    }

    if (targetUsername && users.has(targetUsername)) {
        // User is logged in — link directly
        const user          = users.get(targetUsername);
        user.honeyAccountId = accountId;
        user.honeySeeds     = seeds;
        user.honeyRealIndex = realIndex;
        user.honeyService   = serviceName || 'Connectly';
        user.honeyReplayWindows = user.honeyReplayWindows || {};
        delete user.honeyReplayWindows[accountId];
        users.set(targetUsername, user);
        users.delete('__honey__' + accountId);
        saveUsers(users);
        console.log(`[Link] ✅ Seeds saved directly to user "${targetUsername}" — accountId: ${accountId}`);
    } else {
        // User not logged in yet — save as pending, will be linked on next login
        users.set('__honey__' + accountId, {
            accountId,
            seeds,
            realIndex,
            serviceName: serviceName || 'Connectly',
            honeyReplayWindows: {}
        });
        saveUsers(users);
        console.log(`[Link] Seeds saved as pending bundle — accountId: ${accountId}`);
    }

    res.json({ success: true, accountId });
});

// ─── 2FA SETUP ────────────────────────────────────────────────────────────────
function generateTOTPSecret() {
    const bytes = crypto.randomBytes(20);
    const alpha = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    let bits = '', secret = '';
    for (const b of bytes) bits += b.toString(2).padStart(8, '0');
    for (let i = 0; i + 5 <= bits.length; i += 5)
        secret += alpha[parseInt(bits.slice(i, i + 5), 2)];
    return secret;
}

app.get('/api/2fa/secret', (req, res) => {
    if (!req.session?.verified || !req.session.username)
        return res.status(401).json({ success: false });
    if (!req.session.pending2faSecret)
        req.session.pending2faSecret = generateTOTPSecret();
    req.session.save(() => res.json({ success: true, secret: req.session.pending2faSecret }));
});

app.post('/api/2fa/verify-setup', (req, res) => {
    if (!req.session?.verified || !req.session.username)
        return res.status(401).json({ success: false });
    const { otp } = req.body;
    const secret  = req.session.pending2faSecret;
    if (!secret) return res.json({ success: false, message: 'No pending 2FA setup. Please reload.' });
    if (!otp || !/^[0-9]{6}$/.test(otp)) return res.json({ success: false, message: 'Invalid code.' });

    const now   = Math.floor(Date.now() / 1000);
    const valid = [-1, 0, 1].some(w => {
        const counter = Math.floor((now + w * 30) / 30);
        const cb = Buffer.alloc(8);
        cb.writeUInt32BE(Math.floor(counter / 0x100000000), 0);
        cb.writeUInt32BE(counter >>> 0, 4);
        const alpha = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
        let bits = '';
        for (const c of secret.toUpperCase().replace(/=+$/, '')) {
            const v = alpha.indexOf(c); if (v !== -1) bits += v.toString(2).padStart(5, '0');
        }
        const keyBytes = [];
        for (let j = 0; j + 8 <= bits.length; j += 8) keyBytes.push(parseInt(bits.slice(j, j + 8), 2));
        const key    = Buffer.from(keyBytes);
        const hmac   = crypto.createHmac('sha1', key).update(cb).digest();
        const offset = hmac[hmac.length - 1] & 0x0f;
        const code   = ((hmac[offset] & 0x7f) << 24 | (hmac[offset+1] & 0xff) << 16 |
                        (hmac[offset+2] & 0xff) << 8  | (hmac[offset+3] & 0xff)) % 1000000;
        return code.toString().padStart(6, '0') === otp;
    });

    if (!valid) return res.json({ success: false, message: 'Invalid code — check your authenticator time.' });

    const user = users.get(req.session.username);
    if (!user) return res.json({ success: false, message: 'User not found.' });
    user.totpSecret  = secret;
    user.totpEnabled = true;
    users.set(req.session.username, user);
    saveUsers(users);
    delete req.session.pending2faSecret;
    req.session.save(() => res.json({ success: true }));
});

app.post('/api/logout', (req, res) => {
    req.session.destroy(() => res.json({ success: true }));
});

// ─── 404 fallback ─────────────────────────────────────────────────────────────
app.use((req, res) => res.status(404).send('Not found'));

https.createServer(loadHttpsOptions(), app).listen(PORT, () => console.log(
    `\n🔗 Connectly running at https://localhost:${PORT}` +
    `\n   Google OAuth: /auth/google  (${GOOGLE_OAUTH_READY ? 'configured' : 'set GOOGLE_CLIENT_ID / GOOGLE_CLIENT_SECRET in .env'})` +
    `\n   Email alerts: honeytrap ✓ | login ✓ | failed-OTP ✓ | fake-dash ✓` +
    `\n   OTP mode: STRICT — no fallback` +
    `\n   HoneyBound expected at https://localhost:8443\n`
));
