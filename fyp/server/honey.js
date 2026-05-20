/* ================================================================
   HoneyBound-Web — honey.js  v6

   KEY DESIGN:
   ┌─────────────────────────────────────────────────────────────┐
   │  OTP shown to user = TOTP( base32ToBytes(rawSecret) )       │
   │  → RFC 6238 compliant, works with Instagram/Google/GitHub   │
   │                                                             │
   │  Honeyseed system = PBKDF2(secret+pw, WebAuthn PRF output)  │
   │  → 1 real seed + 19 decoy seeds derived deterministically   │
   │  → Exported to Connectly on enrolment (never at login time) │
   │  → Connectly verifies OTPs locally — no calls back here     │
   │                                                             │
   │  SECRET STORAGE:                                            │
   │  → Encrypted with AES-GCM key derived from WebAuthn PRF     │
   │  → Hardware-backed when the platform authenticator supports │
   │  → Legacy credId-encrypted entries are migrated on access   │
   │                                                             │
   │  DEBUG LOGGING:                                             │
   │  → Timing and state logs only                               │
   │  → No raw seed or decoy material is written to console      │
   └─────────────────────────────────────────────────────────────┘

   Public API: window.Honey
     .addAccount(account, sig, password)  → Promise<entry>
     .generateOTP(accountId)              → Promise<string>  (RFC 6238)
     .verifyOTP(accountId, input)         → Promise<{result, index?}>
     .exportSeedsForConnectly(accountId, sig, password) → Promise<{seeds, realIndex}>
     .getEntry(accountId)                 → entry | null
     .deleteEntry(accountId)             → void
     .logEvent(ev)                       → void
================================================================ */
(function () {
  'use strict';

  var STORE_KEY   = 'hbw_honey_v1';
  var SEED_SS_KEY = 'hbw_seeds_session';
  var SECRET_SS_KEY = 'hbw_secret_session_v1';
  var UNLOCK_SS_KEY = 'hbw_unlock_expires_v1';
  var DECOY_COUNT = 19;
  var CLOCK_SKEW_LIMIT_MS = 30000;
  var CLOCK_CACHE_MS = 15000;
  var SESSION_UNLOCK_MS = 180000;
  var SEED_DERIVATION_VERSION = 2;

  var _seedCache   = new Map();
  var _secretCache = new Map();
  var _clockState  = { checkedAt: 0, skewMs: 0, serverTimeMs: 0 };
  var _sessionKeyCache = new Map();
  var _sessionUnlockExpiresAt = 0;
  var _sessionUnlockTimer = null;
  var _clockBannerEl = null;
  var _clockMonitorTimer = null;

  /* Restore derived seeds from sessionStorage on script load */
  (function restoreSeeds() {
    try {
      var raw = sessionStorage.getItem(SEED_SS_KEY);
      if (!raw) return;
      var map = JSON.parse(raw);
      Object.keys(map).forEach(function(id) {
        var hex   = map[id];
        var bytes = new Uint8Array(hex.match(/.{2}/g).map(function(b) { return parseInt(b, 16); }));
        _seedCache.set(id, bytes);
      });
    } catch(e) {}
  })();

  (function restoreUnlockedState() {
    try {
      var rawSecrets = sessionStorage.getItem(SECRET_SS_KEY);
      if (rawSecrets) {
        var secretMap = JSON.parse(rawSecrets);
        Object.keys(secretMap).forEach(function(id) {
          if (typeof secretMap[id] === 'string' && secretMap[id]) {
            _secretCache.set(id, secretMap[id]);
          }
        });
      }
    } catch(e) {}

    try {
      var rawExpires = sessionStorage.getItem(UNLOCK_SS_KEY);
      var expiresAt = Number(rawExpires || 0);
      if (Number.isFinite(expiresAt) && expiresAt > Date.now()) {
        _sessionUnlockExpiresAt = expiresAt;
        scheduleSessionLock();
      } else {
        sessionStorage.removeItem(UNLOCK_SS_KEY);
        sessionStorage.removeItem(SECRET_SS_KEY);
      }
    } catch(e) {}
  })();

  function persistSeeds() {
    try {
      var map = {};
      _seedCache.forEach(function(bytes, id) { map[id] = toHex(bytes); });
      sessionStorage.setItem(SEED_SS_KEY, JSON.stringify(map));
    } catch(e) {}
  }

  function persistUnlockedSecrets() {
    try {
      var map = {};
      _secretCache.forEach(function(secret, id) {
        if (typeof secret === 'string' && secret) map[id] = secret;
      });
      if (Object.keys(map).length) {
        sessionStorage.setItem(SECRET_SS_KEY, JSON.stringify(map));
      } else {
        sessionStorage.removeItem(SECRET_SS_KEY);
      }
    } catch(e) {}
  }

  function clearUnlockedSession() {
    _sessionKeyCache.clear();
    _secretCache.clear();
    _sessionUnlockExpiresAt = 0;
    try {
      sessionStorage.removeItem(SECRET_SS_KEY);
      sessionStorage.removeItem(UNLOCK_SS_KEY);
    } catch(e) {}
    if (_sessionUnlockTimer) {
      clearTimeout(_sessionUnlockTimer);
      _sessionUnlockTimer = null;
    }
  }

  function scheduleSessionLock() {
    if (_sessionUnlockTimer) clearTimeout(_sessionUnlockTimer);
    if (!_sessionUnlockExpiresAt) return;
    var remaining = Math.max(0, _sessionUnlockExpiresAt - Date.now());
    _sessionUnlockTimer = setTimeout(function() {
      clearUnlockedSession();
      logEvent({ type: 'session-locked', timestamp: Date.now() });
    }, remaining);
  }

  function markSessionUnlocked() {
    _sessionUnlockExpiresAt = Date.now() + SESSION_UNLOCK_MS;
    try { sessionStorage.setItem(UNLOCK_SS_KEY, String(_sessionUnlockExpiresAt)); } catch(e) {}
    persistUnlockedSecrets();
    scheduleSessionLock();
    logEvent({ type: 'session-unlocked', timestamp: Date.now(), expiresAt: _sessionUnlockExpiresAt });
  }

  function hasUnlockedSession() {
    if (!_sessionUnlockExpiresAt) return false;
    if (Date.now() >= _sessionUnlockExpiresAt) {
      clearUnlockedSession();
      return false;
    }
    return true;
  }

  if (typeof window !== 'undefined') {
    window.addEventListener('beforeunload', function() {
      if (!hasUnlockedSession()) clearUnlockedSession();
    });
  }

  /* ── Helpers ── */
  function base32ToBytes(base32) {
    var alpha = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    var bits  = '';
    var out   = [];
    base32 = base32.replace(/=+$/, '').toUpperCase().replace(/[^A-Z2-7]/g, '');
    for (var i = 0; i < base32.length; i++) {
      var v = alpha.indexOf(base32[i]);
      if (v !== -1) bits += v.toString(2).padStart(5, '0');
    }
    for (var j = 0; j + 8 <= bits.length; j += 8)
      out.push(parseInt(bits.substring(j, j + 8), 2));
    return new Uint8Array(out);
  }

  function toHex(buf) {
    return Array.from(buf).map(function(b) { return b.toString(16).padStart(2, '0'); }).join('');
  }

  function concat(a, b) {
    var out = new Uint8Array(a.length + b.length);
    out.set(a); out.set(b, a.length);
    return out;
  }

  function makeClockTamperError(skewMs) {
    var err = new Error(
      'Device clock differs from trusted server time by ' +
      Math.round(Math.abs(skewMs) / 1000) +
      's. Sensitive key operations are blocked until the clock is corrected.'
    );
    err.code = 'CLOCK_TAMPER';
    err.skewMs = skewMs;
    return err;
  }

  function ensureClockBanner() {
    if (typeof document === 'undefined') return null;
    if (_clockBannerEl && document.body && document.body.contains(_clockBannerEl)) return _clockBannerEl;

    var el = document.createElement('div');
    el.id = 'hbw-clock-tamper-banner';
    el.style.cssText = [
      'position:fixed',
      'top:16px',
      'left:50%',
      'transform:translateX(-50%)',
      'z-index:100000',
      'max-width:min(92vw,760px)',
      'padding:12px 16px',
      'border:1px solid rgba(255,77,106,0.45)',
      'border-radius:12px',
      'background:rgba(31,12,18,0.96)',
      'color:#ffd7de',
      'font:600 13px/1.45 Manrope, sans-serif',
      'box-shadow:0 14px 40px rgba(0,0,0,0.35)',
      'display:none'
    ].join(';');
    document.body.appendChild(el);
    _clockBannerEl = el;
    return el;
  }

  function showClockTamperBanner(skewMs) {
    var el = ensureClockBanner();
    if (!el) return;
    el.textContent =
      'Clock tampering detected: this device differs from trusted server time by about ' +
      Math.round(Math.abs(skewMs) / 1000) +
      ' seconds. HoneyBound has blocked sensitive actions until the clock is corrected.';
    el.style.display = 'block';
  }

  function hideClockTamperBanner() {
    var el = ensureClockBanner();
    if (!el) return;
    el.style.display = 'none';
  }

  async function sha256(data) {
    return new Uint8Array(await crypto.subtle.digest('SHA-256', data));
  }

  async function pbkdf2(keyBytes, saltBytes, iterations) {
    var km = await crypto.subtle.importKey('raw', keyBytes, { name: 'PBKDF2' }, false, ['deriveBits']);
    var bits = await crypto.subtle.deriveBits(
      { name: 'PBKDF2', salt: saltBytes, iterations: iterations || 1000, hash: 'SHA-256' },
      km, 160
    );
    return new Uint8Array(bits);
  }

  /* ── Standard RFC 6238 TOTP from raw seed bytes ── */
  async function totpFromSeed(seedBytes, digits, period) {
    digits = digits || 6;
    period = period || 30;
    var counter = Math.floor(Date.now() / 1000 / period);
    var cb = new ArrayBuffer(8);
    new DataView(cb).setUint32(4, counter, false);
    var key  = await crypto.subtle.importKey('raw', seedBytes, { name: 'HMAC', hash: 'SHA-1' }, false, ['sign']);
    var hmac = new Uint8Array(await crypto.subtle.sign('HMAC', key, cb));
    var off  = hmac[hmac.length - 1] & 0x0f;
    var code =
      ((hmac[off]     & 0x7f) << 24) |
      ((hmac[off + 1] & 0xff) << 16) |
      ((hmac[off + 2] & 0xff) << 8)  |
       (hmac[off + 3] & 0xff);
    return (code % Math.pow(10, digits)).toString().padStart(digits, '0');
  }

  /* ── Storage ── */
  function loadStore() {
    try { return JSON.parse(localStorage.getItem(STORE_KEY) || '{}'); } catch(e) { return {}; }
  }
  function saveStore(store) { localStorage.setItem(STORE_KEY, JSON.stringify(store)); }

  async function ensureTrustedClock(force) {
    var now = Date.now();
    if (!force && _clockState.checkedAt && (now - _clockState.checkedAt) < CLOCK_CACHE_MS) {
      if (Math.abs(_clockState.skewMs) > CLOCK_SKEW_LIMIT_MS) {
        showClockTamperBanner(_clockState.skewMs);
        throw makeClockTamperError(_clockState.skewMs);
      }
      hideClockTamperBanner();
      return _clockState;
    }

    var resp = await fetch('/api/honey/time', { cache: 'no-store' });
    if (!resp.ok) throw new Error('Could not verify trusted server time (HTTP ' + resp.status + ').');
    var payload = await resp.json();
    var skewMs = now - Number(payload.serverTimeMs || 0);
    _clockState = {
      checkedAt: now,
      skewMs: skewMs,
      serverTimeMs: Number(payload.serverTimeMs || 0)
    };

    if (Math.abs(skewMs) > CLOCK_SKEW_LIMIT_MS) {
      logEvent({ type: 'clock-tamper-detected', skewMs: skewMs, timestamp: Date.now() });
      showClockTamperBanner(skewMs);
      throw makeClockTamperError(skewMs);
    }
    hideClockTamperBanner();
    return _clockState;
  }

  function startClockTamperMonitor() {
    if (typeof window === 'undefined' || typeof document === 'undefined') return;
    if (_clockMonitorTimer) return;

    function runCheck(force) {
      ensureTrustedClock(!!force).catch(function(err) {
        if (!(err && err.code === 'CLOCK_TAMPER')) {
          console.warn('[HoneyBound] trusted-time check failed:', err && err.message ? err.message : err);
        }
      });
    }

    window.addEventListener('load', function() {
      setTimeout(function() { runCheck(true); }, 600);
    });

    document.addEventListener('visibilitychange', function() {
      if (!document.hidden) runCheck(true);
    });

    _clockMonitorTimer = setInterval(function() {
      if (!document.hidden) runCheck(false);
    }, 10000);
  }

  var PRF_LABEL  = 'encryption';
  var PRF_PREFIX = 'prf1:';

  function getCredIdBytes() {
    var credId = localStorage.getItem('hbw_webauthn_cred_id_v1') || '';
    if (!credId) throw new Error('No WebAuthn credential registered for this device.');
    return Uint8Array.from(atob(credId), function(c) { return c.charCodeAt(0); });
  }

  function assertionToSigBytes(input) {
    if (!input) return null;
    if (input instanceof Uint8Array) return input;
    if (input instanceof ArrayBuffer) return new Uint8Array(input);
    if (input.response && input.response.signature) return new Uint8Array(input.response.signature);
    return null;
  }

  async function sha256Text(text) {
    return new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text)));
  }

  function extractPRFBytes(assertion) {
    if (!assertion || typeof assertion.getClientExtensionResults !== 'function') return null;
    var ext = assertion.getClientExtensionResults();
    if (!ext || !ext.prf || !ext.prf.results || !ext.prf.results.first) return null;
    return new Uint8Array(ext.prf.results.first);
  }

  async function assertWithPRF(label) {
    await ensureTrustedClock(true);
    var challenge = crypto.getRandomValues(new Uint8Array(32));
    var allowId   = getCredIdBytes();
    var firstSalt = await sha256Text('HoneyBound-PRF:' + (label || PRF_LABEL));

    var assertion = await navigator.credentials.get({
      publicKey: {
        challenge: challenge,
        allowCredentials: [{ id: allowId, type: 'public-key' }],
        userVerification: 'required',
        timeout: 60000,
        extensions: { prf: { eval: { first: firstSalt } } }
      }
    });

    if (!extractPRFBytes(assertion)) {
      throw new Error('This browser or authenticator did not return WebAuthn PRF output.');
    }
    return assertion;
  }

  async function derivePRFAESKey(assertion, label) {
    var prfBytes = extractPRFBytes(assertion);
    if (!prfBytes) {
      throw new Error('PRF output missing — cannot derive the hardware-bound AES key.');
    }
    var domain = new TextEncoder().encode('HoneyBound-prf-aes-v1:' + (label || PRF_LABEL) + ':');
    var material = concat(domain, prfBytes);
    var rawKey = await crypto.subtle.digest('SHA-256', material);
    return await crypto.subtle.importKey(
      'raw', rawKey, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']
    );
  }

  async function getPRFAESKey(assertion, label) {
    var resolvedLabel = label || PRF_LABEL;

    if (!assertion && hasUnlockedSession() && _sessionKeyCache.has(resolvedLabel)) {
      markSessionUnlocked();
      return _sessionKeyCache.get(resolvedLabel);
    }

    var activeAssertion = assertion || await assertWithPRF(resolvedLabel);
    var key = await derivePRFAESKey(activeAssertion, resolvedLabel);

    if (resolvedLabel === PRF_LABEL) {
      _sessionKeyCache.set(resolvedLabel, key);
      markSessionUnlocked();
    }

    return key;
  }

  /* Legacy path kept only so older entries can be migrated to PRF-backed storage. */
  async function deriveLegacyAESKey() {
    var credId    = localStorage.getItem('hbw_webauthn_cred_id_v1') || '';
    var credBytes = new TextEncoder().encode('HoneyBound-stable-secret-v1:' + credId);
    var rawKey    = await crypto.subtle.digest('SHA-256', credBytes);
    return await crypto.subtle.importKey(
      'raw', rawKey, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']
    );
  }

  async function encryptSecret(rawSecret, assertion) {
    var key = await getPRFAESKey(assertion, PRF_LABEL);
    var iv  = crypto.getRandomValues(new Uint8Array(12));
    var ct  = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: iv },
      key,
      new TextEncoder().encode(rawSecret)
    );
    var combined = new Uint8Array(12 + ct.byteLength);
    combined.set(iv);
    combined.set(new Uint8Array(ct), 12);
    return PRF_PREFIX + btoa(String.fromCharCode.apply(null, combined));
  }

  async function decryptSecret(encryptedValue, assertion) {
    var encoded  = encryptedValue;
    var key;

    if (typeof encoded === 'string' && encoded.indexOf(PRF_PREFIX) === 0) {
      encoded = encoded.slice(PRF_PREFIX.length);
      key = await getPRFAESKey(assertion, PRF_LABEL);
    } else {
      key = await deriveLegacyAESKey();
    }

    var combined = Uint8Array.from(atob(encoded), function(c) { return c.charCodeAt(0); });
    var iv       = combined.slice(0, 12);
    var ct       = combined.slice(12);
    var plain    = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: iv }, key, ct);
    return new TextDecoder().decode(plain);
  }

  /* ── Get raw secret — cache first, then decrypt via PRF or migrate legacy ── */
  async function getDecryptedSecret(accountId, assertion) {
    await ensureTrustedClock(false);
    var cached = _secretCache.get(accountId);
    if (cached) return cached;

    var store = loadStore();
    var entry = store[accountId];
    if (!entry) throw new Error('Account not found in honey store: ' + accountId);

    /* Legacy plain-text fallback for entries from old versions.
       Migrate immediately so the secret is no longer persisted in plain text. */
    if (!entry.encryptedSecret && entry.secret) {
      var migratedSecret = entry.secret;
      entry.encryptedSecret = await encryptSecret(migratedSecret, assertion);
      entry.hwMode = 'prf';
      delete entry.secret;
      store[accountId] = entry;
      saveStore(store);
      _secretCache.set(accountId, migratedSecret);
      persistUnlockedSecrets();
      return migratedSecret;
    }

    if (entry.encryptedSecret) {
      /* Check credId exists — it is needed to select the resident credential */
      var credId = localStorage.getItem('hbw_webauthn_cred_id_v1');
      if (!credId) {
        throw new Error(
          'Authenticator credential not found in localStorage. ' +
          'The app may have been re-initialised — re-add this account to restore OTPs.'
        );
      }
      /* Let decryption errors propagate with their real message — do NOT swallow them. */
      var secret = await decryptSecret(entry.encryptedSecret, assertion);
      if (typeof entry.encryptedSecret === 'string' && entry.encryptedSecret.indexOf(PRF_PREFIX) !== 0) {
        var migrateAssertion = assertion || await assertWithPRF(PRF_LABEL);
        entry.encryptedSecret = await encryptSecret(secret, migrateAssertion);
        entry.hwMode = 'prf';
        store[accountId] = entry;
        saveStore(store);
      }
      _secretCache.set(accountId, secret);
      persistUnlockedSecrets();
      return secret;
    }

    throw new Error('No secret available for: ' + accountId + ' — please re-add the account.');
  }

  /* ── Derivation timing log ── */
  var DERIV_LOG_KEY = 'hbw_deriv_log_v1';

  function persistDerivTime(ms) {
    try {
      var log = JSON.parse(localStorage.getItem(DERIV_LOG_KEY) || '[]');
      log.push(parseFloat(ms.toFixed(3)));
      if (log.length > 200) log.splice(0, log.length - 200);
      localStorage.setItem(DERIV_LOG_KEY, JSON.stringify(log));
    } catch(e) {}
    if (typeof window !== 'undefined' && typeof window.logDerivationTime === 'function') {
      window.logDerivationTime(ms);
    }
  }

  async function deriveSeedSaltFromPRF(assertion) {
    var prfBytes = extractPRFBytes(assertion);
    if (!prfBytes) {
      throw new Error('PRF output missing — cannot derive deterministic honeyseed material.');
    }
    return await sha256(concat(
      new TextEncoder().encode('HoneyBound-prf-seed-v2:'),
      prfBytes
    ));
  }

  /* ── Seed derivation ── */
  async function deriveRealSeed(base32Secret, assertion, password) {
    if (!assertion) {
      throw new Error('A WebAuthn PRF assertion is required for deterministic seed derivation.');
    }
    var secretBytes = base32ToBytes(base32Secret);
    var seedSalt = await deriveSeedSaltFromPRF(assertion);
    var t0 = performance.now();
    var result;
    if (password) {
      var passwordBytes = new TextEncoder().encode(password);
      result = await pbkdf2(concat(secretBytes, passwordBytes), seedSalt, 1000);
    } else {
      result = await pbkdf2(secretBytes, seedSalt, 1000);
    }
    var elapsed = performance.now() - t0;
    persistDerivTime(elapsed);
    console.log('[HoneyBound] deriveRealSeed: ' + elapsed.toFixed(2) + ' ms');
    return result;
  }

  /* ── Derive 19 decoy seeds ── */
  async function deriveHoneySeeds(derivedSeed) {
    var seeds = [];
    for (var i = 0; i < DECOY_COUNT; i++) {
      var salt = await sha256(concat(derivedSeed, new Uint8Array([i])));
      var s    = await pbkdf2(derivedSeed, salt, 500);
      seeds.push(s);
    }
    return seeds;
  }

  /* ── Add account ── */
  async function addAccount(account, sig, password) {
    var id     = account.id;
    var secret = account.secret;
    var digits = account.digits || 6;
    var period = account.period || 30;
    var assertion = sig || null;

    var store = loadStore();

    var encryptedSecret = await encryptSecret(secret, assertion);

    if (assertion && password !== undefined && password !== null) {
      /* ── HONEYSEED MODE ── */
      var _t0Total    = performance.now();
      var derivedSeed = await deriveRealSeed(secret, assertion, password);

      console.log('[HoneyBound] addAccount: ' + (account.serviceName || id));

      var honeySeeds  = await deriveHoneySeeds(derivedSeed);
      var _totalMs    = performance.now() - _t0Total;
      console.log('[HoneyBound] Honeyseed batch ready in ' + _totalMs.toFixed(2) + ' ms');

      /* Shuffle pool to hide which index is real */
      var pool = [derivedSeed].concat(honeySeeds);
      for (var i = pool.length - 1; i > 0; i--) {
        var j = crypto.getRandomValues(new Uint8Array(1))[0] % (i + 1);
        var tmp = pool[i]; pool[i] = pool[j]; pool[j] = tmp;
      }
      var derivedHex = toHex(derivedSeed);
      var realIndex  = pool.findIndex(function(s) { return toHex(s) === derivedHex; });

      var hashes = [];
      for (var k = 0; k < pool.length; k++) {
        hashes.push(toHex(await sha256(pool[k])));
      }

      store[id] = {
        id: id, serviceName: account.serviceName,
        encryptedSecret: encryptedSecret,
        digits: digits, period: period,
        realIndex: realIndex, seedHashes: hashes,
        honeyEnabled: true,
        hwMode: 'prf',
        seedDerivationVersion: SEED_DERIVATION_VERSION
      };

    } else {
      /* ── STANDARD MODE ── */
      console.log('[HoneyBound] addAccount (standard mode): ' + (account.serviceName || id));

      store[id] = {
        id: id, serviceName: account.serviceName,
        encryptedSecret: encryptedSecret,
        digits: digits, period: period,
        honeyEnabled: false,
        hwMode: 'prf',
        seedDerivationVersion: 0
      };
    }

    saveStore(store);

    _secretCache.set(id, secret);
    persistUnlockedSecrets();
    if (assertion && password !== undefined && password !== null) {
      var ds = await deriveRealSeed(secret, assertion, password);
      _seedCache.set(id, ds);
    }
    persistSeeds();

    logEvent({ type: 'account-added', serviceName: account.serviceName, id: id,
               honeyEnabled: !!(assertion && password !== undefined && password !== null),
               timestamp: Date.now() });
    return store[id];
  }

  /* ── OTP generation ── */
  async function generateOTP(accountId) {
    await ensureTrustedClock(false);
    var store = loadStore();
    var entry = store[accountId];
    if (!entry) throw new Error('Account not in honey store: ' + accountId);

    var secret = await getDecryptedSecret(accountId);
    return await totpFromSeed(base32ToBytes(secret), entry.digits, entry.period);
  }

  /* ── Verify OTP — client-side check ── */
  async function verifyOTP(accountId, inputOTP) {
    var store = loadStore();
    var entry = store[accountId];
    if (!entry) return { result: 'invalid' };

    var secret;
    try { secret = await getDecryptedSecret(accountId); }
    catch(e) { return { result: 'invalid' }; }

    var realOTP = await totpFromSeed(base32ToBytes(secret), entry.digits, entry.period);
    if (inputOTP === realOTP) {
      logEvent({ type: 'login-success', accountId: accountId, serviceName: entry.serviceName, timestamp: Date.now() });
      return { result: 'success' };
    }

    if (!entry.honeyEnabled) {
      logEvent({ type: 'login-invalid', accountId: accountId, serviceName: entry.serviceName, timestamp: Date.now() });
      return { result: 'invalid' };
    }

    var derivedSeed = _seedCache.get(accountId);
    if (derivedSeed) {
      var honeySeeds = await deriveHoneySeeds(derivedSeed);
      for (var i = 0; i < honeySeeds.length; i++) {
        var hOTP = await totpFromSeed(honeySeeds[i], entry.digits, entry.period);
        if (inputOTP === hOTP) {
          logEvent({ type: 'honeytrap-triggered', accountId: accountId, serviceName: entry.serviceName, honeyIndex: i, timestamp: Date.now() });
          return { result: 'honeytrap', index: i };
        }
      }
    }

    logEvent({ type: 'login-invalid', accountId: accountId, serviceName: entry.serviceName, timestamp: Date.now() });
    return { result: 'invalid' };
  }

  /* ── exportSeedsForConnectly ──
     Real seed (index 0) = base32ToBytes(rawSecret) — RFC 6238, same as displayed OTP.
     Decoy seeds (1-19)  = PBKDF2-derived from deterministic PRF-backed material.

     Accounts created before seedDerivationVersion 2 used a non-deterministic signature
     salt. When such an account is exported here, we intentionally migrate it to the new
     deterministic derivation path and expect Connectly to be updated with the returned
     seed set in the same operation.
  ── */
  async function exportSeedsForConnectly(accountId, sig, derivationPassword) {
    var assertion = sig || null;
    var entry = loadStore()[accountId] || null;
    var rawSecret = await getDecryptedSecret(accountId, assertion);
    var realSeedBytes = base32ToBytes(rawSecret);

    var derivedSeed = _seedCache.get(accountId);
    var needsDeterministicMigration = !!(entry && entry.honeyEnabled && entry.seedDerivationVersion !== SEED_DERIVATION_VERSION);

    if (!derivedSeed || needsDeterministicMigration) {
      if (!assertion) throw new Error(
        'Seed cache is cold and no WebAuthn PRF assertion was provided. ' +
        'Re-open the app and re-tap your authenticator to restore deterministic seed derivation.'
      );
      if (needsDeterministicMigration) {
        console.warn('[HoneyBound] exportSeedsForConnectly: migrating legacy account to deterministic PRF seed derivation.');
      }
      derivedSeed = await deriveRealSeed(rawSecret, assertion, derivationPassword);
      _seedCache.set(accountId, derivedSeed);
      persistSeeds();

      if (entry) {
        entry.seedDerivationVersion = SEED_DERIVATION_VERSION;
        entry.hwMode = 'prf';
        var store = loadStore();
        store[accountId] = entry;
        saveStore(store);
      }
    }

    console.log('[HoneyBound] exportSeedsForConnectly: ' + accountId);

    var honeySeeds = await deriveHoneySeeds(derivedSeed);
    console.log('[HoneyBound] Prepared ' + (honeySeeds.length + 1) + ' export seeds for Connectly');

    var allSeeds   = [realSeedBytes].concat(honeySeeds);
    var seedHexArr = allSeeds.map(function(s) { return toHex(s); });

    logEvent({ type: 'account-linked',
               serviceName: loadStore()[accountId] ? loadStore()[accountId].serviceName : accountId,
               timestamp: Date.now() });

    return {
      seeds: seedHexArr,
      realIndex: 0,
      seedDerivationVersion: entry && entry.seedDerivationVersion ? entry.seedDerivationVersion : SEED_DERIVATION_VERSION,
      migrated: needsDeterministicMigration
    };
  }

  /* ── CRUD ── */
  function getEntry(accountId) { return loadStore()[accountId] || null; }

  function deleteEntry(accountId) {
    var store = loadStore();
    delete store[accountId];
    saveStore(store);
    _seedCache.delete(accountId);
    _secretCache.delete(accountId);
    persistUnlockedSecrets();
    persistSeeds();
    logEvent({ type: 'account-deleted', accountId: accountId, timestamp: Date.now() });
  }

  function loadAll() { return Object.values(loadStore()); }

  function cacheSeed(accountId, seedBytes) {
    _seedCache.set(accountId, seedBytes);
    persistSeeds();
  }

  function hasCachedSeed(accountId) {
    var entry = loadStore()[accountId];
    return !!(entry && (entry.encryptedSecret || entry.secret));
  }

  /* ── Event bus ── */
  function logEvent(ev) {
    window.dispatchEvent(new CustomEvent('honey-event', { detail: ev }));
    try {
      var log = JSON.parse(localStorage.getItem('hbw_honey_log_v1') || '[]');
      log.unshift(ev);
      if (log.length > 1000) log.splice(1000);
      localStorage.setItem('hbw_honey_log_v1', JSON.stringify(log));
    } catch(e) {}
  }

  /* ── Expose ── */
  window.Honey = {
    addAccount:               addAccount,
    generateOTP:              generateOTP,
    verifyOTP:                verifyOTP,
    exportSeedsForConnectly:  exportSeedsForConnectly,
    getEntry:                 getEntry,
    deleteEntry:              deleteEntry,
    loadAll:                  loadAll,
    cacheSeed:                cacheSeed,
    hasCachedSeed:            hasCachedSeed,
    logEvent:                 logEvent,
    ensureTrustedClock:       ensureTrustedClock,
    assertWithPRF:            assertWithPRF,
    lockSession:              clearUnlockedSession,
    hasUnlockedSession:       hasUnlockedSession,
    _seedCache:               _seedCache,
    _secretCache:             _secretCache,
    _derivePRFAESKey:         derivePRFAESKey,
    _deriveRealSeed:          deriveRealSeed,
    _deriveHoneySeeds:        deriveHoneySeeds,
    _totpFromSeed:            totpFromSeed,
    _encryptSecret:           encryptSecret,
    _decryptSecret:           decryptSecret,
    _getDecryptedSecret:      getDecryptedSecret
  };

  console.log('[HoneyBound] honey.js v6 loaded — PRF-backed encryption, cold-cache OTP recovery.');
  startClockTamperMonitor();
})();
