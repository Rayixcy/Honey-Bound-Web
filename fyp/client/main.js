// ================================================================
// HoneyBound-Web — main.js  v4
// One-time WebAuthn PRF assertion per session.
// After that, OTPs refresh every 30s — no PIN prompts.
// Hardware binding: PRF extension → HKDF → AES-GCM (TPM/Enclave)
// Fallback: credId-based key when PRF not available.
// ================================================================

var accounts             = [];
var webAuthnCredentialId = null;
var isInitialized        = false;

// _sessionAssertion: the ONE WebAuthn assertion (with PRF) captured on
// this page load. Used to derive seeds for all accounts.
var _sessionAssertion   = null;
var _sessionSig         = null;  // raw sig bytes from same assertion (for PBKDF2)
var _authInProgress     = false;
var _pendingAfterAuth   = [];

var STORAGE_KEY = 'hbw_accounts_v1';
var CRED_KEY    = 'hbw_webauthn_cred_id_v1';
var CONNECTLY_REGISTER_URL =
  (window.HBW_CONFIG && window.HBW_CONFIG.connectlyRegisterUrl) ||
  'https://localhost:3000/api/register-honeybound-account';

/* ── Helpers ── */

function generateRandomId() {
  return Math.random().toString(36).substring(2, 15);
}

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

function getTimeRemaining(period) {
  period = period || 30;
  return period - (Math.floor(Date.now() / 1000) % period);
}

/* ── Persistence ── */

function loadAccounts() {
  var stored = localStorage.getItem(STORAGE_KEY);
  var cred   = localStorage.getItem(CRED_KEY);
  if (stored) {
    try { accounts = JSON.parse(stored); } catch (e) { accounts = []; }
  }
  if (cred) webAuthnCredentialId = cred;
}

function saveAccounts() {
  var metadata = accounts.map(function (account) {
    return {
      id: account.id,
      serviceName: account.serviceName,
      digits: account.digits || 6,
      period: account.period || 30
    };
  });
  localStorage.setItem(STORAGE_KEY, JSON.stringify(metadata));
}

/* ── WebAuthn initialisation — CREATE with PRF extension ────────────
   Registration requests the PRF extension so the credential is
   PRF-capable from the start. Chrome 108+, Edge, Safari all support
   this. Firefox will silently ignore the extension — which is fine,
   honey.js will fall back to the credId-based key automatically.
── */

async function initializeAuthenticator() {
  try {
    var challenge = crypto.getRandomValues(new Uint8Array(32));
    var userId    = crypto.getRandomValues(new Uint8Array(16));

    var credential = await navigator.credentials.create({
      publicKey: {
        challenge: challenge,
        rp:   { name: 'HoneyBound Authenticator', id: window.location.hostname },
        user: { id: userId, name: 'local-user', displayName: 'Local Device User' },
        pubKeyCredParams: [
          { alg: -7,   type: 'public-key' },
          { alg: -257, type: 'public-key' }
        ],
        authenticatorSelection: {
          authenticatorAttachment: 'platform',
          userVerification:        'required',
          residentKey:             'required'
        },
        /* Request PRF extension at registration time so the authenticator
           knows this credential will need PRF support */
        extensions: {
          prf: {}
        },
        timeout: 60000
      }
    });

    var rawId = new Uint8Array(credential.rawId);
    webAuthnCredentialId = btoa(String.fromCharCode.apply(null, rawId));
    localStorage.setItem(CRED_KEY, webAuthnCredentialId);

    /* Check if PRF was granted at registration */
    var ext    = credential.getClientExtensionResults();
    var prfOk  = !!(ext && ext.prf && ext.prf.enabled);
    localStorage.setItem('hbw_prf_supported_v1', prfOk ? 'true' : 'false');
    console.log('[HoneyBound] PRF at registration:', prfOk ? '✓ enabled (hardware binding active)' : '✗ not available (fallback mode)');

    isInitialized = true;

    var initScreen = document.getElementById('initScreen');
    var dashboard  = document.getElementById('dashboard');
    if (initScreen) initScreen.classList.add('hidden');
    if (dashboard)  dashboard.classList.remove('hidden');
    renderAccounts();
    console.log('[HoneyBound] Authenticator initialized — credential created');
  } catch (err) {
    console.error('[HoneyBound] Init error:', err);
    alert('Authentication failed or cancelled: ' + err.message);
  }
}

/* ── One-time session assertion WITH PRF extension ──────────────────
   Called ONCE when the page loads.
   Returns the full WebAuthn assertion (not just sig bytes).
   honey.js extracts PRF output from assertion.getClientExtensionResults().
   Signature bytes are retained only for compatibility with older sessions.
── */

async function acquireSessionAssertion() {
  if (_sessionAssertion) return _sessionAssertion;
  if (_authInProgress) {
    return new Promise(function (resolve, reject) {
      _pendingAfterAuth.push({ resolve: resolve, reject: reject });
    });
  }

  if (!webAuthnCredentialId) throw new Error('No credential registered');

  _authInProgress = true;
  try {
    /* Use honey.js assertWithPRF so the PRF salt strategy is consistent */
    var assertion;
    if (window.Honey && window.Honey.assertWithPRF) {
      assertion = await window.Honey.assertWithPRF('encryption');
    } else {
      /* honey.js not loaded yet — do a plain assertion */
      var challenge   = crypto.getRandomValues(new Uint8Array(32));
      var credIdBytes = Uint8Array.from(atob(webAuthnCredentialId), function (c) { return c.charCodeAt(0); });
      assertion = await navigator.credentials.get({
        publicKey: {
          challenge:        challenge,
          allowCredentials: [{ id: credIdBytes, type: 'public-key' }],
          userVerification: 'required',
          timeout:          60000,
          extensions:       { prf: { eval: { first: new Uint8Array(32) } } }
        }
      });
    }

    _sessionAssertion = assertion;
    _sessionSig       = new Uint8Array(assertion.response.signature);

    _pendingAfterAuth.forEach(function (p) { p.resolve(assertion); });
    _pendingAfterAuth = [];
    return assertion;
  } catch (err) {
    _pendingAfterAuth.forEach(function (p) { p.reject(err); });
    _pendingAfterAuth = [];
    throw err;
  } finally {
    _authInProgress = false;
  }
}

/* Legacy shim: code that calls acquireSessionSig() still works */
async function acquireSessionSig() {
  var assertion = await acquireSessionAssertion();
  return new Uint8Array(assertion.response.signature);
}

/* ── Warm all seeds — enrol accounts with hardware-bound key ────────
   Called once on page load.
   1. Gets the session assertion (ONE PIN prompt).
   2. Passes the full assertion object to honey.js so it can extract PRF.
   3. For each account, derives + caches seed. No further PIN prompts.
── */

async function warmAllSeeds() {
  if (!window.Honey || !accounts.length) return;

  var allEnrolled = accounts.every(function (a) { return window.Honey.getEntry(a.id); });

  if (allEnrolled) {
    /* Already enrolled — just warm the secret cache for this session */
    var needsAssertion = accounts.some(function (a) {
      var entry = window.Honey.getEntry(a.id);
      return entry && !window.Honey._secretCache.get(a.id);
    });

    if (needsAssertion) {
      var assertion = await acquireSessionAssertion();
      for (var i = 0; i < accounts.length; i++) {
        var acc   = accounts[i];
        var entry = window.Honey.getEntry(acc.id);
        if (!entry || window.Honey._secretCache.get(acc.id)) continue;
        try {
          if (entry.encryptedSecret) {
            /* Pass assertion so honey.js can use PRF key to decrypt */
            var decrypted = await window.Honey._getDecryptedSecret(acc.id, assertion);
            window.Honey._secretCache.set(acc.id, decrypted);
          } else if (entry.secret) {
            window.Honey._secretCache.set(acc.id, entry.secret);
          }
        } catch (e) {
          console.error('[HoneyBound] Secret warm failed for ' + acc.serviceName + ':', e.message);
        }
      }
    }
    console.log('[HoneyBound] Session cache warmed — all secrets decrypted in memory.');
    return;
  }

  /* Some accounts not yet enrolled — enrol with assertion */
  var assertion2 = await acquireSessionAssertion();
  var sig2       = new Uint8Array(assertion2.response.signature);

  for (var k = 0; k < accounts.length; k++) {
    var acc3 = accounts[k];
    if (window.Honey.getEntry(acc3.id)) continue;
    try {
      /* Enrol any existing local account entry into the protected store */
      await window.Honey.addAccount(acc3, assertion2, null);
      window.Honey._secretCache.set(acc3.id, acc3.secret);
    } catch (e) {
      console.error('[HoneyBound] Enrol failed for ' + acc3.serviceName + ':', e.message);
    }
  }
  console.log('[HoneyBound] All accounts enrolled.');
}

/* ── OTP generation — RFC 6238, no repeated PIN prompts ─────────── */

async function generateTOTPWithHardware(base32Secret, digits, period, accountId) {
  digits = digits || 6;
  period = period || 30;

  var t0 = performance.now();

  /* Enrol if needed — fires ONE PIN prompt the first time */
  if (accountId && window.Honey && !window.Honey.getEntry(accountId)) {
    try {
      await warmAllSeeds();
    } catch (warmErr) {
      console.warn('[HoneyBound] warmAllSeeds failed, using raw TOTP:', warmErr && warmErr.message);
    }
  }

  var code;
  try {
    if (accountId && window.Honey && window.Honey.getEntry(accountId)) {
      code = await window.Honey.generateOTP(accountId);
    } else {
      code = await rawTOTP(base32Secret, digits, period);
    }
  } catch (otpErr) {
    if (otpErr && otpErr.code === 'CLOCK_TAMPER') throw otpErr;
    console.warn('[HoneyBound] Honey OTP failed, using raw TOTP:', otpErr && otpErr.message);
    code = await rawTOTP(base32Secret, digits, period);
  }

  recordDerivationTime(performance.now() - t0);
  return code;
}

/* ── Raw RFC 6238 TOTP (fallback) ── */
async function rawTOTP(base32Secret, digits, period) {
  var secretBytes = base32ToBytes(base32Secret);
  var counter     = Math.floor(Date.now() / 1000 / period);
  var cb  = new ArrayBuffer(8);
  new DataView(cb).setUint32(4, counter, false);
  var key  = await crypto.subtle.importKey('raw', secretBytes, { name: 'HMAC', hash: 'SHA-1' }, false, ['sign']);
  var hmac = new Uint8Array(await crypto.subtle.sign('HMAC', key, cb));
  var off  = hmac[hmac.length - 1] & 0x0f;
  var code =
    ((hmac[off]     & 0x7f) << 24) |
    ((hmac[off + 1] & 0xff) << 16) |
    ((hmac[off + 2] & 0xff) << 8)  |
     (hmac[off + 3] & 0xff);
  return (code % Math.pow(10, digits)).toString().padStart(digits, '0');
}

/* ── Persist derivation timing ── */
var DERIV_LOG_KEY = 'hbw_deriv_log_v1';

function recordDerivationTime(ms) {
  try {
    var log = JSON.parse(localStorage.getItem(DERIV_LOG_KEY) || '[]');
    log.push(parseFloat(ms.toFixed(2)));
    if (log.length > 100) log.splice(0, log.length - 100);
    localStorage.setItem(DERIV_LOG_KEY, JSON.stringify(log));
  } catch (e) {}
  if (typeof window.logDerivationTime === 'function') window.logDerivationTime(ms);
}

/* ── Copy OTP ── */

async function copyOTP(accountId) {
  var el = document.getElementById('otp-' + accountId);
  if (!el || el.textContent === '------') return;
  var text = el.textContent.replace(/\s/g, '');
  try {
    await navigator.clipboard.writeText(text);
  } catch (e) {
    var ta = document.createElement('textarea');
    ta.value = text; document.body.appendChild(ta);
    ta.select(); document.execCommand('copy');
    document.body.removeChild(ta);
  }
  var btn = document.getElementById('copy-btn-' + accountId);
  if (btn) {
    var orig = btn.innerHTML;
    btn.innerHTML = '✓'; btn.style.color = 'var(--cyber-accent)'; btn.style.borderColor = 'var(--cyber-accent)';
    setTimeout(function () { btn.innerHTML = orig; btn.style.color = ''; btn.style.borderColor = ''; }, 1500);
  }
}

/* ── Rendering ── */

function renderAccounts() {
  var list = document.getElementById('accountList');
  if (!list) return;
  list.innerHTML = '';
  if (accounts.length === 0) {
    list.innerHTML = '<p style="color:#888;text-align:center;padding:40px;">No accounts found.</p>';
    return;
  }

  var CIRC = 2 * Math.PI * 16;

  accounts.forEach(function (account) {
    var tr         = getTimeRemaining(account.period);
    var progress   = (tr / account.period) * CIRC;
    var honeyEntry = window.Honey ? window.Honey.getEntry(account.id) : null;
    var hwMode     = honeyEntry ? (honeyEntry.hwMode || 'fallback') : 'unknown';
    var hwLabel    = hwMode === 'prf' ? '🔐 TPM/Enclave' : '🔒 SW-Fallback';
    var hwColor    = hwMode === 'prf' ? 'var(--cyber-accent)' : '#ffcc00';
    var hwBorder   = hwMode === 'prf' ? 'rgba(0,255,136,0.25)' : 'rgba(255,204,0,0.3)';
    var honeyBadge = honeyEntry && honeyEntry.honeyEnabled
      ? '<span style="font-size:0.68rem;color:#ffcc00;border:1px solid rgba(255,204,0,0.3);border-radius:4px;padding:1px 6px;background:rgba(255,204,0,0.05);">🍯 19 Decoys</span>'
      : '<span style="font-size:0.68rem;color:var(--cyber-text-dim);border:1px solid rgba(255,255,255,0.1);border-radius:4px;padding:1px 6px;">Standard TOTP</span>';

    var div = document.createElement('div');
    div.className = 'account-item';
    div.style.cssText = 'background:rgba(20,26,46,0.7);border:1px solid var(--cyber-border);border-radius:12px;padding:18px 20px;display:flex;justify-content:space-between;align-items:center;gap:12px;margin-bottom:12px;';
    div.innerHTML =
      '<div class="account-info">' +
        '<h3 style="font-size:1.05rem;margin-bottom:4px;">' + account.serviceName + '</h3>' +
        '<div style="font-size:0.78rem;color:var(--cyber-text-dim);display:flex;gap:10px;flex-wrap:wrap;align-items:center;">' +
          '<span style="font-size:0.68rem;color:' + hwColor + ';border:1px solid ' + hwBorder + ';border-radius:4px;padding:1px 6px;">' + hwLabel + '</span>' +
          honeyBadge +
        '</div>' +
      '</div>' +
      '<div style="display:flex;align-items:center;gap:10px;flex-shrink:0;">' +
        '<div class="otp-code" id="otp-' + account.id + '" style="font-family:\'JetBrains Mono\',monospace;font-size:1.75rem;color:var(--cyber-accent);letter-spacing:4px;min-width:120px;text-align:right;">------</div>' +
        '<button id="copy-btn-' + account.id + '" ' +
          'style="background:transparent;border:1px solid rgba(0,204,255,0.35);color:var(--cyber-blue);border-radius:8px;width:34px;height:34px;font-size:1rem;cursor:pointer;display:flex;align-items:center;justify-content:center;flex-shrink:0;" ' +
          'onclick="copyOTP(\'' + account.id + '\')" title="Copy OTP">⎘</button>' +
        '<div style="position:relative;width:40px;height:40px;">' +
          '<svg width="40" height="40" viewBox="0 0 40 40" style="transform:rotate(-90deg);">' +
            '<circle fill="none" stroke="var(--cyber-border)" stroke-width="3" cx="20" cy="20" r="16"/>' +
            '<circle fill="none" stroke="var(--cyber-accent)" stroke-width="3" stroke-linecap="round" ' +
              'id="ring-' + account.id + '" cx="20" cy="20" r="16" ' +
              'stroke-dasharray="' + CIRC + '" stroke-dashoffset="' + (CIRC - progress) + '" ' +
              'style="transition:stroke-dashoffset 1s linear;"/>' +
          '</svg>' +
          '<span id="timer-' + account.id + '" style="position:absolute;top:50%;left:50%;transform:translate(-50%,-50%);font-family:\'JetBrains Mono\',monospace;font-size:0.7rem;color:var(--cyber-text);">' + tr + '</span>' +
        '</div>' +
        '<button ' +
          'style="background:transparent;border:1px solid rgba(255,107,53,0.3);color:var(--cyber-warning);border-radius:8px;width:34px;height:34px;font-size:1.1rem;cursor:pointer;display:flex;align-items:center;justify-content:center;flex-shrink:0;" ' +
          'onclick="deleteAccount(\'' + account.id + '\')" title="Remove">×</button>' +
        '<button id="link-btn-' + account.id + '" ' +
          'style="background:transparent;border:1px solid rgba(0,255,136,0.3);color:var(--cyber-accent);border-radius:8px;width:34px;height:34px;font-size:1rem;cursor:pointer;display:flex;align-items:center;justify-content:center;flex-shrink:0;" ' +
          'onclick="linkToConnectly(\'' + account.id + '\')" title="Link to Connectly">🔗</button>' +
      '</div>';
    list.appendChild(div);
  });
}

/* ── OTP refresh loop ── */

var _otpBusy = false;

async function updateAllOTPs() {
  if (!isInitialized || !accounts.length || _otpBusy) return;
  _otpBusy = true;
  try {
    for (var i = 0; i < accounts.length; i++) {
      var account = accounts[i];
      var otpEl   = document.getElementById('otp-' + account.id);
      var timerEl = document.getElementById('timer-' + account.id);
      var ringEl  = document.getElementById('ring-' + account.id);
      var tr      = getTimeRemaining(account.period);
      var CIRC    = 2 * Math.PI * 16;

      if (timerEl) timerEl.textContent = tr;
      if (ringEl)  ringEl.style.strokeDashoffset = CIRC - (tr / account.period) * CIRC;
      if (!otpEl) continue;

      var isFirstLoad = otpEl.textContent === '------';
      var isNewWindow = (tr === account.period);

      if (isFirstLoad || isNewWindow) {
        try {
          var code = await generateTOTPWithHardware(account.secret, account.digits, account.period, account.id);
          otpEl.textContent = code;
        } catch (e) {
          if (e && e.name !== 'NotAllowedError') {
            console.error('[OTP] ' + account.serviceName + ':', e.message);
          }
        }
      }
    }
  } finally {
    _otpBusy = false;
  }
}

/* ── CRUD ── */

function deleteAccount(id) {
  accounts = accounts.filter(function (a) { return a.id !== id; });
  saveAccounts();
  if (window.Honey) window.Honey.deleteEntry(id);
  renderAccounts();
}

function showAddAccountForm() {
  var el = document.getElementById('addAccountCard');
  if (el) el.classList.remove('hidden');
}
function hideAddAccountForm() {
  var el = document.getElementById('addAccountCard');
  if (el) el.classList.add('hidden');
}

/* ── Link account to Connectly ── */
async function linkToConnectly(accountId) {
  var entry = window.Honey ? window.Honey.getEntry(accountId) : null;
  if (!entry) { alert('Account not found in store.'); return; }
  if (!entry.honeyEnabled) {
    alert('This account uses standard TOTP mode — no honeytrap seeds to export.\n\nRe-add the account with a derivation password to enable Connectly linking.');
    return;
  }

  var pw = prompt('Enter your derivation password to export seeds to Connectly:');
  if (pw === null) return;

  try {
    /* Use the same PRF label as enrolment so deterministic export seeds match. */
    var assertion = await (window.Honey.assertWithPRF
      ? window.Honey.assertWithPRF('encryption')
      : acquireSessionAssertion());

    var exported = await window.Honey.exportSeedsForConnectly(accountId, assertion, pw);
    var resp = await fetch(CONNECTLY_REGISTER_URL, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({
        accountId:   accountId,
        seeds:       exported.seeds,
        realIndex:   exported.realIndex,
        serviceName: entry.serviceName
      })
    });
    if (!resp.ok) throw new Error('HTTP ' + resp.status);
    var result = await resp.json();
    if (!result.success) throw new Error(result.message);
    alert(
      '✅ Seeds registered with Connectly!\nAccount ID: ' + accountId +
      (exported.migrated ? '\n\nThis account was also upgraded to deterministic PRF-based seed derivation.' : '')
    );
  } catch (e) {
    console.error('[linkToConnectly]', e);
    alert('❌ Link failed: ' + (e.message || String(e)));
  }
}

/* ── Exports ── */

window.initializeAuthenticator  = initializeAuthenticator;
window.acquireSessionAssertion  = acquireSessionAssertion;
window.acquireSessionSig        = acquireSessionSig;
window.deleteAccount            = deleteAccount;
window.showAddAccountForm       = showAddAccountForm;
window.hideAddAccountForm       = hideAddAccountForm;
window.generateTOTPWithHardware = generateTOTPWithHardware;
window.copyOTP                  = copyOTP;
window.getTimeRemaining         = getTimeRemaining;
window.loadAccounts             = loadAccounts;
window.saveAccounts             = saveAccounts;
window.updateAllOTPs            = updateAllOTPs;
window.renderAccounts           = renderAccounts;
window.warmAllSeeds             = warmAllSeeds;
window.linkToConnectly          = linkToConnectly;

window.addEventListener('load', function () {
  loadAccounts();
  if (webAuthnCredentialId) {
    isInitialized = true;
    var initScreen = document.getElementById('initScreen');
    var dashboard  = document.getElementById('dashboard');
    if (initScreen) initScreen.classList.add('hidden');
    if (dashboard)  dashboard.classList.remove('hidden');
    renderAccounts();
  }
  setInterval(updateAllOTPs, 1000);
});
