(function () {
  'use strict';

  var ACCOUNTS_KEY = 'hbw_accounts_v1';
  var UID_KEY = 'hbw_user_id_v1';
  var DEVICE_ID_KEY = 'hbw_device_instance_id_v1';
  var CACHE_KEY = 'hbw_account_sync_cache_v1';
  var REVISION_KEY = 'hbw_account_sync_revision_v1';

  var _pollTimer = null;
  var _syncInFlight = false;
  var _promptedRevision = null;
  var _syncCache = [];

  try {
    localStorage.removeItem(CACHE_KEY);
    sessionStorage.removeItem(CACHE_KEY);
  } catch (err) {}

  function parseJson(raw, fallback) {
    try { return JSON.parse(raw); } catch (err) { return fallback; }
  }

  function getUid() {
    return String(localStorage.getItem(UID_KEY) || '').trim();
  }

  function ensureDeviceId() {
    var existing = String(localStorage.getItem(DEVICE_ID_KEY) || '').trim();
    if (existing) return existing;
    var next = Math.random().toString(36).slice(2) + Date.now().toString(36);
    localStorage.setItem(DEVICE_ID_KEY, next);
    return next;
  }

  function getLocalRevision() {
    return Number(localStorage.getItem(REVISION_KEY) || '0') || 0;
  }

  function setLocalRevision(revision) {
    localStorage.setItem(REVISION_KEY, String(Number(revision || 0) || 0));
  }

  function getSyncCache() {
    return _syncCache.slice();
  }

  function setSyncCache(accounts) {
    _syncCache = Array.isArray(accounts) ? accounts.slice() : [];
  }

  function getAccountMetadata() {
    var accounts = parseJson(localStorage.getItem(ACCOUNTS_KEY) || '[]', []);
    if (!Array.isArray(accounts)) return [];
    var seen = Object.create(null);
    return accounts.filter(function (account) {
      if (!account || !account.id) return false;
      var key = String(account.id);
      if (seen[key]) return false;
      seen[key] = true;
      return true;
    });
  }

  function upsertCachedAccount(account) {
    if (!account || !account.id || !account.secret) return;
    var cache = getSyncCache().filter(function (entry) { return entry.id !== account.id; });
    cache.push({
      id: String(account.id),
      serviceName: String(account.serviceName || account.id),
      secret: String(account.secret).replace(/\s+/g, '').toUpperCase(),
      digits: Number(account.digits || 6),
      period: Number(account.period || 30)
    });
    setSyncCache(cache);
  }

  function removeCachedAccount(accountId) {
    setSyncCache(getSyncCache().filter(function (entry) { return entry.id !== accountId; }));
  }

  function replaceCachedAccounts(accounts) {
    setSyncCache((Array.isArray(accounts) ? accounts : []).map(function (account) {
      return {
        id: String(account.id),
        serviceName: String(account.serviceName || account.id),
        secret: String(account.secret || '').replace(/\s+/g, '').toUpperCase(),
        digits: Number(account.digits || 6),
        period: Number(account.period || 30)
      };
    }).filter(function (account) {
      return account.id && account.secret;
    }));
  }

  async function buildSnapshotAccounts() {
    var cached = getSyncCache();
    if (cached.length) return cached;
    if (!window.Honey || typeof window.Honey._getDecryptedSecret !== 'function') return [];

    var metadata = getAccountMetadata();
    if (!metadata.length) return [];

    var assertion = null;
    var out = [];
    for (var i = 0; i < metadata.length; i++) {
      var account = metadata[i];
      try {
        var entry = window.Honey.getEntry ? window.Honey.getEntry(account.id) : null;
        if (!entry) continue;
        if (!assertion && window.Honey.assertWithPRF) {
          assertion = await window.Honey.assertWithPRF('encryption');
        }
        var secret = await window.Honey._getDecryptedSecret(account.id, assertion);
        out.push({
          id: String(account.id),
          serviceName: String(account.serviceName || account.id),
          secret: String(secret || '').replace(/\s+/g, '').toUpperCase(),
          digits: Number(account.digits || entry.digits || 6),
          period: Number(account.period || entry.period || 30)
        });
      } catch (err) {
        console.warn('[HoneySync] Could not prepare account for sync:', account.id, err && err.message ? err.message : err);
      }
    }
    return out.filter(function (account) { return account.id && account.secret; });
  }

  async function pushSnapshot(reason) {
    var uid = getUid();
    if (!uid) return { ok: false, skipped: 'no-uid' };

    var accounts = await buildSnapshotAccounts();
    var res = await fetch('/api/honey/account-sync/' + encodeURIComponent(uid), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        uid: uid,
        deviceId: ensureDeviceId(),
        reason: reason || 'sync',
        accounts: accounts
      })
    });
    var data = await res.json().catch(function () { return {}; });
    if (!res.ok || !data.snapshot) {
      throw new Error(data.error || 'Could not push account snapshot');
    }
    setLocalRevision(data.snapshot.revision);
    return data.snapshot;
  }

  async function fetchSnapshot() {
    var uid = getUid();
    if (!uid) return null;
    var res = await fetch('/api/honey/account-sync/' + encodeURIComponent(uid), { cache: 'no-store' });
    var data = await res.json().catch(function () { return {}; });
    if (!res.ok) {
      throw new Error(data.error || 'Could not load account snapshot');
    }
    return data.snapshot || null;
  }

  async function applySnapshot(snapshot) {
    if (!snapshot || !Array.isArray(snapshot.accounts) || !window.Honey) return false;

    var nextAccounts = snapshot.accounts.slice();
    var existingMeta = getAccountMetadata();
    var existingIds = existingMeta.map(function (account) { return account.id; });
    var nextIds = nextAccounts.map(function (account) { return account.id; });
    var accountsToAdd = nextAccounts.filter(function (account) {
      return existingIds.indexOf(account.id) === -1;
    });

    existingIds.forEach(function (id) {
      if (nextIds.indexOf(id) === -1) {
        window.Honey.deleteEntry(id);
      }
    });

    if (accountsToAdd.length > 0) {
      var credId = localStorage.getItem('hbw_webauthn_cred_id_v1') || '';
      if (!credId) {
        throw new Error('This device has no authenticator credential yet. Import once on the linked phone first.');
      }

      var assertion = await window.Honey.assertWithPRF('encryption');
      for (var i = 0; i < accountsToAdd.length; i++) {
        var account = accountsToAdd[i];
        await window.Honey.addAccount({
          id: account.id,
          serviceName: account.serviceName,
          secret: account.secret,
          digits: account.digits || 6,
          period: account.period || 30
        }, assertion, null);
      }
    }

    var nextMeta = nextAccounts.map(function (account) {
      return {
        id: account.id,
        serviceName: account.serviceName,
        digits: account.digits || 6,
        period: account.period || 30
      };
    });
    localStorage.setItem(ACCOUNTS_KEY, JSON.stringify(nextMeta));
    replaceCachedAccounts(nextAccounts);
    setLocalRevision(snapshot.revision);
    window.dispatchEvent(new CustomEvent('hbw-sync-applied', { detail: snapshot }));
    return true;
  }

  async function checkForRemoteChanges() {
    if (_syncInFlight) return null;
    _syncInFlight = true;
    try {
      var snapshot = await fetchSnapshot();
      if (!snapshot || !snapshot.revision) return null;
      if (snapshot.deviceId === ensureDeviceId()) {
        setLocalRevision(snapshot.revision);
        return null;
      }
      if (Number(snapshot.revision) <= getLocalRevision()) return null;
      if (_promptedRevision === snapshot.revision) return snapshot;

      _promptedRevision = snapshot.revision;
      var shouldApply = window.confirm(
        'New HoneyBound account changes are available from another linked device. Sync them on this device now?'
      );
      if (!shouldApply) return snapshot;
      await applySnapshot(snapshot);
      return snapshot;
    } finally {
      _syncInFlight = false;
    }
  }

  function startPolling(intervalMs) {
    stopPolling();
    _pollTimer = setInterval(function () {
      checkForRemoteChanges().catch(function (err) {
        console.warn('[HoneySync] Remote sync check failed:', err && err.message ? err.message : err);
      });
    }, intervalMs || 15000);
  }

  function stopPolling() {
    clearInterval(_pollTimer);
    _pollTimer = null;
  }

  window.HoneySync = {
    ensureDeviceId: ensureDeviceId,
    getUid: getUid,
    getSyncCache: getSyncCache,
    setSyncCache: setSyncCache,
    upsertCachedAccount: upsertCachedAccount,
    removeCachedAccount: removeCachedAccount,
    replaceCachedAccounts: replaceCachedAccounts,
    getLocalRevision: getLocalRevision,
    setLocalRevision: setLocalRevision,
    pushSnapshot: pushSnapshot,
    fetchSnapshot: fetchSnapshot,
    applySnapshot: applySnapshot,
    checkForRemoteChanges: checkForRemoteChanges,
    startPolling: startPolling,
    stopPolling: stopPolling
  };
})();
