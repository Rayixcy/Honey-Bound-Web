/* ============================================================
   HoneyBound-Web - qr.js
   Link Device QR generation backed by short-lived server sessions.
   ============================================================ */

(function () {
  'use strict';

  var PERIOD = 30;
  var CIRC = 2 * Math.PI * 18;
  var DIV_ID = 'linkDeviceQRDiv';
  var RING_ID = 'linkDeviceRing';
  var TIME_ID = 'linkDeviceCountdown';

  var _qrInstance = null;
  var _refreshTimer = null;
  var _countdownTimer = null;
  var _windowStartSec = Math.floor(Date.now() / 1000);
  var _activeSession = null;

  window.renderLinkQR = function () {
    _windowStartSec = Math.floor(Date.now() / 1000);
    _waitForLib(function () {
      _doRender().catch(function (err) {
        console.warn('[honey] Could not render link QR:', err && err.message ? err.message : err);
        if (typeof window.onHoneyLinkError === 'function') {
          window.onHoneyLinkError('Could not generate a device-link code right now.');
        }
      });
    });
  };

  window.startLinkCountdown = function () {
    clearInterval(_countdownTimer);
    _tick();
    _countdownTimer = setInterval(_tick, 1000);
  };

  window.stopLinkQR = function () {
    clearTimeout(_refreshTimer);
    clearInterval(_countdownTimer);
  };

  window.regenerateLinkQR = function () {
    window.stopLinkQR();
    _windowStartSec = Math.floor(Date.now() / 1000);
    _activeSession = null;
    _waitForLib(function () {
      _doRender().catch(function (err) {
        console.warn('[honey] Could not regenerate link QR:', err && err.message ? err.message : err);
      });
    });
    window.startLinkCountdown();
  };

  function _waitForLib(cb) {
    if (typeof QRCode === 'function') {
      cb();
    } else {
      setTimeout(function () { _waitForLib(cb); }, 100);
    }
  }

  async function _doRender() {
    var div = document.getElementById(DIV_ID);
    if (!div) return;

    var session = await _createLinkSession();
    var payload = session.linkUrl;
    _activeSession = session;

    if (typeof window.onHoneyLinkSession === 'function') {
      window.onHoneyLinkSession(session);
    }

    if (_qrInstance) {
      try {
        _qrInstance.makeCode(payload);
      } catch (e) {
        _qrInstance = null;
        await _doRender();
        return;
      }
    } else {
      div.innerHTML = '';
      _qrInstance = new QRCode(div, {
        text: payload,
        width: 200,
        height: 200,
        colorDark: '#000000',
        colorLight: '#ffffff',
        correctLevel: QRCode.CorrectLevel.M
      });
    }

    _scheduleNextRefresh();
  }

  function _scheduleNextRefresh() {
    clearTimeout(_refreshTimer);
    var now = Math.floor(Date.now() / 1000);
    var elapsed = now - _windowStartSec;
    var msToNext = Math.max(0, (PERIOD - elapsed)) * 1000 + 80;

    _refreshTimer = setTimeout(function () {
      _windowStartSec = Math.floor(Date.now() / 1000);
      _activeSession = null;
      _doRender().catch(function (err) {
        console.warn('[honey] Could not refresh link QR:', err && err.message ? err.message : err);
      });
    }, msToNext);
  }

  function _tick() {
    var now = Math.floor(Date.now() / 1000);
    var elapsed = now - _windowStartSec;
    var remaining = Math.max(0, PERIOD - elapsed);

    var el = document.getElementById(TIME_ID);
    if (el) el.textContent = remaining + 's';

    var ring = document.getElementById(RING_ID);
    if (ring) {
      ring.style.strokeDashoffset = CIRC - (remaining / PERIOD) * CIRC;
      ring.style.stroke = remaining <= 5 ? '#ff4d6a' : 'var(--cyber-blue)';
    }
  }

  async function _createLinkSession() {
    var uid = localStorage.getItem('hbw_user_id_v1') || 'UNKNOWN';
    var res = await fetch('/api/honey/link-device/session', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ uid: uid })
    });
    var data = await res.json().catch(function () { return {}; });
    if (!res.ok || !data.session) {
      throw new Error(data.error || 'Could not create link session');
    }
    return data.session;
  }
})();
