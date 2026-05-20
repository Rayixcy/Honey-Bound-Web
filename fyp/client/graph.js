/* ============================================================
   HoneyBound-Web — graph.js  v3
   - Initialises safely inside DOMContentLoaded
   - Seeds charts from localStorage on load
   - Live ticker every 3s (real data preferred, sim fallback)
   - Single source of truth for all badge updates
============================================================ */
(function () {
  'use strict';

  var C_GREEN = '#00ff88';
  var C_RED   = '#ff4d6a';
  var C_BLUE  = '#00ccff';
  var C_TEXT  = '#8b92a8';
  var C_SIM   = 'rgba(100,130,180,0.5)'; // simulated point colour

  var LOG_KEY       = 'hbw_honey_log_v1';
  var DERIV_LOG_KEY = 'hbw_deriv_log_v1';
  var MAX_POINTS    = 50;
  var TARGET_MS     = 300;
  var HTOTP_BASELINE_MS = 0.24;

  /* counters */
  var otpSuccessCount = 0;
  var otpFailureCount = 0;
  var otpCancelCount  = 0;
  var derivTimes      = [];
  var derivLabels     = [];
  var derivColors     = [];
  var derivCount      = 0;
  var lastSeededDerivCount = -1;

  var successRateChart = null;
  var derivChart       = null;

  function loadStoredDerivationTimings() {
    var timings = [];
    try { timings = JSON.parse(localStorage.getItem(DERIV_LOG_KEY)||'[]'); } catch(e){}
    return timings
      .map(function(v) { return Number(v); })
      .filter(function(v) { return Number.isFinite(v); });
  }

  function getDisplayedDerivationTimings() {
    return derivTimes
      .map(function(v) { return Number(v); })
      .filter(function(v) { return Number.isFinite(v); });
  }

  /* ── wait for DOM ── */
  window.addEventListener('DOMContentLoaded', function () {
    var c1 = document.getElementById('otpSuccessChart');
    var c2 = document.getElementById('derivTimeChart');
    console.log('[graph.js] otpSuccessChart:', c1 ? 'FOUND' : 'MISSING');
    console.log('[graph.js] derivTimeChart:', c2 ? 'FOUND' : 'MISSING');
    if (!c1) { console.warn('[graph.js] Aborting — doughnut canvas missing'); return; }

    Chart.defaults.color       = C_TEXT;
    Chart.defaults.font.family = "'JetBrains Mono', monospace";
    Chart.defaults.font.size   = 11;

    /* ── Pre-seed counters from localStorage BEFORE constructing chart ── */
    (function preSeedCounters() {
      var log = [];
      try { log = JSON.parse(localStorage.getItem(LOG_KEY)||'[]'); } catch(e){}
      log.forEach(function(ev){
        if      (ev.type==='login-success')       otpSuccessCount++;
        else if (ev.type==='login-invalid')       otpFailureCount++;
        else if (ev.type==='honeytrap-triggered') otpFailureCount++;
      });
    })();

    /* ── Doughnut ── */
    successRateChart = new Chart(c1.getContext('2d'), {
      type: 'doughnut',
      data: {
        labels: ['Successful', 'Failed', 'Cancelled'],
        datasets: [{
          data: [otpSuccessCount, otpFailureCount, otpCancelCount],
          backgroundColor: ['rgba(0,255,136,0.85)','rgba(255,77,106,0.85)','rgba(255,204,0,0.75)'],
          borderColor:     ['rgba(0,255,136,0.2)', 'rgba(255,77,106,0.2)', 'rgba(255,204,0,0.2)'],
          borderWidth: 2, hoverOffset: 8
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        cutout: '68%',
        animation: { duration: 500 },
        plugins: {
          legend: { position:'bottom', labels:{ padding:16, usePointStyle:true, pointStyleWidth:10, color:C_TEXT }},
          tooltip: { callbacks: { label: function(ctx) {
            var tot = ctx.dataset.data.reduce(function(a,b){return a+b;},0);
            var pct = tot > 0 ? ((ctx.parsed/tot)*100).toFixed(1) : '0.0';
            return ' '+ctx.label+': '+ctx.parsed+' ('+pct+'%)';
          }}}
        }
      },
      plugins:[{
        id:'centreText',
        beforeDraw: function(chart) {
          if (chart.canvas.id !== 'otpSuccessChart') return;
          var ca = chart.chartArea;
          var cx = (ca.left+ca.right)/2, cy = (ca.top+ca.bottom)/2;
          var d  = chart.data.datasets[0].data;
          var tot = d.reduce(function(a,b){return a+b;},0);
          var pct = tot > 0 ? Math.round((d[0]/tot)*100) : '--';
          var c = chart.ctx; c.save();
          c.font='700 1.9rem \'JetBrains Mono\',monospace';
          c.fillStyle=tot>0?C_GREEN:C_TEXT; c.textAlign='center'; c.textBaseline='middle';
          c.fillText(tot>0?pct+'%':'—', cx, cy-8);
          c.font='500 0.65rem \'Manrope\',sans-serif'; c.fillStyle=C_TEXT;
          c.fillText(tot>0?'success rate':'no data yet', cx, cy+14);
          c.restore();
        }
      }]
    });

    /* ── Line chart ── */
    derivChart = new Chart(c2.getContext('2d'), {
      type: 'line',
      data: {
        labels: derivLabels,
        datasets: [
          {
            label: 'Derivation Time (ms)',
            data: derivTimes,
            borderColor: C_BLUE,
            backgroundColor: 'rgba(0,204,255,0.07)',
            borderWidth: 2,
            pointRadius: 4,
            pointBackgroundColor: derivColors,
            tension: 0.35, fill: true
          },
          {
            label: '300 ms target',
            data: [],
            borderColor: 'rgba(255,77,106,0.6)',
            borderWidth: 1.5,
            borderDash: [6,4],
            pointRadius: 0, fill: false
          }
        ]
      },
      options: {
        animation: false,
        responsive: true,
        maintainAspectRatio: false,
        interaction: { mode:'index', intersect:false },
        scales: {
          y: { beginAtZero:true, suggestedMax:500,
               grid:{color:'rgba(30,41,66,0.6)'},
               ticks:{callback:function(v){return v+' ms';}},
               title:{display:true,text:'Time (ms)',color:C_TEXT} },
          x: { grid:{color:'rgba(30,41,66,0.4)'},
               title:{display:true,text:'Attempt #',color:C_TEXT} }
        },
        plugins: {
          legend:{ position:'bottom', labels:{usePointStyle:true,pointStyleWidth:10,padding:16} },
          tooltip:{ callbacks:{ label:function(ctx){
            if(ctx.datasetIndex===1) return ' Target: 300 ms';
            return ' '+ctx.parsed.y.toFixed(1)+' ms';
          }}}
        }
      }
    });

    /* ── seed from localStorage ── */
    seedFromLog();

    /* ── re-seed after 1.5 s so syncRemoteAuditLog (dashboard.html) has time
       to write Connectly login events into hbw_honey_log_v1 first ── */
    setTimeout(seedFromLog, 1500);
    /* keep re-seeding every 10 s to stay live */
    setInterval(seedFromLog, 10000);

    /* ── pull server audit log directly — catches Connectly events even when
       syncRemoteAuditLog hasn't run yet or localStorage is cold ── */
    fetchRemoteEvents();
    setInterval(fetchRemoteEvents, 10000);

    /* ── honey-event bus — also catches live events fired by syncRemoteAuditLog ── */
    window.addEventListener('honey-event', function(e) {
      var t = e.detail.type;
      if (t==='login-success')        recordOTP('success');
      if (t==='login-invalid')        recordOTP('failure');
      if (t==='honeytrap-triggered')  recordOTP('failure');
    });

    /* ── re-seed immediately when dashboard.html writes new events to localStorage ── */
    window.addEventListener('hbw-log-updated', function() {
      seedFromLog();
    });

    /* ── live ticker ── */
    var _lastIdx = 0;
    try { _lastIdx = JSON.parse(localStorage.getItem(DERIV_LOG_KEY)||'[]').length; } catch(e){}

    setInterval(function() {
      var stored = [];
      try { stored = JSON.parse(localStorage.getItem(DERIV_LOG_KEY)||'[]'); } catch(e){}
      var fresh = stored.slice(_lastIdx);
      _lastIdx = stored.length;
      if (fresh.length > 0) {
        fresh.forEach(function(ms){ addDerivPoint(ms, false); });
      } else {
        /* simulated: realistic PBKDF2 range 80–320 ms, occasional spike */
        var sim = 180 + (Math.random()-0.5)*140 + (Math.random()<0.1 ? Math.random()*180 : 0);
        addDerivPoint(Math.max(30, sim), true);
      }
    }, 3000);
  });

  /* ── fetch events from HBW server audit log and update doughnut ── */
  var _remoteSeenTs = new Set();   /* deduplicate by timestamp+event */

  function fetchRemoteEvents() {
    fetch('https://localhost:8443/api/honey/audit')
      .then(function(r) {
        return r.ok ? r.json() : Promise.reject('HTTP ' + r.status);
      })
      .then(function(remote) {
        if (!Array.isArray(remote) || remote.length === 0) return;

        /* Merge into localStorage so seedFromLog() picks them up and counts cleanly */
        var log = [];
        try { log = JSON.parse(localStorage.getItem(LOG_KEY) || '[]'); } catch(e) {}
        var existingKeys = new Set(log.map(function(e) {
          return (e.type || '') + ':' + (e.timestamp || e.ts || '');
        }));

        var added = 0;
        remote.forEach(function(e) {
          var type = e.event || e.type || '';
          var ts   = e.ts || e.timestamp || '';
          var key  = type + ':' + ts;
          if (existingKeys.has(key)) return;
          existingKeys.add(key);
          log.unshift({ type: type, timestamp: ts, accountId: e.accountId, serviceName: e.serviceName || 'Connectly' });
          added++;
        });

        if (added > 0) {
          if (log.length > 1000) log.splice(1000);
          localStorage.setItem(LOG_KEY, JSON.stringify(log));
          seedFromLog(); /* resets and recounts cleanly */
        }
      })
      .catch(function(err) {
        console.warn('[graph.js] fetchRemoteEvents failed:', err);
      });
  }

  /* ── seed charts from stored data ── */
  function seedFromLog() {
    /* doughnut — reset counters first so repeated calls don't double-count */
    otpSuccessCount = 0;
    otpFailureCount = 0;
    otpCancelCount  = 0;
    var log = [];
    try { log = JSON.parse(localStorage.getItem(LOG_KEY)||'[]'); } catch(e){}
    log.forEach(function(ev){
      if      (ev.type==='login-success')        otpSuccessCount++;
      else if (ev.type==='login-invalid')        otpFailureCount++;
      else if (ev.type==='honeytrap-triggered')  otpFailureCount++;
    });
    refreshDoughnut();

    /* line chart — real timings */
    var timings = loadStoredDerivationTimings();
    if (timings.length !== lastSeededDerivCount || derivTimes.length === 0) {
      var slice = timings.slice(-MAX_POINTS);
      derivTimes.length  = 0;
      derivLabels.length = 0;
      derivColors.length = 0;
      slice.forEach(function(ms, i){
        derivTimes.push(parseFloat(ms.toFixed(2)));
        derivLabels.push('#'+(i+1));
        derivColors.push(C_BLUE);
      });
      derivCount = timings.length;
      lastSeededDerivCount = timings.length;

      if (derivTimes.length > 0) {
        refreshDerivChart();
        updateBadges();
      }
    }
    /* badge is updated regardless — removes "Awaiting" text */
    updateBadges();
  }

  /* ── add one data point to derivation chart ── */
  function addDerivPoint(ms, simulated) {
    if (!derivChart) return;
    derivCount++;
    if (derivTimes.length >= MAX_POINTS) {
      derivTimes.shift(); derivLabels.shift(); derivColors.shift();
    }
    derivTimes.push(parseFloat(ms.toFixed(2)));
    derivLabels.push(simulated ? ('~'+derivCount) : ('#'+derivCount));
    derivColors.push(simulated ? C_SIM : C_BLUE);
    if (!simulated && derivCount > lastSeededDerivCount) {
      lastSeededDerivCount = derivCount;
    }
    refreshDerivChart();
    updateBadges();
  }

  /* ── helpers ── */
  function recordOTP(result) {
    if (!successRateChart) return;
    if      (result==='success') otpSuccessCount++;
    else if (result==='failure') otpFailureCount++;
    else if (result==='cancel')  otpCancelCount++;
    refreshDoughnut();
  }

  function refreshDoughnut() {
    if (!successRateChart) return;
    successRateChart.data.datasets[0].data = [otpSuccessCount, otpFailureCount, otpCancelCount];
    successRateChart.update();
    var tot = otpSuccessCount + otpFailureCount + otpCancelCount;
    var pct = tot > 0 ? Math.round((otpSuccessCount/tot)*100) : 100;
    var el  = document.getElementById('statSuccessRate');
    if (el) el.textContent = pct+'%';
  }

  function refreshDerivChart() {
    if (!derivChart) return;
    derivChart.data.datasets[0].pointBackgroundColor = derivColors.slice();
    derivChart.data.datasets[1].data = derivLabels.map(function(){ return TARGET_MS; });
    derivChart.update();
  }

  function updateBadges() {
    var timings = getDisplayedDerivationTimings();
    if (timings.length === 0) {
      timings = loadStoredDerivationTimings();
    }
    var avg = timings.length > 0
      ? timings.reduce(function(a,b){return a+b;},0) / timings.length
      : null;

    /* stat card */
    var statEl = document.getElementById('statDerivAvg');
    if (statEl) statEl.textContent = avg !== null ? avg.toFixed(0)+'ms' : '—';

    /* perf badge — completely replace text AND style */
    var badge = document.getElementById('derivPerfBadge');
    if (!badge) return;

    if (avg === null) {
      badge.textContent = 'Awaiting data…';
      return;
    }

    if (avg < 1) {
      /* near-zero = cached seed, clarify */
      badge.textContent       = '⚡ < 1 ms — seed cached in memory (no derivation needed)';
      badge.style.borderColor = 'rgba(0,255,136,0.3)';
      badge.style.color       = 'var(--cyber-accent)';
      badge.style.background  = 'rgba(0,255,136,0.06)';
    } else if (avg < 300) {
      badge.textContent       = '✓ Avg '+avg.toFixed(0)+' ms — under 300 ms target';
      badge.style.borderColor = 'rgba(0,255,136,0.3)';
      badge.style.color       = 'var(--cyber-accent)';
      badge.style.background  = 'rgba(0,255,136,0.06)';
    } else {
      badge.textContent       = '⚠ Avg '+avg.toFixed(0)+' ms — above 300 ms target';
      badge.style.borderColor = 'rgba(255,77,106,0.3)';
      badge.style.color       = '#ff4d6a';
      badge.style.background  = 'rgba(255,77,106,0.06)';
    }
  }

  function summariseEvaluation() {
    var log = [];
    var timings = [];
    try { log = JSON.parse(localStorage.getItem(LOG_KEY)||'[]'); } catch(e){}
    try { timings = JSON.parse(localStorage.getItem(DERIV_LOG_KEY)||'[]'); } catch(e){}

    var success = 0;
    var invalid = 0;
    var honeytrap = 0;
    log.forEach(function(ev) {
      if (ev.type === 'login-success') success++;
      else if (ev.type === 'login-invalid') invalid++;
      else if (ev.type === 'honeytrap-triggered') honeytrap++;
    });

    var numeric = timings
      .map(function(v) { return Number(v); })
      .filter(function(v) { return Number.isFinite(v); })
      .sort(function(a, b) { return a - b; });

    var count = numeric.length;
    var avg = count ? numeric.reduce(function(a,b){ return a+b; }, 0) / count : null;
    var min = count ? numeric[0] : null;
    var max = count ? numeric[count - 1] : null;
    var p95 = count ? numeric[Math.min(count - 1, Math.floor(count * 0.95))] : null;
    var totalOtp = success + invalid + honeytrap;
    var successRate = totalOtp ? (success / totalOtp) * 100 : null;
    var baselineDelta = avg !== null ? avg - HTOTP_BASELINE_MS : null;
    var baselineRatio = avg !== null && HTOTP_BASELINE_MS > 0 ? avg / HTOTP_BASELINE_MS : null;

    return {
      generatedAt: new Date().toISOString(),
      baselineMs: HTOTP_BASELINE_MS,
      derivation: {
        sampleCount: count,
        averageMs: avg !== null ? Number(avg.toFixed(2)) : null,
        minMs: min !== null ? Number(min.toFixed(2)) : null,
        maxMs: max !== null ? Number(max.toFixed(2)) : null,
        p95Ms: p95 !== null ? Number(p95.toFixed(2)) : null,
        deltaVsBaselineMs: baselineDelta !== null ? Number(baselineDelta.toFixed(2)) : null,
        ratioVsBaseline: baselineRatio !== null ? Number(baselineRatio.toFixed(2)) : null
      },
      otp: {
        successCount: success,
        invalidCount: invalid,
        honeytrapCount: honeytrap,
        totalCheckedEvents: totalOtp,
        successRatePercent: successRate !== null ? Number(successRate.toFixed(2)) : null
      },
      interpretation: avg === null
        ? 'No derivation samples recorded yet.'
        : avg <= TARGET_MS
          ? 'Prototype derivation is within the local 300 ms target.'
          : 'Prototype derivation exceeds the local 300 ms target.',
      note: 'HTOTP baseline (0.24 ms) is from literature and is not directly equivalent to this browser/WebAuthn prototype overhead.'
    };
  }

  function buildEvaluationText(summary) {
    var d = summary.derivation;
    var o = summary.otp;
    return [
      'HoneyBound-Web Evaluation Summary',
      'Generated: ' + summary.generatedAt,
      '',
      'Derivation Metrics',
      '- Samples: ' + d.sampleCount,
      '- Average: ' + (d.averageMs !== null ? d.averageMs + ' ms' : 'N/A'),
      '- Minimum: ' + (d.minMs !== null ? d.minMs + ' ms' : 'N/A'),
      '- Maximum: ' + (d.maxMs !== null ? d.maxMs + ' ms' : 'N/A'),
      '- P95: ' + (d.p95Ms !== null ? d.p95Ms + ' ms' : 'N/A'),
      '- HTOTP baseline: ' + summary.baselineMs + ' ms',
      '- Delta vs baseline: ' + (d.deltaVsBaselineMs !== null ? d.deltaVsBaselineMs + ' ms' : 'N/A'),
      '- Ratio vs baseline: ' + (d.ratioVsBaseline !== null ? d.ratioVsBaseline + 'x' : 'N/A'),
      '',
      'OTP Outcome Metrics',
      '- Successes: ' + o.successCount,
      '- Invalid: ' + o.invalidCount,
      '- Honeytrap: ' + o.honeytrapCount,
      '- Total checked events: ' + o.totalCheckedEvents,
      '- Success rate: ' + (o.successRatePercent !== null ? o.successRatePercent + '%' : 'N/A'),
      '',
      'Interpretation',
      summary.interpretation,
      summary.note
    ].join('\r\n');
  }

  function exportEvaluationReport() {
    var summary = summariseEvaluation();
    var text = buildEvaluationText(summary);
    var blob = new Blob([text + '\r\n\r\nJSON\r\n' + JSON.stringify(summary, null, 2)], { type: 'text/plain' });
    var a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'honeybound-evaluation-report.txt';
    a.click();
    URL.revokeObjectURL(a.href);
  }

  /* ── public API ── */
  window.logOTPResult = function(r) { recordOTP(r); };
  window.logDerivationTime = function(ms) { addDerivPoint(ms, false); };
  window.getEvaluationSummary = summariseEvaluation;
  window.exportEvaluationReport = exportEvaluationReport;

})();
