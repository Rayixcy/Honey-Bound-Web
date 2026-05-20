/**
 * mailer.js — Connectly Security Alert Emailer  v3
 *
 * ── SETUP (one-time) ──────────────────────────────────────────────────────────
 *  1. Enable 2-Step Verification on your Google account
 *  2. Visit: myaccount.google.com → Security → App Passwords
 *  3. Generate an App Password for "Mail" → copy the 16-char code
 *  4. Set ALERT_FROM, ADMIN_EMAIL, and GMAIL_PASS in dummy-web/.env
 *  5. npm install nodemailer
 * ─────────────────────────────────────────────────────────────────────────────
 *
 * Alerts fired:
 *   sendHoneytrapAlert()        — decoy OTP used (highest priority)
 *   sendFailedOTPAlert()        — invalid OTP (1st attempt + every 3rd)
 *   sendSuccessfulLoginAlert()  — any successful OTP verification
 *   sendFakeDashboardAlert()    — attacker active on fake dashboard
 *   sendGoogleLoginAlert()      — Google OAuth sign-in (new or returning)
 *   sendTestEmail()             — verify config is working
 *
 * Recipients:
 *   Admin always gets every alert.
 *   If the user has a Google email on file, they get CC'd too.
 */

import './env.js';
import nodemailer from 'nodemailer';
import { Resend } from 'resend';
const RESEND_API_KEY = process.env.RESEND_API_KEY || '';
const resend = RESEND_API_KEY ? new Resend(RESEND_API_KEY) : null;

// ── CONFIG — fill these in ────────────────────────────────────────────────────
const ALERT_FROM  = (process.env.ALERT_FROM || '').trim();
const ADMIN_EMAIL = (process.env.ADMIN_EMAIL || '').trim();
const GMAIL_PASS  = process.env.GMAIL_PASS || '';
const APP_NAME    = process.env.APP_NAME || 'Connectly';
const APP_URL     = process.env.APP_URL || 'https://localhost:3000';
// ─────────────────────────────────────────────────────────────────────────────

// ── Check if credentials are still placeholders ───────────────────────────────
const MAILER_READY =
    ALERT_FROM.includes('@') &&
    ADMIN_EMAIL.includes('@') &&
    GMAIL_PASS.replace(/\s/g, '').length >= 16;

if (!MAILER_READY) {
    console.warn('[mailer] ⚠️  Email credentials not configured — alerts disabled.');
    console.warn('[mailer]    Set ALERT_FROM, ADMIN_EMAIL, and GMAIL_PASS environment variables to enable.');
}

let _transporter = null;

function getTransporter() {
    if (!_transporter) {
        _transporter = nodemailer.createTransport({
            service: 'gmail',
            auth: {
                user: ALERT_FROM,
                pass: GMAIL_PASS.replace(/\s/g, '')  // strips spaces from app password
            }
        });
    }
    return _transporter;
}

/** Build recipient list. Admin always gets everything. If userEmail differs, they get CC'd. */
function recipients(userEmail) {
    const to = new Set([ADMIN_EMAIL]);
    if (userEmail && typeof userEmail === 'string' && userEmail.includes('@')) {
        to.add(userEmail.trim().toLowerCase());
    }
    return [...to].join(', ');
}

// ── Shared email shell ────────────────────────────────────────────────────────
function emailShell(accentColor, headerIcon, headerTitle, bodyHtml) {
    return `
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>${headerTitle}</title>
</head>
<body style="margin:0;padding:0;background:#080c14;font-family:'Segoe UI',Helvetica,Arial,sans-serif;">
<table width="100%" cellpadding="0" cellspacing="0" style="background:#080c14;padding:32px 16px;">
  <tr><td align="center">
    <table width="600" cellpadding="0" cellspacing="0" style="max-width:600px;width:100%;">

      <!-- Header -->
      <tr><td style="background:linear-gradient(135deg,#0d1422,#111827);border:1px solid rgba(255,255,255,.07);border-radius:16px 16px 0 0;padding:28px 32px;text-align:center;">
        <div style="font-size:2.8rem;margin-bottom:10px;">${headerIcon}</div>
        <div style="font-family:'Segoe UI',sans-serif;font-size:1.5rem;font-weight:800;color:#fff;letter-spacing:-.02em;">${headerTitle}</div>
        <div style="margin-top:8px;display:inline-block;background:${accentColor}18;border:1px solid ${accentColor}40;border-radius:999px;padding:4px 16px;">
          <span style="font-size:.75rem;font-weight:700;color:${accentColor};letter-spacing:.5px;text-transform:uppercase;">${APP_NAME} Security Alert</span>
        </div>
      </td></tr>

      <!-- Body -->
      <tr><td style="background:#111827;border-left:1px solid rgba(255,255,255,.07);border-right:1px solid rgba(255,255,255,.07);padding:28px 32px;">
        ${bodyHtml}
      </td></tr>

      <!-- Footer -->
      <tr><td style="background:#0d1422;border:1px solid rgba(255,255,255,.07);border-top:none;border-radius:0 0 16px 16px;padding:18px 32px;text-align:center;">
        <p style="margin:0;font-size:.72rem;color:#4b5d78;">
          This alert was sent by <strong style="color:#8896ae;">${APP_NAME}</strong> · <a href="${APP_URL}" style="color:#3b82f6;text-decoration:none;">${APP_URL}</a><br/>
          Powered by HoneyBound-Web security monitoring
        </p>
      </td></tr>

    </table>
  </td></tr>
</table>
</body>
</html>`;
}

// ── Detail row helpers ────────────────────────────────────────────────────────
function detailRow(label, value, valueColor = '#f0f4ff') {
    return `
    <tr>
      <td style="padding:8px 14px;font-size:.78rem;font-weight:700;color:#8896ae;background:#0f1825;border-radius:6px 0 0 6px;white-space:nowrap;width:140px;">${label}</td>
      <td style="padding:8px 14px;font-size:.82rem;font-weight:600;color:${valueColor};background:#0d1422;border-radius:0 6px 6px 0;">${value}</td>
    </tr>
    <tr><td colspan="2" style="padding:3px 0;"></td></tr>`;
}

function detailTable(rows) {
    return `<table width="100%" cellpadding="0" cellspacing="0" style="border-radius:8px;overflow:hidden;margin-bottom:20px;">${rows}</table>`;
}

function sectionTitle(text) {
    return `<p style="font-size:.72rem;font-weight:800;color:#4b5d78;text-transform:uppercase;letter-spacing:.8px;margin:0 0 10px;">${text}</p>`;
}

function divider() {
    return `<hr style="border:none;border-top:1px solid rgba(255,255,255,.06);margin:22px 0;"/>`;
}

function actionBtn(text, url, color) {
    return `
    <div style="text-align:center;margin-top:24px;">
      <a href="${url}" style="display:inline-block;background:${color};color:#fff;font-size:.88rem;font-weight:700;text-decoration:none;padding:12px 28px;border-radius:10px;">${text}</a>
    </div>`;
}

function fmtTime(ts) {
    return new Date(ts || Date.now()).toLocaleString('en-GB', {
        dateStyle: 'medium', timeStyle: 'long', timeZone: 'UTC'
    }) + ' UTC';
}

// ── Send helper ───────────────────────────────────────────────────────────────
async function send({ subject, html, to }) {
    if (!MAILER_READY) {
        console.log(`[mailer] ⏭️  Skipped (not configured): "${subject}"`);
        return false;
    }
    const toAddr = to || ADMIN_EMAIL;
    try {
        const info = await getTransporter().sendMail({
            from:    `"${APP_NAME} Security" <${ALERT_FROM}>`,
            to:      toAddr,
            subject: `[${APP_NAME}] ${subject}`,
            html
        });
        console.log(`[mailer] ✅ Sent: "${subject}" → ${toAddr} (${info.messageId})`);
        return true;
    } catch (err) {
        console.error(`[mailer] ❌ Failed to send "${subject}":`, err.message);
        return false;
    }
}

// ══════════════════════════════════════════════════════════════════════════════
//  PUBLIC API
// ══════════════════════════════════════════════════════════════════════════════

/**
 * 🚨 HONEYTRAP TRIGGERED — highest priority.
 * userEmail: the account owner's Google email — they get CC'd.
 */
export async function sendHoneytrapAlert({ username, accountId, decoyIndex, ip, userAgent, ts, userEmail }) {
    const subject = `🚨 HONEYTRAP DETECTED — ${username}`;
    const html = emailShell(
        '#ff4d6a', '🚨', 'Honeytrap Detected',
        `
        <p style="font-size:1rem;font-weight:700;color:#fca5a5;margin:0 0 20px;">
          Someone used a <strong>decoy OTP seed</strong> to log into account
          <code style="background:#1a0a10;border:1px solid #ff4d6a44;border-radius:4px;padding:2px 7px;color:#ff4d6a;">${username}</code>.
          This is a strong indicator of a <strong style="color:#fff;">credential theft attack</strong>.
        </p>

        ${sectionTitle('Incident Details')}
        ${detailTable(
            detailRow('Username',   username,                                '#f0f4ff') +
            detailRow('Account ID', accountId || 'N/A',                     '#8896ae') +
            detailRow('Decoy Seed', `#${(decoyIndex ?? 0) + 1} of 20`,      '#ff4d6a') +
            detailRow('Time (UTC)', fmtTime(ts),                            '#8896ae') +
            detailRow('IP Address', ip || 'unknown',                        '#f0f4ff') +
            detailRow('User Agent', (userAgent || 'unknown').substring(0,80),'#4b5d78')
        )}

        ${divider()}
        ${sectionTitle('What happened')}
        <p style="font-size:.84rem;color:#8896ae;line-height:1.7;margin:0 0 16px;">
          HoneyBound-Web registers <strong style="color:#f0f4ff;">1 real TOTP seed</strong> and
          <strong style="color:#f0f4ff;">19 decoy seeds</strong> per account. An attacker who
          steals credentials and submits a decoy OTP is caught here — they were silently
          redirected to a fake dashboard and do <em>not</em> know they've been caught.
        </p>

        <div style="background:#1a0a10;border:1px solid #ff4d6a33;border-radius:10px;padding:16px 20px;margin-bottom:16px;">
          <p style="margin:0;font-size:.82rem;font-weight:700;color:#ff4d6a;">⚡ Recommended Actions:</p>
          <ul style="margin:10px 0 0;padding-left:20px;font-size:.8rem;color:#8896ae;line-height:1.9;">
            <li>Force-logout all active sessions for <strong style="color:#f0f4ff;">${username}</strong></li>
            <li>Require a password reset on next login</li>
            <li>Review recent login history for this account</li>
            <li>Check HoneyBound Events for the full attack timeline</li>
          </ul>
        </div>

        ${actionBtn('→ View HoneyBound Events', 'https://localhost:8443/events.html', '#dc2626')}
        `
    );
    return send({ subject, html, to: recipients(userEmail) });
}

/**
 * ⚠️ FAILED OTP ATTEMPT
 * userEmail: CC the account owner if they have a Google email.
 */
export async function sendFailedOTPAlert({ username, ip, userAgent, ts, attemptCount, userEmail }) {
    const subject = `⚠️ Failed OTP Attempt — ${username}`;
    const html = emailShell(
        '#f59e0b', '⚠️', 'Failed OTP Attempt',
        `
        <p style="font-size:1rem;font-weight:700;color:#fcd34d;margin:0 0 20px;">
          An invalid OTP was submitted for account
          <code style="background:#1a1200;border:1px solid #f59e0b44;border-radius:4px;padding:2px 7px;color:#fbbf24;">${username}</code>.
          ${attemptCount > 1
            ? `<br/><span style="color:#f87171;">This is attempt <strong>#${attemptCount}</strong> — possible brute-force.</span>`
            : ''}
        </p>

        ${sectionTitle('Attempt Details')}
        ${detailTable(
            detailRow('Username',   username,                                '#f0f4ff') +
            detailRow('Time (UTC)', fmtTime(ts),                            '#8896ae') +
            detailRow('IP Address', ip || 'unknown',                        '#f0f4ff') +
            detailRow('Attempt #',  String(attemptCount || 1),              '#fbbf24') +
            detailRow('User Agent', (userAgent || 'unknown').substring(0,80),'#4b5d78')
        )}

        ${divider()}
        <p style="font-size:.84rem;color:#8896ae;line-height:1.7;margin:0;">
          A single failed OTP is often just a typo. Multiple failures in a short window suggest
          an automated attack. The account has <strong style="color:#f0f4ff;">not been locked</strong> —
          monitor for further attempts.
        </p>
        `
    );
    return send({ subject, html, to: recipients(userEmail) });
}

/**
 * ✅ SUCCESSFUL LOGIN — fires on every successful OTP verification (password OR Google OAuth).
 * userEmail: CC the account owner so they know their account was accessed.
 */
export async function sendSuccessfulLoginAlert({ username, ip, userAgent, ts, method, userEmail }) {
    const subject = `✅ Successful Login — ${username}`;
    const methodLabel = method === 'google'   ? '🔵 Google OAuth + HoneyBound OTP'
                      : method === 'password' ? '🔑 Password + HoneyBound OTP'
                      : '🔑 Password login';

    const html = emailShell(
        '#22c55e', '✅', 'Successful Login',
        `
        <p style="font-size:1rem;font-weight:700;color:#86efac;margin:0 0 20px;">
          Account <code style="background:#0a1a0f;border:1px solid #22c55e44;border-radius:4px;padding:2px 7px;color:#4ade80;">${username}</code>
          successfully logged in to ${APP_NAME}.
          ${userEmail ? `<br/><span style="color:#8896ae;font-size:.85rem;">A copy of this alert was sent to <strong style="color:#f0f4ff;">${userEmail}</strong>.</span>` : ''}
        </p>

        ${sectionTitle('Login Details')}
        ${detailTable(
            detailRow('Username',   username,       '#f0f4ff') +
            detailRow('Method',     methodLabel,    '#4ade80') +
            detailRow('Time (UTC)', fmtTime(ts),   '#8896ae') +
            detailRow('IP Address', ip || 'unknown','#f0f4ff') +
            detailRow('User Agent', (userAgent || 'unknown').substring(0,80),'#4b5d78')
        )}

        ${divider()}
        <div style="background:#0a1a0f;border:1px solid #22c55e22;border-radius:10px;padding:14px 18px;">
          <p style="margin:0;font-size:.82rem;color:#8896ae;line-height:1.6;">
            If you did not perform this login, your credentials may be compromised.
            <a href="${APP_URL}" style="color:#4ade80;font-weight:700;text-decoration:none;">Sign in immediately</a>
            and change your password.
          </p>
        </div>
        `
    );
    return send({ subject, html, to: recipients(userEmail) });
}

/**
 * 👁️ FAKE DASHBOARD VIEWED — attacker is active, their actions are logged.
 * Only goes to admin (the real user's account was already alerted via honeytrap email).
 */
export async function sendFakeDashboardAlert({ username, ip, userAgent, ts, actions }) {
    const subject = `👁️ Attacker Active on Fake Dashboard — ${username}`;

    const actionsHtml = actions && actions.length
        ? `
          ${sectionTitle('Actions Logged on Fake Dashboard')}
          <table width="100%" cellpadding="0" cellspacing="0" style="margin-bottom:20px;">
            ${actions.map((a, i) => `
            <tr>
              <td style="padding:7px 12px;background:${i % 2 === 0 ? '#0f1825' : '#0d1422'};border-radius:6px 0 0 6px;font-size:.78rem;color:#8896ae;">${a.detail || a.action}</td>
              <td style="padding:7px 12px;background:${i % 2 === 0 ? '#0f1825' : '#0d1422'};border-radius:0 6px 6px 0;font-size:.72rem;color:#4b5d78;text-align:right;white-space:nowrap;">${a.action}</td>
            </tr>
            <tr><td colspan="2" style="padding:2px;"></td></tr>`).join('')}
          </table>`
        : '';

    const html = emailShell(
        '#8b5cf6', '👁️', 'Attacker on Fake Dashboard',
        `
        <p style="font-size:1rem;font-weight:700;color:#c4b5fd;margin:0 0 20px;">
          The attacker who triggered the honeytrap on
          <code style="background:#130e1f;border:1px solid #8b5cf644;border-radius:4px;padding:2px 7px;color:#a78bfa;">${username}</code>
          is now active on the <strong style="color:#fff;">fake dashboard</strong>.
          They believe they are logged in normally.
        </p>

        ${sectionTitle('Session Details')}
        ${detailTable(
            detailRow('Username',   username,                                '#f0f4ff') +
            detailRow('Time (UTC)', fmtTime(ts),                            '#8896ae') +
            detailRow('IP Address', ip || 'unknown',                        '#f0f4ff') +
            detailRow('User Agent', (userAgent || 'unknown').substring(0,80),'#4b5d78')
        )}

        ${actionsHtml}

        ${divider()}
        <div style="background:#130e1f;border:1px solid #8b5cf633;border-radius:10px;padding:16px 20px;">
          <p style="margin:0 0 8px;font-size:.82rem;font-weight:700;color:#a78bfa;">🕵️ You're watching in real-time</p>
          <p style="margin:0;font-size:.8rem;color:#8896ae;line-height:1.7;">
            Every click the attacker makes is logged silently.
            They see a normal-looking ${APP_NAME} — but every action is recorded here.
            Use this window to secure the real account before they notice.
          </p>
        </div>
        `
    );
    // Fake dashboard — admin only (real user got the honeytrap email already)
    return send({ subject, html, to: ADMIN_EMAIL });
}

/**
 * ✅ GOOGLE LOGIN — fires for Google OAuth path (new + returning users).
 * Both admin and the user's Google email receive this.
 */
export async function sendGoogleLoginAlert({ username, email, displayName, ip, ts, isNew }) {
    const subject = isNew
        ? `🎉 New Google Account Registered — ${username}`
        : `✅ Google Sign-In — ${username}`;

    const html = emailShell(
        '#22c55e',
        isNew ? '🎉' : '✅',
        isNew ? 'New Google Account' : 'Google Sign-In',
        `
        <p style="font-size:1rem;font-weight:700;color:#86efac;margin:0 0 20px;">
          ${isNew
            ? `A new ${APP_NAME} account was created via Google OAuth for <strong style="color:#fff;">${displayName}</strong>.`
            : `<strong style="color:#fff;">${displayName}</strong> signed in to ${APP_NAME} via Google OAuth.`}
        </p>

        ${sectionTitle('Login Details')}
        ${detailTable(
            detailRow('Username',     username,                                                '#f0f4ff') +
            detailRow('Google Email', email,                                                  '#4ade80') +
            detailRow('Display Name', displayName,                                            '#f0f4ff') +
            detailRow('Time (UTC)',   fmtTime(ts),                                           '#8896ae') +
            detailRow('IP Address',  ip || 'unknown',                                       '#f0f4ff') +
            detailRow('Account',     isNew ? '🆕 Newly created' : '🔄 Existing account',
                                     isNew ? '#4ade80' : '#60a5fa')
        )}

        ${divider()}
        <div style="background:#0a1a0f;border:1px solid #22c55e22;border-radius:10px;padding:14px 18px;">
          <p style="margin:0;font-size:.82rem;color:#8896ae;line-height:1.6;">
            If you did not perform this login, your Google account may be compromised.
            Secure your Google account at
            <a href="https://myaccount.google.com/security" style="color:#4ade80;font-weight:700;text-decoration:none;">myaccount.google.com/security</a>.
          </p>
        </div>
        `
    );
    // Both admin AND the Google user receive this
    return send({ subject, html, to: recipients(email) });
}

/**
 * Test — verify mailer config is working
 */
export async function sendTestEmail() {
    return send({
        subject: '✅ Mailer test — config working',
        to:      ADMIN_EMAIL,
        html: emailShell('#22c55e', '✅', 'Mailer Working', `
            <p style="font-size:1rem;color:#86efac;font-weight:700;margin:0 0 12px;">
              Your ${APP_NAME} mailer is configured correctly!
            </p>
            <p style="font-size:.84rem;color:#8896ae;margin:0;">
              Security alert emails will now fire on: honeytrap triggers, failed OTPs,
              successful logins, Google sign-ins, and fake dashboard activity.
            </p>`)
    });
}
