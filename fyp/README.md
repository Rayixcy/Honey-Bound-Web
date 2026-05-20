# HoneyBound-Web

HoneyBound-Web is a browser-only HTOTP authenticator prototype that combines:

- WebAuthn platform credentials
- PRF-backed local secret protection
- deterministic PRF-based honeyseed derivation
- honeyseed-based breach detection
- RFC 6238-compatible OTP generation
- a demo integration with the Connectly app

This repository contains the HoneyBound-Web prototype. The paired Connectly demo app lives in:

- `c:\Users\hp\Desktop\project\dummy-web`

## Prototype Scope

This project is a working prototype created for a final-year cybersecurity project.

What it currently demonstrates:

- Browser-based authenticator workflow
- WebAuthn PRF-backed encryption for stored account secrets
- deterministic PRF-based honeyseed derivation for current accounts
- migration of legacy honeyseed accounts when they are re-linked to Connectly
- event logging and live dashboard metrics
- stale-window and replay protection in the HoneyBound + Connectly demo flow
- multi-device linking where a linked phone can become a full HoneyBound dashboard client
- HTTPS Connectly demo deployment for local development
- evaluation export for derivation-time and OTP outcome metrics

What it does not claim:

- production-ready deployment
- full native platform-authenticator clock enforcement guarantees
- completed cross-platform evaluation evidence without separate test records

## Requirements

- Node.js installed
- A browser with WebAuthn platform authenticator support
- Local HTTPS certificates for HoneyBound-Web

By default the HoneyBound server expects these certificate files in:

- `server/localhost.pem`
- `server/localhost-key.pem`

For linked-phone onboarding over your local network, you should use a certificate
that matches the HTTPS hostname or IP the phone opens from the QR code.

## Install

In HoneyBound-Web:

```powershell
cd c:\Users\hp\Desktop\project\fyp
npm install
```

In Connectly:

```powershell
cd c:\Users\hp\Desktop\project\dummy-web
npm install
```

## Run The Prototype

Start HoneyBound-Web first:

```powershell
cd c:\Users\hp\Desktop\project\fyp
npm start
```

Then start Connectly:

```powershell
cd c:\Users\hp\Desktop\project\dummy-web
npm start
```

Open:

- HoneyBound-Web: `https://localhost:8443`
- Connectly: `https://localhost:3000`
- Device-link QR page for phones on the same Wi-Fi: `https://YOUR-PC-LAN-IP:8443/link-device.html`

Important for Google OAuth:

- if Connectly is running over HTTPS, the Google OAuth redirect URI must also be HTTPS
- update it to `https://localhost:3000/auth/google/callback`

## LAN HTTPS Setup For Phone QR Flow

Mobile WebAuthn will not work reliably from plain HTTP. The QR flow now points to
HTTPS by default, but your phone must trust the certificate used by HoneyBound.

HoneyBound supports these environment variables:

- `HBW_PUBLIC_LINK_ORIGIN`
- `HBW_TLS_CERT_PATH`
- `HBW_TLS_KEY_PATH`
- `HBW_TLS_PFX_PATH`
- `HBW_TLS_PFX_PASSPHRASE`

You can use either:

1. PEM files:

```powershell
$env:HBW_PUBLIC_LINK_ORIGIN = "https://YOUR-LAPTOP-NAME-OR-IP:8443"
$env:HBW_TLS_CERT_PATH = "server/your-lan-cert.pem"
$env:HBW_TLS_KEY_PATH = "server/your-lan-key.pem"
npm start
```

2. A PFX bundle:

```powershell
$env:HBW_PUBLIC_LINK_ORIGIN = "https://YOUR-LAPTOP-NAME-OR-IP:8443"
$env:HBW_TLS_PFX_PATH = "server/your-lan-cert.pfx"
$env:HBW_TLS_PFX_PASSPHRASE = "your-password"
npm start
```

Recommended approach:

1. Create or obtain a certificate whose SAN matches the hostname or IP used in `HBW_PUBLIC_LINK_ORIGIN`.
2. Make sure the phone trusts the issuing certificate authority or certificate chain.
3. Start HoneyBound with the matching TLS env vars above.
4. Generate a fresh QR code after restarting the server.

Important:

- A certificate for `localhost` is not enough when the phone opens `https://192.168.x.x:8443`.
- If the phone shows a certificate warning or the browser does not trust the certificate, WebAuthn may still fail.
- Using a local hostname is usually better than a raw IP if you can issue and trust a matching certificate for it.

## Typical Demo Flow

1. Open HoneyBound-Web at `https://localhost:8443`
2. Initialize the authenticator with the device platform authenticator
3. Add a TOTP account
4. Add a derivation password if you want honeyseed protection
5. Link the account to Connectly
6. Log in to Connectly and complete OTP verification
7. View security events and metrics in the HoneyBound dashboard
8. For cross-device testing, open the dashboard profile modal, use the `Link Device` tab, and scan the QR from a phone on the same network
9. After phone setup/import, the phone can open the full `dashboard.html` and act as a primary HoneyBound client

## Key Files

- [client/index.html](c:\Users\hp\Desktop\project\fyp\client\index.html)
- [client/main.js](c:\Users\hp\Desktop\project\fyp\client\main.js)
- [client/dashboard.html](c:\Users\hp\Desktop\project\fyp\client\dashboard.html)
- [client/graph.js](c:\Users\hp\Desktop\project\fyp\client\graph.js)
- [server/honey.js](c:\Users\hp\Desktop\project\fyp\server\honey.js)
- [server/server.js](c:\Users\hp\Desktop\project\fyp\server\server.js)

Connectly integration files:

- [server.js](c:\Users\hp\Desktop\project\dummy-web\server\server.js)
- [users.json](c:\Users\hp\Desktop\project\dummy-web\server\users.json)

## Diagrams

Architecture and sequence diagrams are available in:

- [architecture-sequence-diagrams.md](c:\Users\hp\Desktop\project\fyp\docs\architecture-sequence-diagrams.md)

Implementation notes and documentation caveats are available in:

- [implementation-notes.md](c:\Users\hp\Desktop\project\fyp\docs\implementation-notes.md)

## Evaluation Export

The dashboard includes an `Export Evaluation Report` button.

It produces a text report containing:

- derivation sample count
- average/min/max/p95 derivation latency
- OTP success and failure counts
- success rate
- comparison against the cited HTOTP baseline of `0.24 ms`

This export is intended to support the evaluation chapter, but you still need to run enough test sessions and record the resulting values in the dissertation.

A dissertation-ready results template is provided in:

- [evaluation-results-template.md](c:\Users\hp\Desktop\project\fyp\docs\evaluation-results-template.md)

## Security Notes

- HoneyBound-Web now uses WebAuthn PRF-backed secret storage for current entries.
- Older entries encrypted with the earlier credId-based method are migrated when accessed.
- Current honeyseed derivation is deterministic PRF-based for new accounts and for legacy accounts that are re-linked/exported again.
- The real RFC 6238 OTP still comes from the decrypted raw TOTP secret; Connectly receives one real seed plus deterministic decoy seeds for detection.
- The prototype blocks sensitive operations when device time differs too far from trusted server time.
- Connectly now tracks used OTP windows for HoneyBound-linked accounts and rejects same-window replay.
- Browser state is local to each browser profile. Opening HoneyBound in a different browser on the same machine behaves like a fresh device until it is linked/imported.

## Current Limitations

- Cross-platform support is expected but still needs documented test evidence for Windows, macOS, Android, and iOS.
- The trusted-time guard is prototype-enforced application logic, not a formal OS-level authenticator attestation of clock state.
- The project proposal mentioned SQLite, but the current HoneyBound prototype stores audit data in `server/audit_log.json`.
- Some external integrations, such as Google OAuth and email alerts in Connectly, depend on local credentials/configuration in the demo app.
- Existing legacy Connectly-linked honeyseed accounts should be re-linked once after the deterministic PRF derivation upgrade so Connectly receives the updated decoy set.

## Scripts

HoneyBound-Web:

- `npm start`
- `npm run dev`

Connectly:

- `npm start`
- `npm run dev`

## Suggested Dissertation Wording

If you need to describe the artifact accurately:

"HoneyBound-Web is a working browser-based authenticator prototype that demonstrates WebAuthn PRF-assisted secret protection, honeyseed-based breach detection, replay protection, and evaluation instrumentation. The artifact is suitable for controlled prototype evaluation, while some claims such as cross-platform breadth and platform-level clock enforcement still require formal empirical validation."
