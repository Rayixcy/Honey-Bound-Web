# HoneyBound-Web

HoneyBound-Web is a final-year cybersecurity prototype that explores a stronger browser-based TOTP authenticator. It combines normal six-digit TOTP codes with WebAuthn PRF-assisted local secret protection and honeyseed-style decoy detection through a paired demo app called Connectly.

The project is intentionally presented as a research and demonstration artifact, not as a production authenticator.

## What It Demonstrates

- Browser-based authenticator setup with WebAuthn platform credentials
- PRF-assisted local encryption for stored TOTP secrets
- RFC 6238-compatible OTP generation
- Deterministic honeyseed derivation with one real seed and decoy seeds
- Connectly relying-party demo that verifies real and decoy OTPs
- Honeytrap detection when a decoy OTP is used
- Same-window replay rejection and stale-window checks
- Trusted-time checks for sensitive flows
- Live audit/event dashboard and evaluation export
- Local phone/device linking flow for prototype recovery testing

## Repository Layout

```text
.
|-- fyp/                    # HoneyBound-Web authenticator prototype
|   |-- client/             # Browser UI, dashboard, account/device flows
|   |-- server/             # HTTPS server, audit APIs, honey.js delivery
|   `-- docs/               # Architecture notes, report draft, evaluation template
|-- dummy-web/              # Connectly demo relying-party web app
|   |-- public/             # Login, registration, dashboard and OTP pages
|   `-- server/             # Auth, OTP verification, alerts and persistence
|-- tests/                  # Lightweight GitHub-level regression tests
`-- README.md
```

## Architecture

HoneyBound-Web runs locally on `https://localhost:8443` and acts as the browser authenticator. Connectly runs locally on `https://localhost:3000` and acts as the service that receives a seed bundle, verifies OTP submissions, rejects replayed codes, and raises honeytrap events when a decoy seed matches.

The visible OTP remains a standard TOTP code so the user experience stays compatible with normal authenticator workflows. The research contribution is the added detection path: Connectly can distinguish a real seed OTP from decoy seed OTPs and surface suspicious use back into HoneyBound's audit dashboard.

## Quick Start

Install dependencies for both apps:

```powershell
npm install
npm --prefix fyp install
npm --prefix dummy-web install
```

Create environment files from the examples:

```powershell
Copy-Item fyp\.env.example fyp\.env
Copy-Item dummy-web\.env.example dummy-web\.env
```

Set at least these values:

```text
HBW_DATA_KEY=use-a-long-random-value
SESSION_SECRET=use-a-long-random-value
CONNECTLY_DATA_KEY=use-a-different-long-random-value
```

Start HoneyBound-Web first:

```powershell
npm run start:honeybound
```

Start Connectly in another terminal:

```powershell
npm run start:connectly
```

Open:

- HoneyBound-Web: `https://localhost:8443`
- Connectly: `https://localhost:3000`

## Typical Demo Flow

1. Open HoneyBound-Web and initialize the authenticator.
2. Register or log in to Connectly.
3. Add the Connectly TOTP secret into HoneyBound.
4. Enable honeyseed mode with a derivation password.
5. Link/export the account bundle to Connectly.
6. Log in to Connectly using the OTP from HoneyBound.
7. Trigger success, failure, replay, or decoy scenarios and observe the HoneyBound dashboard/events.

## Tests

Run the lightweight regression tests:

```powershell
npm test
```

The current test suite is intentionally small and focuses on core utility behavior that can run without starting HTTPS/WebAuthn browser flows.

## Screenshots To Add Before Publishing

For the strongest GitHub presentation, add screenshots or a short GIF under a future `assets/` directory:

- HoneyBound dashboard with accounts and security events
- Connectly login and OTP verification flow
- Honeytrap/decoy event in the audit feed
- Device-link QR flow
- Evaluation export screen

## Security Notes

This is a controlled prototype. It should not be used to protect real accounts.

Known limitations include:

- Browser-local storage and browser-profile binding
- Local JSON persistence for demo state
- Local/self-signed HTTPS assumptions
- Prototype-level trusted-time enforcement
- Incomplete cross-platform empirical evaluation
- Limited automated test coverage

The deeper implementation notes are in [fyp/docs/implementation-notes.md](fyp/docs/implementation-notes.md), and the full prototype README is in [fyp/README.md](fyp/README.md).

## GitHub Hygiene Checklist

Before publishing publicly:

- Ensure `node_modules/` is untracked from Git history/current index.
- Do not commit real `.env` files, TLS private keys, app passwords, OAuth secrets, or live `users.json`.
- Add screenshots or a demo GIF.
- Commit a clean working tree.
- Keep the prototype disclaimer visible.
