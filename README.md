# HoneyBound-Web
HoneyBound-Web is a final-year cybersecurity prototype that explores a browser-based TOTP authenticator. It combines normal six-digit TOTP codes with WebAuthn PRF-assisted local secret protection and honeyseed-based decoy detection through a paired demo app called Connectly.

The project is intentionally presented as a research and demonstration artifact, not as a production authenticator.

## What It Demonstrates

- Browser-based authenticator setup with WebAuthn platform credentials
- PRF-assisted local encryption for stored TOTP secrets
- RFC 6238-compatible OTP generation
- Deterministic honeyseed derivation with one real seed and decoy seeds
- Connectly relying-party demo that verifies real and decoy OTPs
- Honeytrap-style detection triggered when a decoy seed-derived OTP is used
- Same-session replay prevention and stale time-window checks
- Trusted-time checks for sensitive authentication flows
- Live audit/event dashboard and evaluation export
- Local device linking flow for prototype recovery testing

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

HoneyBound-Web runs locally on `https://localhost:8443` and acts as the browser authenticator. Connectly runs locally on `https://localhost:3000` and acts as the relying-party demo service that receives a seed bundle, verifies OTP submissions, rejects replayed codes, and raises honeytrap events when a decoy seed is used.

The visible OTP remains a standard TOTP code so the user experience stays compatible with conventional authenticator workflows.

The primary research contribution is the introduction of a detection pathway that distinguishes real from decoy seed-derived OTPs and surfaces suspicious activity in the audit dashboard.

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

## Screenshots

HoneyBound dashboard with accounts and security events:

<img width="734" height="325" alt="HoneyBound dashboard with accounts" src="https://github.com/user-attachments/assets/03f5102f-19a7-41a6-b9a7-f96d78e96337" />
<img width="745" height="373" alt="HoneyBound security events dashboard" src="https://github.com/user-attachments/assets/1f53c280-0b50-45d3-bf8e-60a971e0f1dc" />

Connectly login and OTP verification flow:

<img width="712" height="348" alt="Connectly login flow" src="https://github.com/user-attachments/assets/9a4188b6-d517-42f3-bb5a-c0cab3d1b6a4" />
<img width="670" height="403" alt="Connectly OTP verification flow" src="https://github.com/user-attachments/assets/b6044eab-f6d1-43ef-9562-918ac0dec260" />

Honeytrap/decoy event:

<img width="786" height="269" alt="Honeytrap decoy event" src="https://github.com/user-attachments/assets/98c96fcf-b17b-4f10-9e06-06ff1690b2a2" />

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
