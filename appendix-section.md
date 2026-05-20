# Appendix

## Appendix A: Project Progress Evidence

This appendix provides supporting evidence for the design, implementation and evaluation of HoneyBound-Web. The artefacts listed here support the chapters of the main report by showing the project management record, prototype structure, implementation environment, testing procedure, evaluation evidence and ethical handling of security-related data.

The project followed a staged final-year project workflow. The early stages focused on topic selection, supervisor approval, literature review and research gap identification. The middle stages focused on system design, browser API investigation, WebAuthn experimentation, TOTP integration and honeyseed logic. The final stages focused on Connectly integration, attack simulation, testing, evaluation screenshots, report writing and oral presentation preparation.

The progress evidence demonstrates that the project was developed iteratively rather than as a single final build. Each stage contributed to the final prototype: the literature review informed the security requirements, the design stage defined the architecture, implementation produced the working browser-based authenticator, and evaluation tested whether the system met the stated objectives.

## Appendix B: Final Project Timeline

The project timeline was organised around the following work packages:

| Period | Activity | Output |
|---|---|---|
| October | Title finalisation and domain selection | Confirmed cybersecurity authentication topic |
| October | Supervisor form submission | Project approved for supervision |
| October to November | Literature search | Sources collected on TOTP, WebAuthn, honeywords, honeytokens and HTOTP |
| November | Identification of research gaps | Gap defined around browser-based HTOTP and honeyseed detection |
| November to December | Ethics form submission and supervisor review | Ethical scope clarified for defensive testing |
| December to January | Ethics approval and review presentation | Project scope confirmed before implementation |
| January | Project proposal | Aim, objectives, methodology and technical direction finalised |
| January to February | System architecture design | Browser, server, Connectly and honeyseed components designed |
| February | Client-side WebAuthn implementation | Platform authenticator registration and PRF-backed protection implemented |
| February to March | Client-side enrolment and seed derivation | Account enrolment, encrypted storage and honeyseed derivation implemented |
| March | Server-side honeyword verifier development | Honeytrap verification and event logging implemented |
| March | TOTP integration using otplib | RFC 6238-compatible OTP generation and verification implemented |
| March to April | Full prototype assembly | HoneyBound-Web and Connectly integrated |
| April | Unit testing and functional testing | Main workflows tested |
| April | Attack simulations and cross-platform compatibility testing | Replay, invalid OTP, clock-tamper and honeytrap scenarios tested |
| April to May | Report writing and oral presentation | Dissertation and demonstration material prepared |

## Appendix C: Prototype Artefact Overview

The practical artefact produced by this project is HoneyBound-Web, a browser-based HTOTP-style authenticator. It is supported by a demo relying-party web application called Connectly. HoneyBound-Web acts as the authenticator, while Connectly acts as the service that requires OTP verification.

The prototype demonstrates the following features:

| Feature | Description |
|---|---|
| Browser-only authenticator | The authenticator runs in a browser rather than a native mobile application |
| WebAuthn platform credential support | Local device authentication is used through the browser's WebAuthn API |
| PRF-backed secret protection | Where supported, WebAuthn PRF output is used to help protect stored account secrets |
| Web Crypto API usage | Browser cryptography supports AES-GCM encryption, PBKDF2 derivation and HMAC operations |
| RFC 6238 compatibility | The visible OTP remains compatible with standard six-digit TOTP workflows |
| Honeyseed generation | One genuine seed and multiple decoy seeds are generated for compromise detection |
| Connectly integration | The demo relying party verifies OTPs and detects decoy seed usage |
| Replay resistance | Reuse of an OTP within the same time window is rejected |
| Trusted-time checking | The application compares local time with server time to detect clock mismatch |
| Audit visibility | Login success, invalid OTP, replay, honeytrap and clock events are logged |
| Device linking | QR-based linking allows another browser/device to import the account bundle |

## Appendix D: Development Environment

The prototype was developed and tested in a local development environment. The main technologies used are shown below.

| Category | Technology |
|---|---|
| Runtime | Node.js |
| Server framework | Express.js |
| Client platform | HTML, CSS and JavaScript |
| Browser APIs | WebAuthn and Web Crypto API |
| OTP library | otplib |
| Encryption | AES-GCM |
| Key derivation | PBKDF2 and WebAuthn PRF where available |
| Local persistence | Browser local storage and JSON-based server-side files |
| Demo relying party | Connectly local HTTPS web application |
| Transport | HTTPS for WebAuthn-compatible local testing |

The main HoneyBound-Web application is located in:

`C:\Users\hp\Desktop\project\fyp`

The paired Connectly demo application is located in:

`C:\Users\hp\Desktop\project\dummy-web`

The primary run commands used during development were:

```powershell
cd C:\Users\hp\Desktop\project\fyp
npm install
npm start
```

```powershell
cd C:\Users\hp\Desktop\project\dummy-web
npm install
npm start
```

The local application URLs were:

| Application | URL |
|---|---|
| HoneyBound-Web | `https://localhost:8443` |
| Connectly | `https://localhost:3000` |

## Appendix E: Key Source Files

The following files represent the main implementation artefacts.

| File | Purpose |
|---|---|
| `fyp/client/index.html` | Initial authenticator setup screen |
| `fyp/client/dashboard.html` | Main HoneyBound-Web dashboard |
| `fyp/client/accounts.html` | Account listing and management interface |
| `fyp/client/add-account.html` | Account enrolment workflow |
| `fyp/client/events.html` | Security event log view |
| `fyp/client/link-device.html` | QR-based device linking view |
| `fyp/client/phone-init.html` | Mobile onboarding and linked-device setup |
| `fyp/client/main.js` | Main browser-side application logic |
| `fyp/client/honey.js` | Cryptographic logic, OTP generation, WebAuthn and honeyseed functions |
| `fyp/client/graph.js` | Dashboard metrics and evaluation export |
| `fyp/client/qr.js` | QR device-linking support |
| `fyp/client/sync.js` | Account synchronisation and linked-device logic |
| `fyp/server/server.js` | HoneyBound-Web server, audit logging, time API and device-link APIs |
| `dummy-web/server/server.js` | Connectly demo server and OTP verification logic |
| `dummy-web/public/otp.html` | Connectly OTP verification page |
| `dummy-web/public/2fa-setup.html` | Connectly two-factor setup workflow |
| `dummy-web/public/fakedashboard.html` | Decoy dashboard shown after honeytrap detection |

## Appendix F: System Setup Procedure

The following procedure was used to run the prototype during testing.

1. Install dependencies in both HoneyBound-Web and Connectly using `npm install`.
2. Ensure local HTTPS certificates are available for both applications.
3. Start HoneyBound-Web from `C:\Users\hp\Desktop\project\fyp`.
4. Start Connectly from `C:\Users\hp\Desktop\project\dummy-web`.
5. Open HoneyBound-Web at `https://localhost:8443`.
6. Initialise the authenticator using the platform authenticator prompt.
7. Open Connectly at `https://localhost:3000`.
8. Register or sign in to a Connectly test account.
9. Enable two-factor authentication using a TOTP seed.
10. Add the Connectly TOTP account into HoneyBound-Web.
11. Generate an OTP from HoneyBound-Web and submit it to Connectly.
12. Review the HoneyBound-Web event dashboard for recorded login outcomes.

For linked-device testing, the QR code workflow was used. The phone or second browser opened the link session, initialised its own platform authenticator and imported the account bundle. The linked device then redirected to the full HoneyBound-Web dashboard.

## Appendix G: Main Functional Test Cases

The following test cases were used to confirm that the core prototype features operated as expected.

| Test ID | Test Case | Expected Result | Evidence Type |
|---|---|---|---|
| T01 | Open HoneyBound-Web over HTTPS | Application loads without browser blocking WebAuthn | Screenshot and browser observation |
| T02 | Initialise platform authenticator | Browser displays platform authenticator prompt and registration succeeds | Screenshot |
| T03 | Add a TOTP account | Account is saved in HoneyBound-Web | Screenshot |
| T04 | Generate a six-digit OTP | OTP is generated and refreshes by time window | Screenshot |
| T05 | Register Connectly account | Test account is created successfully | Screenshot |
| T06 | Enable Connectly 2FA | Connectly accepts the TOTP setup code | Screenshot |
| T07 | Login with correct OTP | User reaches Connectly dashboard | Screenshot and event log |
| T08 | Submit invalid OTP | Login is rejected | Screenshot and event log |
| T09 | Reuse same OTP in the same window | Replay attempt is rejected | Screenshot and event log |
| T10 | Submit stale OTP | Expired OTP is rejected | Screenshot and event log |
| T11 | Trigger honeyseed OTP | Honeytrap event is detected | Screenshot and event log |
| T12 | Redirect suspicious session | Suspicious user is sent to fake dashboard | Screenshot |
| T13 | Change device clock | Clock-tamper warning or rejection occurs | Screenshot and event log |
| T14 | Link second device | Linked device imports account bundle | Screenshot |
| T15 | View dashboard events | Recent security events are displayed | Screenshot |

## Appendix H: Attack Simulation Evidence

The prototype was evaluated against controlled attack scenarios. These simulations were carried out using local test accounts and did not involve real user accounts or third-party accounts except where standard TOTP compatibility was demonstrated safely.

| Attack Scenario | Method | Expected Defence | Observed Outcome |
|---|---|---|---|
| Invalid OTP attempt | Submit a random or incorrect six-digit OTP | OTP rejected | Rejected and logged |
| Same-window replay | Submit a previously accepted OTP again before the window changes | Replay rejected | Rejected and logged |
| Stale-window submission | Submit an OTP after its time window expires | OTP rejected as expired | Rejected |
| Honeyseed compromise simulation | Submit an OTP generated from a decoy seed | Honeytrap event triggered | Honeytrap recorded |
| Suspicious login handling | Continue after honeytrap detection | Session redirected away from real dashboard | Fake dashboard displayed |
| Clock manipulation | Manually alter local device time | Sensitive action blocked or warning displayed | Clock-tamper event recorded |
| Device replacement/recovery | Link a second browser or phone | Account bundle imported after setup | Linked-device workflow demonstrated |

These tests support the evaluation chapter by showing that HoneyBound-Web adds detection and visibility beyond a standard TOTP-only login flow.

## Appendix I: Cross-Platform Compatibility Notes

The prototype is browser-based and therefore has cross-platform potential, but full security behaviour depends on browser and device support for WebAuthn features.

| Environment | Expected Support | Notes |
|---|---|---|
| Windows desktop browser | Supported | Demonstrated with platform authenticator support |
| Android mobile browser | Supported where HTTPS and platform authenticator requirements are met | Device linking demonstrated at prototype level |
| iOS mobile browser | Expected where WebAuthn and HTTPS requirements are met | Behaviour may vary by browser and iOS version |
| macOS desktop browser | Expected where WebAuthn platform support is available | Full validation still required |
| Browser without WebAuthn PRF | Limited | Core browser page may load, but PRF-backed protection may not be available |
| Plain HTTP environment | Not suitable | WebAuthn requires a secure context for reliable operation |

The key limitation is that browser support for WebAuthn PRF is not identical across platforms. Therefore, HoneyBound-Web should be described as cross-platform capable at prototype level rather than fully production validated across all operating systems.

## Appendix J: Security Event Categories

HoneyBound-Web records security-relevant events to support audit visibility and evaluation. The event log is useful for demonstrating whether the prototype detects successful logins, failed attempts and suspicious behaviour.

| Event Category | Meaning |
|---|---|
| `login-success` | A valid OTP was accepted |
| `login-invalid` | An incorrect OTP was submitted |
| `otp-replay-rejected` | A previously used OTP was submitted again in the same time window |
| `otp-stale-rejected` | An OTP from an expired time window was submitted |
| `honeytrap-triggered` | An OTP matched a decoy honeyseed |
| `clock-tamper-detected` | Local time differed from trusted server time beyond the accepted threshold |
| `device-linked` | A new browser or mobile device was linked |
| `account-added` | A new TOTP account was enrolled |

The event log supports the research objective of adding audit visibility to TOTP authentication. A traditional TOTP implementation usually returns only success or failure, while HoneyBound-Web can distinguish between normal failure, replay behaviour and decoy seed use.

## Appendix K: Evaluation Data Collection Procedure

The evaluation data was collected through repeated prototype use and observation of the event dashboard. The following procedure was used:

1. Start HoneyBound-Web and Connectly over HTTPS.
2. Initialise the HoneyBound-Web authenticator.
3. Add a TOTP account and enable honeyseed support.
4. Link the account to Connectly.
5. Perform a normal login with a valid OTP.
6. Submit an invalid OTP.
7. Attempt to reuse a valid OTP within the same time window.
8. Wait for an OTP to expire and submit it after the window changes.
9. Trigger a honeytrap event using a decoy seed in the controlled demo environment.
10. Change the local clock to test clock-tamper detection.
11. Link a second device using the QR workflow.
12. Export or record dashboard metrics and event log outcomes.

The main evaluation indicators were:

| Metric | Purpose |
|---|---|
| Derivation latency | Measures usability impact of cryptographic seed derivation |
| Valid OTP success count | Confirms compatibility with normal TOTP login |
| Invalid OTP rejection count | Confirms standard OTP failure handling |
| Replay rejection count | Confirms same-window replay protection |
| Honeytrap detection count | Confirms decoy seed detection |
| Clock-tamper detection count | Confirms trusted-time protection |
| Cross-device linking result | Confirms usability and recovery potential |

## Appendix L: Ethical and Safety Controls

The project was designed as a defensive cybersecurity prototype. Testing was carried out in a controlled local environment using demo accounts and development data. The following controls were applied:

| Ethical Issue | Control |
|---|---|
| Use of authentication data | Test accounts were used rather than real user accounts |
| Honeytrap behaviour | Decoy dashboard behaviour was limited to the controlled Connectly demo |
| Logging of security events | Logs were used only for prototype evaluation and audit demonstration |
| Real-world misuse risk | The system was presented as a defensive proof of concept, not as an attack tool |
| User privacy | No real participant data was required for the technical evaluation |
| Third-party account risk | Compatibility demonstrations were limited and did not require storing real personal account credentials in the report |

If deployed outside a prototype environment, the honeytrap workflow would require organisational approval, legal review, privacy controls, retention limits and clear incident response procedures.

## Appendix M: Limitations Observed During Testing

The following limitations were observed and should be considered when interpreting the results:

1. The prototype is not production-ready and was built for controlled academic evaluation.
2. WebAuthn PRF support varies across browsers, operating systems and authenticator hardware.
3. Browser local storage is tied to a specific browser profile unless device linking is used.
4. The trusted-time check is implemented at application level rather than as a formal hardware-backed proof of clock integrity.
5. JSON-based server persistence is suitable for a prototype but should be replaced by a secure database in production.
6. Device linking requires HTTPS and trusted certificates, especially on mobile devices.
7. Full cross-platform validation across Windows, macOS, Android and iOS remains future work.
8. The canonical TOTP secret still exists locally in encrypted form for RFC 6238 compatibility.

These limitations do not invalidate the prototype, but they define its correct scope: a working final-year proof of concept rather than a deployable commercial authenticator.

## Appendix N: User Guide for Demonstration

This short guide describes the demonstration flow used for project presentation.

1. Open HoneyBound-Web at `https://localhost:8443`.
2. Initialise the authenticator using the browser's platform authenticator prompt.
3. Add a new account using a TOTP secret.
4. Enable honeyseed protection by entering the derivation password.
5. Open Connectly at `https://localhost:3000`.
6. Register or log in to a Connectly test account.
7. Enable two-factor authentication in Connectly.
8. Copy the generated OTP from HoneyBound-Web.
9. Submit the OTP in Connectly and confirm successful login.
10. Open the HoneyBound-Web event dashboard and show the login-success event.
11. Reuse the same OTP and show replay rejection.
12. Submit an invalid OTP and show invalid login logging.
13. Trigger a controlled honeyseed attempt and show honeytrap detection.
14. Show the fake dashboard redirect after honeytrap detection.
15. Open the device-link tab and demonstrate QR-based linking.

This flow demonstrates the main contribution of the project: a familiar TOTP user experience with additional seed protection, replay resistance, honeyseed detection and audit visibility.

## Appendix O: Glossary of Prototype Terms

| Term | Meaning in this Project |
|---|---|
| HoneyBound-Web | The browser-based HTOTP authenticator prototype |
| Connectly | The demo relying-party web application used to test OTP verification |
| TOTP | Time-based One-Time Password, normally refreshed every 30 seconds |
| HTOTP | Honey Time-based One-Time Password approach using real and decoy seed material |
| Honeyseed | A decoy TOTP seed used to detect suspected compromise |
| Real seed | The genuine TOTP seed that generates valid user OTPs |
| Decoy seed | A false seed that should never be used by a legitimate user |
| Honeytrap | A security event triggered when a decoy seed OTP is submitted |
| WebAuthn | Browser API for public-key authentication and platform authenticator use |
| PRF | Pseudo-random function extension used to derive device-bound key material where supported |
| Web Crypto API | Browser cryptography API used for encryption and key derivation |
| Replay attack | Attempt to reuse a previously valid OTP |
| Forward-replay attack | Attempt to exploit time-window handling to use OTPs outside their intended time |
| Trusted-time check | Comparison between local browser time and server time |
| Device linking | QR-based process for importing account data into another browser/device |

## Appendix P: Suggested Appendix Screenshot List

The following screenshots can be placed after this written appendix if the final report requires visual evidence:

1. HoneyBound-Web initialisation page.
2. Browser platform authenticator prompt.
3. Successful passkey or platform credential registration.
4. HoneyBound-Web dashboard.
5. Account enrolment form.
6. TOTP account added successfully.
7. Live OTP display.
8. Connectly registration page.
9. Connectly 2FA setup page.
10. Successful Connectly OTP verification.
11. Invalid OTP rejection.
12. Replay rejection.
13. Honeyseed seed bundle demonstration.
14. Honeytrap event in Connectly.
15. Fake dashboard redirect.
16. HoneyBound-Web event log.
17. Clock-tamper warning.
18. QR code for device linking.
19. Mobile linked-device setup.
20. Linked device dashboard.

These screenshots should be numbered consistently with the main report and should only include test data or blurred personal information.
