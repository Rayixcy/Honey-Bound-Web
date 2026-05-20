# HoneyBound-Web Project Report

## Cover Page

**Project Title:** HoneyBound-Web: A Browser-Based Honeyseed TOTP Authenticator Using WebAuthn PRF  
**Project Type:** Final Year Cybersecurity Project  
**Student Name:** [Insert Name]  
**Student ID:** [Insert ID]  
**Supervisor:** [Insert Supervisor Name]  
**Institution:** [Insert Institution Name]  
**Submission Date:** [Insert Date]

## Abstract

This project presents HoneyBound-Web, a browser-based authenticator prototype that combines standard Time-Based One-Time Passwords (TOTP), honeyword-style decoy seeds, and WebAuthn platform credentials. The system was developed to explore whether browser-native capabilities can be used to strengthen TOTP-based authentication without breaking compatibility with existing six-digit OTP workflows. In the prototype, the real TOTP secret is protected locally using an AES-GCM key derived from WebAuthn PRF output, while an additional deterministic seed-derivation process produces one real seed and nineteen decoy seeds for server-side detection of suspicious OTP use.

The implementation consists of two cooperating parts. The first is HoneyBound-Web, which runs as a browser-focused HTTPS application and handles credential setup, local secret protection, OTP generation, device linking, audit events, and evaluation export. The second is a demo relying-party application called Connectly, which receives seed bundles, verifies OTP submissions, detects honeytrap events, and returns outcome telemetry back to HoneyBound. The project also includes replay protection, stale-window checks, and trusted-time validation to reduce the risk of clock-tampering and forward-replay attacks.

The final artifact demonstrates that a browser-only prototype can support WebAuthn-assisted secret protection, deterministic honeyseed derivation, RFC 6238-compatible OTP generation, multi-device onboarding, and observable breach-detection workflows. However, the system remains a prototype rather than a production-ready authenticator. Some goals, such as complete cross-platform validation, full low-overhead equivalence with HTOTP, and comprehensive empirical evaluation, are only partially achieved and require further work.

## 1. Introduction

Traditional TOTP authenticators are widely used because they are simple, interoperable, and easy to deploy. However, standard TOTP systems have several limitations. If a secret seed is extracted from a device or copied during enrollment, the attacker can generate valid future OTPs without immediately revealing that compromise. Standard TOTP also depends on time synchronization, which can be abused through replay or clock manipulation if additional safeguards are not implemented.

The broader motivation for this project is to investigate whether browser technologies can support a stronger OTP model while remaining compatible with existing services. In particular, the project draws on the idea of HTOTP and honeyword-style deception, where decoy secrets can be used to identify compromise attempts. At the same time, modern browsers expose WebAuthn platform authenticators and PRF-based extensions that can be used as hardware-bound, non-exportable cryptographic inputs. This creates an opportunity to bind secret protection and seed derivation to the user’s device without requiring a native mobile application.

HoneyBound-Web was developed as a working prototype to test this idea. It is not intended to claim production completeness. Instead, it aims to demonstrate that a browser-only authenticator can protect locally stored TOTP material using WebAuthn PRF, derive deterministic honeyseeds for external verification, detect decoy use through a paired relying party, and support practical features such as live audit logging, linked-device onboarding, and evaluation data export.

## 2. Problem Statement

Standard TOTP authentication improves security compared with password-only login, but it still exposes important weaknesses. A copied or exfiltrated seed lets an attacker generate valid OTPs indefinitely. Standard OTP verifiers also normally treat any valid code as genuine, so secret compromise may remain invisible until after account abuse occurs. In addition, browser-based authenticator experiences are often considered weaker than native authenticator apps because they rely on web storage, browser state, and client-side logic.

The core problem addressed in this project is therefore:

How can a browser-based authenticator strengthen TOTP security by detecting compromised OTP material and protecting secrets with hardware-assisted browser primitives, while preserving compatibility with standard six-digit OTP verification workflows?

## 3. Aim and Objectives

### 3.1 Aim

The aim of this project is to design and implement a browser-based TOTP authenticator prototype that uses WebAuthn-assisted secret protection and honeyseed-based detection to improve visibility into OTP compromise while maintaining compatibility with standard TOTP systems.

### 3.2 Objectives

Based on the project objectives file and the final implementation, the main objectives can be summarized as follows:

1. Critically review existing TOTP and HTOTP schemes and identify security weaknesses through literature analysis.
2. Design a dynamic seed derivation mechanism using WebAuthn resident credentials as hardware-bound, non-exportable input material.
3. Avoid reliance on easily exportable static secret storage where possible.
4. Implement server-side honeyword or honeyseed verification using one real seed and nineteen decoys.
5. Preserve backward compatibility with normal six-digit TOTP codes.
6. Produce a largely browser-based prototype application.
7. Reduce replay and clock-tampering risk using trusted-time or stale-window controls.
8. Evaluate derivation performance, OTP outcomes, attack resistance, usability, and implementation limitations.

### 3.3 Objective Status Summary

- **Achieved:** Server-side honeyseed verification in the HoneyBound and Connectly demo flow.
- **Achieved:** Standard six-digit TOTP compatibility.
- **Achieved at prototype level:** Trusted-time checks, stale-window rejection, and replay protection.
- **Largely achieved:** WebAuthn PRF-backed dynamic derivation and a browser-based prototype implementation.
- **Partially achieved:** Full elimination of static secrets, low-overhead equivalence with HTOTP, broad evaluation evidence, and qualitative usability evidence.
- **Not fully achieved as originally written:** Operation without QR use, since QR is used for device linking and onboarding in the current design.

## 4. Scope of the Project

The implemented system is a prototype for controlled evaluation rather than a production authenticator. The current scope includes:

- Browser-based authenticator setup and account management.
- WebAuthn PRF-backed encryption of stored account secrets.
- Deterministic derivation of one real seed and nineteen honeyseeds.
- OTP generation compatible with RFC 6238.
- Integration with a demo relying party called Connectly.
- Trusted-time checks and stale-window validation.
- Replay protection for same-window OTP reuse.
- Audit logging and live event streaming.
- Linked-device onboarding and phone import flow.
- Evaluation export for derivation latency and OTP outcome metrics.

The current scope does not include:

- Production hardening.
- Formal platform-level proof of clock integrity.
- Completed cross-platform validation across all target operating systems and browsers.
- Fully cloud-synchronized account portability.

## 5. Methodology

This project followed a practical design-and-prototype methodology. First, the security problem was framed around shortcomings of standard TOTP and the promise of HTOTP-style deception. Second, a browser-capable architecture was designed around WebAuthn platform credentials, PRF-derived cryptographic material, and local browser storage. Third, the prototype was implemented using JavaScript and Node.js so that both client and server behavior could be tested quickly in a local environment. Finally, instrumentation was added so that derivation latency and OTP verification outcomes could be exported for evaluation.

The methodology was iterative rather than linear. Core features such as account storage and OTP generation were implemented first, then strengthened with PRF-backed encryption, deterministic derivation versioning, replay protection, audit streaming, and linked-device support. This approach was suitable because it allowed the prototype to evolve alongside the security model while preserving a demonstrable working artifact.

## 6. System Design and Architecture

### 6.1 Overall Architecture

The project uses a two-system architecture:

- **HoneyBound-Web:** the browser-focused authenticator prototype running on `https://localhost:8443`
- **Connectly:** a demo web application running on `https://localhost:3000`

HoneyBound-Web provides the user interface for account addition, OTP generation, event viewing, and device linking. Sensitive account secrets are stored in the browser and protected using encryption keys derived from WebAuthn PRF output. The HoneyBound server supplies HTTPS delivery, trusted-time responses, audit persistence, device-link sessions, and telemetry handling.

Connectly acts as the relying party. It stores the exported seed bundle, verifies OTP submissions against the real and decoy seeds, rejects replayed or stale-window OTPs, and notifies HoneyBound of login outcomes. This separation is important because it allows the breach-detection logic to operate in a realistic server-side verification path.

### 6.2 Main Components

The main implementation components are:

- `client/main.js`: user-facing browser logic for account workflows and integration behavior.
- `server/honey.js`: cryptographic core for PRF-backed encryption, deterministic seed derivation, OTP generation, and local event logging.
- `server/server.js`: HoneyBound HTTPS server, audit/event APIs, trusted-time endpoint, device-link flow, and persistence of audit/device snapshots.
- `dummy-web/server/server.js`: Connectly demo server, OTP verification logic, replay detection, telemetry return, session handling, and email-alert integration.

### 6.3 Data Flow

The most important data flow is as follows:

1. The user initializes a WebAuthn credential in the browser.
2. HoneyBound obtains PRF output from a platform authenticator.
3. The raw TOTP secret is encrypted locally using a PRF-derived AES-GCM key.
4. If honeyseed mode is enabled, HoneyBound derives one real seed and nineteen decoys deterministically.
5. The exported bundle is sent to Connectly during account linking.
6. During login, HoneyBound still generates the visible OTP from the real RFC 6238 secret.
7. Connectly verifies the OTP against the real seed and all decoy seeds.
8. If a decoy matches, a honeytrap event is recorded and surfaced back to HoneyBound.

### 6.4 Security Design Choices

Several design decisions define the prototype:

- The displayed OTP remains a standard TOTP generated from the decrypted canonical secret. This preserves interoperability.
- WebAuthn PRF output is used as hardware-assisted secret material rather than storing everything in plain browser storage.
- Deterministic derivation allows the same credential and password combination to regenerate consistent decoy seeds.
- Replay resistance is enforced using stale-window checks and same-window reuse tracking.
- Trusted-time validation is used before PRF-sensitive actions to reduce risk from local clock tampering.

## 7. Implementation

### 7.1 Technologies Used

The project was implemented primarily with:

- JavaScript
- Node.js
- Express.js
- WebAuthn browser APIs
- Web Crypto API
- AES-GCM
- PBKDF2
- HTTPS with local certificates
- JSON-based persistence for prototype data

Although the package file includes `sqlite` and `sqlite3`, the current HoneyBound prototype stores audit and synchronization state in JSON files such as `audit_log.json`, `linked_devices.json`, and `account_sync.json`.

### 7.2 HoneyBound-Web Features

HoneyBound-Web implements the following major features:

- Authenticator initialization using WebAuthn platform credentials.
- Local encryption of TOTP secrets using PRF-derived AES keys.
- Optional derivation password for deterministic honeyseed generation.
- Account addition, storage, retrieval, and deletion.
- RFC 6238-compatible OTP generation.
- Export of one real seed plus nineteen decoy seeds to Connectly.
- Event logging and live audit streaming through Server-Sent Events.
- Trusted-time monitoring and clock-tamper warnings.
- Device-linking and phone onboarding workflows.
- Evaluation export summarizing derivation and OTP metrics.

### 7.3 Connectly Demo Integration

Connectly was used to simulate a relying party that receives and verifies HoneyBound-linked accounts. Its implementation includes:

- Standard user registration and login.
- Optional Google OAuth in the local demo environment.
- Strict OTP verification against stored honeyseed bundles.
- Detection of real-seed success, honeytrap triggers, and invalid OTPs.
- Same-window replay rejection.
- Telemetry reporting back to HoneyBound.
- Fake-dashboard redirection for honeytrap events.
- Email-alert hooks for successful logins, failed OTPs, honeytrap incidents, and fake-dashboard interaction.

This integration is important because the HoneyBound prototype alone cannot demonstrate server-side decoy detection. The paired system shows how the authenticator and the relying party cooperate in practice.

### 7.4 Multi-Device Support

The project also extends beyond a single-browser proof of concept. A laptop user can generate a device-link session and QR code, a phone can scan the QR and initialize its own authenticator context, and account bundles can then be imported into the phone browser. After import, the phone can operate as a full HoneyBound dashboard client rather than a limited viewer. This supports the project’s recovery and cross-device continuity goals, even though broader test evidence is still needed.

## 8. Security Analysis

### 8.1 Threats Addressed

The prototype is designed to address several security concerns:

- Silent compromise of OTP verification material.
- Replay of previously valid OTPs.
- Forward-replay through time-window abuse.
- Exposure of locally stored TOTP secrets.
- Weak visibility into suspicious OTP activity.

### 8.2 Mitigations Implemented

The following mitigations are present in the final prototype:

- **PRF-backed secret protection:** stored secrets are encrypted with keys derived from WebAuthn PRF output.
- **Deterministic honeyseed derivation:** decoy material can be regenerated consistently for linked accounts.
- **Honeytrap verification:** Connectly checks OTPs against one real seed and nineteen decoys.
- **Trusted-time validation:** sensitive actions are blocked when local device time differs too far from server time.
- **Stale-window rejection:** OTPs from significantly different windows are rejected.
- **Same-window replay protection:** Connectly records used windows and blocks reuse.
- **Audit visibility:** login outcomes and security-relevant events are logged and displayed.

### 8.3 Remaining Risks and Limitations

Despite the above improvements, some limitations remain:

- The canonical TOTP secret still exists locally in encrypted form, so the strongest claim of eliminating static secrets is not fully met.
- Browser-local state means different browsers on the same machine do not automatically share the same HoneyBound state.
- The trusted-time mechanism is an application-level safeguard, not a formal proof from the operating system or authenticator hardware.
- Cross-platform behavior is expected but not fully evidenced through completed testing records.
- The full honeytrap detection path depends on server-side support in the paired relying party.

## 9. Testing and Evaluation

### 9.1 Functional Testing

Functional verification of the prototype can be inferred from the implemented flows:

- WebAuthn credential registration and PRF usage.
- Addition of TOTP accounts.
- Standard OTP generation.
- Export and linking of honeyseed bundles to Connectly.
- Successful OTP login through the real seed.
- Honeytrap triggering through a decoy seed.
- Invalid OTP rejection.
- Replay protection within the same time window.
- Device linking and account import to a phone browser.
- Event logging and live dashboard metrics.

### 9.2 Performance and Instrumentation

The dashboard includes an export function that reads real derivation timings and OTP outcome logs from browser storage. It computes summary metrics including:

- sample count
- average derivation time
- minimum derivation time
- maximum derivation time
- 95th percentile derivation time
- login success count
- invalid OTP count
- honeytrap count
- success rate
- comparison with the cited HTOTP baseline of `0.24 ms`

This evaluation support is a strong feature of the prototype because it allows real measurements to be collected from actual runs rather than estimated values. However, the final evidence still depends on the user conducting enough experimental sessions and recording the results in the dissertation.

### 9.3 Evaluation Outcome

At this stage, the evaluation framework is implemented, but the report should describe the results as partially complete unless real exported data has already been collected and inserted. Therefore, the correct academic claim is that the project supports quantitative and qualitative evaluation, but final evidence must still be completed through formal testing sessions.

## 10. Discussion

The prototype shows that a browser-based authenticator can meaningfully strengthen TOTP without abandoning compatibility. A key achievement is that the visible OTP remains a normal six-digit RFC 6238 code, while the backend verification environment can still distinguish between genuine and decoy seed use. This is an effective compromise between deployability and detection capability.

Another important contribution is the use of WebAuthn PRF output for both secret protection and deterministic derivation. This ties the system more closely to hardware-assisted browser primitives than a plain JavaScript-only approach. The resulting design is stronger than storing raw secrets in local storage and more aligned with the project’s original hardware-bound goal.

At the same time, the prototype makes clear that practical trade-offs remain. Full removal of canonical secret storage is not achieved, and the current design still depends on encrypted local persistence. Likewise, the performance-overhead question cannot yet be answered conclusively without complete evaluation data, and some goals from the original proposal had to be adapted to fit a working browser prototype.

## 11. Conclusion

This project successfully produced a working prototype called HoneyBound-Web, a browser-based authenticator that combines WebAuthn PRF-backed secret protection, deterministic honeyseed derivation, RFC 6238-compatible OTP generation, and server-side decoy verification through a paired demo application. The prototype demonstrates that it is feasible to build a browser-first OTP system that improves breach visibility and adds replay and clock-tampering safeguards while remaining interoperable with traditional six-digit TOTP workflows.

The project achieved its most important implementation goals: dynamic PRF-assisted protection, honeyseed-based compromise detection, TOTP compatibility, replay-aware verification, and a practical browser-based artifact. However, some objectives remain only partially complete, especially broad empirical evaluation, strong claims around eliminating static secrets, and formal cross-platform validation. As a result, the most accurate conclusion is that HoneyBound-Web is a successful security prototype and evaluation artifact, but not yet a production-ready authenticator.

## 12. Future Work

The most useful next steps for the project are:

1. Perform full cross-platform testing across Windows, macOS, Android, and iOS with documented results.
2. Collect and report formal evaluation data for derivation latency, verification overhead, and usability.
3. Replace prototype JSON persistence with a more structured and secure storage layer where appropriate.
4. Explore stronger approaches that reduce or remove dependence on a locally stored canonical TOTP secret.
5. Harden the linked-device workflow for broader deployment scenarios.
6. Extend the relying-party integration beyond the demo environment to test real-world interoperability.
7. Add more formal threat modeling and security validation for production-readiness claims.

## 13. References

The final dissertation version of this section should include full academic references. Based on the implemented system, the reference list should include at least:

1. RFC 6238: TOTP: Time-Based One-Time Password Algorithm.
2. WebAuthn specification and related documentation for PRF-capable platform credentials.
3. Relevant HTOTP or honeyword-based authentication literature used in the project proposal.
4. Supporting literature on replay protection, phishing resistance, and browser-based credential security.

## Appendix A. Project Files Used In This Report

This report was written against the implemented project files, especially:

- `fyp/README.md`
- `fyp/server/honey.js`
- `fyp/server/server.js`
- `fyp/docs/implementation-notes.md`
- `fyp/docs/architecture-sequence-diagrams.md`
- `fyp/docs/evaluation-results-template.md`
- `dummy-web/server/server.js`
- `Objective.docx`

## Appendix B. Short Objective-Achievement Summary

| Objective | Status | Summary |
| --- | --- | --- |
| Review TOTP and HTOTP literature | Partially achieved | Likely addressed in written work, not provable from code alone |
| Dynamic WebAuthn-based derivation | Largely achieved | Implemented with WebAuthn PRF-backed deterministic derivation |
| Avoid static secret storage | Partially achieved | Secret still exists locally in encrypted canonical form |
| Server-side detection with 1 real + 19 decoys | Achieved | Implemented in HoneyBound + Connectly demo flow |
| Replicate HTOTP low overhead | Partially achieved | Mechanism exists, full evidence still pending |
| Fully browser-based prototype | Largely achieved | Browser-first implementation completed |
| No QR-code enrolment | Not fully achieved | QR is used for device linking/onboarding |
| No extra installations for end users | Partially achieved | Browser use is simple, but demo setup still needs Node.js and certificates |
| Clock-tamper and forward-replay safeguards | Achieved at prototype level | Trusted-time and replay protections implemented |
| Quantitative evaluation | Partially achieved | Evaluation tooling exists, final datasets still needed |
| Qualitative evaluation | Partially achieved | Limitations documented, formal usability evidence pending |
| Literature comparison | Partially achieved | Comparison framework exists, final evidence pending |
| Standard 6-digit TOTP compatibility | Achieved | RFC 6238 OTP generation preserved |
| Optional honeyword support | Partially achieved | Optional in prototype, but detection depends on server-side support |
