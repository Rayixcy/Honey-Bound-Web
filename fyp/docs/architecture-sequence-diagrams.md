# Architecture And Sequence Diagrams

This file contains lightweight Mermaid diagrams for the HoneyBound-Web prototype and its Connectly demo integration.

## System Architecture

```mermaid
flowchart LR
    U[User]
    B[Browser UI\nHoneyBound-Web client]
    WA[WebAuthn Platform Authenticator\nTPM / Secure Enclave / Device Credential]
    HC[HoneyBound Crypto Logic\nclient/honey.js]
    HS[HoneyBound HTTPS Server\nserver/server.js]
    AL[Audit Log\nserver/audit_log.json]
    C[Connectly Demo App\nhttps://localhost:3000]
    CU[Connectly User Store\ndummy-web/server/users.json]
    M[Linked Phone Browser\nFull HoneyBound Dashboard]

    U --> B
    B <--> WA
    B <--> HC
    B <--> HS
    B <--> C
    M <--> HS
    M <--> HC
    M <--> WA
    HC --> HS
    HS --> AL
    C --> CU
    C --> HS

    HS -. trusted time .-> B
    HS -. trusted time .-> M
    HC -. PRF-backed secret protection .-> WA
    C -. login outcome telemetry .-> HS
```

## Component View

```mermaid
flowchart TB
    subgraph HoneyBound-Web
        IDX[index.html]
    DASH[dashboard.html]
    MD[mobile-dashboard.html]
    PHONE[phone-init.html]
    ACC[accounts.html / add-account.html]
        MAIN[main.js]
        GRAPH[graph.js]
        QR[qr.js]
        CFG[config.js]
        HONEY[honey.js]
        HSERVER[server/server.js]
    end

    subgraph Connectly
        CSERVER[dummy-web/server/server.js]
        CSTORE[dummy-web/server/users.json]
        CPUBLIC[dummy-web/public/*]
    end

    IDX --> MAIN
    DASH --> MAIN
    DASH --> GRAPH
    DASH --> QR
    MD --> HONEY
    MD --> MAIN
    PHONE --> HONEY
    PHONE --> MAIN
    ACC --> MAIN
    ACC --> HONEY
    MAIN --> HONEY
    MAIN --> CFG
    HONEY --> HSERVER
    MAIN --> CSERVER
    CSERVER --> CSTORE
    CSERVER --> CPUBLIC
    CSERVER --> HSERVER
```

## Sequence: Initial Enrolment

```mermaid
sequenceDiagram
    actor User
    participant Browser as HoneyBound Browser UI
    participant WA as WebAuthn Authenticator
    participant Honey as honey.js
    participant HBW as HoneyBound Server
    participant Connectly as Connectly Server

    User->>Browser: Open HoneyBound-Web
    User->>Browser: Initialize authenticator
    Browser->>WA: navigator.credentials.create(..., prf)
    WA-->>Browser: Resident credential created
    Browser->>Browser: Store credential ID + PRF support flag

    User->>Browser: Add account + optional derivation password
    Browser->>Honey: assertWithPRF("encryption")
    Honey->>HBW: GET /api/honey/time
    HBW-->>Honey: Trusted server time
    Honey->>WA: navigator.credentials.get(..., prf)
    WA-->>Honey: Assertion + PRF output
    Browser->>Honey: addAccount(account, assertion, password)
    Honey->>Honey: Encrypt secret with PRF-derived AES key
    Honey->>Honey: Derive deterministic PRF-based real seed + 19 decoys
    Honey-->>Browser: Account stored locally

    opt Honeyseed mode enabled
        Browser->>Honey: exportSeedsForConnectly(accountId, assertion, password)
        Honey-->>Browser: 1 real seed + 19 decoys
        Browser->>Connectly: POST /api/register-honeybound-account
        Connectly-->>Browser: Registration success
    end
```

## Sequence: Linked Phone Becomes Full HoneyBound Client

```mermaid
sequenceDiagram
    actor User
    participant Laptop as HoneyBound Laptop Dashboard
    participant HBW as HoneyBound Server
    participant Phone as Phone Browser
    participant WA as Phone Platform Authenticator
    participant Honey as honey.js

    User->>Laptop: Open Link Device tab
    Laptop->>HBW: Create link session + QR
    User->>Phone: Scan QR and open phone-init.html
    Phone->>WA: Create or reuse phone authenticator credential
    WA-->>Phone: Credential available
    Phone->>HBW: Load synced account bundle
    Phone->>Honey: Import accounts with PRF-backed encryption
    Phone->>HBW: Push synced snapshot
    Phone-->>User: Redirect to full dashboard.html
```

## Sequence: OTP Login Through Connectly

```mermaid
sequenceDiagram
    actor User
    participant ConnectlyUI as Connectly UI
    participant Connectly as Connectly Server
    participant Browser as HoneyBound Browser UI
    participant Honey as honey.js
    participant HBW as HoneyBound Server
    participant WA as WebAuthn Authenticator

    User->>ConnectlyUI: Log in to Connectly over HTTPS
    ConnectlyUI->>Connectly: Username/password or Google session
    Connectly-->>ConnectlyUI: Request OTP + Account ID

    User->>Browser: Open HoneyBound account
    Browser->>Honey: generateOTP(accountId)
    Honey->>HBW: GET /api/honey/time
    HBW-->>Honey: Trusted server time
    Honey->>WA: PRF-backed credential flow if needed
    WA-->>Honey: Assertion / PRF output
    Honey-->>Browser: RFC 6238 OTP

    User->>ConnectlyUI: Submit OTP + Account ID
    ConnectlyUI->>Connectly: POST /api/verify-otp
    Connectly->>Connectly: Check stale window
    Connectly->>Connectly: Check same-window replay cache
    Connectly->>Connectly: Verify real seed / deterministic decoy seeds

    alt Real seed matched
        Connectly->>HBW: POST /api/honey/event (login)
        HBW-->>Connectly: Event logged
        Connectly-->>ConnectlyUI: Success
    else Decoy seed matched
        Connectly->>HBW: POST /api/honey/event (honeytrap)
        HBW-->>Connectly: Event logged
        Connectly-->>ConnectlyUI: Honeytrap response
    else Invalid or replayed OTP
        Connectly->>HBW: POST /api/honey/event (invalid)
        HBW-->>Connectly: Event logged
        Connectly-->>ConnectlyUI: Failure
    end
```

## Sequence: Trusted-Time Clock Guard

```mermaid
sequenceDiagram
    actor User
    participant Browser as HoneyBound Browser UI
    participant Honey as honey.js
    participant HBW as HoneyBound Server
    participant WA as WebAuthn Authenticator

    User->>Browser: Trigger PRF-sensitive action
    Browser->>Honey: assertWithPRF() / decryptSecret() / generateOTP()
    Honey->>HBW: GET /api/honey/time
    HBW-->>Honey: serverTimeMs + unixWindow
    Honey->>Honey: Compare local time vs trusted server time

    alt Clock skew within allowed threshold
        Honey->>WA: Continue WebAuthn / PRF operation
        WA-->>Honey: Assertion / PRF output
        Honey-->>Browser: Operation succeeds
    else Clock skew too large
        Honey->>HBW: Log clock-tamper-detected event
        Honey-->>Browser: Throw CLOCK_TAMPER error
    end
```

## Sequence: Evaluation Export

```mermaid
sequenceDiagram
    actor User
    participant Dashboard as dashboard.html
    participant Graph as graph.js
    participant Store as localStorage

    User->>Dashboard: Click Export Evaluation Report
    Dashboard->>Graph: exportEvaluationReport()
    Graph->>Store: Read hbw_deriv_log_v1
    Graph->>Store: Read hbw_honey_log_v1
    Graph->>Graph: Compute avg/min/max/p95
    Graph->>Graph: Compute success/failure/honeytrap counts
    Graph->>Graph: Compare avg derivation vs 0.24 ms baseline
    Graph-->>User: Download honeybound-evaluation-report.txt
```
