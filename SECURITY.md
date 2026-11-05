# Security Policy and Model — UMAI 0.1

This document provides a rigorous, transparent analysis of the **UMAI (User-Mediated Application Interoperability)** security model. To avoid conflating unrelated layers, it strictly separates:

1. **Application-Level Security Concerns** (how individual applications authenticate users and protect their own backends—orthogonal to UMAI).
2. **Protocol & Browser Transport Guarantees** (what `js/umai.js` guarantees inside the browser).
3. **Server-Side Cryptographic Guarantees** (what `Ed25519` signing, receipts, and optional asymmetric encryption solve across the untrusted browser bridge).
4. **Inherent Limits & Residual Risks of the User-Mediated Principle** (what neither the protocol nor server cryptography can solve on its own, and how production deployments address them).

---

## 1. Separation of Security Concerns (What Is vs. Isn't UMAI's Job)

When evaluating UMAI, it is essential to separate three distinct planes:

| Plane | Responsibility | Scope in Reference Repo |
|---|---|---|
| **Plane A: Individual Application Security** | How Application A or B authenticates its human users (MFA, OIDC/SAML, WebAuthn/Passkeys, session lifetimes), enforces internal RBAC, and secures its database at rest. | **Out of Scope for UMAI.** The sample servers (`pkg/umaiserver`) use a static `admin` / `umai123` login purely as a zero-dependency local demo fixture. Production apps use their existing enterprise IAM. |
| **Plane B: Browser-Mediated Transport (`js/umai.js`)** | Moving `OFFER`, `GET`, `PUT`, and `ACK` frames between two cross-origin browser contexts without any backend-to-backend network path or cross-origin HTTP API exposure. | **Core UMAI Protocol (`js/umai.js`).** Enforces origin allowlisting, `event.source` pinning, private `MessagePort` isolation, and receiver-controlled state transitions. |
| **Plane C: End-to-End Authenticity & Confidentiality** | Ensuring that the mediating browser (or a rogue browser extension) cannot tamper with messages in transit, forge messages, trigger premature outbox deletion, or (optionally) read sensitive payloads. | **Server-Side Cryptography (`pkg/umaiserver/crypto.go`).** Supported natively by `signature` and `receipts` fields in the UMAI `PUT` and `ACK` envelopes. |

### Zero Cross-Origin HTTP Calls & Zero CORS Required
UMAI **never** makes HTTP requests from Application A's frontend to Application B's backend (or vice versa). Each frontend communicates exclusively with its own origin's HTTP API, while the two frontends exchange data in-memory via a dedicated `MessagePort`.
- **Why this matters:** Neither server needs to enable Cross-Origin Resource Sharing (`Access-Control-Allow-Origin` or `Access-Control-Allow-Credentials: true`) for the peer domain. Keeping all HTTP endpoints strictly same-origin prevents a compromised peer domain from making direct credentialed API calls to the other application.

---

## 2. Three Progressive Security Tiers

Depending on the trust relationship between the two applications and the mediating user, UMAI supports three progressive security tiers:

| Security Tier | Threat Addressed | Mechanism | Status in Reference Implementation |
|---|---|---|---|
| **Tier 1: Transport & State-Machine Isolation** | Unauthorized websites framing or snooping on messages; out-of-order protocol injection | `frame-ancestors` CSP, `event.origin` + `event.source` pinning, dedicated `MessagePort`, `_inFlightGets` & `_offeredIds` checks | **Built into `js/umai.js` & `pkg/umaiserver`** |
| **Tier 2: End-to-End Authenticity & Non-Repudiation (Signed Envelopes)** | User, browser extension, or DevTools tampering with payloads/files in transit, stripping signatures, reflecting messages, or forging `ACK`s | Server-side `crypto/ed25519` signatures on `PUT` (`signature`) and signed acceptance receipts on `ACK` (`receipts`) with directional role binding | **Built into `pkg/umaiserver/crypto.go` & supported natively in `PUT`/`ACK` schemas** |
| **Tier 3: End-to-End Confidentiality ("Blind Courier" Encryption)** | Sensitive backend records that the mediating user's browser or extensions must not be able to read in transit | Server A encrypts payload/attachments with Server B's public key (`X25519` + `AES-256-GCM`); Server B decrypts on ingest | **Architectural option (supported transparently without changing `js/umai.js`)** |

---

## 3. Core Browser Protocol Controls (`js/umai.js`)

### 3.1 Strict Origin Allowlisting & Source Pinning
- Every incoming `window.postMessage` event (including UI control notifications) is validated against the configured peer origin (`event.origin === peerOrigin`).
- Outgoing `postMessage` calls always specify the explicit `peerOrigin` target, never the wildcard `*`.
- **Handshake Source Pinning:** During the handshake, the host verifies `event.source === iframe.contentWindow` before accepting `READY`, and the embedded peer verifies `event.source === window.parent` before accepting `INIT`.

### 3.2 Dedicated `MessagePort` Isolation & Lifecycle
- After the initial handshake over `window.postMessage`, all `OFFER`, `GET`, `PUT`, and `ACK` frames travel exclusively over an isolated `MessageChannel` (`MessagePort`).
- If an embedded peer reloads or re-authenticates and emits a new `READY` signal, any previous `MessagePort` is explicitly closed (`port.close()`) before establishing a new channel.

### 3.3 Receiver-Controlled State Machine Enforcement
- **Unsolicited `PUT` Rejection:** Under Rule 2 (Receiver-Controlled Transfer), a receiver only requests unaccepted messages via `GET` (tracked in `_inFlightGets`). Any unsolicited `PUT` whose message ID was not requested by a preceding `GET` is immediately dropped.
- **Offered `ACK` Validation:** Under Rule 6, a sender tracks offered message IDs in `_offeredIds` and ignores any incoming `ACK` identifiers that were never offered.

### 3.4 Content Security Policy (CSP) & Embedding Control
To prevent clickjacking and unauthorized framing:
- **Application A (Embedded):** Enforces `Content-Security-Policy: frame-ancestors 'self' <PeerOrigin>`. Any unauthorized origin attempting to embed Application A is blocked by the browser engine.
- **Application B (Host):** Enforces `Content-Security-Policy: frame-ancestors 'none'; frame-src 'self' <PeerOrigin>`.

---

## 4. End-to-End Cryptographic Signing (`PUT` Signatures & `ACK` Receipts)

### Why Signing Bridges the Core Protocol and Server Storage
Because the user's browser mediates the transfer, a user with browser DevTools open—or a malicious browser extension running inside the browser—sits in the middle of the `MessagePort`. To prevent the browser mediator from altering data in flight or forging acknowledgements, the **UMAI `PUT` and `ACK` wire envelopes** carry opaque cryptographic fields (`signature` on `PUT`, and `receipts` on `ACK`). Application servers verify origin authenticity and byte-level integrity end-to-end **without the browser ever needing private keys or WebCrypto code**.

### How Server-Side Signing Works (`pkg/umaiserver/crypto.go`)
The reference Go server implements zero-dependency `crypto/ed25519` signing and verification with strict anti-downgrade and anti-reflection guarantees:

1. **Outbox Signing with Directional Domain Separation (Sender Server):**
   - When `CreateOutboxMessage` snapshots a message and its attachments into `outbox/{id}`, the sending server computes a canonical SHA-256 digest that binds the **sender role**, **message ID**, **canonical JSON payload hash**, and **sorted attachment hashes**:
     ```text
     UMAI-PUT-V1
     <sender_role>
     <message_id>
     <canonical_payload_json_sha256>
     <att1_sanitized_name>:<att1_size>:<att1_sha256>
     ...
     ```
   - The server signs this digest with its `Ed25519` private key and stores the hex signature in `message.json` (`signature`).
   - `umai.js` passes `signature` along inside the `PUT` envelope as an opaque string.

2. **Mandatory Inbox Verification & Receipt Generation (Receiver Server):**
   - When `AcceptSignedMessage` receives `POST /api/inbox`, signature verification is **mandatory** whenever a peer public key is configured—omitting or stripping the `signature` field is immediately rejected (`ErrInvalidSignature`, preventing signature-strip downgrade attacks).
   - The receiver verifies the signature against the expected `peerRole` (`"app-a"` vs `"app-b"`), preventing any cross-direction reflection attack.
   - If the payload or any attachment byte was modified in the browser (or forged by a script), signature verification fails, the temporary staging directory is purged, and no `ACK` is sent.
   - Upon valid verification and atomic commit, the receiving server signs a cryptographic acceptance receipt binding its own `receiver_role`, the `message_id`, and the `original_message_signature_hex`:
     ```text
     UMAI-ACK-V1
     <receiver_role>
     <message_id>
     <original_message_signature_hex>
     ```
   - This `ack_receipt` is persisted in `inbox/{id}/message.json` (so it is also returned on Rule 5 repeated `ACK`s via `/api/accepted/receipts`) and returned to the browser.

3. **Mandatory Receipt Verification Before Outbox Deletion (Sender Server):**
   - `umai.js` carries `receipts: { [id]: ack_receipt }` inside the `ACK` envelope.
   - In `AcknowledgeMessagesVerified`, the sending server requires a valid `Ed25519` receipt signed by the peer's public key for every signed outbox message—an empty `receipts: {}` map or forged receipt is rejected (`ErrInvalidReceipt`).
   - **Security Guarantee:** An outbox message is never deleted unless the genuine peer server cryptographically proves it accepted the exact original bytes.

---

## 5. Optional Extension: Asymmetric Encryption ("Blind Courier" Mode)

In some enterprise workflows, two backend systems want to use the user's browser session as a transport bridge, but **do not want the user's browser, browser extensions, or client-side memory inspectors to read the sensitive payload or attachments in transit**.

Because UMAI's browser layer (`js/umai.js`) treats `payload` and `attachments` as opaque objects, **asymmetric public-key encryption** can be added purely on the servers without changing a single line of `js/umai.js` or the UI:

1. **Key Configuration:**
   - Application A is configured with Application B's public encryption key (e.g., `X25519` / `crypto/ecdh`), and Application B is configured with Application A's public encryption key.
2. **Encryption on Outbox Creation (Sender Server):**
   - When creating an outbox message, Server A generates an ephemeral `X25519` key pair, derives a shared secret with Server B's public key via `HKDF-SHA256`, and encrypts the JSON payload and each attachment using authenticated encryption (`AES-256-GCM` or `ChaCha20-Poly1305`).
   - Server A signs the resulting ciphertext envelope with its `Ed25519` signing key.
3. **Blind Browser Transit:**
   - The user's browser ferries the encrypted blobs over `MessagePort` via `PUT`. Neither the user nor any browser extension can inspect the plaintext content while in flight.
4. **Decryption on Inbox Acceptance (Receiver Server):**
   - When `POST /api/inbox` arrives at Server B, Server B first verifies Server A's `Ed25519` signature, then decrypts the payload and attachments using its `X25519` private key inside the atomic staging directory before committing the plaintext files to `inbox/{id}`.

---

## 6. Inherent Limits & Residual Risks of the User-Mediated Principle

A rigorous security review must be completely transparent about what the **UMAI principle** cannot solve on its own, and what residual risks remain even when server-side signing and encryption are enabled:

### 6.1 Safety vs. Liveness (Selective Suppression / Denial of Service by the Mediator)
- **What UMAI Guarantees (Safety):** Neither a network drop, a browser crash, nor a malicious browser extension can cause silent data corruption, partial message acceptance (Rule 3), duplicate import (Rule 4), forged message acceptance, or premature outbox deletion without peer acceptance (Rule 6 + signed receipts).
- **What UMAI Cannot Guarantee (Liveness against an Uncooperative User):** Because UMAI is intentionally *user-mediated* (Rule 8: no background delivery without an active session), the mediating browser controls transport execution. A user or client-side extension can always close the tab, block the iframe, or selectively drop `OFFER`/`GET`/`PUT`/`ACK` frames.
  - *Impact:* Selective suppression is strictly a **denial-of-service (availability)** delay—never an integrity failure or data loss. Unacknowledged messages remain safely in the sender's outbox until a healthy session completes reconciliation.

### 6.2 Multi-User Topologies: User-Scoped vs. System-Wide Opportunistic Pool ("Courier Swap" & Concurrency)
Depending on the deployment architecture, a UMAI channel operates in one of two modes:

1. **Mode 1 — User-Scoped Channel ("My Data Only"):**
   - **The Threat:** Server-level `Ed25519` signing proves to Server B that a message genuinely originated from *Server A*. However, in a user-scoped or multi-tenant deployment, consider what happens if a user is logged into Application A as `Alice (Tenant 1)` and logged into Application B as `Bob (Tenant 2)`—or if `Eve` extracts a signed message from her own account on Application A and delivers it while authenticated to a different account on Application B.
   - **How Production Servers Address It:** Server-level signatures bind **who the message is from and who it is intended for** inside the signed `payload` (e.g., `"sender_user": "alice@corp.example"`, `"recipient_tenant": "tenant-1"`). Upon receiving `POST /api/inbox` with a valid Server A signature, Server B verifies that the currently authenticated user/tenant matches the intended `recipient_tenant` / `recipient_user` before importing.
2. **Mode 2 — System-Wide Opportunistic Pool ("Crowdsourced System Bridge"):**
   - **The Pattern:** Organizations can intentionally use *any* authenticated user's open UMAI channel to transfer all pending messages between System A and System B (e.g., if 10 users are online, all 10 browsers act as a pooled transport bridge).
   - **Security in Pooled Mode:** Combining **Tier 2 (`Ed25519` signing)** with **Tier 3 ("Blind Courier" asymmetric encryption)** allows User #4's browser to ferry a message created by User #1 without User #4 being able to read or modify the message in transit.
   - **Withstanding Concurrent "Double Efforts" & Next-Best Selection:**
     - *Correctness under Race Conditions:* In `pkg/umaiserver`, `AcceptSignedMessage` stages uploads in unique `.tmp-{id}-{nanoseconds}` directories under a mutex lock. If two browsers upload the same message simultaneously, the first commits and records the `AckReceipt`, while the second receives the already-stored `AckReceipt` without re-importing.
     - *Load Distribution (`ListOutboxForSession` & Soft In-Flight Leases):* When a browser fetches `GET /api/outbox/{id}` to begin transferring a message, `Storage` places a 15-second soft lease (`inFlightUntil`) on that ID and deterministically rotates unclaimed messages per `sessionID`. Other online browsers automatically pick the next unclaimed message first instead of duplicating work, while if a browser tab closes mid-transfer, the 15-second lease expires and another browser picks it up.

### 6.3 Same-Origin Client Compromise (XSS or Malicious Browser Extensions)
- **The Threat:** If Application A or Application B suffers from a Cross-Site Scripting (XSS) vulnerability on its own origin, or if the user installs a malicious browser extension with host permissions on both domains, that code runs with the user's session privileges inside the browser.
- **What Remains Protected vs. Exposed:**
  - *Protected by Server Signing:* Even with full control over the browser DOM, the attacker **cannot** alter a server-signed message from A in transit without Server B rejecting the signature, and **cannot** trick Server A into deleting an outbox message without Server B actually accepting it and signing a receipt.
  - *Exposed to the User's Session:* Because the attacker is running inside the authenticated user's browser session, they can trigger legitimate API actions on behalf of that user (e.g., reading data the user already has permission to view in the UI, or asking Server A to create a new message on behalf of that user). Standard web application defenses (strict CSP, `HttpOnly` cookies, input escaping, and extension allowlisting on managed enterprise devices) apply here as in any web application.

### 6.4 Traffic Analysis & Metadata Visibility in Transit
- Even when Tier 3 ("Blind Courier" asymmetric encryption) is enabled, the browser transport layer (`js/umai.js`) sees the **message IDs**, **number of attachments**, **encrypted byte sizes**, and **timing of transfers**. If message IDs themselves must not leak business semantics, servers should use opaque random or UUID/timestamp identifiers (such as `msg-<timestamp>-<random_hex>` used in `pkg/umaiserver`) rather than embedding sensitive names in the message ID.

---

## 7. Reference Server Hardening (`pkg/umaiserver`)

The reference Go server (`pkg/umaiserver`) enforces the following web security controls out of the box:

1. **CSRF Protection (`Origin` Verification & `Content-Type` Enforcement):**
   - On every state-changing HTTP method (`POST`, `PUT`, `DELETE`, `PATCH`), `securityMiddleware` verifies that the `Origin` header (when present) matches the server's own host/listen address (`403 Forbidden` on mismatch).
   - JSON endpoints (`POST /api/auth/login`, `POST /api/outbox`, `POST /api/outbox/ack`) reject requests whose `Content-Type` is not `application/json` (`415 Unsupported Media Type`).
   - State-changing requests from the reference frontends include the custom `X-UMAI-Session` header, which cannot be sent cross-origin without a CORS preflight.
2. **Protecting Message IDs on Unauthenticated Endpoints:**
   - `GET /api/status` returns aggregate counts (`outbox_count`, `inbox_count`, `accepted_count`) and public keys, but **never exposes `outbox_ids` or `accepted_ids` to unauthenticated callers**, preventing pre-emptive message ID squatting.
3. **Path Traversal, Duplicate Filenames & Resource Caps:**
   - All filenames are sanitized via `filepath.Base(filepath.Clean(name))` and stripped of control characters and traversal sequences (`..`, `/`, `\`).
   - Duplicate attachment filenames within a single message are rejected with `ErrDuplicateAttachment` rather than silently overwriting a file.
   - HTTP request bodies are bounded via `http.MaxBytesReader`, per-file streams are bounded via `io.LimitReader(r, maxUploadSize + 1)`, and messages are capped at `MaxAttachmentsPerMessage = 50`.
   - Incoming messages are staged in `.tmp-{id}-{timestamp}`, `fsync`ed, signature-verified, and atomically renamed into `inbox/{id}`.
