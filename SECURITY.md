# Security Policy and Model — UMAI 0.1

This document provides a rigorous, transparent analysis of the **UMAI (User-Mediated Application Interoperability)** security model. It is structured from **architectural principles and residual risks at the top** down to a **detailed production implementer's hardening checklist at the end**:

1. **Separation of Security Concerns & Codebase Reuse Boundary** (what UMAI solves in principle vs. application security, and what lives in verbatim reusable `js/umai.js` vs. example code).
2. **Three Progressive Security Tiers** (transport isolation, signed envelopes/receipts, and optional "Blind Courier" encryption).
3. **Inherent Limits & Residual Risks of the User-Mediated Principle** (what neither the browser protocol nor server cryptography can solve on its own).
4. **Guarantees Enforced Verbatim by `js/umai.js`** (what adopters get automatically by reusing the browser engine as-is).
5. **Server-Side Cryptographic Signing & Optional Encryption** (how `signature` and `receipts` protect authenticity across the untrusted browser bridge).
6. **Production Implementer's Hardening Checklist ("All the Bells & Whistles")** (every subtle HTTP, CSP, cookie, CSRF, canonicalization, and storage safeguard demonstrated in `pkg/umaiserver` that real-world implementers should replicate—clearly separated from demo-only fixtures).

---

## 1. Separation of Security Concerns & Codebase Reuse Boundary

### 1.1 Three Distinct Security Planes
When evaluating UMAI, three orthogonal planes must never be conflated:

| Plane | Responsibility | Scope |
|---|---|---|
| **Plane A: Individual Application Security** | How Application A or B authenticates its human users (MFA, OIDC/SAML, WebAuthn/Passkeys, session lifetimes), enforces internal RBAC, and secures its database at rest. | **Out of Scope for UMAI.** Each application retains its existing enterprise IAM. |
| **Plane B: Browser-Mediated Transport** | Moving `OFFER`, `GET`, `PUT`, and `ACK` frames between two cross-origin browser contexts without any backend-to-backend network path or cross-origin HTTP API exposure. | **Core UMAI Protocol (`SPEC.md` & `js/umai.js`).** |
| **Plane C: End-to-End Authenticity & Confidentiality** | Ensuring that the mediating browser (or a rogue browser extension) cannot tamper with messages in transit, forge messages, trigger premature outbox deletion, or (optionally) read sensitive payloads. | **Implementer Backend Policy**, supported natively in the UMAI wire envelopes (`signature` on `PUT`, `receipts` on `ACK`) and demonstrated in `pkg/umaiserver/crypto.go`. |

### 1.2 Verbatim Reusable Code vs. Reference Example Code
Because real-world teams integrate UMAI into existing backends (Java, C#, Go, Python, Node, etc.), this repository strictly separates **verbatim reusable protocol code** from **reference backend/UI examples**:

| Repository Component | Reuse Model | Security Controls Contained Here |
|---|---|---|
| **`js/umai.js`** *(+ `SPEC.md`)* | **Reusable Verbatim in Production.** Zero-dependency browser protocol engine that any web application can drop in directly. | `http:`/`https:` origin validation, `event.source` window pinning, dedicated `MessagePort` lifecycle, receiver-controlled state machine (`_offeredIds`, `_inFlightGets`), `_putQueue` deduplication, batch/ID bounds, and prototype-safe receipt maps. |
| **`pkg/umaiserver/*` & `examples/*`** | **Reference Blueprint (Implementer-Owned in Production).** Demonstrates best-practice server and UI integration around the 5-method `storage` adapter. | HTTP CSP headers (`frame-ancestors`, `frame-src`, `script-src 'self'`), CHIPS `Partitioned` cookies, attachment download sandboxing, `Origin` + custom header CSRF protection, `Ed25519` signing & `ACK` receipt verification, atomic `.tmp` staging, and soft in-flight leases. *(Also includes clearly marked local demo fixtures like `admin`/`umai123` auth and deterministic demo keys.)* |

### 1.3 Zero Cross-Origin HTTP Calls & Zero CORS Required
UMAI **never** makes HTTP requests from Application A's frontend to Application B's backend (or vice versa). Each frontend communicates exclusively with its own origin's HTTP API, while the two frontends exchange data in-memory via a dedicated browser `MessagePort`.
- **Why this matters:** Neither server needs Cross-Origin Resource Sharing (`Access-Control-Allow-Origin` or `Access-Control-Allow-Credentials: true`) for the peer domain (`connect-src 'self'`). Keeping all HTTP endpoints strictly same-origin eliminates an entire class of cross-origin API and credential exposure bugs.

---

## 2. Three Progressive Security Tiers

Depending on the trust model between the two applications and the mediating user, UMAI supports three progressive security tiers:

| Security Tier | Threat Addressed | Mechanism | Where Implemented in Repo |
|---|---|---|---|
| **Tier 1: Transport & State-Machine Isolation** | Unauthorized websites framing or snooping on messages; out-of-order or unsolicited protocol frames | Origin + `event.source` pinning, private `MessagePort`, `_offeredIds` & `_inFlightGets` enforcement (`js/umai.js`) + `frame-ancestors` / `frame-src` CSP (`pkg/umaiserver`) | **Verbatim in `js/umai.js`** + HTTP headers in `pkg/umaiserver` |
| **Tier 2: End-to-End Authenticity & Non-Repudiation (Signed Envelopes)** | User, DevTools, or browser extension tampering with payloads/files in transit, stripping signatures, reflecting messages, or forging `ACK`s | Opaque `signature` (`PUT`) and `receipts` (`ACK`) envelope fields carried by `js/umai.js`; verified server-side via `crypto/ed25519` with directional role binding | **Envelope support verbatim in `js/umai.js`** + signing engine in `pkg/umaiserver/crypto.go` |
| **Tier 3: End-to-End Confidentiality ("Blind Courier" Encryption)** | Sensitive backend records that the mediating user's browser or extensions must not be able to read in transit | Sender server encrypts payload/attachments to receiver server's public key (`X25519` + `AES-256-GCM`); receiver decrypts on ingest | **Architectural option** (works transparently with `js/umai.js` unchanged) |

---

## 3. Inherent Limits & Residual Risks of the User-Mediated Principle

A trustworthy security review must state plainly what the **UMAI principle** cannot solve on its own, and what residual risks remain even when server-side signing and encryption are enabled:

### 3.1 Safety vs. Liveness (Selective Suppression / Denial of Service by the Mediator)
- **What UMAI Guarantees (Safety):** Neither a network drop, a browser crash, nor a malicious browser extension can cause silent data corruption, partial message acceptance (Rule 3), duplicate import (Rule 4), forged message acceptance, or premature outbox deletion without peer acceptance (Rule 6 + signed receipts).
- **What UMAI Cannot Guarantee (Liveness against an Uncooperative Mediator):** Because UMAI is intentionally *user-mediated* (Rule 8: no background delivery without an active session), the mediating browser controls transport execution. A user or client-side extension can close the tab, block the iframe, or selectively drop `OFFER`/`GET`/`PUT`/`ACK` frames.
  - *Impact:* Selective suppression is strictly an **availability (liveness) delay**, never an integrity failure or data loss. Unacknowledged messages remain safely in the sender's outbox until a healthy session completes reconciliation.

### 3.2 Multi-User Topologies: User-Scoped ("Courier Swap") vs. System-Wide Opportunistic Pool
Depending on the deployment's goals, a UMAI channel operates in one of two topologies:

1. **Mode 1 — User-Scoped Channel ("My Data Only") & The "Courier Swap" Risk:**
   - **The Threat:** Server-level `Ed25519` signing proves to Server B that a message originated from *Server A*. However, in a multi-user or multi-tenant deployment, a user could log into Application A as `Alice (Tenant 1)` and into Application B as `Bob (Tenant 2)`—or extract a signed message from one account on A and deliver it while logged into a different account on B.
   - **Required Production Mitigation:** Servers operating in user-scoped mode MUST include the intended recipient/tenant identity inside the signed `payload` (e.g., `"sender_user": "alice@corp.example"`, `"recipient_tenant": "tenant-1"`), and Server B MUST verify that the authenticated session receiving `POST /api/inbox` is authorized for that recipient/tenant before committing.
2. **Mode 2 — System-Wide Opportunistic Pool ("Crowdsourced System Bridge"):**
   - **The Pattern:** Organizations can intentionally allow *any* authenticated user's open UMAI channel to ferry pending messages between System A and System B (e.g., 10 concurrent users act as a shared multi-lane bridge).
   - **Required Production Mitigation:** Combine **Tier 2 (`Ed25519` signing)** with **Tier 3 ("Blind Courier" asymmetric encryption)** so User #4's browser can transport a message created by User #1 without reading or altering its contents, and ensure server inbox/outbox handlers tolerate concurrent duplicate uploads safely (see Section 6.4).

### 3.3 Same-Origin Client Compromise (XSS or Malicious Browser Extensions)
- **The Threat:** If Application A or Application B suffers from a same-origin XSS vulnerability, or if the user installs a malicious browser extension with host permissions on those domains, attacker code executes inside the user's authenticated browser session.
- **What Remains Protected vs. Exposed:**
  - *Protected by Tier 2 Signing:* Even with full DOM access, attacker JS **cannot** modify a server-signed message in flight without the peer server rejecting the signature, and **cannot** trick the sender server into deleting a signed outbox message without a genuine peer-signed `ACK` receipt.
  - *Exposed to the User's Session:* As in any web application, code running inside an authenticated session can invoke same-origin API actions that the logged-in user is permitted to perform. Standard web defenses (strict CSP without `'unsafe-inline'`, `HttpOnly` cookies, output escaping, and enterprise extension policies) remain essential.

### 3.4 Traffic Analysis & Metadata Visibility in Transit
- Even when Tier 3 ("Blind Courier" encryption) is enabled, `js/umai.js` observes **message IDs**, **attachment counts**, **encrypted byte sizes**, and **transfer timing**. Message IDs should therefore always be opaque random/timestamp identifiers (e.g., `msg-<timestamp>-<random_hex>`) rather than strings containing confidential business names.

---

## 4. Guarantees Enforced Verbatim by `js/umai.js`

Every adopter who includes `js/umai.js` verbatim receives the following browser-side protocol and memory protections automatically:

1. **Strict `http:`/`https:` Origin Validation & Window Source Pinning (`isAllowedOrigin`, `_handleWindowMessage`):**
   - Rejects non-HTTP(S) schemes (`javascript:`, `data:`, `file:`, `null`) and validates exact origin matching (`scheme://host:port`) against the configured `peerOrigin`.
   - Outgoing handshake `postMessage` calls always pass the explicit `peerOrigin` target—never the wildcard `'*'`.
   - During the handshake, the host verifies `event.source === iframe.contentWindow` before accepting `READY`, and the embedded peer verifies `event.source === window.parent` before accepting `INIT`, preventing sibling tabs or unrelated frames from hijacking the channel.
2. **Isolated `MessagePort` Transport & Clean Re-Handshake Lifecycle:**
   - All `OFFER`, `GET`, `PUT`, and `ACK` frames travel exclusively over a dedicated `MessageChannel` (`MessagePort`), never over the global `window` bus.
   - If the embedded peer reloads or re-authenticates and sends a fresh `READY`, any previous `MessagePort` is explicitly closed (`port.close()`) before opening a new channel.
3. **Strict Offer-Before-GET, Offer-Before-ACK & Pull-Before-PUT State Machine:**
   - **Unsolicited `PUT` Rejection (`_inFlightGets`):** A receiver tracks requested IDs in `_inFlightGets`. Any incoming `PUT` not preceded by an outgoing `GET` for that ID is immediately dropped.
   - **Unoffered `GET` & `ACK` Rejection (`_offeredIds`):** A sender records offered IDs in `_offeredIds` exclusively during `reconcile()` (`OFFER`). Incoming `GET` requests for unoffered IDs are ignored (preventing peers from probing unoffered records or poisoning `_offeredIds`), and incoming `ACK`s are filtered strictly to offered IDs.
   - **Serialized Queue, `GET` Deduplication & Poison-Pill Backoff (`_queuePut`, `_failedAttempts`):** Duplicate `GET` requests for an already-queued ID are ignored, outgoing `PUT` frames are transmitted one at a time per direction to bound browser memory usage, and any incoming message that fails `acceptMessage` `MAX_AUTO_RETRIES = 3` times in a row backs off from automatic background `GET` retries during that session (resetting on manual `reconcile(true)`).
4. **Envelope Bounds, Payload Normalization & Prototype-Safe Receipt Maps:**
   - Message IDs are validated (`isValidMessageId`: non-empty string `<= 128` chars) and batch arrays in `OFFER`, `GET`, and `ACK` are capped at `MAX_BATCH_IDS = 1000`.
   - `null`/`undefined` payloads are normalized to `{}` while preserving valid falsy JSON primitives (`false`, `0`, `""`).
   - All `receipts` maps are constructed with `Object.create(null)` and `Object.prototype.hasOwnProperty.call`, preventing `__proto__` or `constructor` prototype-pollution attacks over `MessagePort`.

---

## 5. Server-Side Cryptographic Signing & Optional Encryption

### 5.1 End-to-End Signing Architecture (`PUT` Signatures & `ACK` Receipts)
Because the user's browser sits in the middle of the `MessagePort`, UMAI's `PUT` and `ACK` wire schemas include first-class opaque fields (`signature` on `PUT` and `receipts` on `ACK`). `js/umai.js` ferries these strings untouched so backend servers can verify authenticity and byte-level integrity end-to-end **without exposing private keys to the browser**.

In the reference implementation (`pkg/umaiserver/crypto.go`), zero-dependency `crypto/ed25519` signing enforces three end-to-end steps:

1. **Outbox Signing (`UMAI-PUT-V1`):**
   - On `CreateOutboxMessage`, the sender server snapshots the payload and attachments and signs an unambiguous, length-prefixed canonical SHA-256 digest binding its `sender_role`, the intended `receiver_role`, `message_id`, canonical JSON payload hash, attachment count, and each sorted attachment's `(name_len, sanitized_name, byte_size, sha256)`:
     ```text
     UMAI-PUT-V1
     sender:<len>:<sender_role>
     receiver:<len>:<receiver_role>
     id:<len>:<message_id>
     payload:<canonical_payload_json_sha256>
     att_count:<count>
     att:<name_len>:<att1_sanitized_name>:<att1_size>:<att1_sha256>
     ...
     ```
2. **Mandatory Inbox Verification & Receipt Signing (`UMAI-ACK-V1`):**
   - On `POST /api/inbox`, `AcceptSignedMessage` verifies the signature against the peer's public key and expected `sender_role` and `receiver_role`. Any tampered byte, wrong sender or receiver role, or stripped signature is rejected (`ErrInvalidSignature`) and purged from staging before commit.
   - Upon atomic commit, the receiver server signs a length-prefixed acceptance receipt binding its own `receiver_role`, the `message_id`, and the original `message_signature_hex`:
     ```text
     UMAI-ACK-V1
     role:<len>:<receiver_role>
     id:<len>:<message_id>
     sig:<len>:<original_message_signature_hex>
     ```
   - This `ack_receipt` is stored durably alongside the inbox message (so Rule 5 repeated `ACK`s also include it) and returned to `js/umai.js`.
3. **Mandatory Receipt Verification Before Outbox Cleanup:**
   - On `POST /api/outbox/ack`, `AcknowledgeMessagesVerified` verifies the peer's `Ed25519` receipt before deleting any signed outbox message. An outbox record is never deleted unless the genuine peer server cryptographically proves it accepted the exact original bytes.

### 5.2 Optional Extension: Asymmetric Encryption ("Blind Courier" Mode)
When mediating browsers or extensions must not read sensitive payloads or attachments in transit, **asymmetric encryption** layers cleanly on top of server signing **without modifying `js/umai.js`**:
1. **Key Exchange:** Server A holds Server B's public encryption key (`X25519`), and vice versa.
2. **Sign-First (with Named Receiver), Then Encrypt on Outbox Snapshot:**
   - Server A first signs the plaintext canonical digest (`UMAI-PUT-V1`, which explicitly binds both `sender` A and intended `receiver` B) with Server A's `Ed25519` private key.
   - Server A then generates an ephemeral `X25519` key pair, derives a symmetric key with Server B's public key via `HKDF-SHA256`, and encrypts the signed message and attachment files using `AES-256-GCM` (or `ChaCha20-Poly1305`).
   - *Why Sign-First with Named Receiver Matters:* If a message were encrypted without naming the receiver inside the signed part (or signed only on the outer ciphertext), a recipient B in a multi-server mesh could decrypt A's message and re-encrypt it to a third party C with A's signature still intact (*surreptitious forwarding*). Signing first with `receiver` bound inside `UMAI-PUT-V1` and then encrypting to that receiver closes this completely.
3. **Blind Transit & Decrypt-then-Verify on Ingest:** `js/umai.js` transports the opaque ciphertext blobs via `PUT`; Server B decrypts inside its temporary staging directory using its `X25519` private key and verifies Server A's `Ed25519` signature (confirming both `sender: A` and `receiver: B`) prior to atomic commit.

---

## 6. Production Implementer's Hardening Checklist ("All the Bells & Whistles")

While **`js/umai.js` can be reused verbatim**, every production team writes or configures its own **HTTP headers, session cookies, CSRF middleware, storage adapter, and (optional) server-side signing**.

In our reference codebase (`pkg/umaiserver` and `examples/*`), we pulled a number of subtle security strings to harden these integration boundaries. **Real-world implementers should treat Sections 6.1–6.4 as a concrete security watchlist for their own backends**, while replacing the local demo fixtures listed in Section 6.5.

### 6.1 Browser Framing, CSP, Cookies & UI Messaging Watchlist
- **Explicit CSP Frame Pinning (and Removing Conflicting `X-Frame-Options`):**
  - *Embedded App A:* Emit `Content-Security-Policy: frame-ancestors 'self' https://app-b.example.com;` on the embedded sync route, and ensure reverse proxies do **not** emit `X-Frame-Options: DENY` or `SAMEORIGIN` on that route (which would block cross-origin framing).
  - *Host App B:* Emit `Content-Security-Policy: frame-ancestors 'none'; frame-src 'self' https://app-a.example.com;` so only the expected peer origin can be framed.
- **Strict `script-src 'self'` Without `'unsafe-inline'`:**
  - Keep all initialization and adapter glue in external `.js` files and serve `script-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'` together with `Referrer-Policy: no-referrer`.
- **Cross-Origin Iframe Session Cookies (CHIPS / `Partitioned`) & No `localStorage` Tokens:**
  - Store session identifiers strictly in `HttpOnly` cookies (never in `localStorage` or `sessionStorage`, where XSS could exfiltrate a long-lived bearer token).
  - Because Embedded App A runs inside Host App B's cross-origin `<iframe>`, modern browsers treat App A's session cookie as third-party. Over HTTPS, issue the embedded session cookie with:
    `Set-Cookie: session=...; Path=/; Secure; HttpOnly; SameSite=None; Partitioned`
  - Only trust `X-Forwarded-Proto: https` when the HTTP connection arrives from a trusted local reverse proxy (loopback).
- **Sandboxing All Attachment & Document Download Endpoints:**
  - Peers may exchange `.html`, `.svg`, or `.xml` files as message attachments. Every attachment/document download response MUST emit:
    - `Content-Disposition: attachment; filename="..."`
    - `Content-Security-Policy: default-src 'none'; sandbox`
    - `X-Content-Type-Options: nosniff`
  - Without these headers, navigating directly to a downloaded `.html` or `.svg` attachment URL could execute stored XSS inside the receiving application's origin.
- **Origin-Pinned Custom UI `postMessage` Calls (Outside `umai.js`):**
  - `js/umai.js` already pins `peerOrigin` and `event.source` for all UMAI frames. If your UI sends any *additional* helper messages between the iframe and host window (such as login/logout tray notifications or height adjustments, as in `examples/app-a/static/sync.js` and `examples/app-b/static/minimal.js`), NEVER call `postMessage(msg, '*')`—always pass the explicit `peerOrigin` and check `event.origin` and `event.source` on receipt.

### 6.2 HTTP API & CSRF Hardening Watchlist (Including the `Sec-Fetch-Site` Gotcha)
- **Zero CORS Headers:** Do not add `Access-Control-Allow-Origin` for the peer application's domain.
- **The W3C `Sec-Fetch-Site: cross-site` Cross-Origin Iframe Gotcha:**
  - *Trap to watch out for:* Per the W3C Fetch Metadata specification, when Embedded App A (`https://app-a.example`) runs inside Host App B's cross-origin `<iframe>` (`https://app-b.example`) and calls its **own** backend (`fetch('https://app-a.example/api/inbox')`), the browser sends `Origin: https://app-a.example` **but sets `Sec-Fetch-Site: cross-site`** because the top-level ancestor frame is cross-site!
  - *Correct CSRF Pattern (implemented in `pkg/umaiserver/server.go`):* Do **not** blindly block `Sec-Fetch-Site: cross-site` on the embedded app's API (which would break embedded `SameSite=None; Partitioned` cookie requests). Instead:
    1. On every state-changing method (`POST`, `PUT`, `DELETE`, `PATCH`), verify that the `Origin` header—when present—strictly matches your server's own origin (`403 Forbidden` otherwise).
    2. If `Origin` is omitted/stripped on a cookie-authenticated request, require an explicit custom header (e.g., `X-UMAI-CSRF: 1` or `Authorization`), which cross-site HTML `<form enctype="multipart/form-data">` CSRF attacks cannot set without triggering a blocked CORS preflight.
    3. Enforce `Content-Type: application/json` (`415 Unsupported Media Type` otherwise) on all JSON endpoints (`/api/outbox`, `/api/outbox/ack`, etc.).
- **Unauthenticated Endpoint Hygiene (Preventing ID Squatting):**
  - Public health or status endpoints (`GET /api/status`) must **never** expose pending `outbox_ids` or `accepted_ids` to unauthenticated callers; otherwise an unauthenticated observer could learn pending IDs and attempt pre-emptive ID squatting.

### 6.3 Server-Side Signing & Canonicalization Watchlist (When Implementing Tier 2)
- **Fail-Closed Signature & Receipt Verification (No Downgrades):**
  - When a peer public key is configured, `POST /api/inbox` MUST reject empty/missing `signature` strings (`ErrInvalidSignature`), and `POST /api/outbox/ack` (`AcknowledgeMessagesVerified`) MUST fail closed—rejecting missing `receipts[id]` entries, empty `receipts: {}` maps, or unreadable/corrupt/unsigned outbox metadata (`ErrInvalidReceipt` / `ErrInvalidSignature`) without deleting the outbox directory.
- **Crash-Safe Staging & Startup Reconciliation (`inbox/` $\leftrightarrow$ `accepted.json`):**
  - Stream incoming multipart attachments into a unique temporary staging directory (e.g., `.tmp-{id}-{nanoseconds}`), bound per-file bytes (`io.LimitReader(r, maxUploadSize + 1)`), bound attachment count (`MaxAttachmentsPerMessage`), `fsync`, verify the cryptographic signature, atomically rename into `inbox/{id}`, and commit the ID to durable `acceptedIDs`. On server startup (`NewStorage`), purge any leftover `.tmp-*` staging directories and automatically reconcile committed `inbox/{id}/message.json` directories into `acceptedIDs` so a crash or power loss between directory rename and `accepted.json` persistence self-heals without split-brain state.
- **Verify Signature Match on Duplicate `POST /api/inbox` Probes:**
  - When `POST /api/inbox` receives an ID that is already in `acceptedIDs` (e.g., due to a lost `ACK` or concurrent pooled upload), verify that the incoming `signature` matches the stored message's `signature` before returning the cached `ack_receipt`.
- **Injective Length-Prefixed Canonical Digests & Attachment Counts:**
  - Never concatenate variable-length strings with bare delimiters alone (e.g., `name:size:hash`), as filenames containing `:` could cause canonicalization collisions. Length-prefix every variable-length string (`role:<len>:...`, `id:<len>:...`, `att:<name_len>:<name>:<size>:<sha256>`), include `att_count:<n>`, and sort attachments deterministically by sanitized name.
- **Directional Sender & Receiver Role Binding (`sender_role` & `receiver_role`):**
  - Bind both the sender's and the intended receiver's logical role/origin (`sender:<len>:...` and `receiver:<len>:...`) into `UMAI-PUT-V1` and the receiver's role into `UMAI-ACK-V1` so a peer or courier cannot reflect a signed message backwards or misdirect a message signed for Peer B to Peer C.
- **Empty/Null Payload Canonicalization Equivalence (`nil` -> `{}`):**
  - Normalize `nil` / `null` payloads to `{}` on both outbox signing and inbox verification so JSON serialization across Go/backend maps and browser Structured Clone produces identical digests.

### 6.4 Atomic Storage, File Hygiene & Pooled-Channel Concurrency Watchlist
- **Reject Duplicate Sanitized Attachment Filenames:**
  - Sanitize every filename (`filepath.Base`, strip `..`, `/`, `\`, null bytes, and control chars `< 32`), and **reject duplicate sanitized filenames within a single message** (`ErrDuplicateAttachment`) rather than letting a second attachment silently overwrite the first on disk while both appear in metadata.
- **Symlink Rejection & Restrictive File Modes:**
  - When snapshotting local files or serving attachments from disk, check `os.Lstat` and require `fi.Mode().IsRegular()` so symbolic links are never followed; create storage directories with `0700` and files with `0600`.
- **Soft In-Flight Leases for Multi-User Pooled Channels (Bandwidth Optimization):**
  - If multiple concurrent users share a system-wide outbox pool (`ListOutboxForSession`), place a short soft priority lease (e.g., `15s` `inFlightUntil` when `GET /api/outbox/{id}` is called) and deterministically rotate unclaimed IDs by session hash. Rather than acting as a hard exclusion lock, this bandwidth-optimization hint steers concurrent browsers toward different unclaimed messages first while relying on receiver deduplication (Rules 4 & 5) for correctness.
- **HTTP Server Timeouts:**
  - Configure explicit `ReadHeaderTimeout`, `ReadTimeout`, `WriteTimeout`, `IdleTimeout`, and `MaxHeaderBytes` on the HTTP server or reverse proxy to prevent Slowloris socket exhaustion.

### 6.5 Demo-Only Safeguards in `pkg/umaiserver` (Replace in Production)
To keep this repository self-contained and runnable with zero external infrastructure, `pkg/umaiserver` includes several hardened local fixtures that **are specific to the demo server and should be replaced by enterprise infrastructure in production**:
- **Loopback-Only Demo Defaults (`AllowDemoDefaults` / `-demo`):** Deterministic role demo keys (`DeriveDemoKeyPair`) and the default `admin` / `umai123` password are automatically permitted **only when listening on a loopback address (`127.0.0.1`, `localhost`, `[::1]`)**. Binding to a non-loopback network interface refuses to start unless `UMAI_SIGNING_PRIVATE_KEY`, `UMAI_PEER_PUBLIC_KEY`, and a non-default password are set (or `-demo` is explicitly passed).
- **Static Demo Login (`AuthManager`):** Issues scoped `HttpOnly` cookies (`umai_session_a` / `umai_session_b`, with zero bearer tokens in `localStorage`), uses constant-time SHA-256 credential comparison (`crypto/subtle.ConstantTimeCompare`), and caps active sessions (`MaxActiveSessions = 10000`). *Production apps replace this completely with their own OIDC/SAML/WebAuthn/MFA session middleware.*
