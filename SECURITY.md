# Security Policy and Model — UMAI 0.1

This document outlines the security architecture, trust boundaries, threat model, server-side cryptographic signing, optional end-to-end encryption, and reference server hardening for UMAI (User-Mediated Application Interoperability).

---

## 1. Architectural Boundary: UMAI Protocol vs. Application Backends

UMAI is a **pure browser-to-browser coordination protocol** (`js/umai.js`) operating over `window.postMessage` and `MessageChannel`.

- **The Core Protocol (`js/umai.js`)** ends at the 5-method JavaScript storage adapter (`getOutboxIds`, `getMessage`, `isAccepted`, `acceptMessage`, `onAcknowledged`) inside each application's own frontend context.
- **Zero Cross-Origin HTTP Calls & Zero CORS Required:** UMAI never makes HTTP requests from Application A's frontend to Application B's backend (or vice versa). Each frontend communicates exclusively with its own origin's backend (or local browser storage), while the two frontends exchange data in-memory via a dedicated `MessagePort`.
  - **Relief for Operations & Security Teams:** Neither application server needs to enable Cross-Origin Resource Sharing (`Access-Control-Allow-Origin` or `Access-Control-Allow-Credentials: true`) for the peer domain. Keeping all HTTP endpoints strictly same-origin prevents a compromised peer origin from making direct credentialed API calls to the other application.

---

## 2. Three Layers of Security (Transport, Integrity Signing, and Optional Encryption)

Depending on the trust relationship between the two applications and the mediating user, UMAI supports three progressive security tiers:

| Security Tier | Threat Addressed | Mechanism | Status in Reference Implementation |
|---|---|---|---|
| **Tier 1: Transport & State-Machine Isolation** | Unauthorized websites framing or snooping on messages; out-of-order protocol injection | `frame-ancestors` CSP, `event.origin` + `event.source` pinning, dedicated `MessagePort`, `_inFlightGets` & `_offeredIds` checks | **Built into `js/umai.js` & `pkg/umaiserver`** |
| **Tier 2: End-to-End Authenticity & Non-Repudiation (Signed Envelopes)** | User, browser extension, or DevTools tampering with payloads/files in transit, or forging `ACK`s | Server-side `crypto/ed25519` signatures on `PUT` (`signature`) and signed acceptance receipts on `ACK` (`receipts`) | **Built into `pkg/umaiserver/crypto.go` & supported natively in `PUT`/`ACK` schemas** |
| **Tier 3: End-to-End Confidentiality (Blind Courier Encryption)** | Sensitive backend records that the mediating user's browser or extensions must not be able to read in transit | Server A encrypts payload/attachments with Server B's public key (`X25519` + `AES-256-GCM`); Server B decrypts on ingest | **Architectural option (supported transparently without changing `js/umai.js`)** |

---

## 3. Core Protocol Security Controls (`js/umai.js`)

### 3.1 Strict Origin Allowlisting & Source Pinning
- Every incoming `window.postMessage` event is validated against the configured peer origin (`isAllowedOrigin(event.origin, this.peerOrigin)`).
- Outgoing `postMessage` calls always specify an explicit target origin, never the wildcard `*` for UMAI protocol frames.
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
While `js/umai.js` runs in the browser, the **UMAI `PUT` and `ACK` wire envelopes** carry optional opaque cryptographic fields (`signature` on `PUT`, and `receipts` on `ACK`) so that application servers can verify origin authenticity and byte-level integrity end-to-end **without the browser ever needing cryptographic keys or WebCrypto code**.

### How Server-Side Signing Works (`pkg/umaiserver/crypto.go`)
The reference Go server implements zero-dependency `crypto/ed25519` signing out of the box:

1. **Outbox Signing (Sender Server):**
   - When `CreateOutboxMessage` snapshots a message and its attachments into `outbox/{id}`, the sending server computes a canonical SHA-256 digest:
     ```text
     UMAI-PUT-V1
     <message_id>
     <canonical_payload_json_sha256>
     <att1_sanitized_name>:<att1_size>:<att1_sha256>
     ...
     ```
   - The server signs this digest with its `Ed25519` private key and stores the hex signature in `message.json` (`signature`).
   - `umai.js` passes `signature` along inside the `PUT` envelope as an opaque string.

2. **Inbox Verification & Receipt Generation (Receiver Server):**
   - When `AcceptSignedMessage` receives the multipart `POST /api/inbox`, it stages the uploaded attachments, computes their SHA-256 hashes, reconstructs the canonical `UMAI-PUT-V1` digest, and verifies the sender's `Ed25519` signature against the configured peer public key.
   - If the payload or any attachment was modified in the browser (or forged by a script), signature verification fails, the staging directory is purged, and no `ACK` is sent.
   - Upon valid verification and atomic commit, the receiving server signs a cryptographic acceptance receipt:
     ```text
     UMAI-ACK-V1
     <message_id>
     <original_message_signature_hex>
     ```
   - This `ack_receipt` is persisted in `inbox/{id}/message.json` (so it can also be re-sent on Rule 5 repeated `ACK`s via `/api/accepted/receipts`) and returned to the browser.

3. **Verified Outbox Cleanup (Sender Server):**
   - `umai.js` carries `receipts: { [id]: ack_receipt }` inside the `ACK` envelope.
   - In `AcknowledgeMessagesVerified`, the sending server verifies the receiver's `Ed25519` signature over `UMAI-ACK-V1` before deleting the message from `outbox/`.
   - **Security Guarantee:** An outbox message is only deleted when the genuine peer server cryptographically proves it accepted the exact original bytes.

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
   - Once committed, Application B's UI displays the decrypted message as normal.

---

## 6. Reference Server Hardening (`pkg/umaiserver`)

The reference Go server (`pkg/umaiserver`) enforces the following web security controls:

### 6.1 CSRF Protection (`Origin` Verification & `Content-Type` Enforcement)
- **Same-Origin `Origin` Check:** On every state-changing HTTP method (`POST`, `PUT`, `DELETE`, `PATCH`), `securityMiddleware` verifies that the `Origin` header (when present) matches the server's own host/listen address (`403 Forbidden` on mismatch).
- **Strict `Content-Type: application/json`:** JSON endpoints (`POST /api/auth/login`, `POST /api/outbox`, `POST /api/outbox/ack`) reject requests whose `Content-Type` is not `application/json` (`415 Unsupported Media Type`), preventing simple HTML `<form>` or `text/plain` cross-site submissions.
- **Explicit Session Header (`X-UMAI-Session`):** State-changing requests from the reference frontends include the custom `X-UMAI-Session` header, which cannot be sent cross-origin without a CORS preflight.

### 6.2 Protecting Message IDs on Unauthenticated Endpoints
- `GET /api/status` returns aggregate counts (`outbox_count`, `inbox_count`, `accepted_count`) and public keys, but **never exposes `outbox_ids` or `accepted_ids` to unauthenticated callers**. This prevents pre-emptive message ID squatting.

### 6.3 Path Traversal, Duplicate Filenames & Resource Caps
- **Path Sanitization:** All filenames are sanitized via `filepath.Base(filepath.Clean(name))` and stripped of control characters and traversal sequences (`..`, `/`, `\`).
- **Duplicate Attachment Rejection:** If a single message contains two attachments that sanitize to the same filename, creation/acceptance is rejected with `ErrDuplicateAttachment` rather than silently overwriting a file.
- **Request & Attachment Caps:** HTTP request bodies are bounded via `http.MaxBytesReader`, per-file streams are bounded via `io.LimitReader(r, maxUploadSize + 1)`, and messages are capped at `MaxAttachmentsPerMessage = 50`.
- **All-or-Nothing Atomic Staging:** Incoming messages are written to `.tmp-{id}-{timestamp}`, `fsync`ed, signature-verified, and atomically renamed into `inbox/{id}`.

---

## 7. Known Limitations (0.1 Release)

1. **Experimental Reference Implementation:** UMAI 0.1 is an open-source reference architecture and proof of concept.
2. **Transfer Progress Granularity:** Native `postMessage` transfer of large `File` objects via Structured Clone does not expose fine-grained byte-level progress events in current browser engines.
3. **Chunking & Partial Resumes:** Transfers that are cancelled or cut short restart from byte zero on the next session.
