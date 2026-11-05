# Security Policy and Model — UMAI 0.1

This document outlines the security architecture, trust boundaries, threat model, reference server considerations, and roadmap for UMAI (User-Mediated Application Interoperability).

---

## 1. Architectural Boundary: UMAI Protocol vs. Application Backends

UMAI is a **pure browser-to-browser coordination protocol** (`js/umai.js`) operating over `window.postMessage` and `MessageChannel`.

- **The Core Protocol (`js/umai.js`)** ends at the 5-method JavaScript storage adapter (`getOutboxIds`, `getMessage`, `isAccepted`, `acceptMessage`, `onAcknowledged`) inside each application's own frontend context.
- **No Cross-Origin HTTP Calls:** UMAI never makes HTTP requests from Application A's frontend to Application B's backend (or vice versa). Each frontend communicates exclusively with its own origin's backend (or local browser storage), while the two frontends exchange data in-memory via a dedicated `MessagePort`.
- **The Reference Demo Servers (`pkg/umaiserver`)** are simplified, self-contained teaching implementations provided to demonstrate the protocol on a single machine or dual-VPS testbed. Production applications integrating UMAI use their own existing authentication, CSRF protection, and session management.

---

## 2. Threat Model & Trust Assumptions

### 2.1 Core Trust Assumptions (v0.1 Transport Model)
- **The User's Browser is the Trusted Mediator:** In UMAI 0.1, the user's browser execution environment (and the user operating it) is the trusted bridge connecting two isolated applications.
- **Transport-Layer vs. Origin-Cryptographic Trust:** In v0.1, UMAI guarantees that the browser only accepts `postMessage` frames from the configured `peerOrigin`. Because the receiving backend accepts the ingested message from its own authenticated frontend session, a user who deliberately tampers with their own browser DevTools (or installs a malicious browser extension) could alter a message in transit before it is posted to the receiving backend.
  - *When the user is trusted* (e.g., a user synchronizing their own files between two tools they control), transport-level origin isolation is sufficient.
  - *When the user is an untrusted courier* between two institutional systems that require non-repudiation (so the user cannot modify a document in flight), **End-to-End Object Signing** (see Section 6) should be layered onto the message payload.
- **Mutual Pre-Configuration:** Both applications must agree on each other's canonical origin (`https://app-a.example.ch` and `https://app-b.example.net`).
- **No Shared Secrets Over UMAI:** Passwords, API tokens, and session cookies are never transmitted over UMAI protocol messages.

---

## 3. Core Protocol Security Controls (`js/umai.js`)

### 3.1 Strict Origin Allowlisting & Source Verification
- Every incoming `window.postMessage` event is validated against the configured peer origin (`isAllowedOrigin(event.origin, this.peerOrigin)`).
- Outgoing `postMessage` calls always specify an explicit target origin, never the wildcard `*` for UMAI protocol frames.
- **Handshake Source Pinning:** In host mode, `READY` frames should additionally verify `event.source === iframe.contentWindow`; in embedded mode, `INIT` frames should verify `event.source === window.parent`.

### 3.2 Dedicated `MessagePort` Isolation & Lifecycle
- After the initial handshake over `window.postMessage`, all `OFFER`, `GET`, `PUT`, and `ACK` frames travel exclusively over an isolated `MessageChannel` (`MessagePort`).
- If an embedded peer reloads or re-authenticates and emits a new `READY` signal, any previous `MessagePort` is explicitly closed (`port.close()`) before establishing a new channel.

### 3.3 Receiver-Controlled State Machine Enforcement
- **Unsolicited `PUT` Rejection:** Under Rule 2 (Receiver-Controlled Transfer), a receiver only requests unaccepted messages via `GET` (tracked in `_inFlightGets`). Any unsolicited `PUT` whose message ID was not requested by a preceding `GET` must be dropped.
- **Offered `ACK` Validation:** Under Rule 6, a sender should only process `ACK` identifiers that correspond to messages actually present in its outbox / offered set.

### 3.4 Content Security Policy (CSP) & Embedding Control
To prevent clickjacking and unauthorized framing:
- **Application A (Embedded):** Enforces `Content-Security-Policy: frame-ancestors 'self' <PeerOrigin>`. Any unauthorized origin attempting to embed Application A is blocked by the browser engine.
- **Application B (Host):** Enforces `Content-Security-Policy: frame-ancestors 'none'; frame-src 'self' <PeerOrigin>`.

---

## 4. Reference Server Security & Hardening (`pkg/umaiserver`)

When deploying the reference Go server (`pkg/umaiserver`) or designing an application backend to support a UMAI frontend, the following web security controls apply:

### 4.1 Cross-Site Request Forgery (CSRF) & `SameSite` Cookies
- **Why CSRF Matters:** If an application uses `SameSite=None; Secure` cookies (to allow cookie delivery inside a cross-site iframe), the browser will attach that cookie to cross-site `POST` requests (such as HTML `<form enctype="multipart/form-data">` submissions to `/api/inbox` or `text/plain` `fetch` requests to `/api/outbox/ack`).
- **Required Server Controls:**
  1. **Strict `Origin` Header Check on State-Changing Routes:** Every `POST`, `PUT`, `DELETE`, or `PATCH` handler must verify that the HTTP `Origin` header exactly matches the server's own origin (since UMAI frontends only ever call their own backend).
  2. **Strict `Content-Type` Enforcement:** JSON endpoints (`/api/outbox`, `/api/outbox/ack`) must require `Content-Type: application/json`, which forces a CORS preflight on cross-origin requests and blocks simple HTML form submissions.
  3. **Custom Header Requirement (`X-UMAI-Session` / `X-Requested-With`):** Requiring a custom header on state-changing API calls guarantees that simple cross-site requests cannot succeed without a CORS preflight.

### 4.2 No Cross-Origin CORS Required
- Because Application A's frontend only calls Application A's backend, and Application B's frontend only calls Application B's backend, **neither backend needs `Access-Control-Allow-Origin` or `Access-Control-Allow-Credentials: true` for the peer origin**.
- Keeping all API routes strictly same-origin prevents the peer origin (if compromised) from making direct credentialed `fetch()` calls against the other application's HTTP API.

### 4.3 Protecting Message IDs & Preventing Pre-Emptive ID Squatting
- Acceptance in UMAI is idempotent and first-writer-wins per message ID (`Rule 5`).
- If an unauthenticated endpoint (such as `GET /api/status`) exposes pending `outbox_ids` or `accepted_ids`, an attacker who can also trigger a forged `POST /api/inbox` could pre-register a fake message under a real pending `msg-id`. When the legitimate message is later offered, Rule 5 would issue a repeated `ACK` and cause the sender to delete the real message from its outbox.
- **Mitigation:** Public status endpoints must never return `outbox_ids` or `accepted_ids` to unauthenticated callers (return boolean health status or aggregate counts only).

### 4.4 Path Traversal, Filename Collisions & Resource Caps
- **Path Sanitization:** All filenames are sanitized via `filepath.Base(filepath.Clean(name))` and stripped of control characters and traversal sequences (`..`, `/`, `\`).
- **Duplicate Attachment Names:** If a single message contains two attachments that sanitize to the same base filename, the server must reject the message rather than silently overwriting the first attachment.
- **Total Request Size & Attachment Count Caps:** In addition to per-file `io.LimitReader` enforcement (`-max-upload`), servers should wrap the entire HTTP request body in `http.MaxBytesReader` and cap the maximum number of attachments per message to prevent disk/memory exhaustion.
- **All-or-Nothing Atomic Staging:** Incoming messages are written to `.tmp-{id}-{timestamp}`, `fsync`ed, and atomically renamed into `inbox/{id}` only after all attachments succeed.

---

## 5. Browser Cookie Restrictions & Cross-Origin Iframes

Modern browsers (Chrome, Safari, Firefox) block third-party cookies by default in cross-site iframes:
- **Production Same-Origin Iframe Talk:** Inside an `<iframe src="https://app-a.example.ch/sync.html">`, `fetch('/api/inbox')` is a same-origin request to `app-a.example.ch`, but cookies on that request are treated as third-party because the top-level document is `app-b.example.net`.
- **Supported Authentication Patterns:**
  1. **CHIPS (`Partitioned` Cookies):** Setting `SameSite=None; Secure; HttpOnly; Partitioned` allows the embedded iframe to maintain an isolated, HttpOnly cookie partitioned by the top-level site.
  2. **Top-Level Tab Login + Explicit Session Header (`X-UMAI-Session`):** The user signs into Application A in a standalone tab, and the session token is passed via an explicit HTTP header (`X-UMAI-Session`), bypassing third-party cookie blocking while automatically providing CSRF resistance on state-changing endpoints.

---

## 6. Optional Extension: End-to-End Signed Messages & ACKs (Untrusted Courier Model)

In environments where the two applications do not trust the user's browser against local tampering (e.g., certifying official records between two enterprises via the user's browser), UMAI supports **opaque cryptographic envelopes** without requiring any cryptography in the browser:

1. **Outbox Signing (Sender Backend):**
   - When creating an outbox snapshot, the sending server signs canonical metadata `{ id, sender_origin, receiver_origin, payload_sha256, attachments: [{ name, size, sha256 }] }` using its private key (e.g., standard library `crypto/ed25519` or post-quantum `ML-DSA`).
   - The signature is stored alongside `message.json` and passed as an opaque field in the `PUT` envelope.
2. **Inbox Verification (Receiver Backend):**
   - Before committing the staging directory in `AcceptMessage`, the receiving server verifies the sender's signature against the configured peer public key and checks that the computed SHA-256 hashes of all uploaded attachments match the signed manifest.
   - Forged or modified messages are rejected before acceptance.
3. **Signed Acknowledgements (Receiver $\rightarrow$ Sender Backend):**
   - Upon accepting a message, the receiving server produces a signed receipt `Sign({ type: "UMAI-ACK", id, message_signature_hash })`.
   - The browser carries this receipt in the `ACK` frame, and the sending server verifies the receipt before deleting the message from `outbox/`. This mathematically guarantees that an outbox message is only deleted after the genuine peer server has verified and accepted the exact original bytes.
