# Security Policy and Model — UMAI 0.1

This document provides a rigorous, transparent analysis of the **UMAI (User-Mediated Application Interoperability)** security model. It is structured from **architectural principles and residual risks at the top** down to a **detailed production implementer's hardening checklist at the end**:

1. **Separation of Security Concerns & Codebase Reuse Boundary** (what UMAI solves in principle vs. application security, and what lives in verbatim reusable `js/umai.js` vs. example code).
2. **Three Progressive Security Tiers** (transport isolation, signed envelopes/receipts, and optional "Blind Courier" encryption).
3. **Inherent Limits & Residual Risks of the User-Mediated Principle** (what neither the browser protocol nor server cryptography can solve on its own).
4. **Guarantees Enforced Verbatim by `js/umai.js`** (what adopters get automatically by reusing the browser engine as-is).
5. **Server-Side Cryptographic Signing & Optional Encryption** (how `signature` and `receipts` protect authenticity across the untrusted browser bridge).
6. **Production Implementer's Hardening Checklist ("All the Bells & Whistles")** (every subtle HTTP, CSP, cookie, CSRF, canonicalization, and storage safeguard implemented in `pkg/umaispool` and `internal/demoapp` that real-world implementers should replicate—clearly separated from demo-only fixtures).

---

## 1. Separation of Security Concerns & Codebase Reuse Boundary

### 1.1 Three Distinct Security Planes
When evaluating UMAI, three orthogonal planes must never be conflated:

| Plane | Responsibility | Scope |
|---|---|---|
| **Plane A: Individual Application Security** | How Application A or B authenticates its human users (MFA, OIDC/SAML, WebAuthn/Passkeys, session lifetimes), enforces internal RBAC, and secures its database at rest. | **Out of Scope for UMAI.** Each application retains its existing enterprise IAM. |
| **Plane B: Browser-Mediated Transport** | Moving `OFFER`, `GET`, `PUT`, and `ACK` frames between two cross-origin browser contexts without any backend-to-backend network path or cross-origin HTTP API exposure. | **Core UMAI Protocol (`SPEC.md` & `js/umai.js`).** |
| **Plane C: End-to-End Authenticity & Confidentiality** | Ensuring that the mediating browser (or a rogue browser extension) cannot tamper with messages in transit, forge messages, trigger premature outbox deletion, or (optionally) read sensitive payloads. | **Implementer Backend Policy**, supported natively in the UMAI wire envelopes (`signature` on `PUT`, `receipts` on `ACK`) and implemented in `pkg/umaispool/crypto.go`. |

### 1.2 Verbatim Reusable Code vs. Demo Application Code
Because real-world teams either adopt the reusable file-spool components directly or integrate UMAI into existing backends (Java, C#, Go, Python, Node, etc.), this repository strictly separates **reusable protocol & spool libraries** from **demo application glue**:

| Repository Component | Reuse Model | Security Controls Contained Here |
|---|---|---|
| **`js/umai.js`** *(+ `SPEC.md`)* | **Reusable Verbatim in Production.** Zero-dependency browser protocol engine that any web application can drop in directly. | `http:`/`https:` origin validation, `event.source` window pinning, dedicated `MessagePort` lifecycle, receiver-controlled state machine (`_offeredIds`, `_inFlightGets`), `_putQueue` deduplication, batch/ID bounds, bounded tree-shaped JSON validation, and prototype-safe receipt maps. |
| **`pkg/umaispool/*` & `js/umai-spool.js`** | **Reusable Verbatim for File-Spool / HTTP Integrations.** Standalone Go spool engine + HTTP handler and matching browser adapter with zero demo fixtures. | Mandatory fail-closed `Authorizer` hook, explicit `LocalIdentity`/`PeerIdentity` & `Ed25519` signing/receipt verification (no demo key fallback), same-origin `Origin` + `X-UMAI-CSRF` protection, `application/octet-stream` sandboxed downloads, `.staging/`/`.committing/`/`accepted.json` atomic commits, soft in-flight leases, and all-or-nothing attachment retrieval in `js/umai-spool.js`. |
| **`internal/demoapp/*` & `examples/*`** | **Demo Application Layer (Replaced in Production).** Sample web servers and UIs consuming `pkg/umaispool` and `js/umai-spool.js` verbatim. | Framing CSP headers (`frame-ancestors`, `frame-src`, `script-src 'self'`), CHIPS `Partitioned` session cookies, local `docs/` CRUD workspace, static `admin`/`umai123` login (`AuthManager`), and deterministic demo keys gated behind `-demo` on loopback. |

### 1.3 Zero Cross-Origin HTTP Calls & Zero CORS Required
UMAI **never** makes HTTP requests from Application A's frontend to Application B's backend (or vice versa). Each frontend communicates exclusively with its own origin's HTTP API, while the two frontends exchange data in-memory via a dedicated browser `MessagePort`.
- **Why this matters:** Neither server needs Cross-Origin Resource Sharing (`Access-Control-Allow-Origin` or `Access-Control-Allow-Credentials: true`) for the peer domain (`connect-src 'self'`). Keeping all HTTP endpoints strictly same-origin eliminates an entire class of cross-origin API and credential exposure bugs.

---

## 2. Three Progressive Security Tiers

Depending on the trust model between the two applications and the mediating user, UMAI supports three progressive security tiers:

| Security Tier | Threat Addressed | Mechanism | Where Implemented in Repo |
|---|---|---|---|
| **Tier 1: Transport & State-Machine Isolation** | Unauthorized websites framing or snooping on messages; out-of-order or unsolicited protocol frames | Origin + `event.source` pinning, private `MessagePort`, `_offeredIds` & `_inFlightGets` enforcement (`js/umai.js`) + `frame-ancestors` / `frame-src` CSP (`internal/demoapp`) | **Verbatim in `js/umai.js`** + HTTP headers in `internal/demoapp` |
| **Tier 2: End-to-End Authenticity & Non-Repudiation (Signed Envelopes)** | User, DevTools, or browser extension tampering with payloads/files in transit, stripping signatures, reflecting messages, or forging `ACK`s | Opaque `signature` (`PUT`) and `receipts` (`ACK`) envelope fields carried by `js/umai.js`; verified server-side via `crypto/ed25519` with directional identity binding | **Envelope support verbatim in `js/umai.js`** + signing engine in `pkg/umaispool/crypto.go` |
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

### 3.5 Browser Deserialization Boundary, Content Inspection & Adapter Durability Contract
- **Pre-JavaScript Browser Deserialization:** Incoming `window.postMessage` and `MessagePort` frames undergo browser structured-clone deserialization *before* `js/umai.js` receives control. Consequently, `js/umai.js` cannot prevent every browser-level memory or CPU exhaustion attack from a hostile connected peer, and deployments MUST NOT assume a malicious sender necessarily crashes itself first or leaves the receiving page unaffected.
- **What `js/umai.js` Bounds vs. What Remains Outside Core:**
  - *Bounded inside `js/umai.js`:* Cheap envelope and batch-count checks first, active-connection and solicited-transfer (`conn.offeredIds`, `conn.inFlightGets` / `conn.expiredGets`) checks before expensive payload traversal, bounded tree-shaped JSON validation and serialization, bounded message sizes (`50 MiB` default), bounded queues (`1,000`) and concurrency (`maxConcurrency`), and paced backend acceptance lookups.
  - *Application & Backend Validation Required:* `js/umai.js` intentionally does not include a generic content-inspection or MIME-detection framework. Application-specific decoding/rendering must enforce its own format and safety checks, and backend security must never depend on frontend validation.
  - *Adapter Durability Responsibility:* `js/umai.js` cannot verify physical storage durability itself; it enforces protocol ordering and relies on the application's `storage` adapter fulfilling its durability and atomic-deduplication contract before returning `{ accepted: true }`.

---

## 4. Guarantees Enforced Verbatim by `js/umai.js`

Every adopter who includes `js/umai.js` verbatim receives the following browser-side protocol, lifecycle, and memory protections automatically:

1. **Strict `http:`/`https:` Origin Validation & Window Source Pinning (`parseHttpOrigin`, `isAllowedOrigin`, `_handleWindowMessage`):**
   - The `UmaiSession` constructor validates `options.peerOrigin` immediately and throws an error on wildcard (`'*'`), `'null'`, or non-HTTP(S) schemes (`javascript:`, `data:`, `file:`).
   - Exact origin matching (`scheme://host:port`) is always enforced (`inc.origin === exp.origin`).
   - Outgoing handshake `postMessage` calls always pass the explicit `peerOrigin` target—never the wildcard `'*'`.
   - During the handshake, the host verifies `event.source === expectedSource` (`iframe.contentWindow` or `peerWindow`) before accepting `READY`, and the embedded peer verifies `event.source === expectedSource` (`window.parent` or `window.opener`) before accepting `INIT`, preventing sibling tabs or unrelated frames from hijacking the channel. Also, calling `start()` on a session that is already `'connected'` or `'handshaking'` is idempotent so an unnecessary `start()` call never invalidates a healthy connection.
2. **Isolated `MessagePort` Transport, Explicit Connection-Owned State & Callback Safety (`_createConnection`, `_closeConnection`, `_isActiveConn`, `_isSameLifecycle`, `_resetChannelState`):**
   - All `OFFER`, `GET`, `PUT`, and `ACK` frames travel exclusively over a dedicated `MessageChannel` (`MessagePort`), never over the global `window` bus.
   - All mutable per-channel queues, reservations, retry counters, worker flags, and timers (`offeredIds`, `pendingOfferIds`, `inFlightLookupIds`, `deferredOfferIds`, `pendingAcks`, `inFlightGets`, `expiredGets`, `timedOutGets`, `failedAttempts`, `acceptingIds`, `pendingGetQueue`, `incomingPutQueue`, `putQueue`, `getExpiryTimer`, `lookupTimer`) belong to an explicit per-connection state object (`conn = _createConnection(port)`) rather than session-global containers.
   - Each handshake, `setPeerWindow()`, and `stop()` advances `_lifecycleSeq` and explicitly closes the prior connection via `_closeConnection(conn)`—setting `conn.closed = true`, cancelling `conn.getExpiryTimer` and `conn.lookupTimer`, detaching `port.onmessage`, closing `port`, and clearing `this._conn`—while every new channel allocates a fresh `conn` instance.
   - All user callbacks (`onStatusChange`, `onSyncStatus`, `onLog`, `onError`, `onTransfer`) are wrapped in `try/catch`-isolated helpers, and every asynchronous storage boundary, error handler (`catch`), callback boundary, and `finally` continuation verifies `_isSameLifecycle(seq)` (during pre-port `start()`/`handshaking` transitions) or `_isActiveConn(conn)` (for connected `MessagePort` operations) before emitting frames, scheduling timers, invoking callbacks, or starting further `storage` work. Even if an in-flight promise from a superseded connection settles late, `conn.closed` and `_isActiveConn(conn)` suppress all side effects and any local bookkeeping touches only that closed `conn`'s private containers, never a replacement connection.
3. **Strict Offer-Before-GET, Offer-Before-ACK, Pull-Before-PUT, Bounded Coalescing & Controlled Concurrency (`maxConcurrency`, `getTimeoutMs`):**
   - **Serialized `reconcile()` Without Heartbeat Starvation & Large-Outbox (`> 1,000`) Progress:** `reconcile()` calls are serialized per connection (`conn.reconciling`, `conn.reconcilePending`) so stale `getOutboxIds()` snapshots cannot overwrite newer ones, while always processing each completed snapshot before servicing a coalesced `conn.reconcilePending` request (excluding any IDs acknowledged mid-read) so slow `getOutboxIds()` calls overlapped by periodic heartbeats still emit `OFFER`s and never livelock. When an outbox holds more than `MAX_BATCH_IDS = 1000` messages, `js/umai.js` distinguishes full outbox membership from the `<= 1,000` advertised batch—retiring genuinely removed IDs while protecting active transfers and rotating idle `conn.offeredIds` slots so reordered outboxes make continuous progress.
   - **Unoffered `GET` & `ACK` Rejection + Coalesced `ACK` Draining (`conn.offeredIds`, `conn.pendingAcks`):** Incoming `GET` and `ACK` frames are filtered strictly to `conn.offeredIds`. Valid `ACK`s are coalesced into a bounded `conn.pendingAcks` `Map` (`<= 1000`, upgrading empty receipts to non-empty receipts so an earlier empty receipt cannot suppress a later valid receipt) and drained by a single sequential worker per connection (`_drainPendingAcks`); if `onAcknowledged` fails, the IDs stay in `conn.offeredIds` so subsequent `ACK`s retry cleanly.
   - **Independent Acceptance Lookups, Offer-Flood Pacing, Bounded Deferred Queue & Non-Blocking `GET` Timeout:** Incoming `OFFER` frames are coalesced into `conn.pendingOfferIds` (`<= 1000`), skipping any ID already queued in `conn.pendingGetQueue`, requested in `conn.inFlightGets`, actively accepting in `conn.acceptingIds`, or halted by the per-message connection retry cutoff (`conn.failedAttempts` / `conn.timedOutGets`) **before** querying storage. Acceptance lookups (`storage.getAcceptance(ids)`) run **independently of `GET` transfer capacity** (paced by `lookupMinIntervalMs`, default `20` ms, to cap lookup rate under sustained `OFFER` floods) so Rule 5 repeated `ACK`s for already-accepted IDs are emitted immediately even when `conn.pendingGetQueue` is completely full (`MAX_BATCH_IDS = 1000`). Unaccepted IDs enter `conn.pendingGetQueue` while total outstanding incoming work (`conn.pendingGetQueue.length + conn.inFlightGets.size + conn.acceptingIds.size`) is below `MAX_BATCH_IDS = 1000`; any overflow unaccepted IDs are retained in bounded `conn.deferredOfferIds` (`<= 1000`) and promoted automatically as transfer capacity opens. Stalled `GET` reservations expire automatically via timer after `getTimeoutMs` (default `120000` ms), demoting from `conn.inFlightGets` into bounded `conn.expiredGets` (`<= 1000`) and re-queuing at the tail of `conn.pendingGetQueue` (up to `MAX_AUTO_RETRIES = 3`) so waiting messages can advance—while still admitting a late `PUT` from `conn.expiredGets` whenever a receive slot is free. Unsolicited `PUT`s (absent from both `conn.inFlightGets` and `conn.expiredGets`) are immediately dropped.
   - **Controlled Concurrency (`maxConcurrency`, default `1`, configurable `1..16`), OFFER Lookup Outage Backoff & Per-Message Retry Cutoff:** Outgoing `GET` reservations, outgoing `PUT` transmissions (`conn.putQueue`), and incoming `acceptMessage` executions (`conn.incomingPutQueue`) are bounded to `maxConcurrency` concurrent operations per direction. Incoming `PUT` frames commit directly through atomic, idempotent `storage.acceptMessage(msg)` without a second post-`PUT` `getAcceptance([id])` lookup. Transient `getAcceptance(ids)` outages or malformed batch responses during `OFFER` reconciliation do **not** burn per-message retries: unresolved IDs remain in `conn.pendingOfferIds`, new `GET` dispatches pause while lookup backoff is active (`_isLookupBackoffActive`) so payloads are not transferred unnecessarily during an outage, and the connection retries automatically under capped exponential backoff (`lookupRetryBaseMs = 500` ms doubling up to `lookupRetryMaxMs = 30000` ms) until the backend recovers. Separately, any individual message whose `PUT` validation, `acceptMessage(msg)`, or `GET` timeout fails `MAX_AUTO_RETRIES = 3` times hits a bounded (`<= 1000` FIFO-evicted) **retry cutoff** (`conn.failedAttempts` / `conn.timedOutGets`) until manual `reconcile(true)` or a new connection.
4. **Strict Adapter Input Validation, Whole-Batch Acceptance Verification, Strict JSON Payload Normalization, Envelope Bounds & Prototype-Safe Receipt Maps:**
   - Message IDs are validated against the normative `SPEC.md` grammar (`isValidMessageId`: `/^[a-zA-Z0-9._-]{1,128}$/`, excluding `"."`, `".."`, and any ID containing `".."`) and batch arrays in `OFFER`, `GET`, and `ACK` are capped at `MAX_BATCH_IDS = 1000`.
   - `payload` is recursively validated (`isStrictJsonValue`, up to `MAX_JSON_DEPTH = 64`, tracking visited objects and pre-serialization byte budgets) to ensure it is a strict, tree-shaped JSON value (`null`, booleans, finite numbers, strings, plain arrays, and plain objects with data properties only—rejecting `Blob`, `File`, `ArrayBuffer`, `TypedArray`, `Date`, `Map`, `Set`, getters, circular references, and shared-reference DAG bombs before `JSON.stringify`), normalized via `JSON.parse(JSON.stringify(...))` (`null`/`undefined` normalized to `{}` while preserving falsy primitives `false`, `0`, `""`), and measured in UTF-8 bytes alongside `attachments` (`att instanceof Blob`, `<= maxAttachments` default `50`, combined payload + attachment size `<= maxMessageBytes` default `50 MB`). Note that this browser-side JSON structural validation/normalization is distinct from server-side `UMAI-PUT-V1` cryptographic digest canonicalization.
   - `getAcceptance(ids)` requires a single return representation—a plain ID-keyed object (`Object.prototype` or `null` prototype)—validated as a complete batch (`validateBatchAcceptance` / `parseAcceptanceEntry` checking `Object.prototype.hasOwnProperty.call` for every requested `id`). If the return value is not a plain object or *any* requested ID is missing or malformed, the **entire batch** fails validation with zero state mutation (producing neither a false `ACK` nor a premature `GET`) and enters capped lookup backoff. Similarly, `acceptMessage(msg)` requires explicit boolean `res === true` or `res.accepted === true` (`parseAcceptanceResult`).
   - All `receipts` maps are constructed with `Object.create(null)` and `Object.prototype.hasOwnProperty.call` with signatures/receipts bounded to `MAX_SIGNATURE_LEN = 4096`, preventing `__proto__` or `constructor` prototype-pollution attacks over `MessagePort`.

---

## 5. Server-Side Cryptographic Signing & Optional Encryption

### 5.1 End-to-End Signing Architecture (`PUT` Signatures & `ACK` Receipts)
Because the user's browser sits in the middle of the `MessagePort`, UMAI's `PUT` and `ACK` wire schemas include first-class opaque fields (`signature` on `PUT` and `receipts` on `ACK`). `js/umai.js` ferries these strings untouched so backend servers can verify authenticity and byte-level integrity end-to-end **without exposing private keys to the browser**.

In the reusable spool implementation (`pkg/umaispool/crypto.go`), zero-dependency `crypto/ed25519` signing enforces three end-to-end steps:

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
   - This `ack_receipt` is atomically persisted inside the consolidated `accepted.json` index (`id -> ack_receipt`) and its parent `dataDir` is durably synchronized (`fsync`) **before** moving the message from `.committing/` into `inbox/` or reporting confirmed acceptance (so hot-folder consumers never see an un-flushed message, and Rule 5 repeated `ACK`s always include the receipt even if `inbox/m-<sha256(id)>/` is later archived or deleted).
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

### 5.3 Cross-Origin Iframe Authentication, Federated IdPs & First-Party Companion Window Mode
In hub-and-spoke deployments where Application B (a specialty application) embeds a minimal interface of Application A (a messaging platform) inside a cross-origin `<iframe>`, **Application A's session is needed only inside its own origin**. Two complementary browser patterns are supported out of the box:

1. **Primary Pattern — Embedded `<iframe>` with Partitioned Session Cookies (CHIPS):**
   - When Application A's authentication can complete inside the iframe (or via a partitioned session cookie `Set-Cookie: ...; Secure; HttpOnly; SameSite=None; Partitioned`), Application B embeds `https://app-a.example/sync.html` directly inside an `<iframe>`.
2. **Fallback Pattern — First-Party Companion Window Mode (`window.open` + `setPeerWindow`, Zero Custom Auth Endpoints):**
   - **When It Is Needed:** External Federated Identity Providers (OIDC, SAML, enterprise SSO) often forbid framing (`X-Frame-Options: DENY` / `frame-ancestors 'none'`), and strict browser privacy settings may block third-party cookies inside cross-origin iframes entirely. Moreover, because modern browsers partition cookies by top-level site, logging in inside a top-level popup sets a cookie in the `(app-a.example, app-a.example)` first-party partition rather than the iframe's `(app-b.example, app-a.example)` third-party partition.
   - **Why Custom Cross-Partition Session-Transfer Endpoints Should Be Avoided:** Attempting to copy or mint an iframe session from a top-level popup via custom `/bootstrap` or pairing-code HTTP endpoints introduces avoidable session-fixation and cross-context token-transfer attack surface.
   - **How First-Party Companion Window Mode Works (`examples/app-a/static/sync.js`, `examples/app-b/static/minimal.js`, `examples/app-b/static/app.js`):**
     1. When the user clicks **"Open Companion Window"** in Application B (or inside `/sync.html`), Application B opens `https://app-a.example/sync.html?companion=1` (or Application A's top-level UI) in a top-level popup window via `const companionWin = window.open(url, 'umai_companion', 'popup,width=440,height=560')` (without `noopener`) and calls `umaiSession.setPeerWindow(companionWin)`.
     2. Inside that popup, Application A runs as a **top-level first-party window**: standard `SameSite=Lax` cookies and normal OIDC/SAML redirects work natively with zero third-party cookie dependency and zero custom auth-transfer endpoints.
     3. Once authenticated, Application A's `UmaiSession` (`role: 'embedded'`) automatically targets `window.opener` and completes the origin- and `event.source`-pinned `READY` → `INIT` (`MessagePort`) → `INIT_ACK` handshake with Application B. When the companion window is later closed, Application B detects `companionWin.closed` and cleanly reverts to the embedded iframe target (`umaiSession.setPeerWindow(null)`).

---

## 6. Production Implementer's Hardening Checklist ("All the Bells & Whistles")

While **`js/umai.js` can be reused verbatim**, every production team writes or configures its own **HTTP headers, session cookies, CSRF middleware, storage adapter, and (optional) server-side signing**.

In our codebase (`pkg/umaispool`, `js/umai-spool.js`, `internal/demoapp`, and `examples/*`), we pulled a number of subtle security strings to harden these integration boundaries. **Real-world implementers writing custom backends should treat Sections 6.1–6.4 as a concrete security watchlist** (or adopt `pkg/umaispool` + `js/umai-spool.js` directly for file-spool deployments), while replacing the local demo fixtures listed in Section 6.5.

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
  - *Correct CSRF Pattern (implemented in `pkg/umaispool/handler.go` and `internal/demoapp/server.go`):* Do **not** blindly block `Sec-Fetch-Site: cross-site` on the embedded app's API (which would break embedded `SameSite=None; Partitioned` cookie requests). Instead:
    1. On every state-changing method (`POST`, `PUT`, `DELETE`, `PATCH`), verify that the `Origin` header—when present—strictly matches your server's own **scheme and host** (`403 Forbidden` otherwise).
    2. If `Origin` is omitted/stripped on a cookie-authenticated request, require an explicit custom header (e.g., `X-UMAI-CSRF: 1` or `Authorization`), which cross-site HTML `<form enctype="multipart/form-data">` CSRF attacks cannot set without triggering a blocked CORS preflight.
    3. Enforce `Content-Type: application/json` (`415 Unsupported Media Type` otherwise) on all JSON endpoints (`/api/outbox`, `/api/outbox/ack`, etc.).
- **Strict Separation Between Static Asset Root and `DataDir`:**
  - Never allow the static file handler root (`staticDir`) to overlap with `DataDir` or fall back to `"."`, and restrict static serving to explicit web asset extensions (excluding hidden paths and data files).
- **Unauthenticated Endpoint Hygiene (Preventing ID Squatting):**
  - Public health or status endpoints (`GET /api/status`) must **never** expose pending `outbox_ids` or `accepted_ids` to unauthenticated callers; otherwise an unauthenticated observer could learn pending IDs and attempt pre-emptive ID squatting.

### 6.3 Server-Side Signing & Canonicalization Watchlist (When Implementing Tier 2)
- **Fail-Closed Signature & Receipt Verification (No Downgrades):**
  - When a peer public key is configured, `POST /api/inbox` MUST reject empty/missing `signature` strings (`ErrInvalidSignature`), and `POST /api/outbox/ack` (`AcknowledgeMessagesVerified`) MUST fail closed—rejecting missing `receipts[id]` entries, empty `receipts: {}` maps, or unreadable/corrupt/unsigned outbox metadata (`ErrInvalidReceipt` / `ErrInvalidSignature`) without deleting the outbox directory.
  - On the client side, `storage.onAcknowledged(ids, receipts)` MUST inspect the HTTP response status (`if (!res.ok) throw ...`) so server-side receipt rejections surface clearly rather than failing silently.
- **Dedicated `.staging/` & `.committing/` Directories, Authoritative `accepted.json` Commit Point & Collision-Resistant Keys (`m-<sha256(id)>`):**
  - Store inbox and outbox message directories under collision-resistant internal keys `m-<sha256(id)>` (`StorageDirKey(id)`), keeping the exact protocol `id` in `message.json`, verifying `msg.ID == id` on every read, and never calling `os.RemoveAll` on an existing target directory (`ErrStorageCollision`), so case-variant IDs (`CaseID` vs `caseid`) or Windows-reserved names (`CON`, `NUL`, trailing dots) cannot overwrite or delete another message on any filesystem.
  - Stage server-created incoming (`inbox/`) and outgoing (`outbox/`) messages inside `.staging/`, validate Message IDs against `^[a-zA-Z0-9._-]{1,128}$` (excluding `"."`, `".."`, and any ID containing `".."`), bound per-file bytes (`io.LimitReader(r, maxUploadSize + 1)`), bound attachment count (`MaxAttachmentsPerMessage`), validate optional parameterless `media_type` (`lowercase type/subtype`, `<= 127` ASCII bytes, treated strictly as an unverified sender declaration while generic attachment downloads remain `application/octet-stream`), and check every file and directory `Sync()` / `Close()` error across a strict 4-stage inbox commit sequence: (1) write and `fsync` attachments and `message.json` inside `.staging/`, (2) `rename()` into `.committing/m-<sha256(id)>/` + `fsync` `.committing/` (invisible to external `inbox/` consumers), (3) atomically replace and `fsync` the consolidated `accepted.json` (`id -> { accepted_at, ack_receipt, digest }` in UTC) **plus `fsync(dataDir)`**, and (4) `rename()` from `.committing/m-<sha256(id)>/` into `inbox/m-<sha256(id)>/` + `fsync(inbox/)`. Never delete a staged message once `accepted.json` has been renamed on disk, and if `fsync(dataDir)` or the move into `inbox/` fails, retain the message inside `.committing/` (`pendingCommits`) out of consumer-visible `inbox/` and do **not** report confirmed acceptance via `GetAcceptance` or duplicate `POST /api/inbox` until synchronization and inbox exposure succeed. On startup (`NewStorage`), purge `.staging/`, finish moving any `.committing/` entry whose ID is in `accepted.json` into `inbox/` (or discard uncommitted `.committing/` leftovers), and reconcile `inbox/m-<sha256(id)>/message.json` into `accepted.json`. External producers publishing directly to `outbox/` (`umaispool.Publish` / `cmd/umai-spool`) stage exclusively inside the producer-owned `<dataDir>/prepare/` directory (which server restarts never purge) and atomically rename into `outbox/m-<sha256(id)>/` without ever overwriting an already-published ID (`ErrAlreadyPublished`). (Note: On local filesystems, full physical power-loss durability also depends on OS/filesystem write-barrier settings; high-assurance deployments should back the storage adapter with an ACID database.)
- **Verify Full Content Digest & Signature on Duplicate `POST /api/inbox` Submissions:**
  - Whenever `AcceptMessage` / `AcceptSignedMessage` (`POST /api/inbox`) receives an ID that is already in `pendingCommits`, in `accepted.json` (whether `inbox/m-<sha256(id)>/` is still present or has been archived/deleted by a consumer), or in an existing `inbox/` directory, `pkg/umaispool` streams and hashes the incoming payload, attachments, and normalized `media_type` metadata to compute `CanonicalPutDigest` (failing closed if any attachment stream read fails or is incomplete), verifies the sender's Ed25519 signature when signing is configured, and compares the incoming digest against the stored `digest` in `accepted.json`. Matching duplicates return `200 OK` with the original `accepted_at` and `ack_receipt`; conflicting content under the same ID is rejected with `ErrConflictingDuplicate` (`409 Conflict`) without modifying existing acceptance state.
- **Injective Length-Prefixed Canonical Digests, Optional `media_type` & Attachment Counts:**
  - Never concatenate variable-length strings with bare delimiters alone (e.g., `name:size:hash`), as filenames containing `:` could cause canonicalization collisions. Length-prefix every variable-length string (`role:<len>:...`, `id:<len>:...`, `att:<name_len>:<name>:<size>:<sha256>:<media_type_len>:<media_type>`), normalize optional `media_type` consistently before signing and verification, include `att_count:<n>`, and sort attachments deterministically by sanitized name.
- **Directional Sender & Receiver Role Binding (`sender_role` & `receiver_role`):**
  - Bind both the sender's and the intended receiver's logical role/origin (`sender:<len>:...` and `receiver:<len>:...`) into `UMAI-PUT-V1` and the receiver's role into `UMAI-ACK-V1` so a peer or courier cannot reflect a signed message backwards or misdirect a message signed for Peer B to Peer C.
- **Empty/Null Payload Canonicalization Equivalence (`nil` -> `{}`) & Exact JSON Numbers (RFC 7493):**
  - Normalize `nil` / `null` payloads to `{}` on both outbox signing and inbox verification, use `(payload !== undefined && payload !== null) ? payload : {}` in JS adapters so valid falsy scalars (`false`, `0`, `""`) are never coerced to `{}`, and decode JSON payloads with exact number tokens (`json.Decoder.UseNumber()` in Go) so 64-bit integers are never silently rounded to `float64`. Because browser `JSON.parse()` uses IEEE-754 double precision, applications passing integers beyond `±(2^53 - 1)` across the browser should encode them as strings per RFC 7493 (I-JSON).

### 6.4 Atomic Storage, File Hygiene & Pooled-Channel Concurrency Watchlist
- **Reject Duplicate Attachment Filenames (`os.O_EXCL` & Exact Name Deduplication):**
  - Sanitize every filename (`filepath.Base`, reject `"."`, `".."`, `/`, `\`, null bytes, and control chars `< 32`), check exact duplicate names (`seenNames[cleanName]`), and open staged attachment files with `os.O_CREATE|os.O_WRONLY|os.O_EXCL` (`ErrDuplicateAttachment`) so any filesystem collision (including case-insensitive APFS/HFS+/NTFS or Unicode-normalization collisions on the underlying volume) fails closed and aborts the import rather than overwriting an earlier attachment.
- **Symlink Rejection, Outbox Attachment Completeness & Restrictive File Modes:**
  - When snapshotting local files or serving attachments from disk, check `os.Lstat` and require `fi.Mode().IsRegular()` so symbolic links are never followed; create storage directories with `0700` and files with `0600`.
  - Require external outbox producers to prepare complete messages outside `outbox/` and publish via atomic same-filesystem directory `rename()` into `outbox/m-<sha256(id)>/`; as a supplementary sanity check (not a substitute for atomic publication), `ListOutboxForSession` also verifies that `message.json` and every declared attachment exist as regular files with their declared byte size before offering the message ID.
- **Soft In-Flight Leases for Multi-User Pooled Channels (Bandwidth Optimization):**
  - If multiple concurrent users share a system-wide outbox pool (`ListOutboxForSession`), place a short soft priority lease (e.g., `15s` `inFlightUntil` when `GET /api/outbox/{id}` is called) and deterministically rotate unclaimed IDs by session hash. Rather than acting as a hard exclusion lock, this bandwidth-optimization hint steers concurrent browsers toward different unclaimed messages first while relying on receiver deduplication (Rules 4 & 5) for correctness.
- **HTTP Server Timeouts, Multipart Buffering & Error Status Classification:**
  - Configure explicit `ReadHeaderTimeout`, `ReadTimeout`, `WriteTimeout`, `IdleTimeout`, and `MaxHeaderBytes` on the HTTP server or reverse proxy to prevent Slowloris socket exhaustion.
  - Decouple `ParseMultipartForm` memory (`DefaultMultipartMemory = 4 MiB` in `pkg/umaispool`) from `MaxUploadSize` (`DefaultMaxUploadSize = 100 MiB`) so larger file parts spill to temporary files cleaned up via `MultipartForm.RemoveAll()` rather than buffering up to `MaxUploadSize` in parser memory per upload (note: `DefaultMultipartMemory` bounds only that multipart parser's file-part buffering, not total request or server memory; `http.MaxBytesReader` request-size caps and concurrency controls remain essential).
  - Return accurate HTTP status codes without leaking internal filesystem paths (`413` for oversized bodies/files, `409` for conflicting duplicates/collisions, `404` for missing items, `400` for client/signature validation errors, and `500` for storage/durability `fsync` failures).

### 6.5 Demo-Only Safeguards in `internal/demoapp` (Replace in Production)
To keep this repository self-contained and runnable with zero external infrastructure, `internal/demoapp` (separate from `pkg/umaispool`) includes several hardened local fixtures that **are specific to the demo servers and should be replaced by enterprise infrastructure in production**:
- **Explicit Demo Mode Opt-In (`AllowDemoDefaults` / `-demo` / `UMAI_DEMO=1`):** Deterministic role demo keys (`DeriveDemoKeyPair`) and the default `admin` / `umai123` password are **refused by default on all addresses (including `127.0.0.1` behind a local reverse proxy)** unless `-demo` (or `UMAI_DEMO=1` / `AllowDemoDefaults: true`) is explicitly passed, and `-demo` additionally verifies that `ListenAddr`, `PeerOrigin`, and `PeerEmbedURL` are all loopback addresses (`127.0.0.1`, `localhost`, `[::1]`). Without `-demo`, `NewServer` refuses to start unless `UMAI_SIGNING_PRIVATE_KEY`, `UMAI_PEER_PUBLIC_KEY`, and `UMAI_AUTH_PASS` are explicitly configured.
- **Static Demo Login (`AuthManager`):** Issues scoped `HttpOnly` cookies (`umai_session_a` / `umai_session_b`, with zero bearer tokens in `localStorage`), uses constant-time SHA-256 credential comparison (`crypto/subtle.ConstantTimeCompare`), and caps active sessions (`MaxActiveSessions = 10000`). *Production apps replace this completely with their own OIDC/SAML/WebAuthn/MFA session middleware.*
