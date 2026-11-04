# Security Policy and Model — UMAI 0.1

This document outlines the security architecture, trust boundaries, threat model, and operational limitations for UMAI (User-Mediated Application Interoperability).

---

## 1. Threat Model & Trust Assumptions

UMAI coordinates data exchange between two independent web origins through a user's web browser session.

### Trust Assumptions
- **The User's Browser is Trusted as Mediator:** The client device and browser execution environment are assumed to be uncompromised.
- **Mutual Pre-Configuration:** Both applications must have prior agreement on each other's canonical origin (e.g., `https://app-a.example.ch` and `https://app-b.example.net`).
- **No Shared Secrets Over UMAI:** Passwords, API tokens, and session cookies are never transmitted over UMAI protocol messages. Each application manages its own independent authentication.
- **Possession of Window Reference Is Not Authorization:** Simply being able to locate an iframe window does not grant rights to transmit data. All communication requires origin validation.

---

## 2. Core Security Controls

### 2.1 Strict Origin Allowlisting
- Every incoming `window.postMessage` event is validated against an exact, configured peer origin (`event.origin === peerOrigin`).
- Target origins for outgoing `postMessage` calls must be explicit origins, never the wildcard `*`.
- Origin mismatches cause messages to be dropped immediately.

### 2.2 Dedicated MessagePort Isolation
- After initial handshake validation over `window.postMessage`, communication shifts to a point-to-point `MessagePort` created via `MessageChannel`.
- Once transferred, `MessagePort` channels cannot be intercepted by other scripts running in the parent or neighboring frames.

### 2.3 Content Security Policy (CSP) & Embedding Control
To prevent clickjacking and unauthorized embedding:
- **Application A (Embedded):** Enforces `Content-Security-Policy: frame-ancestors 'self' <PeerOrigin>`. Any other origin attempting to embed Application A is blocked by the browser engine.
- **Application B (Host):** Enforces `Content-Security-Policy: frame-ancestors 'none'; frame-src 'self' <PeerOrigin>`.

### 2.4 Server-Side Path Traversal & Filename Sanitization
- All uploaded, received, and snapshotted filenames are sanitized using `filepath.Base(filepath.Clean(name))`.
- Directory separators (`/`, `\`), null bytes, and traversal tokens (`..`) are stripped or rejected.
- Files are saved strictly within dedicated application subdirectories (`docs/`, `outbox/{id}/attachments/`, `inbox/{id}/attachments/`).

### 2.5 All-or-Nothing Acceptance
- Incoming attachments are written to an isolated staging directory (`.tmp-{id}-{timestamp}`).
- If any file fails verification, is truncated, or exceeds upload limits, the entire staging directory is deleted.
- No partial message state is ever committed to the inbox or marked as accepted in `accepted.json`.

---

## 3. Browser Cookie Restrictions & Authentication Boundaries

### Cross-Site Iframe Cookie Policy
Modern web browsers (Google Chrome, Apple Safari, Mozilla Firefox) enforce strict third-party cookie blocking:
- If Application A runs on `https://app-a.example.ch` and is embedded inside `https://app-b.example.net`, the browser considers cookies for Application A to be third-party context.
- With default privacy settings, third-party cookies without `SameSite=None; Secure; Partitioned` may be withheld in the embedded frame.
- **UMAI Fallback Pattern:**
  Application A provides a fallback option ("Log in in separate tab"). The user opens Application A in a top-level tab, signs in, and the session is established. Both applications can then reconcile without circumventing browser security policies.

---

## 4. Resource Consumption & DoS Mitigations

### 4.1 Maximum Attachment Size Limits
- Both Go servers enforce a configurable maximum upload and transfer limit (`-max-upload`, default 100 MB).
- Incoming streams are wrapped in `io.LimitReader(r, maxUploadSize + 1)`. If the payload exceeds the limit, the connection is terminated and temporary files are purged.

### 4.2 Serialized Transfers
- `js/umai.js` enforces a single-message transfer queue for outgoing `PUT` operations.
- Multiple attachments are not read into memory simultaneously, preventing browser tab crashes from unbounded parallel heap allocation.

---

## 5. Known Limitations (0.1 Release)

1. **Experimental Prototype:** UMAI 0.1 is an open-source proof of concept. It has not undergone formal third-party cryptographic audit.
2. **Transfer Progress Granularity:** Native `postMessage` transfer of large `File` objects via Structured Clone does not expose fine-grained byte-level transfer progress events in current browser engines.
3. **Chunking & Partial Resumes:** Transfers that are cancelled or cut short must restart from byte zero. Chunked streaming is planned for future versions.
