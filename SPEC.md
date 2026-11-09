# UMAI 0.1 Specification

**User-Mediated Application Interoperability**  
**Version:** 0.1 (Draft / Experimental Reference Specification)  

### Status of This Document
This document specifies **UMAI 0.1**, an experimental, vendor-neutral protocol and browser transport binding for user-mediated application interoperability. Key words `MUST`, `MUST NOT`, `SHOULD`, `SHOULD NOT`, and `MAY` in this document are to be interpreted as normative requirements per RFC 2119.

---

## 1. Abstract & Scope

UMAI (User-Mediated Application Interoperability) defines a symmetric, receiver-controlled communication protocol that enables two independent web applications to exchange immutable messages and binary attachments directly through an authenticated user's browser, without requiring direct server-to-server network integrations, API gateways, or third-party message brokers.

This specification is organized into three distinct tiers:
1. **Core Protocol:** Transport-independent rules, invariants, and state machines.
2. **Browser Transport Binding:** Concrete mapping to browser APIs (`postMessage`, `MessageChannel`, `File`/`Blob`).
3. **Application Responsibilities:** Local storage, immutability snapshots, and authentication boundaries.

---

## 2. Terminology

- **Peer:** An independent web application participating in a UMAI exchange. Either peer can act as sender and receiver concurrently.
- **Mediator:** The user's web browser tab/window providing the execution context and runtime transport between the peers.
- **Message:** An immutable logical unit of exchange consisting of a globally unique identifier, arbitrary structured JSON payload metadata, and zero or more binary attachments.
- **Outbox:** Local storage maintained by a peer holding prepared outgoing messages that have not yet been acknowledged by the receiver.
- **Inbox:** Local storage maintained by a peer holding successfully accepted incoming messages.
- **Accepted Set:** A durable record of message IDs that have been fully received, verified, and committed by the receiver.

---

## 3. Core Protocol

### 3.1 The Four Protocol Messages

UMAI defines exactly four operations. No additional message types are required for data transfer:

| Type | Direction | Semantics |
|---|---|---|
| `OFFER` | Sender → Receiver | Announces message IDs currently available in the sender's outbox. |
| `GET` | Receiver → Sender | Requests delivery of specified message IDs that have not yet been accepted. |
| `PUT` | Sender → Receiver | Delivers one complete message payload and all associated binary attachments. |
| `ACK` | Receiver → Sender | Confirms that one or more message IDs have been successfully accepted and committed. |

### 3.2 Protocol Rules & Invariants

#### Rule 1 — Immutability & Globally Unique Message IDs
Every message is assigned a globally unique identifier (Message ID) upon creation. Once offered, its payload and attachments MUST NEVER change. Any modification to metadata or attachments constitutes a new message and requires a distinct Message ID.
- **Normative Message ID Format:** A Message ID MUST be a non-empty ASCII string of `1` to `128` characters matching `^[a-zA-Z0-9._-]{1,128}$` (excluding `"."`, `".."`, and any string containing `".."`).
- **Collision Resistance & Entropy:** Senders MUST generate Message IDs with at least **64 bits of cryptographic randomness** (CSPRNG), such as `msg-<unix_ms>-<16_hex_chars>` (as implemented in `pkg/umaiserver`) or a standard UUIDv4 / UUIDv7 (`36` characters), so that Message IDs are globally unique across sessions, restarts, and tenants without central coordination.

#### Rule 2 — Receiver-Controlled Transfer
The sender does not push messages uninvited. The sender advertises available message IDs using `OFFER`. The receiver evaluates the offer against its Accepted Set and requests only those IDs it does not possess using `GET`. Conversely, a sender MUST ignore `GET` or `ACK` messages referencing Message IDs that it has not offered, and a receiver MUST ignore unsolicited `PUT` messages that it did not request via `GET`.

#### Rule 3 — Complete Messages Only (All-or-Nothing Acceptance)
A `PUT` operation transmits one complete logical message including all associated binary attachments.
- The receiver MUST either accept the entire message and all attachments or reject the entire transfer.
- Partial messages MUST NEVER be accepted or exposed to the application.
- If a transfer is interrupted before complete acceptance, the receiver discards all staged data. The next reconciliation will request the message again from scratch.

#### Rule 4 — Receiver Acknowledgement
The receiver issues an `ACK` only AFTER the message and all attachments have been completely stored and the Message ID has been committed to the durable Accepted Set. An error or failure prior to acceptance MUST NEVER result in an `ACK`.

#### Rule 5 — Repeated Acknowledgements (Crucial Invariant)
Whenever a sender offers a Message ID that the receiver has already accepted in the past, the receiver MUST immediately send `ACK` again for that ID.
The receiver MUST NOT send `GET` or accept `PUT` for an already-accepted message.
*Rationale:* Network disruptions or browser closures may cause an initial `ACK` to be lost. Repeated acknowledgements allow the sender to safely clean up its outbox without risking duplicate imports.

#### Rule 6 — Sender Cleanup & Non-Reuse of Acknowledged IDs
Upon receiving an `ACK` for a Message ID, the sender MAY remove that message and its attachment snapshots from its outbox. Senders may choose to retain messages longer for auditing purposes. Once a Message ID has been acknowledged and removed from the outbox, the sender MUST NEVER reuse that Message ID for any future message (Rule 1).

#### Rule 7 — Reconnection & Reconciliation
When communication between peers is established or restored, both peers exchange their outstanding outbox offers (`OFFER`). No specialized recovery protocol or vector clock mechanism is required.

#### Rule 8 — User Mediation & Bounded Execution
Transfers occur exclusively while an active browser session connects both applications. Closing the browser tab pauses the transport immediately. Subsequent sessions resume reconciliation naturally via Rule 7.

### 3.3 Separation of Technical Acceptance (`ACK`) from Business Classification & Legal Delivery

UMAI strictly separates **transport-level technical acceptance** from **application-specific business processing**:

1. **Durable Technical Acceptance (`ACK`):**
   - Issuing an `ACK` (Rule 4) signifies solely that the receiving application has verified the technical integrity of the message (complete payload and attachments, plus optional cryptographic signature verification) and durably persisted it into an incoming staging store or **"Unassigned Incoming Tray"** alongside its Message ID in the Accepted Set.
2. **Deferred Business Classification:**
   - UMAI does **not** decide which business case, dossier, workflow, or category an incoming message belongs to, nor whether a user must supply additional business metadata.
   - Receiving applications SHOULD accept valid incoming messages into a durable incoming tray first (returning `ACK` immediately so the sender can clean up its outbox) and allow the user or downstream application logic to classify, route, or reject the business record asynchronously afterward.
   - Rejecting `acceptMessage()` due to missing interactive business context or downstream domain rules MUST be avoided, as it causes the transport layer to treat the transfer as a technical failure.
3. **Distinction from Legal or Statutory Delivery Receipts:**
   - A UMAI `ACK` (and its optional cryptographic `ack_receipt`) is a **technical transport confirmation** proving that the receiving system's storage layer accepted the bytes. It MUST NOT be conflated with a legally effective submission confirmation or statutory delivery receipt unless the application layer explicitly exchanges a separate, domain-level receipt message for that purpose.

---

## 4. Wire Format & Protocol Envelopes

Every protocol message is encoded as a structured object containing standard envelope fields:

```typescript
interface UmaiEnvelope {
  protocol: "UMAI";
  version: 1;
  type: "OFFER" | "GET" | "PUT" | "ACK";
}
```

### 4.1 OFFER Message
```json
{
  "protocol": "UMAI",
  "version": 1,
  "type": "OFFER",
  "ids": ["msg-1730750000-01", "msg-1730750000-02"]
}
```

### 4.2 GET Message
```json
{
  "protocol": "UMAI",
  "version": 1,
  "type": "GET",
  "ids": ["msg-1730750000-02"]
}
```

### 4.3 PUT Message
```javascript
{
  protocol: "UMAI",
  version: 1,
  type: "PUT",
  id: "msg-1730750000-02",
  payload: {
    subject: "Contract Agreement",
    created_by: "Alice",
    custom_data: { status: "approved" }
  },
  attachments: [
    /* Native File or Blob objects */
  ],
  signature: "optional-hex-encoded-sender-signature" // Optional opaque cryptographic signature from sender server
}
```
*Note:* `payload` MUST contain strictly JSON-representable values (`null`, booleans, finite IEEE-754 numbers, strings, plain arrays, and plain objects; implementations MAY enforce a reasonable nesting depth limit such as `64` and MUST reject non-JSON structured-clone objects inside `payload`). Binary attachments are transmitted exclusively in `attachments` as native binary objects (`File` or `Blob`) via the browser Structured Clone Algorithm and MUST NOT be Base64-encoded. If the sender server signs outgoing messages, the `signature` field is carried opaquely by the browser and verified by the receiving server prior to acceptance.

### 4.4 ACK Message
```json
{
  "protocol": "UMAI",
  "version": 1,
  "type": "ACK",
  "ids": ["msg-1730750000-02"],
  "receipts": {
    "msg-1730750000-02": "optional-hex-encoded-receiver-ack-receipt"
  }
}
```
*Note:* When server-side signing is enabled, the receiver server returns a signed acceptance receipt (`ack_receipt`) binding the accepted `id` to the sender's message signature. The browser carries `receipts` opaquely in the `ACK` envelope (including on Rule 5 repeated `ACK`s) so the sender server can verify authentic peer acceptance before deleting the outbox entry.

---

## 5. Browser Transport Binding

The browser transport binding maps UMAI messages onto standard browser primitives:
- `window.postMessage`
- `MessageChannel` / `MessagePort`
- Cross-window references: HTML `<iframe>` (`iframe.contentWindow` / `window.parent`) **or** Top-Level Companion/Popup Windows (`window.open` / `window.opener`)
- Structured Clone Algorithm

### 5.1 Handshake & Point-to-Point Channel Establishment

The core `OFFER` / `GET` / `PUT` / `ACK` protocol operates strictly over a dedicated `MessagePort` and is independent of whether the peer window is embedded in an `<iframe>` or opened as a top-level browser window:

1. **Supported Window Topologies:**
   - **Embedded `<iframe>` Topology (Primary):** Application B (Host) embeds a lightweight sync page of Application A (`embedded` role) within an `<iframe>`. Here, the host targets `iframe.contentWindow` and the embedded peer targets `window.parent`.
   - **Top-Level Companion / Popup Window Topology (Zero-Third-Party-Cookie Fallback):** Application B (Host) opens Application A (`embedded`/companion role) in a top-level window via `const peerWin = window.open(url, ...)` (or attaches to an existing opener relationship). Here, the host passes `peerWindow: peerWin` and the companion window targets `window.opener`. Because both applications run as top-level first-party windows, this topology operates without any reliance on third-party or partitioned cookies.
2. **Readiness Signal:** Once loaded and authenticated, the peer window (`embedded` role) announces readiness to its host window (`window.parent` or `window.opener`):
   ```javascript
   targetHostWindow.postMessage({ protocol: "UMAI", version: 1, type: "READY" }, peerOrigin);
   ```
3. **Port Transfer (Fail-Closed Window Binding):** The host validates `event.origin === peerOrigin` and strictly verifies that the expected target window (`iframe.contentWindow` or `peerWindow`) is bound and open (`expectedSource !== null`) and that `event.source === expectedSource` (never dynamically adopting an unbound `event.source`). It then instantiates a `MessageChannel`, retains `port1`, and transfers `port2` to the peer window:
   ```javascript
   targetPeerWindow.postMessage(
     { protocol: "UMAI", version: 1, type: "INIT" },
     peerOrigin,
     [channel.port2]
   );
   ```
4. **Port Confirmation:** The peer window verifies `event.origin === peerOrigin` and strictly checks that `expectedSource` (`window.parent` or `window.opener`) is non-null and `event.source === expectedSource`, claims `event.ports[0]`, and sends `INIT_ACK` over the private port.
5. **Private Point-to-Point Channel:** All subsequent protocol messages (`OFFER`, `GET`, `PUT`, `ACK`) travel exclusively over the dedicated `MessagePort`.

### 5.2 Concurrency, Transfer Ordering & Recommended Size Bounds
To prevent browser memory exhaustion and uncontrolled adapter amplification, an implementation SHOULD bound both outgoing `PUT` concurrency and receiver-side `GET` / `acceptMessage` concurrency (`maxConcurrency = 1` by default in `js/umai.js`, configurable up to `16`), coalesce repeated `OFFER` announcements and `ACK` notifications into bounded structures (`MAX_BATCH_IDS = 1000`), cap total outstanding incoming work (`_pendingGetQueue.length + _inFlightGets.size + _acceptingIds.size <= MAX_BATCH_IDS`), and expire stalled `GET` reservations (`getTimeoutMs = 120000` ms by default in `js/umai.js`) so slow messages do not permanently block waiting transfers while still admitting a late `PUT` if a receive slot is free. Because browser `MessagePort` transfers clone structured payloads and `File`/`Blob` attachments and backend storage adapters typically buffer or stream a single message per HTTP request, implementations SHOULD validate and normalize `payload` to strict JSON values and bound individual messages—including both UTF-8 serialized JSON payload bytes and total attachment bytes—to a practical interactive envelope (default `<= 50 MB` combined payload + attachment size and `<= 50` native `Blob`/`File` attachments per message in `js/umai.js`, configurable by the deployment).

---

## 6. Application Responsibilities

UMAI does not prescribe internal application schemas or databases, but imposes three invariant requirements:

1. **Snapshotting:** Before an outgoing message is offered, any selected documents must be snapshotted into an immutable message directory. Subsequent changes or deletions to local working files must not modify the offered attachment data.
2. **Crash-Resistant Acceptance:** When accepting a `PUT` message, the receiver must stage incoming files and metadata in a temporary workspace, verify completion and integrity, and atomically commit the files before adding the ID to the durable Accepted Set.
3. **Accepted ID Durability & Storage Scaling:** The Accepted Set must survive application restarts and browser closures so Rule 5 repeated acknowledgements remain reliable across sessions.
   - **Compact Storage Footprint:** Because an Accepted Set entry stores only the `umai_message_id` (`<= 128` bytes), creation timestamp, and optional `ack_receipt` (`~128` hex bytes)—not the document attachments themselves—each entry occupies roughly `150–250 bytes`. Even 1,000,000 accepted messages require only `~150–250 MB` in a standard indexed database table (`PRIMARY KEY (umai_message_id)`), providing `O(1)` / `O(log N)` lookups.
   - **Optional Multi-Year Retention Horizon:** If a deployment wishes to prune Accepted Set entries after a long retention window (e.g., `1–2 years`), both peers SHOULD enforce a shorter maximum outbox lifetime (e.g., unacknowledged outbox messages expire after `90 days`), and the receiver SHOULD verify payload/signature equality if an existing record with the same ID still resides in its long-term archive.

---

## 7. Versioning & Extensibility

- The protocol version is identified by the integer field `version: 1`.
- Any non-backward-compatible change to message envelopes, rules, or state machines requires incrementing the version number.
- Peers encountering an unsupported protocol version MUST ignore incoming envelopes or log a fatal version mismatch error.
