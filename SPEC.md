# UMAI 0.1 Specification

**User-Mediated Application Interoperability**  
**Version:** 0.1 (Draft / Experimental Reference Specification)  
**Date:** November 2026  

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

#### Rule 1 — Immutability
Every message is assigned a globally unique identifier (Message ID) upon creation. Once offered, its payload and attachments MUST NEVER change. Any modification to metadata or attachments constitutes a new message and requires a distinct Message ID.

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

#### Rule 6 — Sender Cleanup
Upon receiving an `ACK` for a Message ID, the sender MAY remove that message and its attachment snapshots from its outbox. Senders may choose to retain messages longer for auditing purposes.

#### Rule 7 — Reconnection & Reconciliation
When communication between peers is established or restored, both peers exchange their outstanding outbox offers (`OFFER`). No specialized recovery protocol or vector clock mechanism is required.

#### Rule 8 — User Mediation & Bounded Execution
Transfers occur exclusively while an active browser session connects both applications. Closing the browser tab pauses the transport immediately. Subsequent sessions resume reconciliation naturally via Rule 7.

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
*Note:* Binary attachments are transmitted as native binary objects (`File` or `Blob`) via the browser Structured Clone Algorithm. Attachments MUST NOT be Base64-encoded. If the sender server signs outgoing messages, the `signature` field is carried opaquely by the browser and verified by the receiving server prior to acceptance.

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
- HTML `<iframe>`
- Structured Clone Algorithm

### 5.1 Handshake & Point-to-Point Channel Establishment

To ensure strict origin isolation and prevent unauthorized snooping:
1. **Topology:** Application B (Host) embeds Application A (Peer) within an `<iframe>`.
2. **Readiness Signal:** Once loaded and authenticated, the embedded peer announces readiness to the parent window:
   ```javascript
   window.parent.postMessage({ protocol: "UMAI", version: 1, type: "READY" }, peerOrigin);
   ```
3. **Port Transfer:** The host validates `event.origin === peerOrigin`, instantiates a `MessageChannel`, retains `port1`, and transfers `port2` to the embedded window:
   ```javascript
   iframe.contentWindow.postMessage(
     { protocol: "UMAI", version: 1, type: "INIT" },
     peerOrigin,
     [channel.port2]
   );
   ```
4. **Port Confirmation:** The embedded peer verifies `event.origin === peerOrigin`, claims `event.ports[0]`, and sends `INIT_ACK` over the private port.
5. **Private Point-to-Point Channel:** All subsequent protocol messages (`OFFER`, `GET`, `PUT`, `ACK`) travel exclusively over the dedicated `MessagePort`.

### 5.2 Concurrency & Transfer Ordering
To prevent browser memory exhaustion, an implementation SHOULD serialize `PUT` transfers, transmitting at most one `PUT` message at a time per direction.

---

## 6. Application Responsibilities

UMAI does not prescribe internal application schemas or databases, but imposes three invariant requirements:

1. **Snapshotting:** Before an outgoing message is offered, any selected documents must be snapshotted into an immutable message directory. Subsequent changes or deletions to local working files must not modify the offered attachment data.
2. **Crash-Resistant Acceptance:** When accepting a `PUT` message, the receiver must stage incoming files and metadata in a temporary workspace, verify completion and integrity, and atomically commit the files before adding the ID to the durable Accepted Set.
3. **Accepted ID Durability:** The Accepted Set must survive application restarts and browser closures.

---

## 7. Versioning & Extensibility

- The protocol version is identified by the integer field `version: 1`.
- Any non-backward-compatible change to message envelopes, rules, or state machines requires incrementing the version number.
- Peers encountering an unsupported protocol version MUST ignore incoming envelopes or log a fatal version mismatch error.
