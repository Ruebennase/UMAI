# Coding Agent Assignment: UMAI 0.1

## User-Mediated Application Interoperability

Build the first open-source proof of concept of **UMAI**, a minimal protocol for exchanging messages and binary attachments between independent web applications through an authenticated user's browser.

The result must be a complete, runnable GitHub-ready repository, including a concise protocol specification, reusable JavaScript implementation, two Go demo applications, tests and documentation.

**Fundamental principle:** Keep it exceptionally simple. Do not introduce infrastructure or abstractions that are not essential to demonstrating UMAI.

---

## 1. What UMAI is

UMAI stands for **User-Mediated Application Interoperability**.

It enables two independent web applications to exchange immutable messages, including binary attachments, using standard browser communication mechanisms.

The browser mediates the communication. The application servers do not communicate directly with each other.

UMAI is:

- Symmetric: either application can send and receive.
- Message-oriented: messages may contain structured JSON data and binary attachments.
- User-mediated: exchange happens while an authorised browser session connects the applications.
- Resumable: incomplete exchanges are retried when the applications reconnect.
- Receiver-controlled: receivers decide which offered messages they need.
- Application-agnostic: UMAI does not prescribe business schemas or internal storage.

UMAI is **not** a distributed transaction framework, message broker, background synchronisation service, REST API replacement for every use case, or business workflow engine.

## 2. The four UMAI protocol messages

Implement exactly four core protocol message types:

| Type | Direction | Meaning |
|---|---|---|
| `OFFER` | Sender → Receiver | Announces available immutable messages |
| `GET` | Receiver → Sender | Requests messages not yet accepted |
| `PUT` | Sender → Receiver | Delivers one complete message and its attachments |
| `ACK` | Receiver → Sender | Confirms acceptance of message IDs |

Every application can act as sender and receiver simultaneously.

### Fundamental rules

**Rule 1 — Immutability**

Every message receives a globally unique ID when created.

Once offered, its payload and attachments must never change. A different payload requires a new message ID.

**Rule 2 — Receiver-controlled transfer**

The sender announces its available messages using `OFFER`.

The receiver requests only messages that it has not already accepted.

**Rule 3 — Complete messages only**

A `PUT` contains one complete logical message, including all its attachments.

The receiver either accepts the entire message or rejects it.

Partial messages are never accepted.

Interrupted transfers restart from scratch.

**Rule 4 — Receiver acknowledgement**

After accepting a message, the receiver sends an `ACK`.

The receiver decides what acceptance means internally. UMAI does not dictate storage or business processing, but the receiver must be able to remember accepted IDs across browser sessions for as long as they may be reoffered.

**Rule 5 — Repeated acknowledgements**

This rule is particularly important.

Whenever a sender offers a message that the receiver has already accepted, the receiver sends `ACK` again.

It must not request the message again.

This allows senders to clean up messages even when earlier acknowledgements were lost.

**Rule 6 — Sender cleanup**

The sender may remove a message from its outbox once it has received and locally processed the corresponding `ACK`.

It is allowed to retain the message longer.

**Rule 7 — Reconnection**

When the browser reconnects the applications, both sides exchange their outstanding offers again.

No special recovery protocol is necessary.

**Rule 8 — No autonomous background delivery**

Transfers occur only while an authorised browser session connects both applications.

Closing the browser stops the transport. A later session resumes reconciliation.

## 3. Minimal wire format

Use structured JavaScript objects transmitted by `postMessage` or `MessagePort`.

Every protocol message contains:

```javascript
{
  protocol: "UMAI",
  version: 1,
  type: "OFFER",
  ids: ["msg-001", "msg-002"]
}
```

Examples:

**OFFER**

```javascript
{
  protocol: "UMAI",
  version: 1,
  type: "OFFER",
  ids: ["msg-001", "msg-002"]
}
```

**GET**

```javascript
{
  protocol: "UMAI",
  version: 1,
  type: "GET",
  ids: ["msg-002"]
}
```

**PUT**

```javascript
{
  protocol: "UMAI",
  version: 1,
  type: "PUT",
  id: "msg-002",
  payload: {
    subject: "Example message",
    text: "Hello from application A"
  },
  attachments: [
    file1,
    file2
  ]
}
```

The attachments are native browser `File` objects.

Do not encode them as Base64.

**ACK**

```javascript
{
  protocol: "UMAI",
  version: 1,
  type: "ACK",
  ids: ["msg-002"]
}
```

The example IDs are illustrative. Real message IDs must be globally unique.

Keep the wire protocol as small as possible.

If message correlation, transport errors or capability negotiation require additional fields, introduce only the minimum necessary and document them.

An error before acceptance must never be interpreted as an ACK.

## 4. Browser transport

Implement UMAI over standard browser technologies:

- `iframe`
- `window.postMessage`
- `MessageChannel` / `MessagePort`
- Structured Clone Algorithm
- Native `File` and `Blob` objects

No third-party JavaScript libraries.

The applications must run on different domains.

For the demo:

- Application B is the host page.
- Application A is embedded inside B as an iframe.

Despite this deployment arrangement, the UMAI protocol and JavaScript library must be symmetric.

A and B must both be able to initiate exchanges and send or receive messages.

Establish the communication channel securely:

1. B loads the iframe containing A.
2. A announces readiness.
3. Both sides validate their configured peer origin and window identity.
4. Establish a `MessageChannel` where appropriate.
5. Begin bidirectional reconciliation.

Do not send documents before both applications are ready and the communication channel is validated.

Use exact configured origins, never a wildcard target origin for sensitive communication.

When testing locally on `localhost` vs `127.0.0.1`, browsers treat them as distinct origins. The handshake origin check should either recognize `localhost` and `127.0.0.1` as equivalent loopback origins on the matching port, or enforce consistent use of one loopback hostname across both applications.

Do not assume that iframe embedding grants access to the other application's DOM.

## 5. Two independent Go demo applications

Implement two fully functional web applications.

### Technology

- Go standard library only.
- Plain HTML.
- Vanilla JavaScript.
- Plain CSS.
- No frontend or backend frameworks.
- No external runtime dependencies.
- No database.
- No Docker.
- No frontend bundler.
- No Node.js requirement.

Each application must run as an independent Go executable.

Both may reuse shared Go code if this reduces duplication, but they must operate independently.

### Application A

Runs on configurable address, default:

`127.0.0.1:8081`

Provides:

- Web UI showing its own documents and messages.
- Local `docs/` directory.
- Local `outbox/` directory or equivalent simple storage.
- List, upload, download and delete documents.
- Create a new outgoing UMAI message.
- Attach one or multiple documents to a message.
- View received messages.
- Embedded iframe-compatible mode.
- Send and receive UMAI messages.

### Application B

Runs on configurable address, default:

`127.0.0.1:8082`

Provides the same functionality as A, plus a host page embedding A in an iframe.

Display both applications side by side, allowing the user to see the contents and synchronisation status of each.

### File storage

Use simple local directories. To ensure that both applications remain strictly isolated when run concurrently on the same machine from the repository root, each application must default to its own dedicated storage directory (for example, `./data-a` and `./data-b`), while remaining fully configurable via command-line flags or environment variables.

For example:

```text
data-a/ (or app-a/)
  docs/
  outbox/
  inbox/
  accepted.json

data-b/ (or app-b/)
  docs/
  outbox/
  inbox/
  accepted.json
```

Actual document files will be provided manually.

Do not generate large sample documents.

Outgoing message attachments must remain immutable after the message has been created. If necessary, copy selected documents into a message-specific snapshot directory.

Store accepted message IDs and outstanding messages in a simple, persistent way, such as JSON files on disk.

File and metadata updates should avoid obvious crash corruption, for example by writing temporary files followed by atomic rename where supported.

No database is necessary.

Keep file paths safe and prevent directory traversal.

If a received filename already exists, do not silently overwrite an unrelated document.

## 6. Sending and receiving

Each application must be able to:

1. Create an outgoing message.
2. Add arbitrary JSON metadata.
3. Attach one or more files.
4. Place the message in its outbox.
5. Announce the message via `OFFER`.
6. Respond to `GET`.
7. Send the complete message via `PUT`.
8. Accept incoming messages and store their attachments.
9. Send `ACK` after acceptance.
10. Repeat `ACK` for any previously accepted message offered again.
11. Remove acknowledged messages from the outbox.

The UI should make it easy to create messages in both A and B.

For simplicity, transfer only one `PUT` at a time per direction.

Do not implement attachment chunking or partial-transfer recovery in UMAI 0.1.

## 7. All-or-nothing acceptance

For the demo applications, receiving a message means:

- The entire JSON payload is available.
- All attachments are present.
- All files can be stored successfully.
- The accepted message ID is recorded.
- Only then is `ACK` sent.

Do not acknowledge partial transfers.

If the browser closes or a transfer fails before acceptance, the receiver must not treat the message as accepted.

The next synchronisation requests the whole message again.

Avoid exposing partially imported messages as completed.

The protocol itself must not prescribe the receiver's internal transaction implementation.

## 8. Automatic synchronisation

As soon as the user visits B's synchronisation page:

1. B loads A in an iframe.
2. Both applications initialise their UMAI adapters.
3. Once both are authenticated and ready, synchronisation begins automatically.
4. A offers its outstanding outgoing messages to B.
5. B offers its outstanding outgoing messages to A.
6. Both receivers request messages they have not accepted.
7. Messages and attachments are transferred.
8. Receivers acknowledge successful acceptance.
9. Both applications update their UI.

There must be no need to click a separate Synchronise button, although a manual Retry button is acceptable.

Whenever an application receives an `OFFER` (even an empty offer `ids: []`), if it has not yet offered its own outbox, it should symmetrically trigger its own `OFFER` in response. In addition, implementations should include a lightweight periodic reconciliation check (for example, every few seconds while connected) so that messages prepared while the remote application was still authenticating or logging in are automatically announced without manual intervention.

When the browser page is reopened, the applications automatically reconcile their outstanding messages again.

Both directions should work without requiring the user to choose a sender and receiver.

## 9. Simple demo authentication

Add a minimal authentication mechanism, especially for embedded application A.

Requirements:

- A supports a configurable demo username and password.
- Authentication is checked on the server.
- Use server-side sessions and secure cookies.
- If A is not authenticated, the embedded page shows a login option.
- If iframe authentication is blocked by browser cookie restrictions, provide a way to log in using a separate top-level browser tab.
- Once authentication is available in the embedded context, synchronisation can start.
- Do not share passwords, session cookies or authentication tokens through UMAI messages.

Keep authentication deliberately simple.

**Important cookie scoping rule (RFC 6265 § 8.5):**

In web browsers, cookies are scoped by host/domain, not by port number. When running both demo applications locally on the same host (such as `127.0.0.1:8081` and `127.0.0.1:8082`), using the same cookie name will cause one application's session cookie to overwrite the other's! Applications must use scoped cookie names (such as `umai_session_a` and `umai_session_b`) and/or provide session tokens via an explicit HTTP header (such as `X-UMAI-Session`). This also protects authentication when third-party cookies are blocked inside cross-origin iframes.

Document that cross-site cookie policies can prevent an existing top-level session from being available inside an iframe.

A working embedded authentication flow is desirable, but do not introduce a complex identity infrastructure just to overcome browser privacy restrictions.

If the browser prevents the intended flow, show a clear explanation rather than silently weakening security.

## 10. Security

The demo will be accessible over the internet, so do not leave obvious vulnerabilities.

Implement at least:

- Strict peer-origin allowlists.
- Source-window verification during channel establishment.
- Validation of protocol message types and input structure.
- Server-side authentication for protected operations.
- Filename sanitisation.
- Directory traversal protection.
- Maximum allowed attachment size configurable on the server.
- No arbitrary filesystem access.
- No uncontrolled cross-origin CORS access.
- No wildcard iframe embedding permissions.
- Reasonable upload and request limits.
- Protection against unintended duplicate processing.
- Explicit static asset MIME types (ensure `Content-Type: text/css; charset=utf-8` is served with `nosniff`, preventing strict browsers from rejecting stylesheets).
- Anti-cache headers (`Cache-Control: no-cache, no-store, must-revalidate`) during local development to avoid browsers serving stale cached stylesheets or Service Workers from other projects tested on the same local port.

Both applications must explicitly configure which other origin they trust.

UMAI must not treat possession of an iframe window reference as sufficient authorisation for unrestricted document access.

## 11. Deployment

The applications will run on the same VPS behind an existing Caddy reverse proxy.

Two different public domains will point to the same VPS.

Example:

```text
https://app-a.example.ch
    -> Caddy
    -> 127.0.0.1:8081

https://app-b.example.net
    -> Caddy
    -> 127.0.0.1:8082
```

These are different sites, not just different ports on the same domain.

All domains, origins, ports and local directories must be configurable using command-line arguments or environment variables.

Provide a minimal example Caddyfile.

TLS termination is handled by Caddy.

The Go servers can use local HTTP behind the reverse proxy.

Set the necessary `Content-Security-Policy` headers to permit A to be embedded by B.

Do not assume the two applications share cookies, local storage or browser origins.

## 12. User interface

Keep the interface simple, clean and functional.

No elaborate visual design.

Application B's main page should show:

**Left:** Application B
- Documents.
- Outbox messages.
- Received messages.
- Create message.

**Right:** Embedded Application A
- Documents.
- Outbox messages.
- Received messages.
- Create message.

Both sides should show:

- Whether the UMAI peer is connected.
- Number of outgoing messages.
- Number of received messages.
- Number of messages successfully acknowledged.
- Current synchronisation activity.
- Transfer errors, if any.

Provide an understandable progress indication.

Message-level progress is sufficient.

Do not implement elaborate byte-level transfer progress because native `postMessage(File)` does not provide reliable progress events.

## 13. Tests

Implement meaningful tests for the actual protocol behaviour.

At minimum, verify:

**Basic exchange**
- A sends a message to B.
- B sends a message to A.
- Messages with no attachments.
- Messages with multiple binary attachments.
- SHA-256 integrity of received attachments.

**Repeated acknowledgements**
- Receiver accepts a message.
- Initial ACK is deliberately suppressed.
- Sender offers the same message again.
- Receiver sends ACK again without requesting PUT.
- Sender removes the message from its outbox.

**Interrupted transfer**
- Interrupt before successful acceptance.
- Reconnect.
- Sender offers the message again.
- Receiver requests it again.
- Complete transfer succeeds.

**Duplicate prevention**
- Previously accepted message is offered again.
- Receiver does not import it twice.
- Receiver repeats ACK.

**Immutability**
- Sender cannot change an already prepared message while preserving the same message ID.

**Restart**
- Restart either Go server.
- Previously accepted message IDs and pending outgoing messages remain available.

**Browser tests**
- Chrome or Edge.
- Firefox, if practical.
- Cross-site iframe embedding.
- Authentication behaviour with third-party cookies disabled.

Large-file tests with 100 MB, 500 MB and 1 GB should be possible using user-provided files.

Do not automatically generate or commit large binary files.

Tests should make clear what was actually verified and what remains untested.

## 14. GitHub repository structure

Use a structure approximately like this:

```text
umai/
├── README.md
├── LICENSE
├── SPEC.md
├── SECURITY.md
├── .gitignore
├── js/
│   └── umai.js
├── examples/
│   ├── app-a/
│   │   ├── main.go
│   │   ├── static/
│   │   └── docs/
│   └── app-b/
│       ├── main.go
│       ├── static/
│       └── docs/
├── tests/
└── deploy/
    └── Caddyfile.example
```

Adjust the structure if a simpler layout is better.

Use Go's standard testing tools and avoid introducing test frameworks unnecessarily.

The repository should not contain real user documents, passwords, session data or generated binary files.

## 15. Documentation

### README.md

Explain:

- What UMAI is.
- The problem it solves.
- How the four-message protocol works.
- Why messages are immutable.
- Why repeated ACKs matter.
- How browser-mediated communication works.
- How to run the two demo applications.
- How to deploy behind Caddy.
- How to test bidirectional exchange.
- Known limitations.

Include a simple architectural diagram, preferably Mermaid.

### SPEC.md

Provide a concise, vendor-neutral UMAI 0.1 specification.

Define:

- Terminology.
- Message IDs.
- Immutable messages.
- `OFFER`, `GET`, `PUT`, `ACK`.
- Message structure and binary attachments.
- Acceptance and duplicate handling.
- Repeated ACK behaviour.
- Reconnection behaviour.
- Security expectations.
- Protocol versioning.

A developer must be able to implement an independent UMAI adapter from this document without reading the example source code.

Keep the specification short and precise.

### SECURITY.md

Document:

- Trust assumptions.
- Browser origin validation.
- Authentication boundaries.
- iframe and cookie limitations.
- Application-level authorisation.
- Large-file resource risks.
- Known limitations of this experimental implementation.

### Licence

Use MIT or Apache-2.0. Prefer MIT for simplicity.

Include the appropriate licence text.

## 16. Explicit non-goals

Do not implement:

- OpenAPI or AsyncAPI integration.
- REST-based server-to-server document exchange.
- Message brokers.
- Distributed transactions.
- Two-phase commit.
- Chunked or resumable partial-file transfers.
- Databases.
- WebSocket infrastructure.
- WebRTC.
- Docker.
- Kubernetes.
- React, Vue or other UI frameworks.
- npm packages or frontend build pipelines.
- Complex authentication infrastructure.
- Business-specific message semantics.
- Artificial abstractions intended for hypothetical future requirements.

Keep the protocol tiny and the implementation understandable.

## 17. Completion criteria

The assignment is complete when:

1. Both Go applications start independently.
2. Both serve real documents from their own local directories.
3. B embeds A from a different domain.
4. Both can create immutable messages with binary attachments.
5. Synchronisation starts automatically once the browser connection is ready.
6. Both directions work.
7. Received attachments are byte-identical to the originals.
8. Interrupted transfers can be retried from scratch.
9. Previously accepted messages are not imported twice.
10. Lost ACKs are recovered through repeated acknowledgements.
11. Go server restarts do not erase the relevant protocol state.
12. The repository contains a usable specification, tests and deployment instructions.
13. Everything runs without dependencies beyond Go, a modern browser and Caddy for public HTTPS deployment.

## 18. Development approach

Implement the smallest functioning end-to-end version first.

Suggested order:

1. Two Go servers with document directories.
2. Host/iframe communication.
3. Binary `File` transfer in both directions.
4. Four UMAI protocol messages.
5. Outbox and accepted-ID persistence.
6. Reconciliation and repeated ACK handling.
7. Simple UI.
8. Demo authentication.
9. Failure tests and documentation.

Prioritise working software over architectural elegance.

Do not introduce a generic abstraction unless the current implementation actually needs it.

Where browser restrictions prevent the intended behaviour, document the limitation rather than introducing a large workaround.

**Final objective:** A small, understandable, openly publishable reference implementation proving that independent web applications can exchange immutable messages and binary attachments reliably through an authenticated user's browser, without requiring direct server-to-server integrations.

The project should be small enough that another developer can understand its essential protocol in an afternoon.

## 19. Protocol independence, reliability testing and public release

### Protocol independence

UMAI must be defined independently of HTTP, Go, JavaScript, iframes or any particular implementation technology.

The four protocol operations (`OFFER`, `GET`, `PUT`, `ACK`), immutable messages, receiver-controlled delivery, repeated acknowledgements and reconnection semantics constitute the protocol.

The browser-based JavaScript implementation is UMAI's first transport binding, not the protocol itself.

`SPEC.md` must clearly distinguish between:

- The transport-independent UMAI core protocol.
- The browser transport binding using `postMessage`, `MessageChannel` and `File`/`Blob`.
- Application-specific responsibilities such as storage, authentication and business processing.

### Mandatory lost-ACK test

Implement a real end-to-end test demonstrating UMAI's repeated acknowledgement mechanism:

1. A sends a message to B.
2. B successfully accepts and records the message.
3. Deliberately suppress B's first ACK.
4. A retains the message in its outbox.
5. On the next synchronisation, A offers the same message again.
6. B recognises the previously accepted message ID.
7. B sends ACK again without requesting or receiving another PUT.
8. A processes the ACK and removes the message from its outbox.
9. Verify that B has accepted the message exactly once.

This must test actual protocol behaviour, not merely simulate the outcome in the UI.

### Public release

Prepare the repository for an initial public release named:

**UMAI 0.1 — Browser-Mediated Message Exchange**

Mark the release as experimental.

Avoid claiming production-grade exactly-once delivery, guaranteed background synchronisation or unrestricted browser interoperability.

Document verified capabilities, known limitations and remaining tests.

The goal is a minimal, understandable, vendor-neutral protocol with a working reference implementation that other developers can independently adopt and extend.
