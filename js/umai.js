/**
 * UMAI 0.1 — User-Mediated Application Interoperability
 * Reference JavaScript implementation of the UMAI core protocol and browser transport.
 *
 * Implements the four protocol messages:
 *   - OFFER (Sender -> Receiver): Announces available immutable message IDs
 *   - GET   (Receiver -> Sender): Requests messages not yet accepted
 *   - PUT   (Sender -> Receiver): Delivers complete message payload and File attachments
 *   - ACK   (Receiver -> Sender): Confirms acceptance of message IDs
 *
 * Adheres to all fundamental UMAI rules:
 *   - Immutability of messages
 *   - Receiver-controlled transfer
 *   - Complete messages only (no partial acceptance)
 *   - Receiver acknowledgement
 *   - Repeated acknowledgements for already-accepted messages
 *   - Sender cleanup upon ACK
 *   - Symmetrical operation (both peers can send and receive simultaneously)
 *
 * Transport: window.postMessage & MessageChannel / MessagePort with Structured Clone (File/Blob)
 * Zero third-party dependencies.
 */

(function (global) {
  'use strict';

  const PROTOCOL_NAME = 'UMAI';
  const PROTOCOL_VERSION = 1;
  const MAX_BATCH_IDS = 1000;
  const MAX_AUTO_RETRIES = 3;
  const DEFAULT_GET_TIMEOUT_MS = 120000;
  const DEFAULT_LOOKUP_MIN_INTERVAL_MS = 20;
  const DEFAULT_LOOKUP_RETRY_BASE_MS = 500;
  const DEFAULT_LOOKUP_RETRY_MAX_MS = 30000;
  const DEFAULT_MAX_CONCURRENCY = 1;
  const MAX_CONCURRENCY_CAP = 16;
  const DEFAULT_MAX_ATTACHMENTS = 50;
  const DEFAULT_MAX_MESSAGE_BYTES = 50 * 1024 * 1024;
  const MAX_SIGNATURE_LEN = 4096;
  const MAX_JSON_DEPTH = 64;
  const MESSAGE_ID_REGEX = /^[a-zA-Z0-9._-]{1,128}$/;

  /**
   * Validates a message identifier against the SPEC.md normative grammar:
   * 1..128 ASCII characters in [a-zA-Z0-9._-], excluding ".", "..", and any ".." sequence.
   */
  function isValidMessageId(id) {
    return (
      typeof id === 'string' &&
      id.length >= 1 &&
      id.length <= 128 &&
      id !== '.' &&
      id !== '..' &&
      !id.includes('..') &&
      MESSAGE_ID_REGEX.test(id)
    );
  }

  /**
   * Validates whether an incoming object is a valid UMAI message envelope.
   */
  function isValidUmaiMessage(data) {
    return (
      data &&
      typeof data === 'object' &&
      data.protocol === PROTOCOL_NAME &&
      data.version === PROTOCOL_VERSION &&
      typeof data.type === 'string'
    );
  }

  /**
   * Parses and validates a concrete HTTP(S) origin string, rejecting wildcards ('*'),
   * opaque ('null') origins, and non-HTTP(S) schemes.
   */
  function parseHttpOrigin(originStr) {
    if (typeof originStr !== 'string' || !originStr || originStr === '*' || originStr === 'null') {
      return null;
    }
    try {
      const u = new URL(originStr);
      if ((u.protocol !== 'http:' && u.protocol !== 'https:') || !u.host || u.origin === 'null') {
        return null;
      }
      return u;
    } catch (e) {
      return null;
    }
  }

  /**
   * Validates whether incoming origin strictly equals expected origin (HTTP/HTTPS only).
   */
  function isAllowedOrigin(incomingOrigin, expectedOrigin) {
    const inc = parseHttpOrigin(incomingOrigin);
    const exp = parseHttpOrigin(expectedOrigin);
    if (!inc || !exp) return false;
    return inc.origin === exp.origin;
  }

  /**
   * Validates an attachment entry is a native File/Blob instance with a non-negative finite byte size.
   */
  function isValidAttachment(att) {
    if (typeof Blob === 'undefined' || !att || !(att instanceof Blob)) {
      return false;
    }
    return typeof att.size === 'number' && Number.isFinite(att.size) && att.size >= 0;
  }

  /**
   * Recursively verifies that a value is a strict, tree-shaped JSON-representable value
   * (null, boolean, finite number, string, plain Array, or plain Object up to MAX_JSON_DEPTH):
   * - Rejects structured-clone non-JSON types (Blob, File, ArrayBuffer, TypedArray, Date, RegExp,
   *   Map, Set), accessor properties, circular references, and shared object/array references (DAGs).
   * - Accumulates a strict lower bound on UTF-8 JSON byte length (`budget.bytes <= budget.maxBytes`)
   *   so oversized payloads abort during traversal before `JSON.stringify()` allocates large strings.
   */
  function isStrictJsonValue(
    val,
    depth = 0,
    seenObjects = new Set(),
    budget = { bytes: 0, maxBytes: MAX_MESSAGE_BYTES, steps: 0, maxSteps: MAX_MESSAGE_BYTES + 1024 }
  ) {
    if (depth > MAX_JSON_DEPTH || ++budget.steps > budget.maxSteps) {
      return false;
    }
    if (val === null) {
      budget.bytes += 4;
      return budget.bytes <= budget.maxBytes;
    }
    const t = typeof val;
    if (t === 'boolean') {
      budget.bytes += val ? 4 : 5;
      return budget.bytes <= budget.maxBytes;
    }
    if (t === 'string') {
      budget.bytes += val.length + 2;
      return budget.bytes <= budget.maxBytes;
    }
    if (t === 'number') {
      if (!Number.isFinite(val)) {
        return false;
      }
      budget.bytes += String(val).length;
      return budget.bytes <= budget.maxBytes;
    }
    if (t !== 'object') {
      return false;
    }

    // Reject both circular references and shared-reference DAG amplification
    if (seenObjects.has(val)) {
      return false;
    }
    seenObjects.add(val);

    if (Array.isArray(val)) {
      const keys = Object.keys(val);
      if (keys.length !== val.length) {
        return false;
      }
      budget.bytes += 2 + (val.length > 1 ? val.length - 1 : 0);
      if (budget.bytes > budget.maxBytes) {
        return false;
      }
      for (let i = 0; i < val.length; i++) {
        const desc = Object.getOwnPropertyDescriptor(val, i);
        if (!desc || !Object.prototype.hasOwnProperty.call(desc, 'value')) {
          return false;
        }
        if (!isStrictJsonValue(desc.value, depth + 1, seenObjects, budget)) {
          return false;
        }
      }
      return true;
    }

    const proto = Object.getPrototypeOf(val);
    if (proto !== Object.prototype && proto !== null) {
      return false;
    }

    budget.bytes += 2;
    if (budget.bytes > budget.maxBytes) {
      return false;
    }

    const keys = Object.keys(val);
    let emittedProps = 0;
    for (let i = 0; i < keys.length; i++) {
      if (++budget.steps > budget.maxSteps) {
        return false;
      }
      const k = keys[i];
      const desc = Object.getOwnPropertyDescriptor(val, k);
      if (!desc || !Object.prototype.hasOwnProperty.call(desc, 'value')) {
        return false;
      }
      if (desc.value === undefined) {
        continue;
      }
      budget.bytes += (emittedProps > 0 ? 1 : 0) + k.length + 3;
      if (budget.bytes > budget.maxBytes) {
        return false;
      }
      emittedProps++;
      if (!isStrictJsonValue(desc.value, depth + 1, seenObjects, budget)) {
        return false;
      }
    }
    return true;
  }

  /**
   * Measures the UTF-8 byte length of a string.
   */
  function utf8ByteLength(str) {
    if (typeof TextEncoder !== 'undefined') {
      return new TextEncoder().encode(str).byteLength;
    }
    if (typeof Buffer !== 'undefined') {
      return Buffer.byteLength(str, 'utf8');
    }
    return str.length;
  }

  /**
   * Validates strict tree-shaped JSON payload types, normalizes the payload via JSON round-trip so the
   * exact measured JSON representation is forwarded, and validates payload + attachment sizes/counts
   * against maxAttachments and maxMessageBytes.
   * Returns { totalBytes, normalizedPayload } or null if invalid or exceeding bounds.
   */
  function normalizeAndValidateMessage(payload, attachments, maxAttachments, maxMessageBytes) {
    if (!Array.isArray(attachments) || attachments.length > maxAttachments) {
      return null;
    }

    let attachmentBytes = 0;
    for (let i = 0; i < attachments.length; i++) {
      const att = attachments[i];
      if (!isValidAttachment(att)) {
        return null;
      }
      attachmentBytes += att.size;
      if (attachmentBytes > maxMessageBytes) {
        return null;
      }
    }

    const maxPayloadBytes = maxMessageBytes - attachmentBytes;
    const candidate = (payload !== undefined && payload !== null) ? payload : {};
    const budget = {
      bytes: 0,
      maxBytes: maxPayloadBytes,
      steps: 0,
      maxSteps: maxPayloadBytes + 1024
    };
    if (!isStrictJsonValue(candidate, 0, new Set(), budget)) {
      return null;
    }

    let jsonStr;
    try {
      jsonStr = JSON.stringify(candidate);
    } catch (e) {
      return null;
    }
    if (typeof jsonStr !== 'string') {
      return null;
    }

    const payloadBytes = utf8ByteLength(jsonStr);
    if (payloadBytes < 0 || payloadBytes > maxPayloadBytes) {
      return null;
    }

    const totalBytes = attachmentBytes + payloadBytes;

    let normalizedPayload;
    try {
      normalizedPayload = JSON.parse(jsonStr);
    } catch (e) {
      return null;
    }

    return {
      totalBytes,
      normalizedPayload
    };
  }

  /**
   * Normalizes an adapter acceptMessage(msg) response ({ accepted: boolean, ackReceipt?: string } or boolean).
   * Requires an explicit boolean `true` or `{ accepted: true }` (never truthy strings or numbers).
   */
  function parseAcceptanceResult(res) {
    if (typeof res === 'boolean') {
      return { accepted: res, ackReceipt: '' };
    }
    if (res && typeof res === 'object' && !Array.isArray(res) && typeof res.accepted === 'boolean') {
      const rawReceipt = typeof res.ackReceipt === 'string'
        ? res.ackReceipt
        : (typeof res.ack_receipt === 'string' ? res.ack_receipt : '');
      const ackReceipt = rawReceipt.length <= MAX_SIGNATURE_LEN ? rawReceipt : '';
      return { accepted: res.accepted, ackReceipt: res.accepted ? ackReceipt : '' };
    }
    return {
      accepted: false,
      ackReceipt: ''
    };
  }

  /**
   * Strictly validates a single ID's entry from getAcceptance(ids):
   * Must be a plain object with an explicit boolean `accepted` field and optional string `ackReceipt` / `ack_receipt`.
   * Missing or malformed entries return { valid: false } so they never trigger a false ACK or false GET.
   */
  function parseAcceptanceEntry(entry) {
    if (!entry || typeof entry !== 'object' || Array.isArray(entry) || typeof entry.accepted !== 'boolean') {
      return { valid: false, accepted: false, ackReceipt: '' };
    }
    const proto = Object.getPrototypeOf(entry);
    if (proto !== Object.prototype && proto !== null) {
      return { valid: false, accepted: false, ackReceipt: '' };
    }
    let ackReceipt = '';
    if (entry.ackReceipt !== undefined) {
      if (typeof entry.ackReceipt !== 'string' || entry.ackReceipt.length > MAX_SIGNATURE_LEN) {
        return { valid: false, accepted: false, ackReceipt: '' };
      }
      ackReceipt = entry.ackReceipt;
    } else if (entry.ack_receipt !== undefined) {
      if (typeof entry.ack_receipt !== 'string' || entry.ack_receipt.length > MAX_SIGNATURE_LEN) {
        return { valid: false, accepted: false, ackReceipt: '' };
      }
      ackReceipt = entry.ack_receipt;
    }
    return {
      valid: true,
      accepted: entry.accepted,
      ackReceipt: entry.accepted ? ackReceipt : ''
    };
  }

  /**
   * Validates the complete batch response from storage.getAcceptance(queryIds).
   * Requires `batchRes` to be a plain ID-keyed object (Object.prototype or null prototype) containing
   * an explicit `{ accepted: boolean, ackReceipt?: string }` own-property entry for EVERY requested ID.
   * If `batchRes` is not a plain object, or ANY requested ID is missing or malformed, the entire batch
   * fails validation (returning null) so partial/corrupt responses never trigger false ACKs or false GETs.
   */
  function validateBatchAcceptance(batchRes, queryIds) {
    if (!batchRes || typeof batchRes !== 'object' || Array.isArray(batchRes)) {
      return null;
    }
    const proto = Object.getPrototypeOf(batchRes);
    if (proto !== Object.prototype && proto !== null) {
      return null;
    }
    const normalized = Object.create(null);
    for (let i = 0; i < queryIds.length; i++) {
      const id = queryIds[i];
      if (!Object.prototype.hasOwnProperty.call(batchRes, id)) {
        return null;
      }
      const parsed = parseAcceptanceEntry(batchRes[id]);
      if (!parsed.valid) {
        return null;
      }
      normalized[id] = {
        accepted: parsed.accepted,
        ackReceipt: parsed.ackReceipt
      };
    }
    return normalized;
  }

  /**
   * Main UMAI Session Adapter.
   */
  class UmaiSession {
    /**
     * @param {Object} options
     * @param {string} options.peerOrigin Expected concrete HTTP(S) origin of the remote application (e.g. 'http://127.0.0.1:8081')
     * @param {string} [options.role] 'host' or 'embedded' (auto-detected if omitted)
     * @param {HTMLIFrameElement} [options.iframe] The iframe element (for 'host' role when using iframe embedding)
     * @param {Window} [options.peerWindow] Optional direct Window reference (e.g. popup from window.open or window.opener)
     * @param {number} [options.maxConcurrency=1] Controlled concurrency limit for in-flight PUT transfers per direction (1..16)
     * @param {number} [options.maxAttachments=50] Maximum attachments permitted per message
     * @param {number} [options.maxMessageBytes=52428800] Maximum total message byte size (JSON payload + attachments, default 50 MB)
     * @param {number} [options.getTimeoutMs=120000] Timeout (ms) before an unanswered GET releases its active slot for other messages
     * @param {number} [options.lookupMinIntervalMs=20] Minimum pacing interval (ms) between consecutive getAcceptance() batches under offer floods
     * @param {number} [options.lookupRetryBaseMs=500] Initial retry delay (ms) for transient getAcceptance() lookup failures
     * @param {number} [options.lookupRetryMaxMs=30000] Maximum capped backoff delay (ms) for repeated getAcceptance() lookup failures
     * @param {Object} options.storage Handlers for reading/writing local messages:
     *   - getOutboxIds(): Promise<string[]>
     *   - getMessage(id): Promise<{ id: string, payload: any, attachments: File[], signature?: string }>
     *   - getAcceptance(ids: string[]): Promise<Record<string, { accepted: boolean, ackReceipt?: string }>>
     *   - acceptMessage(msg: { id: string, payload: any, attachments: File[], signature?: string }): Promise<{ accepted: boolean, ackReceipt?: string } | boolean>
     *   - onAcknowledged(ids: string[], receipts?: Record<string, string>): Promise<void>
     * @param {Function} [options.onStatusChange] Callback: ({ state, detail }) => void
     * @param {Function} [options.onLog] Callback: ({ level, message, details }) => void
     * @param {Function} [options.onError] Callback: (error) => void
     * @param {Function} [options.onTransfer] Callback: ({ direction, type, id, info }) => void
     */
    constructor(options) {
      if (!options || !options.peerOrigin) {
        throw new Error('UMAI: peerOrigin is required');
      }
      const parsedPeerOrigin = parseHttpOrigin(options.peerOrigin);
      if (!parsedPeerOrigin) {
        throw new Error('UMAI: peerOrigin must be a valid concrete http:// or https:// origin (wildcards are forbidden)');
      }
      if (!options.storage || typeof options.storage.getAcceptance !== 'function') {
        throw new Error('UMAI: storage interface with getAcceptance(ids) is required');
      }

      this.peerOrigin = parsedPeerOrigin.origin;
      this.maxConcurrency = (typeof options.maxConcurrency === 'number' && options.maxConcurrency >= 1)
        ? Math.min(Math.floor(options.maxConcurrency), MAX_CONCURRENCY_CAP)
        : DEFAULT_MAX_CONCURRENCY;
      this.maxAttachments = (typeof options.maxAttachments === 'number' && options.maxAttachments >= 0)
        ? Math.floor(options.maxAttachments)
        : DEFAULT_MAX_ATTACHMENTS;
      this.maxMessageBytes = (typeof options.maxMessageBytes === 'number' && options.maxMessageBytes >= 0)
        ? Math.floor(options.maxMessageBytes)
        : DEFAULT_MAX_MESSAGE_BYTES;
      this.getTimeoutMs = (typeof options.getTimeoutMs === 'number' && Number.isFinite(options.getTimeoutMs) && options.getTimeoutMs >= 10)
        ? Math.floor(options.getTimeoutMs)
        : DEFAULT_GET_TIMEOUT_MS;
      this.lookupMinIntervalMs = (typeof options.lookupMinIntervalMs === 'number' && Number.isFinite(options.lookupMinIntervalMs) && options.lookupMinIntervalMs >= 0)
        ? Math.floor(options.lookupMinIntervalMs)
        : DEFAULT_LOOKUP_MIN_INTERVAL_MS;
      this.lookupRetryBaseMs = (typeof options.lookupRetryBaseMs === 'number' && Number.isFinite(options.lookupRetryBaseMs) && options.lookupRetryBaseMs >= 10)
        ? Math.floor(options.lookupRetryBaseMs)
        : DEFAULT_LOOKUP_RETRY_BASE_MS;
      this.lookupRetryMaxMs = (typeof options.lookupRetryMaxMs === 'number' && Number.isFinite(options.lookupRetryMaxMs) && options.lookupRetryMaxMs >= this.lookupRetryBaseMs)
        ? Math.floor(options.lookupRetryMaxMs)
        : Math.max(this.lookupRetryBaseMs, DEFAULT_LOOKUP_RETRY_MAX_MS);

      this.storage = options.storage;
      this.onStatusChange = options.onStatusChange || (() => {});
      this.onSyncStatus = options.onSyncStatus || (() => {});
      this.onLog = options.onLog || (() => {});
      this.onError = options.onError || (() => {});
      this.onTransfer = options.onTransfer || (() => {});

      this.iframe = options.iframe || null;
      this.peerWindow = options.peerWindow || null;
      const isChildContext = typeof window !== 'undefined' && ((window.parent && window.parent !== window) || !!window.opener);
      this.role = options.role || (isChildContext && !this.iframe && !this.peerWindow ? 'embedded' : 'host');

      this._conn = null;
      this._lifecycleSeq = 0;
      this._stopped = false;
      this.state = 'disconnected'; // 'disconnected' | 'handshaking' | 'connected'
      this._windowListener = this._handleWindowMessage.bind(this);
      this._windowListenerRegistered = false;
      this._syncInterval = null;
      this._readyInterval = null;
    }

    /**
     * Active MessagePort for the current connection, or null when not attached.
     * Assigning a port attaches a fresh isolated connection object; assigning null closes any active connection.
     */
    get port() {
      return this._conn ? this._conn.port : null;
    }

    set port(newPort) {
      if (newPort) {
        this._attachConnection(newPort);
      } else {
        this._resetChannelState();
      }
    }

    /**
     * Connection-pinned MessagePort listener for the currently attached connection.
     */
    get _portListener() {
      return this._conn ? this._conn.portListener : (() => {});
    }

    /**
     * Creates an isolated per-connection state record owning all mutable channel queues,
     * reservations, retry counters, worker flags, and timers for a single MessagePort.
     */
    _createConnection(port) {
      const conn = {
        closed: false,
        port: port,
        portListener: null,
        peerOfferedOnce: false,

        // Outgoing PUT queue and active worker tracking
        putQueue: [],
        activePuttingIds: new Set(),
        activeSendCount: 0,

        // Coalesced incoming ACK queue and single-worker tracking
        pendingAcks: new Map(),
        activeAckBatchSet: new Set(),
        processingAcks: false,

        // Serialized outbox reconciliation state
        reconciling: false,
        reconcilePending: false,
        reconcileForcePending: false,
        reconcilePromise: null,
        ackedDuringOutboxRead: new Set(),

        // Coalesced incoming OFFER queue, in-flight lookup reservation, deferred unaccepted overflow, and single-worker state
        pendingOfferIds: new Set(),
        inFlightLookupIds: new Set(),
        deferredOfferIds: new Set(),
        processingOffers: false,
        lastLookupStartedAt: 0,
        lookupFailureCount: 0,
        nextLookupAllowedAt: 0,
        lookupTimer: null,

        // Receiver GET windowing queue, active reservations, and bounded expired reservation history
        pendingGetQueue: [],
        inFlightGets: new Map(),
        expiredGets: new Set(),
        timedOutGets: new Map(),
        getExpiryTimer: null,

        // Track message IDs currently being committed in acceptMessage() and queue incoming PUTs up to maxConcurrency
        acceptingIds: new Set(),
        incomingPutQueue: [],
        activeAcceptCount: 0,

        // Track message IDs offered to the peer (bounded to MAX_BATCH_IDS)
        offeredIds: new Set(),

        // Bounded per-ID connection retry cutoff counter for rejected/corrupt PUT messages (<= MAX_BATCH_IDS)
        failedAttempts: new Map()
      };
      conn.portListener = (event) => this._handlePortMessage(event, conn);
      return conn;
    }

    /**
     * Closes any prior connection and attaches a fresh connection object for `port`.
     */
    _attachConnection(port) {
      if (this._conn) {
        this._closeConnection(this._conn);
        this._conn = null;
      }
      const conn = this._createConnection(port);
      this._conn = conn;
      port.onmessage = conn.portListener;
      return conn;
    }

    /**
     * Explicitly marks `conn` closed, cancels its timers, and detaches/closes its MessagePort
     * so no further frames, callbacks, timers, or storage work can proceed on `conn`.
     */
    _closeConnection(conn) {
      if (!conn) {
        return;
      }
      conn.closed = true;
      if (conn.getExpiryTimer) {
        clearTimeout(conn.getExpiryTimer);
        conn.getExpiryTimer = null;
      }
      if (conn.lookupTimer) {
        clearTimeout(conn.lookupTimer);
        conn.lookupTimer = null;
      }
      if (conn.port) {
        const port = conn.port;
        conn.port = null;
        try {
          port.onmessage = null;
          port.close();
        } catch (e) {
          // ignore close errors
        }
      }
      if (this._conn === conn) {
        this._conn = null;
      }
    }

    /**
     * Resolves the target Window for handshake messages (supports both iframe and top-level popup/opener windows).
     */
    _getTargetWindow() {
      if (this.peerWindow && !this.peerWindow.closed) {
        return this.peerWindow;
      }
      if (this.role === 'host') {
        return (this.iframe && this.iframe.contentWindow) ? this.iframe.contentWindow : null;
      }
      if (typeof window !== 'undefined') {
        if (window.parent && window.parent !== window) {
          return window.parent;
        }
        if (window.opener && !window.opener.closed) {
          return window.opener;
        }
      }
      return null;
    }

    /**
     * Dynamically bind or update a peer Window reference (e.g., after opening a top-level companion popup via window.open)
     * and initiate the handshake.
     * @param {Window} win
     */
    setPeerWindow(win) {
      const nextWin = (win && !win.closed) ? win : null;
      if (this.peerWindow === nextWin) return;
      this.peerWindow = nextWin;
      const wasActive = this.state !== 'disconnected';
      this._resetChannelState();
      if (wasActive) {
        const seq = this._lifecycleSeq;
        this._setState('handshaking', this.peerWindow ? 'Switching to companion window' : 'Switching to embedded iframe');
        if (!this._isSameLifecycle(seq)) return;
        if (this.role === 'host' && this._getTargetWindow()) {
          this._initiateHostHandshake(null, seq);
        }
      }
    }

    /**
     * Returns true if the session is still in the same non-stopped pre-connection lifecycle sequence
     * (used across startup/handshaking callbacks before a connection object is established).
     */
    _isSameLifecycle(seq) {
      return this._lifecycleSeq === seq && !this._stopped && this.state !== 'disconnected';
    }

    /**
     * Returns true if `conn` is still the active, unclosed connected channel for this session.
     */
    _isActiveConn(conn) {
      return Boolean(
        conn &&
        !conn.closed &&
        this._conn === conn &&
        this.state === 'connected' &&
        conn.port !== null
      );
    }

    /**
     * Safe callback wrappers so exceptions or session mutations inside user callbacks
     * never corrupt internal worker flags or counters.
     */
    _emitStatusChange(info) {
      try {
        this.onStatusChange(info);
      } catch (err) {
        // ignore user callback exception
      }
    }

    _emitSyncStatus(info) {
      try {
        this.onSyncStatus(info);
      } catch (err) {
        // ignore user callback exception
      }
    }

    _emitError(err) {
      try {
        this.onError(err);
      } catch (cbErr) {
        // ignore user callback exception
      }
    }

    _emitTransfer(info) {
      try {
        this.onTransfer(info);
      } catch (err) {
        // ignore user callback exception
      }
    }

    /**
     * Inserts or updates an entry in a Map bounded to MAX_BATCH_IDS (evicting the oldest entry if full).
     */
    _setBoundedMap(map, key, value) {
      if (map.has(key)) {
        map.delete(key);
      } else if (map.size >= MAX_BATCH_IDS) {
        const oldestKey = map.keys().next().value;
        if (oldestKey !== undefined) {
          map.delete(oldestKey);
        }
      }
      map.set(key, value);
    }

    /**
     * Advances the pre-connection lifecycle sequence and explicitly closes the active connection (if any),
     * cancelling its timers and closing its MessagePort while leaving its private containers isolated from future connections.
     */
    _resetChannelState() {
      this._lifecycleSeq++;
      if (this._conn) {
        this._closeConnection(this._conn);
        this._conn = null;
      }
    }

    /**
     * Schedules a wakeup timer for the earliest expiring active GET reservation on `conn` so stalled slots
     * are freed promptly for other waiting messages even when idle.
     */
    _scheduleGetExpiryTimer(conn = this._conn) {
      if (!conn) {
        return;
      }
      if (conn.getExpiryTimer) {
        clearTimeout(conn.getExpiryTimer);
        conn.getExpiryTimer = null;
      }
      if (!this._isActiveConn(conn) || conn.inFlightGets.size === 0) {
        return;
      }

      let earliestTs = Infinity;
      for (const ts of conn.inFlightGets.values()) {
        if (ts < earliestTs) {
          earliestTs = ts;
        }
      }
      const delayMs = Math.max(5, (earliestTs + this.getTimeoutMs) - Date.now() + 2);
      const timer = setTimeout(() => {
        conn.getExpiryTimer = null;
        if (!this._isActiveConn(conn)) {
          return;
        }
        const freed = this._pruneExpiredGets(conn);
        if (freed > 0) {
          this._notifySyncStatus();
          this._dispatchNextGets(conn);
        }
        this._scheduleGetExpiryTimer(conn);
      }, delayMs);
      if (timer && typeof timer.unref === 'function') {
        timer.unref();
      }
      conn.getExpiryTimer = timer;
    }

    /**
     * Demotes expired active GET reservations from conn.inFlightGets so they no longer occupy
     * an active concurrency slot:
     *   - Moves the ID into bounded conn.expiredGets (<= MAX_BATCH_IDS) so a slow legitimate PUT
     *     that arrives later can still be accepted if a concurrency slot is free.
     *   - Appends the ID to the tail of conn.pendingGetQueue (behind other waiting messages, up to
     *     MAX_AUTO_RETRIES timeouts) so a permanently unresponsive ID never blocks progress.
     */
    _pruneExpiredGets(conn = this._conn) {
      if (!conn || conn.closed) {
        return 0;
      }
      const now = Date.now();
      let freed = 0;
      for (const [id, ts] of Array.from(conn.inFlightGets.entries())) {
        if (now - ts >= this.getTimeoutMs) {
          conn.inFlightGets.delete(id);
          freed++;

          if (!conn.expiredGets.has(id)) {
            if (conn.expiredGets.size >= MAX_BATCH_IDS) {
              const oldest = conn.expiredGets.values().next().value;
              conn.expiredGets.delete(oldest);
            }
            conn.expiredGets.add(id);
          }

          const timeouts = (conn.timedOutGets.get(id) || 0) + 1;
          this._setBoundedMap(conn.timedOutGets, id, timeouts);

          const totalOutstanding = conn.pendingGetQueue.length + conn.inFlightGets.size + conn.acceptingIds.size;
          if (
            timeouts < MAX_AUTO_RETRIES &&
            (conn.failedAttempts.get(id) || 0) < MAX_AUTO_RETRIES &&
            !conn.acceptingIds.has(id) &&
            !conn.pendingGetQueue.includes(id) &&
            totalOutstanding < MAX_BATCH_IDS
          ) {
            conn.pendingGetQueue.push(id);
          }
        }
      }
      return freed;
    }

    /**
     * Log a protocol event safely.
     */
    log(level, message, details = null) {
      try {
        this.onLog({ level, message, details, timestamp: new Date().toISOString() });
      } catch (err) {
        // ignore user callback exception
      }
    }

    /**
     * Update adapter connection state.
     */
    _setState(newState, detail = '') {
      this.state = newState;
      this._emitStatusChange({ state: newState, detail });
      this.log('info', `State changed: ${newState} ${detail ? `(${detail})` : ''}`);
      this._notifySyncStatus(detail);
    }

    /**
     * Computes outgoing and incoming pending work counts for the active connection (or zero when unattached).
     */
    _computeSyncCounts() {
      const conn = this._conn;
      if (!conn || conn.closed) {
        return { pendingOutgoing: 0, pendingIncoming: 0 };
      }
      this._pruneExpiredGets(conn);
      const ackPending = conn.pendingAcks.size + conn.activeAckBatchSet.size;
      const pendingOutgoing = conn.putQueue.length + conn.activeSendCount + ackPending;
      const pendingIncoming =
        conn.pendingOfferIds.size +
        conn.deferredOfferIds.size +
        (conn.processingOffers ? 1 : 0) +
        conn.pendingGetQueue.length +
        conn.inFlightGets.size +
        conn.acceptingIds.size;
      return { pendingOutgoing, pendingIncoming };
    }

    /**
     * Broadcast real-time synchronization status (transfers ongoing vs complete sync).
     */
    _notifySyncStatus(detail = '') {
      const { pendingOutgoing, pendingIncoming } = this._computeSyncCounts();
      const isSyncing = pendingOutgoing > 0 || pendingIncoming > 0;
      const info = {
        isSyncing: isSyncing,
        state: this.state,
        pendingOutgoing: pendingOutgoing,
        pendingIncoming: pendingIncoming,
        detail: detail || (isSyncing ? 'Synchronizing...' : (this.state === 'connected' ? 'In sync' : ''))
      };
      this._emitSyncStatus(info);
    }

    /**
     * Get snapshot of current synchronization status.
     */
    getSyncStatus() {
      const { pendingOutgoing, pendingIncoming } = this._computeSyncCounts();
      const isSyncing = pendingOutgoing > 0 || pendingIncoming > 0;
      return {
        isSyncing: isSyncing,
        state: this.state,
        pendingOutgoing: pendingOutgoing,
        pendingIncoming: pendingIncoming
      };
    }

    /**
     * Start the UMAI adapter and initiate handshake with peer.
     * Idempotent when already connected or handshaking so redundant start() calls never disrupt an active channel.
     */
    start() {
      if (this.state === 'connected' || this.state === 'handshaking') return;

      this._stopped = false;
      const seq = this._lifecycleSeq;
      this._setState('handshaking', `Starting as ${this.role}`);
      if (!this._isSameLifecycle(seq)) {
        return;
      }

      if (typeof window !== 'undefined' && window.addEventListener && !this._windowListenerRegistered) {
        window.addEventListener('message', this._windowListener);
        this._windowListenerRegistered = true;
      }

      // Start periodic reconciliation heartbeat once connected
      if (!this._syncInterval) {
        this._syncInterval = setInterval(() => {
          if (this.state === 'connected') {
            this.reconcile(false);
          }
        }, 3000);
        if (this._syncInterval && typeof this._syncInterval.unref === 'function') {
          this._syncInterval.unref();
        }
      }

      if (this.role === 'embedded') {
        // Embedded app informs parent window that it is ready
        this._sendReadySignal();
        // Periodically announce ready until parent responds with INIT
        if (!this._readyInterval) {
          this._readyInterval = setInterval(() => {
            if (this.state === 'connected' || this.state === 'disconnected') {
              clearInterval(this._readyInterval);
              this._readyInterval = null;
              return;
            }
            this._sendReadySignal();
          }, 1000);
          if (this._readyInterval && typeof this._readyInterval.unref === 'function') {
            this._readyInterval.unref();
          }
        }
      } else {
        // Host role: if target window (iframe or popup) is already available, we can initiate
        if (this._getTargetWindow()) {
          this._initiateHostHandshake(null, seq);
        }
      }
    }

    /**
     * Stop and cleanup session, explicitly closing the active connection and invalidating in-flight operations.
     */
    stop() {
      this._stopped = true;
      if (this._syncInterval) {
        clearInterval(this._syncInterval);
        this._syncInterval = null;
      }
      if (this._readyInterval) {
        clearInterval(this._readyInterval);
        this._readyInterval = null;
      }
      if (typeof window !== 'undefined' && window.removeEventListener && this._windowListenerRegistered) {
        window.removeEventListener('message', this._windowListener);
        this._windowListenerRegistered = false;
      }
      this._resetChannelState();
      this._setState('disconnected');
    }

    /**
     * Send READY signal from embedded/popup window to host (parent or opener).
     */
    _sendReadySignal() {
      const targetWin = this._getTargetWindow();
      if (targetWin && (typeof window === 'undefined' || targetWin !== window)) {
        try {
          targetWin.postMessage(
            { protocol: PROTOCOL_NAME, version: PROTOCOL_VERSION, type: 'READY' },
            this.peerOrigin
          );
        } catch (err) {
          this.log('error', 'Failed to send READY signal', err.message);
        }
      }
    }

    /**
     * Host initializes MessageChannel and posts port2 to peer window (iframe or popup).
     */
    _initiateHostHandshake(targetOrigin = null, expectedSeq = null) {
      if (expectedSeq !== null && !this._isSameLifecycle(expectedSeq)) {
        return;
      }
      const targetWin = this._getTargetWindow();
      if (!targetWin) {
        this.log('warn', 'Cannot initiate handshake: target window (iframe or peerWindow) missing');
        return;
      }

      const destOrigin = targetOrigin || this.peerOrigin;
      if (!isAllowedOrigin(destOrigin, this.peerOrigin)) {
        this.log('error', `Refusing to initiate handshake with disallowed origin: ${destOrigin}`);
        return;
      }

      try {
        this._resetChannelState();
        const channel = new MessageChannel();
        this._attachConnection(channel.port1);

        targetWin.postMessage(
          { protocol: PROTOCOL_NAME, version: PROTOCOL_VERSION, type: 'INIT' },
          destOrigin,
          [channel.port2]
        );

        this.log('info', `Sent INIT and MessagePort to peer application (${destOrigin})`);
      } catch (err) {
        this.log('error', 'Error creating MessageChannel/sending port', err.message);
        this._emitError(err);
      }
    }

    /**
     * Top-level window message handler (used for the initial secure handshake).
     */
    _handleWindowMessage(event) {
      if (this._stopped) {
        return;
      }

      // Validate origin strictly
      if (!isAllowedOrigin(event.origin, this.peerOrigin)) {
        return;
      }

      const data = event.data;
      if (!isValidUmaiMessage(data)) {
        return;
      }

      const expectedSource = this._getTargetWindow();
      // Fail-closed window binding: both host and embedded roles must know their target window
      // in advance (iframe.contentWindow, peerWindow, window.parent, or window.opener), and
      // event.source must strictly equal expectedSource. Never auto-adopt an unknown window.
      if (!expectedSource || !event.source || event.source !== expectedSource) {
        return;
      }

      if (this.role === 'host') {
        if (data.type === 'READY') {
          const preSeq = this._lifecycleSeq;
          this.log('info', 'Received READY from peer');
          if (this._lifecycleSeq !== preSeq || this._stopped) return;

          this._resetChannelState();
          const seq = this._lifecycleSeq;
          this._setState('handshaking', 'Peer sent READY; re-establishing channel');
          if (!this._isSameLifecycle(seq)) return;

          this._initiateHostHandshake(event.origin, seq);
        }
      } else if (this.role === 'embedded') {
        if (data.type === 'INIT' && event.ports && event.ports.length > 0) {
          if (this._readyInterval) {
            clearInterval(this._readyInterval);
            this._readyInterval = null;
          }
          this._resetChannelState();
          const conn = this._attachConnection(event.ports[0]);
          this.log('info', 'Received MessagePort from host application');
          if (conn.closed || this._conn !== conn || this._stopped) return;

          this._onEstablished(conn, true);
        }
      }
    }

    /**
     * Called once the point-to-point MessagePort is established.
     */
    _onEstablished(conn = this._conn, sendInitAck = false) {
      if (!conn || conn.closed || this._conn !== conn || !conn.port || this._stopped) {
        return;
      }
      this._setState('connected', `Connected to ${this.peerOrigin}`);
      if (!this._isActiveConn(conn)) {
        return;
      }
      if (sendInitAck) {
        this._sendToPort({
          protocol: PROTOCOL_NAME,
          version: PROTOCOL_VERSION,
          type: 'INIT_ACK'
        }, conn);
      }
      if (!this._isActiveConn(conn)) {
        return;
      }
      // Rule 7: Reconnection - both sides exchange outstanding offers
      this.reconcile(true, conn);
    }

    /**
     * Dedicated MessagePort event handler for all protocol messages on `conn`.
     */
    async _handlePortMessage(event, conn = this._conn) {
      if (!conn || conn.closed || this._conn !== conn || !conn.port || this._stopped) {
        return;
      }

      const data = event.data;
      if (!isValidUmaiMessage(data)) {
        this.log('warn', 'Ignored invalid protocol message on port', data);
        return;
      }

      try {
        switch (data.type) {
          case 'INIT_ACK':
            if (this.role === 'host' && this.state !== 'connected') {
              this._onEstablished(conn, false);
            }
            break;

          case 'OFFER':
            if (this._isActiveConn(conn)) {
              await this._handleOffer(data, conn);
            }
            break;

          case 'GET':
            if (this._isActiveConn(conn)) {
              await this._handleGet(data, conn);
            }
            break;

          case 'PUT':
            if (this._isActiveConn(conn)) {
              this._handlePut(data, conn).catch((err) => {
                if (this._isActiveConn(conn)) {
                  this.log('error', 'Error handling PUT message', err.message);
                  this._emitError(err);
                }
              });
            }
            break;

          case 'ACK':
            if (this._isActiveConn(conn)) {
              await this._handleAck(data, conn);
            }
            break;

          default:
            this.log('warn', `Unknown message type received: ${data.type}`);
        }
      } catch (err) {
        if (this._isActiveConn(conn)) {
          this.log('error', `Error handling ${data.type} message`, err.message);
          this._emitError(err);
        }
      }
    }

    /**
     * Sends a raw message object over `conn`'s MessagePort if `conn` is still the active connection.
     */
    _sendToPort(msg, conn = this._conn, transferList = []) {
      if (!this._isActiveConn(conn)) {
        return false;
      }
      conn.port.postMessage(msg, transferList);
      return true;
    }

    /**
     * Trigger reconciliation: serializes getOutboxIds() reads on `conn` so older snapshots never overwrite newer ones,
     * retires stale conn.offeredIds against the complete outbox, and announces only tracked IDs via OFFER.
     * @param {boolean} [force=true] If false, skips sending OFFER when outbox is empty
     */
    reconcile(force = true, conn = this._conn) {
      if (!this._isActiveConn(conn)) {
        if (force) {
          this.log('warn', 'Reconciliation requested while disconnected; ignoring');
        }
        return Promise.resolve();
      }

      if (force) {
        conn.failedAttempts.clear();
        conn.timedOutGets.clear();
        conn.lookupFailureCount = 0;
        conn.nextLookupAllowedAt = 0;
        conn.lastLookupStartedAt = 0;
      }

      if (conn.reconciling && conn.reconcilePromise) {
        conn.reconcilePending = true;
        if (force) {
          conn.reconcileForcePending = true;
        }
        return conn.reconcilePromise;
      }

      conn.reconciling = true;
      conn.reconcilePromise = this._runReconcileLoop(force, conn);
      return conn.reconcilePromise;
    }

    async _runReconcileLoop(initialForce, conn) {
      let nextForce = initialForce;
      try {
        while (this._isActiveConn(conn)) {
          conn.reconcilePending = false;
          conn.reconcileForcePending = false;
          conn.ackedDuringOutboxRead.clear();
          if (nextForce) {
            conn.failedAttempts.clear();
            conn.timedOutGets.clear();
            conn.lookupFailureCount = 0;
            conn.nextLookupAllowedAt = 0;
            conn.lastLookupStartedAt = 0;
            if (conn.lookupTimer) {
              clearTimeout(conn.lookupTimer);
              conn.lookupTimer = null;
            }
            if (conn.pendingOfferIds.size > 0) {
              this._drainPendingOffers(conn);
            } else if (conn.pendingGetQueue.length > 0 || conn.deferredOfferIds.size > 0) {
              this._dispatchNextGets(conn);
            }
          }

          const outboxIds = await this.storage.getOutboxIds();
          if (!this._isActiveConn(conn)) return;

          // 1. Always process the completed serialized outbox snapshot before servicing a coalesced
          //    conn.reconcilePending request so periodic heartbeats faster than getOutboxIds() never starve OFFERs.
          //    Exclude any IDs whose ACK completed while getOutboxIds() was in flight.
          const rawList = Array.isArray(outboxIds) ? outboxIds : [];
          const fullOutboxSet = new Set();
          for (let i = 0; i < rawList.length; i++) {
            const id = rawList[i];
            if (isValidMessageId(id) && !conn.ackedDuringOutboxRead.has(id)) {
              fullOutboxSet.add(id);
            }
          }
          conn.ackedDuringOutboxRead.clear();

          // 2. Retire stale conn.offeredIds that are no longer present in the complete outbox
          //    and have no active outgoing PUT or pending ACK work.
          const activeProtected = new Set(conn.putQueue);
          for (const id of conn.activePuttingIds) activeProtected.add(id);
          for (const id of conn.pendingAcks.keys()) activeProtected.add(id);
          for (const id of conn.activeAckBatchSet) activeProtected.add(id);

          for (const trackedId of Array.from(conn.offeredIds)) {
            if (!fullOutboxSet.has(trackedId) && !activeProtected.has(trackedId)) {
              conn.offeredIds.delete(trackedId);
            }
          }

          // 3. Also drain any pending receiver GET window if slots are open
          this._dispatchNextGets(conn);
          if (!this._isActiveConn(conn)) return;

          // 4. Select up to MAX_BATCH_IDS to advertise, advertising strictly IDs that are tracked in conn.offeredIds.
          const candidateIds = Array.from(fullOutboxSet).slice(0, MAX_BATCH_IDS);
          if (!nextForce && candidateIds.length === 0) {
            if (conn.reconcilePending) {
              nextForce = conn.reconcileForcePending;
              continue;
            }
            return;
          }

          const candidateSet = new Set(candidateIds);
          const advertisedIds = [];
          for (let i = 0; i < candidateIds.length; i++) {
            const id = candidateIds[i];
            if (conn.offeredIds.has(id)) {
              advertisedIds.push(id);
              continue;
            }
            if (conn.offeredIds.size >= MAX_BATCH_IDS) {
              // Evict an idle offered ID from an earlier window of a >1,000-entry outbox
              for (const oldId of conn.offeredIds) {
                if (!candidateSet.has(oldId) && !activeProtected.has(oldId)) {
                  conn.offeredIds.delete(oldId);
                  break;
                }
              }
            }
            if (conn.offeredIds.size < MAX_BATCH_IDS) {
              conn.offeredIds.add(id);
              advertisedIds.push(id);
            }
          }

          this.log('info', `Reconciling: offering ${advertisedIds.length} outbox message(s)`, advertisedIds);
          if (!this._isActiveConn(conn)) return;

          const offerMsg = {
            protocol: PROTOCOL_NAME,
            version: PROTOCOL_VERSION,
            type: 'OFFER',
            ids: advertisedIds
          };

          if (this._sendToPort(offerMsg, conn)) {
            this._emitTransfer({ direction: 'outgoing', type: 'OFFER', ids: offerMsg.ids });
            if (!this._isActiveConn(conn)) return;
          }

          if (conn.reconcilePending) {
            nextForce = conn.reconcileForcePending;
            continue;
          }
          break;
        }
      } catch (err) {
        if (this._isActiveConn(conn)) {
          this.log('error', 'Failed to retrieve outbox for OFFER', err.message);
          this._emitError(err);
        }
      } finally {
        conn.reconciling = false;
        conn.reconcilePromise = null;
      }
    }

    /**
     * Returns true while an acceptance-lookup outage backoff window is currently active on `conn`.
     */
    _isLookupBackoffActive(conn = this._conn) {
      return Boolean(conn && !conn.closed && conn.lookupFailureCount > 0 && Date.now() < conn.nextLookupAllowedAt);
    }

    /**
     * Re-queues an unresolved incoming message ID back into bounded conn.pendingOfferIds for acceptance lookup retry.
     * Never places an unresolved ID into conn.pendingGetQueue or conn.deferredOfferIds, which strictly hold IDs
     * already confirmed unaccepted (`accepted: false`) by a completed lookup.
     */
    _requeueUnresolvedId(id, conn = this._conn) {
      if (!this._isActiveConn(conn) || this._shouldSkipOfferLookup(id, conn)) {
        return;
      }
      if (conn.pendingOfferIds.size < MAX_BATCH_IDS) {
        conn.pendingOfferIds.add(id);
      }
    }

    /**
     * Schedules a connection-scoped timer on `conn` to resume offer lookups and/or held GET transfers
     * once lookup pacing or outage backoff elapses.
     */
    _schedulePendingOfferDrain(delayMs, conn = this._conn) {
      if (
        !this._isActiveConn(conn) ||
        (conn.pendingOfferIds.size === 0 && conn.pendingGetQueue.length === 0 && conn.deferredOfferIds.size === 0)
      ) {
        return;
      }
      if (conn.lookupTimer) {
        clearTimeout(conn.lookupTimer);
        conn.lookupTimer = null;
      }
      const waitMs = Math.max(1, Math.ceil(delayMs));
      const timer = setTimeout(() => {
        conn.lookupTimer = null;
        if (!this._isActiveConn(conn)) {
          return;
        }
        if (conn.pendingOfferIds.size > 0) {
          this._drainPendingOffers(conn);
        } else if (!this._isLookupBackoffActive(conn)) {
          this._dispatchNextGets(conn);
        } else {
          this._schedulePendingOfferDrain(conn.nextLookupAllowedAt - Date.now(), conn);
        }
      }, waitMs);
      if (timer && typeof timer.unref === 'function') {
        timer.unref();
      }
      conn.lookupTimer = timer;
    }

    /**
     * Fail-closed OFFER batch acceptance lookup helper on `conn`:
     * - Records lookup start timestamp (`conn.lastLookupStartedAt`) for lookup rate pacing.
     * - Invokes `storage.getAcceptance(ids)` with a defensive copy and validates the complete
     *   batch via `validateBatchAcceptance` (failing closed if any requested ID is missing or malformed).
     * - Resets lookup outage backoff counters on success, or delegates to `_recordLookupFailure` on error.
     */
    async _queryValidatedAcceptance(queryIds, conn = this._conn) {
      if (!this._isActiveConn(conn) || !Array.isArray(queryIds) || queryIds.length === 0) {
        return null;
      }
      const reservedIds = [];
      for (const id of queryIds) {
        if (!conn.acceptingIds.has(id) && !conn.inFlightLookupIds.has(id)) {
          conn.inFlightLookupIds.add(id);
          reservedIds.push(id);
        }
      }
      const releaseReserved = () => {
        for (const id of reservedIds) {
          conn.inFlightLookupIds.delete(id);
        }
      };

      conn.lastLookupStartedAt = Date.now();
      try {
        const batchRes = await this.storage.getAcceptance(queryIds.slice());
        if (!this._isActiveConn(conn)) {
          releaseReserved();
          return null;
        }
        const validated = validateBatchAcceptance(batchRes, queryIds);
        if (!validated) {
          throw new Error(`Invalid or incomplete getAcceptance batch response (${queryIds.length} ID(s) requested)`);
        }
        releaseReserved();
        conn.lookupFailureCount = 0;
        conn.nextLookupAllowedAt = 0;
        return validated;
      } catch (err) {
        releaseReserved();
        if (this._isActiveConn(conn)) {
          this._recordLookupFailure(queryIds, err, conn);
        }
        return null;
      }
    }

    /**
     * Records a transient or malformed getAcceptance() failure on `conn` without burning per-message acceptance retries:
     * re-queues unresolved IDs and schedules an automatic retry with capped exponential backoff.
     */
    _recordLookupFailure(failedIds, err, conn = this._conn) {
      if (!this._isActiveConn(conn)) return;
      for (const id of failedIds) {
        this._requeueUnresolvedId(id, conn);
      }
      conn.lookupFailureCount++;
      const shift = Math.min(conn.lookupFailureCount - 1, 16);
      const backoffMs = Math.min(this.lookupRetryMaxMs, this.lookupRetryBaseMs * Math.pow(2, shift));
      conn.nextLookupAllowedAt = Date.now() + backoffMs;

      this.log(
        'error',
        `Acceptance lookup failed (attempt ${conn.lookupFailureCount}, retrying in ${backoffMs}ms): ${err.message}`
      );
      this._emitError(err);
      if (!this._isActiveConn(conn)) return;
      this._schedulePendingOfferDrain(backoffMs, conn);
    }

    /**
     * Promotes previously verified unaccepted IDs from bounded conn.deferredOfferIds into conn.pendingGetQueue
     * whenever incoming transfer capacity (< MAX_BATCH_IDS) opens up.
     */
    _promoteDeferredOffers(conn = this._conn) {
      if (!this._isActiveConn(conn) || conn.deferredOfferIds.size === 0) {
        return;
      }
      for (const id of Array.from(conn.deferredOfferIds)) {
        const totalOutstanding =
          conn.pendingGetQueue.length +
          conn.inFlightGets.size +
          conn.acceptingIds.size;
        if (totalOutstanding >= MAX_BATCH_IDS) {
          break;
        }
        conn.deferredOfferIds.delete(id);
        if (!this._shouldSkipOfferLookup(id, conn)) {
          conn.pendingGetQueue.push(id);
        }
      }
    }

    /**
     * Returns true if `id` on `conn` is already queued for GET, currently requested, currently being accepted,
     * or has reached the per-message connection retry cutoff (`conn.failedAttempts` / `conn.timedOutGets`).
     */
    _shouldSkipOfferLookup(id, conn = this._conn) {
      if (!conn || conn.closed) {
        return true;
      }
      if (
        conn.inFlightLookupIds.has(id) ||
        conn.inFlightGets.has(id) ||
        conn.acceptingIds.has(id) ||
        conn.pendingGetQueue.includes(id)
      ) {
        return true;
      }
      const failCount = conn.failedAttempts.get(id) || 0;
      const timeoutCount = conn.timedOutGets.get(id) || 0;
      if (failCount >= MAX_AUTO_RETRIES || timeoutCount >= MAX_AUTO_RETRIES) {
        this.log(
          'warn',
          `Skipping automatic GET for message ${id}: reached session retry cutoff (${Math.max(failCount, timeoutCount)}/${MAX_AUTO_RETRIES})`
        );
        return true;
      }
      return false;
    }

    /**
     * Handles incoming OFFER on `conn`:
     * - Coalesces eligible offered IDs into a bounded set (conn.pendingOfferIds) so repeated OFFER frames
     *   never spawn unbounded parallel getAcceptance() calls.
     * - Skips IDs already queued for GET, currently requested, or currently being accepted before lookup.
     */
    async _handleOffer(offer, conn = this._conn) {
      if (!this._isActiveConn(conn) || !offer || !Array.isArray(offer.ids)) {
        return;
      }
      this._pruneExpiredGets(conn);

      const offeredIds = offer.ids
        .filter(isValidMessageId)
        .slice(0, MAX_BATCH_IDS);
      this.log('info', `Received OFFER with ${offeredIds.length} message(s)`, offeredIds);
      this._emitTransfer({ direction: 'incoming', type: 'OFFER', ids: offeredIds });
      if (!this._isActiveConn(conn)) {
        return;
      }

      // Symmetrical reconciliation: ensure our own outbox is offered in return
      if (!conn.peerOfferedOnce) {
        conn.peerOfferedOnce = true;
        this.reconcile(false, conn);
        if (!this._isActiveConn(conn)) {
          return;
        }
      }

      if (offeredIds.length === 0) return;

      for (const id of offeredIds) {
        if (
          conn.pendingOfferIds.size +
          conn.inFlightLookupIds.size +
          conn.acceptingIds.size >= MAX_BATCH_IDS
        ) {
          break;
        }
        if (this._shouldSkipOfferLookup(id, conn)) {
          continue;
        }
        conn.pendingOfferIds.add(id);
      }

      // Dispatch any already-ready GET work before starting a new acceptance lookup batch
      this._dispatchNextGets(conn);
      if (!this._isActiveConn(conn)) {
        return;
      }

      await this._drainPendingOffers(conn);
    }

    /**
     * Single-worker loop per connection that drains coalesced conn.pendingOfferIds independently of GET capacity:
     * - Enforces lookup rate pacing (`lookupMinIntervalMs`) and capped exponential backoff on lookup outages.
     * - Immediately emits batched repeated ACKs for already-accepted IDs (Rule 5) even if the GET queue is full.
     * - Enqueues unaccepted IDs into conn.pendingGetQueue when capacity permits, or retains overflow in bounded conn.deferredOfferIds.
     */
    async _drainPendingOffers(conn = this._conn) {
      if (!this._isActiveConn(conn) || conn.processingOffers || conn.pendingOfferIds.size === 0) {
        return;
      }

      const now = Date.now();
      const earliestByPacing = conn.lastLookupStartedAt > 0
        ? (conn.lastLookupStartedAt + this.lookupMinIntervalMs)
        : 0;
      const allowedAt = Math.max(conn.nextLookupAllowedAt, earliestByPacing);
      if (now < allowedAt) {
        this._schedulePendingOfferDrain(allowedAt - now, conn);
        return;
      }

      if (conn.lookupTimer) {
        clearTimeout(conn.lookupTimer);
        conn.lookupTimer = null;
      }

      conn.processingOffers = true;
      try {
        while (this._isActiveConn(conn) && conn.pendingOfferIds.size > 0) {
          const loopNow = Date.now();
          const loopEarliest = conn.lastLookupStartedAt > 0
            ? (conn.lastLookupStartedAt + this.lookupMinIntervalMs)
            : 0;
          const loopAllowedAt = Math.max(conn.nextLookupAllowedAt, loopEarliest);
          if (loopNow < loopAllowedAt) {
            this._schedulePendingOfferDrain(loopAllowedAt - loopNow, conn);
            break;
          }

          this._pruneExpiredGets(conn);
          // Ensure any already-queued GETs are not held behind a batch lookup
          this._dispatchNextGets(conn);
          if (!this._isActiveConn(conn)) return;

          const rawBatch = Array.from(conn.pendingOfferIds).slice(0, MAX_BATCH_IDS);
          for (const id of rawBatch) {
            conn.pendingOfferIds.delete(id);
          }

          const queryIds = [];
          const seen = new Set();
          for (const id of rawBatch) {
            if (!isValidMessageId(id) || seen.has(id)) {
              continue;
            }
            seen.add(id);
            if (this._shouldSkipOfferLookup(id, conn)) {
              continue;
            }
            queryIds.push(id);
          }

          if (queryIds.length === 0) {
            this._dispatchNextGets(conn);
            continue;
          }

          const validatedBatch = await this._queryValidatedAcceptance(queryIds, conn);
          if (!this._isActiveConn(conn)) {
            return;
          }
          if (!validatedBatch) {
            break;
          }

          const alreadyAccepted = [];
          const repeatedReceipts = Object.create(null);

          for (const id of queryIds) {
            if (!this._isActiveConn(conn)) return;
            if (
              conn.inFlightGets.has(id) ||
              conn.acceptingIds.has(id) ||
              conn.pendingGetQueue.includes(id)
            ) {
              continue;
            }

            const entry = validatedBatch[id];
            if (entry.accepted) {
              conn.failedAttempts.delete(id);
              conn.timedOutGets.delete(id);
              conn.expiredGets.delete(id);
              conn.deferredOfferIds.delete(id);
              alreadyAccepted.push(id);
              if (entry.ackReceipt) {
                repeatedReceipts[id] = entry.ackReceipt;
              }
            } else {
              const failCount = conn.failedAttempts.get(id) || 0;
              const timeoutCount = conn.timedOutGets.get(id) || 0;
              if (failCount >= MAX_AUTO_RETRIES || timeoutCount >= MAX_AUTO_RETRIES) {
                continue;
              }
              const totalOutstanding =
                conn.pendingGetQueue.length +
                conn.inFlightGets.size +
                conn.acceptingIds.size;
              if (totalOutstanding < MAX_BATCH_IDS) {
                conn.deferredOfferIds.delete(id);
                conn.pendingGetQueue.push(id);
              } else if (!conn.deferredOfferIds.has(id) && conn.deferredOfferIds.size < MAX_BATCH_IDS) {
                conn.deferredOfferIds.add(id);
              }
            }
          }

          if (!this._isActiveConn(conn)) return;

          // Rule 5: Repeated acknowledgements (never gated on GET transfer capacity)
          if (alreadyAccepted.length > 0) {
            this.log('info', `Rule 5: Sending repeated ACK for already accepted ID(s)`, alreadyAccepted);
            if (!this._isActiveConn(conn)) return;

            const ackMsg = {
              protocol: PROTOCOL_NAME,
              version: PROTOCOL_VERSION,
              type: 'ACK',
              ids: alreadyAccepted,
              receipts: repeatedReceipts
            };
            if (this._sendToPort(ackMsg, conn)) {
              this._emitTransfer({ direction: 'outgoing', type: 'ACK', ids: alreadyAccepted, repeated: true });
              if (!this._isActiveConn(conn)) return;
            }
          }

          // Rule 2: Receiver-controlled transfer with bounded GET window (maxConcurrency)
          this._dispatchNextGets(conn);
        }
      } finally {
        conn.processingOffers = false;
        if (this._isActiveConn(conn)) {
          if (conn.pendingOfferIds.size > 0 && !conn.lookupTimer) {
            const remNow = Date.now();
            const remEarliest = conn.lastLookupStartedAt > 0
              ? (conn.lastLookupStartedAt + this.lookupMinIntervalMs)
              : 0;
            const remAllowedAt = Math.max(conn.nextLookupAllowedAt, remEarliest);
            this._schedulePendingOfferDrain(Math.max(1, remAllowedAt - remNow), conn);
          }
          this._notifySyncStatus();
        }
      }
    }

    /**
     * Dispatches GET requests from conn.pendingGetQueue up to the configured maxConcurrency window,
     * first promoting any deferred unaccepted IDs if queue capacity has opened up.
     * Pauses new GET dispatches while an acceptance-lookup outage backoff is active so queued payloads
     * are not transferred unnecessarily during a backend lookup outage.
     */
    _dispatchNextGets(conn = this._conn) {
      if (!this._isActiveConn(conn)) return;
      this._pruneExpiredGets(conn);

      if (this._isLookupBackoffActive(conn)) {
        this._scheduleGetExpiryTimer(conn);
        if (!conn.lookupTimer) {
          this._schedulePendingOfferDrain(conn.nextLookupAllowedAt - Date.now(), conn);
        }
        return;
      }

      this._promoteDeferredOffers(conn);

      const activeReceives = conn.inFlightGets.size + conn.acceptingIds.size;
      const availableSlots = this.maxConcurrency - activeReceives;
      if (availableSlots <= 0 || conn.pendingGetQueue.length === 0) {
        this._scheduleGetExpiryTimer(conn);
        return;
      }

      const toFetch = [];
      while (toFetch.length < availableSlots && conn.pendingGetQueue.length > 0) {
        const nextId = conn.pendingGetQueue.shift();
        if (!conn.inFlightGets.has(nextId) && !conn.acceptingIds.has(nextId)) {
          toFetch.push(nextId);
        }
      }

      if (toFetch.length > 0) {
        const now = Date.now();
        for (const id of toFetch) {
          conn.expiredGets.delete(id);
          conn.inFlightGets.set(id, now);
        }
        this._scheduleGetExpiryTimer(conn);
        this._notifySyncStatus(`Requesting ${toFetch.length} unaccepted message(s)...`);
        this.log('info', `Requesting unaccepted message(s) via GET`, toFetch);
        if (!this._isActiveConn(conn)) return;

        const getMsg = {
          protocol: PROTOCOL_NAME,
          version: PROTOCOL_VERSION,
          type: 'GET',
          ids: toFetch
        };
        if (this._sendToPort(getMsg, conn)) {
          this._emitTransfer({ direction: 'outgoing', type: 'GET', ids: toFetch });
        }
      }
    }

    /**
     * Handles incoming GET on `conn`:
     * Queues outgoing PUT messages strictly for IDs that were previously offered on `conn`.
     */
    async _handleGet(get, conn = this._conn) {
      if (!this._isActiveConn(conn) || !get || !Array.isArray(get.ids)) {
        return;
      }
      const rawIds = get.ids
        .filter(isValidMessageId)
        .slice(0, MAX_BATCH_IDS);
      const requestedIds = rawIds.filter(id => conn.offeredIds.has(id));
      if (requestedIds.length !== rawIds.length) {
        this.log('warn', `Ignored GET for unoffered ID(s)`, rawIds.filter(id => !conn.offeredIds.has(id)));
      }
      this.log('info', `Received GET request for ${requestedIds.length} message(s)`, requestedIds);
      this._emitTransfer({ direction: 'incoming', type: 'GET', ids: requestedIds });
      if (!this._isActiveConn(conn)) {
        return;
      }

      for (const id of requestedIds) {
        this._queuePut(id, conn);
      }
    }

    /**
     * Enqueues a message ID on `conn` to be transferred as a PUT (deduplicating queued/active IDs and capping queue size).
     */
    _queuePut(id, conn = this._conn) {
      if (!this._isActiveConn(conn)) return;
      if (conn.putQueue.includes(id) || conn.activePuttingIds.has(id) || conn.putQueue.length >= MAX_BATCH_IDS) {
        return;
      }
      conn.putQueue.push(id);
      this._notifySyncStatus(`Transfer queued for message ${id}`);
      if (!this._isActiveConn(conn)) return;
      this._processPutQueue(conn);
    }

    /**
     * Bounded outgoing transfer worker on `conn`: sends up to maxConcurrency PUT transfers at a time per direction.
     */
    async _processPutQueue(conn = this._conn) {
      if (
        !this._isActiveConn(conn) ||
        conn.activeSendCount >= this.maxConcurrency ||
        conn.putQueue.length === 0
      ) {
        return;
      }

      const id = conn.putQueue.shift();
      conn.activeSendCount++;
      conn.activePuttingIds.add(id);

      try {
        this._notifySyncStatus(`Sending message ${id}...`);
        this.log('info', `Preparing PUT for message ${id}`);
        if (!this._isActiveConn(conn)) {
          return;
        }

        const msg = await this.storage.getMessage(id);
        if (!this._isActiveConn(conn)) {
          return;
        }
        if (!msg || typeof msg !== 'object') {
          this.log('warn', `Message ${id} not found in outbox, skipping PUT`);
          return;
        }
        if (msg.id !== id) {
          throw new Error(`Storage getMessage(${id}) returned mismatched message ID: ${msg.id}`);
        }
        const validated = normalizeAndValidateMessage(msg.payload, msg.attachments, this.maxAttachments, this.maxMessageBytes);
        if (!validated) {
          throw new Error(`Outgoing message ${id} payload or attachments invalid or exceed size/count bounds`);
        }
        const sigStr = (msg.signature !== undefined && msg.signature !== null) ? msg.signature : '';
        if (typeof sigStr !== 'string' || sigStr.length > MAX_SIGNATURE_LEN) {
          throw new Error(`Outgoing message ${id} has invalid signature field`);
        }

        const putMsg = {
          protocol: PROTOCOL_NAME,
          version: PROTOCOL_VERSION,
          type: 'PUT',
          id: id,
          payload: validated.normalizedPayload,
          attachments: msg.attachments,
          signature: sigStr
        };

        this.log(
          'info',
          `Sending PUT for message ${id} with ${msg.attachments.length} attachment(s)`
        );
        if (!this._isActiveConn(conn)) {
          return;
        }

        if (this._sendToPort(putMsg, conn)) {
          this._emitTransfer({
            direction: 'outgoing',
            type: 'PUT',
            id: id,
            attachmentCount: msg.attachments.length
          });
        }
      } catch (err) {
        if (this._isActiveConn(conn)) {
          this.log('error', `Failed to send PUT for message ${id}`, err.message);
          this._emitError(err);
        }
      } finally {
        conn.activePuttingIds.delete(id);
        conn.activeSendCount = Math.max(0, conn.activeSendCount - 1);
        if (this._isActiveConn(conn)) {
          this._notifySyncStatus();
          // Process next item in queue if still active
          this._processPutQueue(conn);
        }
      }
    }

    /**
     * Handles incoming PUT on `conn`:
     * - Rule 2: Enforces receiver-controlled transfer:
     *     * Active GETs (conn.inFlightGets) transition directly into conn.acceptingIds within maxConcurrency.
     *     * Late responses for expired GETs (conn.expiredGets) are admitted ONLY if an acceptance/receive
     *       slot is currently free ((conn.inFlightGets.size + conn.acceptingIds.size) < maxConcurrency), so
     *       an expired slow message never steals a slot already reused by another message.
     * - Rule 3: Complete messages only. Strictly validates JSON payload types + attachments and bounds.
     */
    async _handlePut(put, conn = this._conn) {
      if (!this._isActiveConn(conn) || !put || typeof put !== 'object') {
        return;
      }
      this._pruneExpiredGets(conn);

      const id = put.id;
      if (!isValidMessageId(id) || conn.acceptingIds.has(id)) {
        this.log('warn', `Ignored invalid or duplicate in-flight PUT for message ${id}`);
        return;
      }

      const isActiveGet = conn.inFlightGets.has(id);
      const isLateEligible = !isActiveGet && conn.expiredGets.has(id);
      if (!isActiveGet && !isLateEligible) {
        this.log('warn', `Ignored unsolicited PUT for message ${id}`);
        return;
      }

      if (isActiveGet) {
        if (
          conn.acceptingIds.size >= this.maxConcurrency ||
          conn.incomingPutQueue.length >= this.maxConcurrency
        ) {
          this.log('warn', `Ignored PUT for ${id}: acceptance concurrency full`);
          return;
        }
        conn.inFlightGets.delete(id);
      } else {
        // Late response after slot expiry: only admit if a concurrency slot is currently free.
        // Note: when deferred here, recovery does not depend on a sender heartbeat—_pruneExpiredGets()
        // already appended `id` to the tail of conn.pendingGetQueue (for attempts < MAX_AUTO_RETRIES),
        // so the receiver automatically dispatches a fresh GET once active slots finish.
        if (
          (conn.inFlightGets.size + conn.acceptingIds.size) >= this.maxConcurrency ||
          conn.incomingPutQueue.length >= this.maxConcurrency
        ) {
          this.log('info', `Deferred late PUT for ${id}: receive slot currently in use by another transfer`);
          return;
        }
        conn.expiredGets.delete(id);
        const queuedIdx = conn.pendingGetQueue.indexOf(id);
        if (queuedIdx !== -1) {
          conn.pendingGetQueue.splice(queuedIdx, 1);
        }
      }
      this._scheduleGetExpiryTimer(conn);

      // Validate wire format, strict JSON payload, & bounds (Rule 3: reject malformed envelopes before touching storage)
      const sigStr = (put.signature !== undefined && put.signature !== null) ? put.signature : '';
      const validated = normalizeAndValidateMessage(put.payload, put.attachments, this.maxAttachments, this.maxMessageBytes);
      if (
        typeof sigStr !== 'string' ||
        sigStr.length > MAX_SIGNATURE_LEN ||
        !validated
      ) {
        const fails = (conn.failedAttempts.get(id) || 0) + 1;
        this._setBoundedMap(conn.failedAttempts, id, fails);
        const err = new Error(`Rejected PUT for message ${id}: invalid JSON payload/attachments or exceeded size/count bounds`);
        this.log('error', err.message);
        this._emitError(err);
        if (!this._isActiveConn(conn)) {
          return;
        }
        this._notifySyncStatus();
        this._dispatchNextGets(conn);
        return;
      }

      conn.acceptingIds.add(id);
      conn.incomingPutQueue.push({
        id: id,
        payload: validated.normalizedPayload,
        attachments: put.attachments,
        signature: sigStr
      });
      this._notifySyncStatus(`Receiving message ${id} (${put.attachments.length} attachment(s))...`);
      if (!this._isActiveConn(conn)) {
        return;
      }
      await this._processIncomingPutQueue(conn);
    }

    /**
     * Processes queued incoming PUTs on `conn` up to maxConcurrency at a time.
     */
    async _processIncomingPutQueue(conn = this._conn) {
      if (
        !this._isActiveConn(conn) ||
        conn.activeAcceptCount >= this.maxConcurrency ||
        conn.incomingPutQueue.length === 0
      ) {
        return;
      }

      const item = conn.incomingPutQueue.shift();
      if (!item || !this._isActiveConn(conn)) {
        return;
      }

      const { id, payload, attachments, signature } = item;
      conn.activeAcceptCount++;

      try {
        this.log(
          'info',
          `Received PUT for message ${id} with ${attachments.length} attachment(s)`
        );
        this._emitTransfer({
          direction: 'incoming',
          type: 'PUT',
          id: id,
          attachmentCount: attachments.length
        });
        if (!this._isActiveConn(conn)) {
          return;
        }

        // Rules 3, 4 & 5: Commit complete message via atomic, idempotent storage.acceptMessage()
        // directly (without a redundant post-PUT getAcceptance([id]) round-trip).
        const acceptRes = parseAcceptanceResult(await this.storage.acceptMessage({
          id: id,
          payload: payload,
          attachments: attachments,
          signature: signature
        }));

        if (!this._isActiveConn(conn)) {
          return;
        }

        if (acceptRes.accepted) {
          conn.failedAttempts.delete(id);
          conn.timedOutGets.delete(id);
          conn.expiredGets.delete(id);
          conn.deferredOfferIds.delete(id);
          this.log('info', `Successfully accepted message ${id}. Sending ACK.`);
          if (!this._isActiveConn(conn)) {
            return;
          }
          const receipts = Object.create(null);
          if (acceptRes.ackReceipt) {
            receipts[id] = acceptRes.ackReceipt;
          }
          const ackMsg = {
            protocol: PROTOCOL_NAME,
            version: PROTOCOL_VERSION,
            type: 'ACK',
            ids: [id],
            receipts: receipts
          };
          if (this._sendToPort(ackMsg, conn)) {
            this._emitTransfer({ direction: 'outgoing', type: 'ACK', ids: [id] });
          }
        } else {
          const fails = (conn.failedAttempts.get(id) || 0) + 1;
          this._setBoundedMap(conn.failedAttempts, id, fails);
          this.log('error', `Acceptance rejected by local storage for message ${id} (attempt ${fails}/${MAX_AUTO_RETRIES}); NO ACK sent`);
        }
      } catch (err) {
        if (this._isActiveConn(conn)) {
          // Transfer failure or storage error: do not send ACK
          const fails = (conn.failedAttempts.get(id) || 0) + 1;
          this._setBoundedMap(conn.failedAttempts, id, fails);
          this.log('error', `Failed to accept message ${id} (attempt ${fails}/${MAX_AUTO_RETRIES}): ${err.message}; NO ACK sent`);
          this._emitError(err);
        }
      } finally {
        conn.acceptingIds.delete(id);
        conn.activeAcceptCount = Math.max(0, conn.activeAcceptCount - 1);
        if (this._isActiveConn(conn)) {
          this._notifySyncStatus();
          if (this._isActiveConn(conn)) {
            // Request next window of GETs and process any queued PUTs
            this._dispatchNextGets(conn);
            this._processIncomingPutQueue(conn);
          }
        }
      }
    }

    /**
     * Handles incoming ACK on `conn`:
     * - Rule 6: Sender cleanup upon receiving ACK.
     * - Only acknowledges IDs that were actually offered on `conn`.
     * - Coalesces repeated ACKs into bounded conn.pendingAcks work (upgrading empty receipts to non-empty receipts).
     */
    async _handleAck(ack, conn = this._conn) {
      if (!this._isActiveConn(conn) || !ack || !Array.isArray(ack.ids)) {
        return;
      }
      const rawIds = ack.ids
        .filter(isValidMessageId)
        .slice(0, MAX_BATCH_IDS);
      const validIds = rawIds.filter(id => conn.offeredIds.has(id));
      if (validIds.length !== rawIds.length) {
        this.log('warn', `Ignored unoffered ACK ID(s)`, rawIds.filter(id => !conn.offeredIds.has(id)));
      }
      this.log('info', `Received ACK confirming acceptance of ${validIds.length} message(s)`, validIds);
      this._emitTransfer({ direction: 'incoming', type: 'ACK', ids: validIds });
      if (!this._isActiveConn(conn) || validIds.length === 0) {
        return;
      }

      const hasReceiptsObj = Boolean(ack.receipts && typeof ack.receipts === 'object');
      for (const id of validIds) {
        let incomingReceipt = '';
        if (
          hasReceiptsObj &&
          Object.prototype.hasOwnProperty.call(ack.receipts, id) &&
          typeof ack.receipts[id] === 'string' &&
          ack.receipts[id].length <= MAX_SIGNATURE_LEN
        ) {
          incomingReceipt = ack.receipts[id];
        }

        if (conn.pendingAcks.has(id)) {
          // Never let an empty receipt overwrite a non-empty receipt; upgrade when a non-empty receipt arrives
          if (incomingReceipt !== '') {
            conn.pendingAcks.set(id, incomingReceipt);
          }
        } else if (conn.pendingAcks.size < MAX_BATCH_IDS) {
          conn.pendingAcks.set(id, incomingReceipt);
        }
      }

      await this._drainPendingAcks(conn);
    }

    /**
     * Single-worker loop per connection that drains coalesced conn.pendingAcks sequentially.
     * If storage.onAcknowledged() fails (e.g. due to an invalid/missing receipt), the IDs remain in
     * conn.offeredIds so a subsequent ACK carrying a valid receipt retries cleanly.
     */
    async _drainPendingAcks(conn = this._conn) {
      if (!this._isActiveConn(conn) || conn.processingAcks || conn.pendingAcks.size === 0) {
        return;
      }

      conn.processingAcks = true;
      try {
        while (this._isActiveConn(conn) && conn.pendingAcks.size > 0) {
          const entries = Array.from(conn.pendingAcks.entries()).slice(0, MAX_BATCH_IDS);
          const batchIds = [];
          const receipts = Object.create(null);

          for (let i = 0; i < entries.length; i++) {
            const [id, rec] = entries[i];
            conn.pendingAcks.delete(id);
            conn.activeAckBatchSet.add(id);
            batchIds.push(id);
            if (rec !== '') {
              receipts[id] = rec;
            }
          }

          this._notifySyncStatus(`Acknowledging ${batchIds.length} message(s)...`);
          if (!this._isActiveConn(conn)) {
            return;
          }

          try {
            await this.storage.onAcknowledged(batchIds, receipts);
            if (!this._isActiveConn(conn)) {
              return;
            }
            for (const id of batchIds) {
              conn.activeAckBatchSet.delete(id);
              conn.offeredIds.delete(id);
              conn.pendingAcks.delete(id);
              if (conn.reconciling) {
                conn.ackedDuringOutboxRead.add(id);
              }
            }
            this.log('info', `Removed acknowledged message(s) from outbox:`, batchIds);
          } catch (err) {
            if (!this._isActiveConn(conn)) {
              return;
            }
            for (const id of batchIds) {
              conn.activeAckBatchSet.delete(id);
            }
            this.log('error', 'Error processing ACK in local storage', err.message);
            this._emitError(err);
          }
        }
      } finally {
        conn.processingAcks = false;
        conn.activeAckBatchSet.clear();
        if (this._isActiveConn(conn)) {
          this._notifySyncStatus();
        }
      }
    }
  }

  // Export to global scope / CommonJS
  if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
      UmaiSession,
      PROTOCOL_NAME,
      PROTOCOL_VERSION,
      isValidUmaiMessage,
      isValidMessageId
    };
  } else {
    global.UMAI = {
      UmaiSession,
      PROTOCOL_NAME,
      PROTOCOL_VERSION,
      isValidUmaiMessage,
      isValidMessageId
    };
  }
})(typeof window !== 'undefined' ? window : this);
