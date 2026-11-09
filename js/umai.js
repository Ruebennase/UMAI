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

      this.port = null;
      this._generation = 0;
      this._stopped = false;
      this.state = 'disconnected'; // 'disconnected' | 'handshaking' | 'connected'
      this._windowListener = this._handleWindowMessage.bind(this);
      this._portListener = (event) => this._handlePortMessage(event, this._generation, this.port);

      // Outgoing PUT queue and active worker tracking
      this._putQueue = [];
      this._activePuttingIds = new Set();
      this._activeSendCount = 0;

      // Coalesced incoming ACK queue and single-worker tracking
      this._pendingAcks = new Map();
      this._activeAckBatchSet = new Set();
      this._processingAcks = false;

      // Serialized outbox reconciliation state
      this._reconciling = false;
      this._reconcilePending = false;
      this._reconcileForcePending = false;
      this._reconcilePromise = null;
      this._ackedDuringOutboxRead = new Set();

      // Coalesced incoming OFFER queue, in-flight lookup reservation, deferred unaccepted overflow, and single-worker state
      this._pendingOfferIds = new Set();
      this._inFlightLookupIds = new Set();
      this._deferredOfferIds = new Set();
      this._processingOffers = false;
      this._lastLookupStartedAt = 0;
      this._lookupFailureCount = 0;
      this._nextLookupAllowedAt = 0;
      this._lookupTimer = null;

      // Receiver GET windowing queue, active reservations, and bounded expired reservation history
      this._pendingGetQueue = [];
      this._inFlightGets = new Map();
      this._expiredGets = new Set();
      this._timedOutGets = new Map();
      this._getExpiryTimer = null;

      // Track message IDs currently being committed in acceptMessage() and queue incoming PUTs up to maxConcurrency
      this._acceptingIds = new Set();
      this._incomingPutQueue = [];
      this._activeAcceptCount = 0;

      // Track message IDs offered to the peer (bounded to MAX_BATCH_IDS)
      this._offeredIds = new Set();

      // Bounded per-ID session retry cutoff counter for rejected/corrupt PUT messages (<= MAX_BATCH_IDS)
      this._failedAttempts = new Map();
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
        const gen = this._generation;
        this._setState('handshaking', this.peerWindow ? 'Switching to companion window' : 'Switching to embedded iframe');
        if (!this._isSameGeneration(gen)) return;
        if (this.role === 'host' && this._getTargetWindow()) {
          this._initiateHostHandshake(null, gen);
        }
      }
    }

    /**
     * Returns true if the session is still in the same non-stopped lifecycle generation
     * (used across startup/handshaking callbacks before a port is connected).
     */
    _isSameGeneration(gen) {
      return this._generation === gen && this.state !== 'disconnected';
    }

    /**
     * Returns true if the given generation and MessagePort are still the active connected channel.
     */
    _isGenerationActive(gen, port) {
      return this.state === 'connected' && this._generation === gen && this.port === port && port !== null;
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
     * Closes the current MessagePort (if any), increments the connection generation to invalidate
     * any in-flight async work from the prior channel, and clears per-channel state.
     */
    _resetChannelState() {
      this._generation++;
      if (this._getExpiryTimer) {
        clearTimeout(this._getExpiryTimer);
        this._getExpiryTimer = null;
      }
      if (this._lookupTimer) {
        clearTimeout(this._lookupTimer);
        this._lookupTimer = null;
      }
      if (this.port) {
        try {
          this.port.onmessage = null;
          this.port.close();
        } catch (e) {
          // ignore close errors
        }
        this.port = null;
      }
      this._peerOfferedOnce = false;
      this._putQueue = [];
      this._activePuttingIds.clear();
      this._activeSendCount = 0;
      this._pendingAcks.clear();
      this._activeAckBatchSet.clear();
      this._processingAcks = false;
      this._reconciling = false;
      this._reconcilePending = false;
      this._reconcileForcePending = false;
      this._reconcilePromise = null;
      this._ackedDuringOutboxRead.clear();
      this._pendingOfferIds.clear();
      this._inFlightLookupIds.clear();
      this._deferredOfferIds.clear();
      this._processingOffers = false;
      this._lastLookupStartedAt = 0;
      this._lookupFailureCount = 0;
      this._nextLookupAllowedAt = 0;
      this._pendingGetQueue = [];
      this._inFlightGets.clear();
      this._expiredGets.clear();
      this._timedOutGets.clear();
      this._failedAttempts.clear();
      this._acceptingIds.clear();
      this._incomingPutQueue = [];
      this._activeAcceptCount = 0;
      this._offeredIds.clear();
    }

    /**
     * Schedules a wakeup timer for the earliest expiring active GET reservation so stalled slots
     * are freed promptly for other waiting messages even when idle.
     */
    _scheduleGetExpiryTimer(gen = this._generation, port = this.port) {
      if (this._getExpiryTimer) {
        clearTimeout(this._getExpiryTimer);
        this._getExpiryTimer = null;
      }
      if (!this._isGenerationActive(gen, port) || this._inFlightGets.size === 0) {
        return;
      }

      let earliestTs = Infinity;
      for (const ts of this._inFlightGets.values()) {
        if (ts < earliestTs) {
          earliestTs = ts;
        }
      }
      const delayMs = Math.max(5, (earliestTs + this.getTimeoutMs) - Date.now() + 2);
      const timer = setTimeout(() => {
        this._getExpiryTimer = null;
        if (!this._isGenerationActive(gen, port)) {
          return;
        }
        const freed = this._pruneExpiredGets();
        if (freed > 0) {
          this._notifySyncStatus();
          this._dispatchNextGets(gen, port);
        }
        this._scheduleGetExpiryTimer(gen, port);
      }, delayMs);
      if (timer && typeof timer.unref === 'function') {
        timer.unref();
      }
      this._getExpiryTimer = timer;
    }

    /**
     * Demotes expired active GET reservations from _inFlightGets so they no longer occupy
     * an active concurrency slot:
     *   - Moves the ID into bounded _expiredGets (<= MAX_BATCH_IDS) so a slow legitimate PUT
     *     that arrives later can still be accepted if a concurrency slot is free.
     *   - Appends the ID to the tail of _pendingGetQueue (behind other waiting messages, up to
     *     MAX_AUTO_RETRIES timeouts) so a permanently unresponsive ID never blocks progress.
     */
    _pruneExpiredGets() {
      const now = Date.now();
      let freed = 0;
      for (const [id, ts] of Array.from(this._inFlightGets.entries())) {
        if (now - ts >= this.getTimeoutMs) {
          this._inFlightGets.delete(id);
          freed++;

          if (!this._expiredGets.has(id)) {
            if (this._expiredGets.size >= MAX_BATCH_IDS) {
              const oldest = this._expiredGets.values().next().value;
              this._expiredGets.delete(oldest);
            }
            this._expiredGets.add(id);
          }

          const timeouts = (this._timedOutGets.get(id) || 0) + 1;
          this._setBoundedMap(this._timedOutGets, id, timeouts);

          const totalOutstanding = this._pendingGetQueue.length + this._inFlightGets.size + this._acceptingIds.size;
          if (
            timeouts < MAX_AUTO_RETRIES &&
            (this._failedAttempts.get(id) || 0) < MAX_AUTO_RETRIES &&
            !this._acceptingIds.has(id) &&
            !this._pendingGetQueue.includes(id) &&
            totalOutstanding < MAX_BATCH_IDS
          ) {
            this._pendingGetQueue.push(id);
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
     * Broadcast real-time synchronization status (transfers ongoing vs complete sync).
     */
    _notifySyncStatus(detail = '') {
      this._pruneExpiredGets();
      const ackPending = this._pendingAcks.size + this._activeAckBatchSet.size;
      const pendingOutgoing = this._putQueue.length + this._activeSendCount + ackPending;
      const pendingIncoming =
        this._pendingOfferIds.size +
        this._deferredOfferIds.size +
        (this._processingOffers ? 1 : 0) +
        this._pendingGetQueue.length +
        this._inFlightGets.size +
        this._acceptingIds.size;
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
      this._pruneExpiredGets();
      const ackPending = this._pendingAcks.size + this._activeAckBatchSet.size;
      const pendingOutgoing = this._putQueue.length + this._activeSendCount + ackPending;
      const pendingIncoming =
        this._pendingOfferIds.size +
        this._deferredOfferIds.size +
        (this._processingOffers ? 1 : 0) +
        this._pendingGetQueue.length +
        this._inFlightGets.size +
        this._acceptingIds.size;
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
      const gen = this._generation;
      this._setState('handshaking', `Starting as ${this.role}`);
      if (!this._isSameGeneration(gen)) {
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
          this._initiateHostHandshake(null, gen);
        }
      }
    }

    /**
     * Stop and cleanup session, invalidating any in-flight async operations.
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
      this._failedAttempts.clear();
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
    _initiateHostHandshake(targetOrigin = null, expectedGen = null) {
      if (expectedGen !== null && !this._isSameGeneration(expectedGen)) {
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
        const gen = this._generation;
        const channel = new MessageChannel();
        const port = channel.port1;
        this.port = port;
        port.onmessage = (event) => this._handlePortMessage(event, gen, port);

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
          const preGen = this._generation;
          this.log('info', 'Received READY from peer');
          if (this._generation !== preGen || this._stopped) return;

          this._resetChannelState();
          const gen = this._generation;
          this._setState('handshaking', 'Peer sent READY; re-establishing channel');
          if (!this._isSameGeneration(gen)) return;

          this._initiateHostHandshake(event.origin, gen);
        }
      } else if (this.role === 'embedded') {
        if (data.type === 'INIT' && event.ports && event.ports.length > 0) {
          if (this._readyInterval) {
            clearInterval(this._readyInterval);
            this._readyInterval = null;
          }
          this._resetChannelState();
          const gen = this._generation;
          const port = event.ports[0];
          this.port = port;
          port.onmessage = (ev) => this._handlePortMessage(ev, gen, port);
          this.log('info', 'Received MessagePort from host application');
          if (this._generation !== gen || this._stopped || this.port !== port) return;

          this._onEstablished(gen, port, true);
        }
      }
    }

    /**
     * Called once the point-to-point MessagePort is established.
     */
    _onEstablished(gen = this._generation, port = this.port, sendInitAck = false) {
      this._setState('connected', `Connected to ${this.peerOrigin}`);
      if (!this._isGenerationActive(gen, port)) {
        return;
      }
      if (sendInitAck) {
        this._sendToPort({
          protocol: PROTOCOL_NAME,
          version: PROTOCOL_VERSION,
          type: 'INIT_ACK'
        }, gen, port);
      }
      if (!this._isGenerationActive(gen, port)) {
        return;
      }
      // Rule 7: Reconnection - both sides exchange outstanding offers
      this.reconcile(true, gen, port);
    }

    /**
     * Dedicated MessagePort event handler for all protocol messages.
     */
    async _handlePortMessage(event, gen = this._generation, port = this.port) {
      if (gen !== this._generation || port !== this.port || !port) {
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
              this._onEstablished(gen, port, false);
            }
            break;

          case 'OFFER':
            if (this._isGenerationActive(gen, port)) {
              await this._handleOffer(data, gen, port);
            }
            break;

          case 'GET':
            if (this._isGenerationActive(gen, port)) {
              await this._handleGet(data, gen, port);
            }
            break;

          case 'PUT':
            if (this._isGenerationActive(gen, port)) {
              this._handlePut(data, gen, port).catch((err) => {
                if (this._isGenerationActive(gen, port)) {
                  this.log('error', 'Error handling PUT message', err.message);
                  this._emitError(err);
                }
              });
            }
            break;

          case 'ACK':
            if (this._isGenerationActive(gen, port)) {
              await this._handleAck(data, gen, port);
            }
            break;

          default:
            this.log('warn', `Unknown message type received: ${data.type}`);
        }
      } catch (err) {
        if (this._isGenerationActive(gen, port)) {
          this.log('error', `Error handling ${data.type} message`, err.message);
          this._emitError(err);
        }
      }
    }

    /**
     * Sends a raw message object over the established MessagePort if the generation is still active.
     */
    _sendToPort(msg, gen = this._generation, port = this.port, transferList = []) {
      if (!this._isGenerationActive(gen, port)) {
        return false;
      }
      port.postMessage(msg, transferList);
      return true;
    }

    /**
     * Trigger reconciliation: serializes getOutboxIds() reads so older snapshots never overwrite newer ones,
     * retires stale _offeredIds against the complete outbox, and announces only tracked IDs via OFFER.
     * @param {boolean} [force=true] If false, skips sending OFFER when outbox is empty
     */
    reconcile(force = true, gen = this._generation, port = this.port) {
      if (!this._isGenerationActive(gen, port)) {
        if (force) {
          this.log('warn', 'Reconciliation requested while disconnected; ignoring');
        }
        return Promise.resolve();
      }

      if (force) {
        this._failedAttempts.clear();
        this._timedOutGets.clear();
        this._lookupFailureCount = 0;
        this._nextLookupAllowedAt = 0;
        this._lastLookupStartedAt = 0;
      }

      if (this._reconciling && this._reconcilePromise) {
        this._reconcilePending = true;
        if (force) {
          this._reconcileForcePending = true;
        }
        return this._reconcilePromise;
      }

      this._reconciling = true;
      this._reconcilePromise = this._runReconcileLoop(force, gen, port);
      return this._reconcilePromise;
    }

    async _runReconcileLoop(initialForce, gen, port) {
      let nextForce = initialForce;
      try {
        while (this._isGenerationActive(gen, port)) {
          this._reconcilePending = false;
          this._reconcileForcePending = false;
          this._ackedDuringOutboxRead.clear();
          if (nextForce) {
            this._failedAttempts.clear();
            this._timedOutGets.clear();
            this._lookupFailureCount = 0;
            this._nextLookupAllowedAt = 0;
            this._lastLookupStartedAt = 0;
            if (this._lookupTimer) {
              clearTimeout(this._lookupTimer);
              this._lookupTimer = null;
            }
            if (this._pendingOfferIds.size > 0) {
              this._drainPendingOffers(gen, port);
            } else if (this._pendingGetQueue.length > 0 || this._deferredOfferIds.size > 0) {
              this._dispatchNextGets(gen, port);
            }
          }

          const outboxIds = await this.storage.getOutboxIds();
          if (!this._isGenerationActive(gen, port)) return;

          // 1. Always process the completed serialized outbox snapshot before servicing a coalesced
          //    _reconcilePending request so periodic heartbeats faster than getOutboxIds() never starve OFFERs.
          //    Exclude any IDs whose ACK completed while getOutboxIds() was in flight.
          const rawList = Array.isArray(outboxIds) ? outboxIds : [];
          const fullOutboxSet = new Set();
          for (let i = 0; i < rawList.length; i++) {
            const id = rawList[i];
            if (isValidMessageId(id) && !this._ackedDuringOutboxRead.has(id)) {
              fullOutboxSet.add(id);
            }
          }
          this._ackedDuringOutboxRead.clear();

          // 2. Retire stale _offeredIds that are no longer present in the complete outbox
          //    and have no active outgoing PUT or pending ACK work.
          const activeProtected = new Set(this._putQueue);
          for (const id of this._activePuttingIds) activeProtected.add(id);
          for (const id of this._pendingAcks.keys()) activeProtected.add(id);
          for (const id of this._activeAckBatchSet) activeProtected.add(id);

          for (const trackedId of Array.from(this._offeredIds)) {
            if (!fullOutboxSet.has(trackedId) && !activeProtected.has(trackedId)) {
              this._offeredIds.delete(trackedId);
            }
          }

          // 3. Also drain any pending receiver GET window if slots are open
          this._dispatchNextGets(gen, port);
          if (!this._isGenerationActive(gen, port)) return;

          // 4. Select up to MAX_BATCH_IDS to advertise, advertising strictly IDs that are tracked in _offeredIds.
          const candidateIds = Array.from(fullOutboxSet).slice(0, MAX_BATCH_IDS);
          if (!nextForce && candidateIds.length === 0) {
            if (this._reconcilePending) {
              nextForce = this._reconcileForcePending;
              continue;
            }
            return;
          }

          const candidateSet = new Set(candidateIds);
          const advertisedIds = [];
          for (let i = 0; i < candidateIds.length; i++) {
            const id = candidateIds[i];
            if (this._offeredIds.has(id)) {
              advertisedIds.push(id);
              continue;
            }
            if (this._offeredIds.size >= MAX_BATCH_IDS) {
              // Evict an idle offered ID from an earlier window of a >1,000-entry outbox
              for (const oldId of this._offeredIds) {
                if (!candidateSet.has(oldId) && !activeProtected.has(oldId)) {
                  this._offeredIds.delete(oldId);
                  break;
                }
              }
            }
            if (this._offeredIds.size < MAX_BATCH_IDS) {
              this._offeredIds.add(id);
              advertisedIds.push(id);
            }
          }

          this.log('info', `Reconciling: offering ${advertisedIds.length} outbox message(s)`, advertisedIds);
          if (!this._isGenerationActive(gen, port)) return;

          const offerMsg = {
            protocol: PROTOCOL_NAME,
            version: PROTOCOL_VERSION,
            type: 'OFFER',
            ids: advertisedIds
          };

          if (this._sendToPort(offerMsg, gen, port)) {
            this._emitTransfer({ direction: 'outgoing', type: 'OFFER', ids: offerMsg.ids });
            if (!this._isGenerationActive(gen, port)) return;
          }

          if (this._reconcilePending) {
            nextForce = this._reconcileForcePending;
            continue;
          }
          break;
        }
      } catch (err) {
        if (this._isGenerationActive(gen, port)) {
          this.log('error', 'Failed to retrieve outbox for OFFER', err.message);
          this._emitError(err);
        }
      } finally {
        if (this._isGenerationActive(gen, port)) {
          this._reconciling = false;
          this._reconcilePromise = null;
        }
      }
    }

    /**
     * Returns true while an acceptance-lookup outage backoff window is currently active.
     */
    _isLookupBackoffActive() {
      return this._lookupFailureCount > 0 && Date.now() < this._nextLookupAllowedAt;
    }

    /**
     * Re-queues an unresolved incoming message ID back into bounded _pendingOfferIds for acceptance lookup retry.
     * Never places an unresolved ID into _pendingGetQueue or _deferredOfferIds, which strictly hold IDs
     * already confirmed unaccepted (`accepted: false`) by a completed lookup.
     */
    _requeueUnresolvedId(id) {
      if (this._shouldSkipOfferLookup(id)) {
        return;
      }
      if (this._pendingOfferIds.size < MAX_BATCH_IDS) {
        this._pendingOfferIds.add(id);
      }
    }

    /**
     * Schedules a generation-scoped timer to resume offer lookups and/or held GET transfers
     * once lookup pacing or outage backoff elapses.
     */
    _schedulePendingOfferDrain(delayMs, gen = this._generation, port = this.port) {
      if (
        !this._isGenerationActive(gen, port) ||
        (this._pendingOfferIds.size === 0 && this._pendingGetQueue.length === 0 && this._deferredOfferIds.size === 0)
      ) {
        return;
      }
      if (this._lookupTimer) {
        clearTimeout(this._lookupTimer);
        this._lookupTimer = null;
      }
      const waitMs = Math.max(1, Math.ceil(delayMs));
      const timer = setTimeout(() => {
        this._lookupTimer = null;
        if (!this._isGenerationActive(gen, port)) {
          return;
        }
        if (this._pendingOfferIds.size > 0) {
          this._drainPendingOffers(gen, port);
        } else if (!this._isLookupBackoffActive()) {
          this._dispatchNextGets(gen, port);
        } else {
          this._schedulePendingOfferDrain(this._nextLookupAllowedAt - Date.now(), gen, port);
        }
      }, waitMs);
      if (timer && typeof timer.unref === 'function') {
        timer.unref();
      }
      this._lookupTimer = timer;
    }

    /**
     * Fail-closed OFFER batch acceptance lookup helper:
     * - Records lookup start timestamp (`_lastLookupStartedAt`) for lookup rate pacing.
     * - Invokes `storage.getAcceptance(ids)` with a defensive copy and validates the complete
     *   batch via `validateBatchAcceptance` (failing closed if any requested ID is missing or malformed).
     * - Resets lookup outage backoff counters on success, or delegates to `_recordLookupFailure` on error.
     */
    async _queryValidatedAcceptance(queryIds, gen = this._generation, port = this.port) {
      if (!this._isGenerationActive(gen, port) || !Array.isArray(queryIds) || queryIds.length === 0) {
        return null;
      }
      const reservedIds = [];
      for (const id of queryIds) {
        if (!this._acceptingIds.has(id) && !this._inFlightLookupIds.has(id)) {
          this._inFlightLookupIds.add(id);
          reservedIds.push(id);
        }
      }
      const releaseReserved = () => {
        if (!this._isGenerationActive(gen, port)) {
          return;
        }
        for (const id of reservedIds) {
          this._inFlightLookupIds.delete(id);
        }
      };

      this._lastLookupStartedAt = Date.now();
      try {
        const batchRes = await this.storage.getAcceptance(queryIds.slice());
        if (!this._isGenerationActive(gen, port)) {
          return null;
        }
        const validated = validateBatchAcceptance(batchRes, queryIds);
        if (!validated) {
          throw new Error(`Invalid or incomplete getAcceptance batch response (${queryIds.length} ID(s) requested)`);
        }
        releaseReserved();
        this._lookupFailureCount = 0;
        this._nextLookupAllowedAt = 0;
        return validated;
      } catch (err) {
        if (this._isGenerationActive(gen, port)) {
          releaseReserved();
          this._recordLookupFailure(queryIds, err, gen, port);
        }
        return null;
      }
    }

    /**
     * Records a transient or malformed getAcceptance() failure without burning per-message acceptance retries:
     * re-queues unresolved IDs and schedules an automatic retry with capped exponential backoff.
     */
    _recordLookupFailure(failedIds, err, gen = this._generation, port = this.port) {
      if (!this._isGenerationActive(gen, port)) return;
      for (const id of failedIds) {
        this._requeueUnresolvedId(id);
      }
      this._lookupFailureCount++;
      const shift = Math.min(this._lookupFailureCount - 1, 16);
      const backoffMs = Math.min(this.lookupRetryMaxMs, this.lookupRetryBaseMs * Math.pow(2, shift));
      this._nextLookupAllowedAt = Date.now() + backoffMs;

      this.log(
        'error',
        `Acceptance lookup failed (attempt ${this._lookupFailureCount}, retrying in ${backoffMs}ms): ${err.message}`
      );
      this._emitError(err);
      if (!this._isGenerationActive(gen, port)) return;
      this._schedulePendingOfferDrain(backoffMs, gen, port);
    }

    /**
     * Promotes previously verified unaccepted IDs from bounded _deferredOfferIds into _pendingGetQueue
     * whenever incoming transfer capacity (< MAX_BATCH_IDS) opens up.
     */
    _promoteDeferredOffers(gen = this._generation, port = this.port) {
      if (!this._isGenerationActive(gen, port) || this._deferredOfferIds.size === 0) {
        return;
      }
      for (const id of Array.from(this._deferredOfferIds)) {
        const totalOutstanding =
          this._pendingGetQueue.length +
          this._inFlightGets.size +
          this._acceptingIds.size;
        if (totalOutstanding >= MAX_BATCH_IDS) {
          break;
        }
        this._deferredOfferIds.delete(id);
        if (!this._shouldSkipOfferLookup(id)) {
          this._pendingGetQueue.push(id);
        }
      }
    }

    /**
     * Returns true if `id` is already queued for GET, currently requested, currently being accepted,
     * or has reached the per-message session retry cutoff (`_failedAttempts` / `_timedOutGets`).
     */
    _shouldSkipOfferLookup(id) {
      if (
        this._inFlightLookupIds.has(id) ||
        this._inFlightGets.has(id) ||
        this._acceptingIds.has(id) ||
        this._pendingGetQueue.includes(id)
      ) {
        return true;
      }
      const failCount = this._failedAttempts.get(id) || 0;
      const timeoutCount = this._timedOutGets.get(id) || 0;
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
     * Handles incoming OFFER:
     * - Coalesces eligible offered IDs into a bounded set (_pendingOfferIds) so repeated OFFER frames
     *   never spawn unbounded parallel getAcceptance() calls.
     * - Skips IDs already queued for GET, currently requested, or currently being accepted before lookup.
     */
    async _handleOffer(offer, gen = this._generation, port = this.port) {
      if (!this._isGenerationActive(gen, port) || !offer || !Array.isArray(offer.ids)) {
        return;
      }
      this._pruneExpiredGets();

      const offeredIds = offer.ids
        .filter(isValidMessageId)
        .slice(0, MAX_BATCH_IDS);
      this.log('info', `Received OFFER with ${offeredIds.length} message(s)`, offeredIds);
      this._emitTransfer({ direction: 'incoming', type: 'OFFER', ids: offeredIds });
      if (!this._isGenerationActive(gen, port)) {
        return;
      }

      // Symmetrical reconciliation: ensure our own outbox is offered in return
      if (!this._peerOfferedOnce) {
        this._peerOfferedOnce = true;
        this.reconcile(false, gen, port);
        if (!this._isGenerationActive(gen, port)) {
          return;
        }
      }

      if (offeredIds.length === 0) return;

      for (const id of offeredIds) {
        if (
          this._pendingOfferIds.size +
          this._inFlightLookupIds.size +
          this._acceptingIds.size >= MAX_BATCH_IDS
        ) {
          break;
        }
        if (this._shouldSkipOfferLookup(id)) {
          continue;
        }
        this._pendingOfferIds.add(id);
      }

      // Dispatch any already-ready GET work before starting a new acceptance lookup batch
      this._dispatchNextGets(gen, port);
      if (!this._isGenerationActive(gen, port)) {
        return;
      }

      await this._drainPendingOffers(gen, port);
    }

    /**
     * Single-worker loop per generation that drains coalesced _pendingOfferIds independently of GET capacity:
     * - Enforces lookup rate pacing (`lookupMinIntervalMs`) and capped exponential backoff on lookup outages.
     * - Immediately emits batched repeated ACKs for already-accepted IDs (Rule 5) even if the GET queue is full.
     * - Enqueues unaccepted IDs into _pendingGetQueue when capacity permits, or retains overflow in bounded _deferredOfferIds.
     */
    async _drainPendingOffers(gen = this._generation, port = this.port) {
      if (!this._isGenerationActive(gen, port) || this._processingOffers || this._pendingOfferIds.size === 0) {
        return;
      }

      const now = Date.now();
      const earliestByPacing = this._lastLookupStartedAt > 0
        ? (this._lastLookupStartedAt + this.lookupMinIntervalMs)
        : 0;
      const allowedAt = Math.max(this._nextLookupAllowedAt, earliestByPacing);
      if (now < allowedAt) {
        this._schedulePendingOfferDrain(allowedAt - now, gen, port);
        return;
      }

      if (this._lookupTimer) {
        clearTimeout(this._lookupTimer);
        this._lookupTimer = null;
      }

      this._processingOffers = true;
      try {
        while (this._isGenerationActive(gen, port) && this._pendingOfferIds.size > 0) {
          const loopNow = Date.now();
          const loopEarliest = this._lastLookupStartedAt > 0
            ? (this._lastLookupStartedAt + this.lookupMinIntervalMs)
            : 0;
          const loopAllowedAt = Math.max(this._nextLookupAllowedAt, loopEarliest);
          if (loopNow < loopAllowedAt) {
            this._schedulePendingOfferDrain(loopAllowedAt - loopNow, gen, port);
            break;
          }

          this._pruneExpiredGets();
          // Ensure any already-queued GETs are not held behind a batch lookup
          this._dispatchNextGets(gen, port);
          if (!this._isGenerationActive(gen, port)) return;

          const rawBatch = Array.from(this._pendingOfferIds).slice(0, MAX_BATCH_IDS);
          for (const id of rawBatch) {
            this._pendingOfferIds.delete(id);
          }

          const queryIds = [];
          const seen = new Set();
          for (const id of rawBatch) {
            if (!isValidMessageId(id) || seen.has(id)) {
              continue;
            }
            seen.add(id);
            if (this._shouldSkipOfferLookup(id)) {
              continue;
            }
            queryIds.push(id);
          }

          if (queryIds.length === 0) {
            this._dispatchNextGets(gen, port);
            continue;
          }

          const validatedBatch = await this._queryValidatedAcceptance(queryIds, gen, port);
          if (!this._isGenerationActive(gen, port)) {
            return;
          }
          if (!validatedBatch) {
            break;
          }

          const alreadyAccepted = [];
          const repeatedReceipts = Object.create(null);

          for (const id of queryIds) {
            if (!this._isGenerationActive(gen, port)) return;
            if (
              this._inFlightGets.has(id) ||
              this._acceptingIds.has(id) ||
              this._pendingGetQueue.includes(id)
            ) {
              continue;
            }

            const entry = validatedBatch[id];
            if (entry.accepted) {
              this._failedAttempts.delete(id);
              this._timedOutGets.delete(id);
              this._expiredGets.delete(id);
              this._deferredOfferIds.delete(id);
              alreadyAccepted.push(id);
              if (entry.ackReceipt) {
                repeatedReceipts[id] = entry.ackReceipt;
              }
            } else {
              const failCount = this._failedAttempts.get(id) || 0;
              const timeoutCount = this._timedOutGets.get(id) || 0;
              if (failCount >= MAX_AUTO_RETRIES || timeoutCount >= MAX_AUTO_RETRIES) {
                continue;
              }
              const totalOutstanding =
                this._pendingGetQueue.length +
                this._inFlightGets.size +
                this._acceptingIds.size;
              if (totalOutstanding < MAX_BATCH_IDS) {
                this._deferredOfferIds.delete(id);
                this._pendingGetQueue.push(id);
              } else if (!this._deferredOfferIds.has(id) && this._deferredOfferIds.size < MAX_BATCH_IDS) {
                this._deferredOfferIds.add(id);
              }
            }
          }

          if (!this._isGenerationActive(gen, port)) return;

          // Rule 5: Repeated acknowledgements (never gated on GET transfer capacity)
          if (alreadyAccepted.length > 0) {
            this.log('info', `Rule 5: Sending repeated ACK for already accepted ID(s)`, alreadyAccepted);
            if (!this._isGenerationActive(gen, port)) return;

            const ackMsg = {
              protocol: PROTOCOL_NAME,
              version: PROTOCOL_VERSION,
              type: 'ACK',
              ids: alreadyAccepted,
              receipts: repeatedReceipts
            };
            if (this._sendToPort(ackMsg, gen, port)) {
              this._emitTransfer({ direction: 'outgoing', type: 'ACK', ids: alreadyAccepted, repeated: true });
              if (!this._isGenerationActive(gen, port)) return;
            }
          }

          // Rule 2: Receiver-controlled transfer with bounded GET window (maxConcurrency)
          this._dispatchNextGets(gen, port);
        }
      } finally {
        if (this._isGenerationActive(gen, port)) {
          this._processingOffers = false;
          if (this._pendingOfferIds.size > 0 && !this._lookupTimer) {
            const remNow = Date.now();
            const remEarliest = this._lastLookupStartedAt > 0
              ? (this._lastLookupStartedAt + this.lookupMinIntervalMs)
              : 0;
            const remAllowedAt = Math.max(this._nextLookupAllowedAt, remEarliest);
            this._schedulePendingOfferDrain(Math.max(1, remAllowedAt - remNow), gen, port);
          }
          this._notifySyncStatus();
        }
      }
    }

    /**
     * Dispatches GET requests from _pendingGetQueue up to the configured maxConcurrency window,
     * first promoting any deferred unaccepted IDs if queue capacity has opened up.
     * Pauses new GET dispatches while an acceptance-lookup outage backoff is active so queued payloads
     * are not transferred unnecessarily during a backend lookup outage.
     */
    _dispatchNextGets(gen = this._generation, port = this.port) {
      if (!this._isGenerationActive(gen, port)) return;
      this._pruneExpiredGets();

      if (this._isLookupBackoffActive()) {
        this._scheduleGetExpiryTimer(gen, port);
        if (!this._lookupTimer) {
          this._schedulePendingOfferDrain(this._nextLookupAllowedAt - Date.now(), gen, port);
        }
        return;
      }

      this._promoteDeferredOffers(gen, port);

      const activeReceives = this._inFlightGets.size + this._acceptingIds.size;
      const availableSlots = this.maxConcurrency - activeReceives;
      if (availableSlots <= 0 || this._pendingGetQueue.length === 0) {
        this._scheduleGetExpiryTimer(gen, port);
        return;
      }

      const toFetch = [];
      while (toFetch.length < availableSlots && this._pendingGetQueue.length > 0) {
        const nextId = this._pendingGetQueue.shift();
        if (!this._inFlightGets.has(nextId) && !this._acceptingIds.has(nextId)) {
          toFetch.push(nextId);
        }
      }

      if (toFetch.length > 0) {
        const now = Date.now();
        for (const id of toFetch) {
          this._expiredGets.delete(id);
          this._inFlightGets.set(id, now);
        }
        this._scheduleGetExpiryTimer(gen, port);
        this._notifySyncStatus(`Requesting ${toFetch.length} unaccepted message(s)...`);
        this.log('info', `Requesting unaccepted message(s) via GET`, toFetch);
        if (!this._isGenerationActive(gen, port)) return;

        const getMsg = {
          protocol: PROTOCOL_NAME,
          version: PROTOCOL_VERSION,
          type: 'GET',
          ids: toFetch
        };
        if (this._sendToPort(getMsg, gen, port)) {
          this._emitTransfer({ direction: 'outgoing', type: 'GET', ids: toFetch });
        }
      }
    }

    /**
     * Handles incoming GET:
     * Queues outgoing PUT messages strictly for IDs that were previously offered by this sender.
     */
    async _handleGet(get, gen = this._generation, port = this.port) {
      if (!this._isGenerationActive(gen, port) || !get || !Array.isArray(get.ids)) {
        return;
      }
      const rawIds = get.ids
        .filter(isValidMessageId)
        .slice(0, MAX_BATCH_IDS);
      const requestedIds = rawIds.filter(id => this._offeredIds.has(id));
      if (requestedIds.length !== rawIds.length) {
        this.log('warn', `Ignored GET for unoffered ID(s)`, rawIds.filter(id => !this._offeredIds.has(id)));
      }
      this.log('info', `Received GET request for ${requestedIds.length} message(s)`, requestedIds);
      this._emitTransfer({ direction: 'incoming', type: 'GET', ids: requestedIds });
      if (!this._isGenerationActive(gen, port)) {
        return;
      }

      for (const id of requestedIds) {
        this._queuePut(id, gen, port);
      }
    }

    /**
     * Enqueues a message ID to be transferred as a PUT (deduplicating queued/active IDs and capping queue size).
     */
    _queuePut(id, gen = this._generation, port = this.port) {
      if (!this._isGenerationActive(gen, port)) return;
      if (this._putQueue.includes(id) || this._activePuttingIds.has(id) || this._putQueue.length >= MAX_BATCH_IDS) {
        return;
      }
      this._putQueue.push(id);
      this._notifySyncStatus(`Transfer queued for message ${id}`);
      if (!this._isGenerationActive(gen, port)) return;
      this._processPutQueue(gen, port);
    }

    /**
     * Bounded outgoing transfer worker: sends up to maxConcurrency PUT transfers at a time per direction.
     */
    async _processPutQueue(gen = this._generation, port = this.port) {
      if (
        !this._isGenerationActive(gen, port) ||
        this._activeSendCount >= this.maxConcurrency ||
        this._putQueue.length === 0
      ) {
        return;
      }

      const id = this._putQueue.shift();
      this._activeSendCount++;
      this._activePuttingIds.add(id);

      try {
        this._notifySyncStatus(`Sending message ${id}...`);
        this.log('info', `Preparing PUT for message ${id}`);
        if (!this._isGenerationActive(gen, port)) {
          return;
        }

        const msg = await this.storage.getMessage(id);
        if (!this._isGenerationActive(gen, port)) {
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
        if (!this._isGenerationActive(gen, port)) {
          return;
        }

        if (this._sendToPort(putMsg, gen, port)) {
          this._emitTransfer({
            direction: 'outgoing',
            type: 'PUT',
            id: id,
            attachmentCount: msg.attachments.length
          });
        }
      } catch (err) {
        if (this._isGenerationActive(gen, port)) {
          this.log('error', `Failed to send PUT for message ${id}`, err.message);
          this._emitError(err);
        }
      } finally {
        if (this._isGenerationActive(gen, port)) {
          this._activePuttingIds.delete(id);
          this._activeSendCount = Math.max(0, this._activeSendCount - 1);
          this._notifySyncStatus();
          // Process next item in queue if still active
          this._processPutQueue(gen, port);
        }
      }
    }

    /**
     * Handles incoming PUT:
     * - Rule 2: Enforces receiver-controlled transfer:
     *     * Active GETs (_inFlightGets) transition directly into _acceptingIds within maxConcurrency.
     *     * Late responses for expired GETs (_expiredGets) are admitted ONLY if an acceptance/receive
     *       slot is currently free ((_inFlightGets.size + _acceptingIds.size) < maxConcurrency), so
     *       an expired slow message never steals a slot already reused by another message.
     * - Rule 3: Complete messages only. Strictly validates JSON payload types + attachments and bounds.
     */
    async _handlePut(put, gen = this._generation, port = this.port) {
      if (!this._isGenerationActive(gen, port) || !put || typeof put !== 'object') {
        return;
      }
      this._pruneExpiredGets();

      const id = put.id;
      if (!isValidMessageId(id) || this._acceptingIds.has(id)) {
        this.log('warn', `Ignored invalid or duplicate in-flight PUT for message ${id}`);
        return;
      }

      const isActiveGet = this._inFlightGets.has(id);
      const isLateEligible = !isActiveGet && this._expiredGets.has(id);
      if (!isActiveGet && !isLateEligible) {
        this.log('warn', `Ignored unsolicited PUT for message ${id}`);
        return;
      }

      if (isActiveGet) {
        if (
          this._acceptingIds.size >= this.maxConcurrency ||
          this._incomingPutQueue.length >= this.maxConcurrency
        ) {
          this.log('warn', `Ignored PUT for ${id}: acceptance concurrency full`);
          return;
        }
        this._inFlightGets.delete(id);
      } else {
        // Late response after slot expiry: only admit if a concurrency slot is currently free.
        // Note: when deferred here, recovery does not depend on a sender heartbeat—_pruneExpiredGets()
        // already appended `id` to the tail of _pendingGetQueue (for attempts < MAX_AUTO_RETRIES),
        // so the receiver automatically dispatches a fresh GET once active slots finish.
        if (
          (this._inFlightGets.size + this._acceptingIds.size) >= this.maxConcurrency ||
          this._incomingPutQueue.length >= this.maxConcurrency
        ) {
          this.log('info', `Deferred late PUT for ${id}: receive slot currently in use by another transfer`);
          return;
        }
        this._expiredGets.delete(id);
        const queuedIdx = this._pendingGetQueue.indexOf(id);
        if (queuedIdx !== -1) {
          this._pendingGetQueue.splice(queuedIdx, 1);
        }
      }
      this._scheduleGetExpiryTimer(gen, port);

      // Validate wire format, strict JSON payload, & bounds (Rule 3: reject malformed envelopes before touching storage)
      const sigStr = (put.signature !== undefined && put.signature !== null) ? put.signature : '';
      const validated = normalizeAndValidateMessage(put.payload, put.attachments, this.maxAttachments, this.maxMessageBytes);
      if (
        typeof sigStr !== 'string' ||
        sigStr.length > MAX_SIGNATURE_LEN ||
        !validated
      ) {
        const fails = (this._failedAttempts.get(id) || 0) + 1;
        this._setBoundedMap(this._failedAttempts, id, fails);
        const err = new Error(`Rejected PUT for message ${id}: invalid JSON payload/attachments or exceeded size/count bounds`);
        this.log('error', err.message);
        this._emitError(err);
        if (!this._isGenerationActive(gen, port)) {
          return;
        }
        this._notifySyncStatus();
        this._dispatchNextGets(gen, port);
        return;
      }

      this._acceptingIds.add(id);
      this._incomingPutQueue.push({
        id: id,
        payload: validated.normalizedPayload,
        attachments: put.attachments,
        signature: sigStr,
        gen: gen,
        port: port
      });
      this._notifySyncStatus(`Receiving message ${id} (${put.attachments.length} attachment(s))...`);
      if (!this._isGenerationActive(gen, port)) {
        return;
      }
      await this._processIncomingPutQueue(gen, port);
    }

    /**
     * Processes queued incoming PUTs up to maxConcurrency at a time.
     */
    async _processIncomingPutQueue(gen = this._generation, port = this.port) {
      if (
        !this._isGenerationActive(gen, port) ||
        this._activeAcceptCount >= this.maxConcurrency ||
        this._incomingPutQueue.length === 0
      ) {
        return;
      }

      const item = this._incomingPutQueue.shift();
      if (!item || !this._isGenerationActive(item.gen, item.port)) {
        return;
      }

      const { id, payload, attachments, signature } = item;
      this._activeAcceptCount++;

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
        if (!this._isGenerationActive(gen, port)) {
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

        if (!this._isGenerationActive(gen, port)) {
          return;
        }

        if (acceptRes.accepted) {
          this._failedAttempts.delete(id);
          this._timedOutGets.delete(id);
          this._expiredGets.delete(id);
          this._deferredOfferIds.delete(id);
          this.log('info', `Successfully accepted message ${id}. Sending ACK.`);
          if (!this._isGenerationActive(gen, port)) {
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
          if (this._sendToPort(ackMsg, gen, port)) {
            this._emitTransfer({ direction: 'outgoing', type: 'ACK', ids: [id] });
          }
        } else {
          const fails = (this._failedAttempts.get(id) || 0) + 1;
          this._setBoundedMap(this._failedAttempts, id, fails);
          this.log('error', `Acceptance rejected by local storage for message ${id} (attempt ${fails}/${MAX_AUTO_RETRIES}); NO ACK sent`);
        }
      } catch (err) {
        if (this._isGenerationActive(gen, port)) {
          // Transfer failure or storage error: do not send ACK
          const fails = (this._failedAttempts.get(id) || 0) + 1;
          this._setBoundedMap(this._failedAttempts, id, fails);
          this.log('error', `Failed to accept message ${id} (attempt ${fails}/${MAX_AUTO_RETRIES}): ${err.message}; NO ACK sent`);
          this._emitError(err);
        }
      } finally {
        if (this._isGenerationActive(gen, port)) {
          this._acceptingIds.delete(id);
          this._activeAcceptCount = Math.max(0, this._activeAcceptCount - 1);
          this._notifySyncStatus();
          if (this._isGenerationActive(gen, port)) {
            // Request next window of GETs and process any queued PUTs
            this._dispatchNextGets(gen, port);
            this._processIncomingPutQueue(gen, port);
          }
        }
      }
    }

    /**
     * Handles incoming ACK:
     * - Rule 6: Sender cleanup upon receiving ACK.
     * - Only acknowledges IDs that were actually offered by this sender.
     * - Coalesces repeated ACKs into bounded _pendingAcks work (upgrading empty receipts to non-empty receipts).
     */
    async _handleAck(ack, gen = this._generation, port = this.port) {
      if (!this._isGenerationActive(gen, port) || !ack || !Array.isArray(ack.ids)) {
        return;
      }
      const rawIds = ack.ids
        .filter(isValidMessageId)
        .slice(0, MAX_BATCH_IDS);
      const validIds = rawIds.filter(id => this._offeredIds.has(id));
      if (validIds.length !== rawIds.length) {
        this.log('warn', `Ignored unoffered ACK ID(s)`, rawIds.filter(id => !this._offeredIds.has(id)));
      }
      this.log('info', `Received ACK confirming acceptance of ${validIds.length} message(s)`, validIds);
      this._emitTransfer({ direction: 'incoming', type: 'ACK', ids: validIds });
      if (!this._isGenerationActive(gen, port) || validIds.length === 0) {
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

        if (this._pendingAcks.has(id)) {
          // Never let an empty receipt overwrite a non-empty receipt; upgrade when a non-empty receipt arrives
          if (incomingReceipt !== '') {
            this._pendingAcks.set(id, incomingReceipt);
          }
        } else if (this._pendingAcks.size < MAX_BATCH_IDS) {
          this._pendingAcks.set(id, incomingReceipt);
        }
      }

      await this._drainPendingAcks(gen, port);
    }

    /**
     * Single-worker loop per generation that drains coalesced _pendingAcks sequentially.
     * If storage.onAcknowledged() fails (e.g. due to an invalid/missing receipt), the IDs remain in
     * _offeredIds so a subsequent ACK carrying a valid receipt retries cleanly.
     */
    async _drainPendingAcks(gen = this._generation, port = this.port) {
      if (!this._isGenerationActive(gen, port) || this._processingAcks || this._pendingAcks.size === 0) {
        return;
      }

      this._processingAcks = true;
      try {
        while (this._isGenerationActive(gen, port) && this._pendingAcks.size > 0) {
          const entries = Array.from(this._pendingAcks.entries()).slice(0, MAX_BATCH_IDS);
          const batchIds = [];
          const receipts = Object.create(null);

          for (let i = 0; i < entries.length; i++) {
            const [id, rec] = entries[i];
            this._pendingAcks.delete(id);
            this._activeAckBatchSet.add(id);
            batchIds.push(id);
            if (rec !== '') {
              receipts[id] = rec;
            }
          }

          this._notifySyncStatus(`Acknowledging ${batchIds.length} message(s)...`);
          if (!this._isGenerationActive(gen, port)) {
            return;
          }

          try {
            await this.storage.onAcknowledged(batchIds, receipts);
            if (!this._isGenerationActive(gen, port)) {
              return;
            }
            for (const id of batchIds) {
              this._activeAckBatchSet.delete(id);
              this._offeredIds.delete(id);
              this._pendingAcks.delete(id);
              if (this._reconciling) {
                this._ackedDuringOutboxRead.add(id);
              }
            }
            this.log('info', `Removed acknowledged message(s) from outbox:`, batchIds);
          } catch (err) {
            if (!this._isGenerationActive(gen, port)) {
              return;
            }
            for (const id of batchIds) {
              this._activeAckBatchSet.delete(id);
            }
            this.log('error', 'Error processing ACK in local storage', err.message);
            this._emitError(err);
          }
        }
      } finally {
        if (this._isGenerationActive(gen, port)) {
          this._processingAcks = false;
          this._activeAckBatchSet.clear();
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
