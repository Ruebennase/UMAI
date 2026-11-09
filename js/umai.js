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
   * Recursively verifies that a value contains strictly JSON-representable data
   * (null, boolean, finite number, string, plain Array, or plain Object up to MAX_JSON_DEPTH),
   * rejecting structured-clone non-JSON types such as Blob, File, ArrayBuffer, TypedArray,
   * Date, RegExp, Map, Set, accessor properties, or deep/circular graphs.
   */
  function isStrictJsonValue(val, depth = 0) {
    if (depth > MAX_JSON_DEPTH) {
      return false;
    }
    if (val === null) {
      return true;
    }
    const t = typeof val;
    if (t === 'boolean' || t === 'string') {
      return true;
    }
    if (t === 'number') {
      return Number.isFinite(val);
    }
    if (t !== 'object') {
      return false;
    }

    if (Array.isArray(val)) {
      const keys = Object.keys(val);
      if (keys.length !== val.length) {
        return false;
      }
      for (let i = 0; i < val.length; i++) {
        const desc = Object.getOwnPropertyDescriptor(val, i);
        if (!desc || !Object.prototype.hasOwnProperty.call(desc, 'value')) {
          return false;
        }
        if (!isStrictJsonValue(desc.value, depth + 1)) {
          return false;
        }
      }
      return true;
    }

    const proto = Object.getPrototypeOf(val);
    if (proto !== Object.prototype && proto !== null) {
      return false;
    }

    const keys = Object.keys(val);
    for (let i = 0; i < keys.length; i++) {
      const k = keys[i];
      const desc = Object.getOwnPropertyDescriptor(val, k);
      if (!desc || !Object.prototype.hasOwnProperty.call(desc, 'value')) {
        return false;
      }
      if (desc.value === undefined) {
        continue;
      }
      if (!isStrictJsonValue(desc.value, depth + 1)) {
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
   * Validates strict JSON payload types, normalizes the payload via JSON round-trip so the exact
   * measured JSON representation is forwarded, and validates payload + attachment sizes/counts
   * against maxAttachments and maxMessageBytes.
   * Returns { totalBytes, normalizedPayload } or null if invalid or exceeding bounds.
   */
  function normalizeAndValidateMessage(payload, attachments, maxAttachments, maxMessageBytes) {
    const candidate = (payload !== undefined && payload !== null) ? payload : {};
    if (!isStrictJsonValue(candidate, 0)) {
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
    if (payloadBytes < 0 || payloadBytes > maxMessageBytes) {
      return null;
    }

    if (!Array.isArray(attachments) || attachments.length > maxAttachments) {
      return null;
    }

    let totalBytes = payloadBytes;
    for (let i = 0; i < attachments.length; i++) {
      const att = attachments[i];
      if (!isValidAttachment(att)) {
        return null;
      }
      totalBytes += att.size;
      if (totalBytes > maxMessageBytes) {
        return null;
      }
    }

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
   * Normalizes an adapter acceptance response ({ accepted: boolean, ackReceipt?: string } or boolean).
   * Requires an explicit boolean `true` or `{ accepted: true }` (never truthy strings or numbers).
   */
  function parseAcceptanceResult(res) {
    if (typeof res === 'boolean') {
      return { accepted: res, ackReceipt: '' };
    }
    if (res && typeof res === 'object' && typeof res.accepted === 'boolean') {
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
     * @param {Object} options.storage Handlers for reading/writing local messages:
     *   - getOutboxIds(): Promise<string[]>
     *   - getMessage(id): Promise<{ id: string, payload: any, attachments: File[], signature?: string }>
     *   - isAccepted(id): Promise<{ accepted: boolean, ackReceipt?: string } | boolean>
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
      if (!options.storage) {
        throw new Error('UMAI: storage interface is required');
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

      // Coalesced incoming OFFER queue and single-worker flag
      this._pendingOfferIds = new Set();
      this._processingOffers = false;

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

      // Track per-ID acceptance failures in this session to prevent poison-pill retry loops
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
     * Closes the current MessagePort (if any), increments the connection generation to invalidate
     * any in-flight async work from the prior channel, and clears per-channel state.
     */
    _resetChannelState() {
      this._generation++;
      if (this._getExpiryTimer) {
        clearTimeout(this._getExpiryTimer);
        this._getExpiryTimer = null;
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
      this._pendingOfferIds.clear();
      this._processingOffers = false;
      this._pendingGetQueue = [];
      this._inFlightGets.clear();
      this._expiredGets.clear();
      this._timedOutGets.clear();
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
          this._timedOutGets.set(id, timeouts);

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
      const pendingIncoming = this._pendingOfferIds.size + this._pendingGetQueue.length + this._inFlightGets.size + this._acceptingIds.size;
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
      const pendingIncoming = this._pendingOfferIds.size + this._pendingGetQueue.length + this._inFlightGets.size + this._acceptingIds.size;
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
              await this._handlePut(data, gen, port);
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
          if (nextForce) {
            this._failedAttempts.clear();
            this._timedOutGets.clear();
          }

          const outboxIds = await this.storage.getOutboxIds();
          if (!this._isGenerationActive(gen, port)) return;

          // If a newer reconcile() was requested while getOutboxIds() was pending, fetch the fresher snapshot
          if (this._reconcilePending) {
            nextForce = nextForce || this._reconcileForcePending;
            continue;
          }

          // 1. Build complete validated outbox snapshot (deduplicated while preserving adapter priority order)
          const rawList = Array.isArray(outboxIds) ? outboxIds : [];
          const fullOutboxSet = new Set();
          for (let i = 0; i < rawList.length; i++) {
            const id = rawList[i];
            if (isValidMessageId(id)) {
              fullOutboxSet.add(id);
            }
          }

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
     * Handles incoming OFFER:
     * - Coalesces offered IDs into a bounded set (_pendingOfferIds) so repeated OFFER frames
     *   never spawn unbounded parallel isAccepted() loops.
     */
    async _handleOffer(offer, gen = this._generation, port = this.port) {
      if (!this._isGenerationActive(gen, port) || !offer || !Array.isArray(offer.ids)) {
        return;
      }
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
        if (this._pendingOfferIds.size >= MAX_BATCH_IDS) {
          break;
        }
        this._pendingOfferIds.add(id);
      }

      await this._drainPendingOffers(gen, port);
    }

    /**
     * Single-worker loop per generation that drains coalesced _pendingOfferIds,
     * sends repeated ACKs for already-accepted IDs (Rule 5), and enqueues unaccepted IDs for bounded GETs (Rule 2).
     */
    async _drainPendingOffers(gen = this._generation, port = this.port) {
      if (!this._isGenerationActive(gen, port) || this._processingOffers || this._pendingOfferIds.size === 0) {
        return;
      }

      this._processingOffers = true;
      try {
        while (this._isGenerationActive(gen, port) && this._pendingOfferIds.size > 0) {
          this._pruneExpiredGets();
          const batch = Array.from(this._pendingOfferIds).slice(0, MAX_BATCH_IDS);
          for (const id of batch) {
            this._pendingOfferIds.delete(id);
          }

          const alreadyAccepted = [];
          const repeatedReceipts = Object.create(null);

          for (const id of batch) {
            if (!this._isGenerationActive(gen, port)) return;
            const acc = parseAcceptanceResult(await this.storage.isAccepted(id));
            if (!this._isGenerationActive(gen, port)) return;

            if (acc.accepted) {
              this._failedAttempts.delete(id);
              this._timedOutGets.delete(id);
              this._expiredGets.delete(id);
              alreadyAccepted.push(id);
              if (acc.ackReceipt) {
                repeatedReceipts[id] = acc.ackReceipt;
              }
            } else {
              const failCount = this._failedAttempts.get(id) || 0;
              const timeoutCount = this._timedOutGets.get(id) || 0;
              if (failCount >= MAX_AUTO_RETRIES || timeoutCount >= MAX_AUTO_RETRIES) {
                this.log('warn', `Skipping automatic GET for message ${id} after ${Math.max(failCount, timeoutCount)} unsuccessful attempts in this session`);
                continue;
              }
              const totalOutstanding =
                this._pendingGetQueue.length +
                this._inFlightGets.size +
                this._acceptingIds.size;
              if (
                !this._inFlightGets.has(id) &&
                !this._acceptingIds.has(id) &&
                !this._pendingGetQueue.includes(id) &&
                totalOutstanding < MAX_BATCH_IDS
              ) {
                this._pendingGetQueue.push(id);
              }
            }
          }

          if (!this._isGenerationActive(gen, port)) return;

          // Rule 5: Repeated acknowledgements
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
          this._notifySyncStatus();
        }
      }
    }

    /**
     * Dispatches GET requests from _pendingGetQueue up to the configured maxConcurrency window.
     */
    _dispatchNextGets(gen = this._generation, port = this.port) {
      if (!this._isGenerationActive(gen, port)) return;
      this._pruneExpiredGets();

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
        if (this._acceptingIds.size >= this.maxConcurrency) {
          this.log('warn', `Ignored PUT for ${id}: acceptance concurrency full`);
          return;
        }
        this._inFlightGets.delete(id);
      } else {
        // Late response after slot expiry: only admit if a concurrency slot is currently free
        if ((this._inFlightGets.size + this._acceptingIds.size) >= this.maxConcurrency) {
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
        this._failedAttempts.set(id, fails);
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

        // Duplicate check: if already accepted, send ACK again and do not import twice
        const alreadyAcc = parseAcceptanceResult(await this.storage.isAccepted(id));
        if (!this._isGenerationActive(gen, port)) {
          return;
        }
        if (alreadyAcc.accepted) {
          this._failedAttempts.delete(id);
          this._timedOutGets.delete(id);
          this._expiredGets.delete(id);
          this.log('info', `Message ${id} already accepted; sending ACK without re-importing`);
          if (!this._isGenerationActive(gen, port)) {
            return;
          }
          const receipts = Object.create(null);
          if (alreadyAcc.ackReceipt) {
            receipts[id] = alreadyAcc.ackReceipt;
          }
          const ackMsg = {
            protocol: PROTOCOL_NAME,
            version: PROTOCOL_VERSION,
            type: 'ACK',
            ids: [id],
            receipts: receipts
          };
          if (this._sendToPort(ackMsg, gen, port)) {
            this._emitTransfer({ direction: 'outgoing', type: 'ACK', ids: [id], repeated: true });
          }
          return;
        }

        // Rule 3 & 4: Attempt atomic acceptance with normalized JSON payload
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
          this._failedAttempts.set(id, fails);
          this.log('error', `Acceptance rejected by local storage for message ${id} (attempt ${fails}/${MAX_AUTO_RETRIES}); NO ACK sent`);
        }
      } catch (err) {
        if (this._isGenerationActive(gen, port)) {
          // Transfer failure or storage error: do not send ACK
          const fails = (this._failedAttempts.get(id) || 0) + 1;
          this._failedAttempts.set(id, fails);
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
