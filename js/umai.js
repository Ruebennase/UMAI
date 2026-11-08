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
  const GET_TIMEOUT_MS = 15000;
  const DEFAULT_MAX_CONCURRENCY = 1;
  const MAX_CONCURRENCY_CAP = 16;
  const DEFAULT_MAX_ATTACHMENTS = 50;
  const DEFAULT_MAX_MESSAGE_BYTES = 50 * 1024 * 1024;
  const MAX_SIGNATURE_LEN = 4096;
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
   * Measures the UTF-8 serialized JSON byte length of a message payload, or returns -1 if unserializable.
   */
  function measurePayloadBytes(payload) {
    try {
      const safePayload = (payload !== undefined && payload !== null) ? payload : {};
      const jsonStr = JSON.stringify(safePayload);
      if (typeof jsonStr !== 'string') return -1;
      if (typeof TextEncoder !== 'undefined') {
        return new TextEncoder().encode(jsonStr).byteLength;
      }
      if (typeof Buffer !== 'undefined') {
        return Buffer.byteLength(jsonStr, 'utf8');
      }
      return jsonStr.length;
    } catch (e) {
      return -1;
    }
  }

  /**
   * Validates payload and attachments against maxAttachments and maxMessageBytes (including JSON payload bytes).
   * Returns total byte size (payload + attachments), or -1 if invalid or exceeding bounds.
   */
  function validateMessageSize(payload, attachments, maxAttachments, maxMessageBytes) {
    const payloadBytes = measurePayloadBytes(payload);
    if (payloadBytes < 0 || payloadBytes > maxMessageBytes) {
      return -1;
    }
    if (!Array.isArray(attachments) || attachments.length > maxAttachments) {
      return -1;
    }
    let totalBytes = payloadBytes;
    for (let i = 0; i < attachments.length; i++) {
      const att = attachments[i];
      if (!isValidAttachment(att)) {
        return -1;
      }
      totalBytes += att.size;
      if (totalBytes > maxMessageBytes) {
        return -1;
      }
    }
    return totalBytes;
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
      this.state = 'disconnected'; // 'disconnected' | 'handshaking' | 'connected'
      this._windowListener = this._handleWindowMessage.bind(this);
      this._portListener = (event) => this._handlePortMessage(event, this._generation, this.port);

      // Concurrency control: bounded outgoing PUT transfers and bounded incoming OFFER/GET/PUT processing
      this._putQueue = [];
      this._activeSendCount = 0;
      this._ackingCount = 0;

      // Coalesced incoming OFFER queue and single-worker flag
      this._pendingOfferIds = new Set();
      this._processingOffers = false;

      // Receiver GET windowing queue and in-flight tracking (id -> timestampMs)
      this._pendingGetQueue = [];
      this._inFlightGets = new Map();

      // Track message IDs currently being committed in acceptMessage() and queue incoming PUTs up to maxConcurrency
      this._acceptingIds = new Set();
      this._incomingPutQueue = [];
      this._activeAcceptCount = 0;

      // Track message IDs offered to the peer so only offered IDs can be acknowledged
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
      this._resetChannelState();
      if (this.state !== 'disconnected') {
        this._setState('handshaking', this.peerWindow ? 'Switching to companion window' : 'Switching to embedded iframe');
        if (this.role === 'host' && this._getTargetWindow()) {
          this._initiateHostHandshake();
        }
      }
    }

    /**
     * Returns true if the given generation and MessagePort are still the active connected channel.
     */
    _isGenerationActive(gen, port) {
      return this.state === 'connected' && this._generation === gen && this.port === port && port !== null;
    }

    /**
     * Closes the current MessagePort (if any), increments the connection generation to invalidate
     * any in-flight async work from the prior channel, and clears per-channel state.
     */
    _resetChannelState() {
      this._generation++;
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
      this._activeSendCount = 0;
      this._ackingCount = 0;
      this._pendingOfferIds.clear();
      this._processingOffers = false;
      this._pendingGetQueue = [];
      this._inFlightGets.clear();
      this._acceptingIds.clear();
      this._incomingPutQueue = [];
      this._activeAcceptCount = 0;
      this._offeredIds.clear();
    }

    /**
     * Prune expired in-flight GET reservations so transiently missing/failed sender PUTs can be retried.
     */
    _pruneExpiredGets() {
      const now = Date.now();
      for (const [id, ts] of this._inFlightGets.entries()) {
        if (now - ts >= GET_TIMEOUT_MS) {
          this._inFlightGets.delete(id);
        }
      }
    }

    /**
     * Returns true if a GET request for id is currently active and has not expired.
     */
    _isGetInFlight(id) {
      if (!this._inFlightGets.has(id)) return false;
      const ts = this._inFlightGets.get(id);
      if (Date.now() - ts >= GET_TIMEOUT_MS) {
        this._inFlightGets.delete(id);
        return false;
      }
      return true;
    }

    /**
     * Log a protocol event.
     */
    log(level, message, details = null) {
      this.onLog({ level, message, details, timestamp: new Date().toISOString() });
    }

    /**
     * Update adapter connection state.
     */
    _setState(newState, detail = '') {
      this.state = newState;
      this.onStatusChange({ state: newState, detail });
      this.log('info', `State changed: ${newState} ${detail ? `(${detail})` : ''}`);
      this._notifySyncStatus(detail);
    }

    /**
     * Broadcast real-time synchronization status (transfers ongoing vs complete sync).
     */
    _notifySyncStatus(detail = '') {
      this._pruneExpiredGets();
      const pendingOutgoing = this._putQueue.length + this._activeSendCount + this._ackingCount;
      const pendingIncoming = this._pendingOfferIds.size + this._pendingGetQueue.length + this._inFlightGets.size + this._acceptingIds.size + this._incomingPutQueue.length;
      const isSyncing = pendingOutgoing > 0 || pendingIncoming > 0;
      const info = {
        isSyncing: isSyncing,
        state: this.state,
        pendingOutgoing: pendingOutgoing,
        pendingIncoming: pendingIncoming,
        detail: detail || (isSyncing ? 'Synchronizing...' : (this.state === 'connected' ? 'In sync' : ''))
      };
      try {
        this.onSyncStatus(info);
      } catch (err) {
        // ignore callback error
      }
    }

    /**
     * Get snapshot of current synchronization status.
     */
    getSyncStatus() {
      this._pruneExpiredGets();
      const pendingOutgoing = this._putQueue.length + this._activeSendCount + this._ackingCount;
      const pendingIncoming = this._pendingOfferIds.size + this._pendingGetQueue.length + this._inFlightGets.size + this._acceptingIds.size + this._incomingPutQueue.length;
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

      this._setState('handshaking', `Starting as ${this.role}`);
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
      }

      if (this.role === 'embedded') {
        // Embedded app informs parent window that it is ready
        this._sendReadySignal();
        // Periodically announce ready until parent responds with INIT
        if (!this._readyInterval) {
          this._readyInterval = setInterval(() => {
            if (this.state === 'connected') {
              clearInterval(this._readyInterval);
              this._readyInterval = null;
              return;
            }
            this._sendReadySignal();
          }, 1000);
        }
      } else {
        // Host role: if target window (iframe or popup) is already available, we can initiate
        if (this._getTargetWindow()) {
          this._initiateHostHandshake();
        }
      }
    }

    /**
     * Stop and cleanup session, invalidating any in-flight async operations.
     */
    stop() {
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
    _initiateHostHandshake(targetOrigin = null) {
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
        this.onError(err);
      }
    }

    /**
     * Top-level window message handler (used for the initial secure handshake).
     */
    _handleWindowMessage(event) {
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
          this.log('info', 'Received READY from peer');
          this._resetChannelState();
          this._setState('handshaking', 'Peer sent READY; re-establishing channel');
          this._initiateHostHandshake(event.origin);
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
          port.onmessage = (event) => this._handlePortMessage(event, gen, port);
          this.log('info', 'Received MessagePort from host application');

          this._onEstablished(gen, port, true);
        }
      }
    }

    /**
     * Called once the point-to-point MessagePort is established.
     */
    _onEstablished(gen = this._generation, port = this.port, sendInitAck = false) {
      this._setState('connected', `Connected to ${this.peerOrigin}`);
      if (sendInitAck) {
        this._sendToPort({
          protocol: PROTOCOL_NAME,
          version: PROTOCOL_VERSION,
          type: 'INIT_ACK'
        }, gen, port);
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
          this.onError(err);
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
     * Trigger reconciliation: announces all local outbox message IDs via OFFER.
     * @param {boolean} [force=true] If false, skips sending OFFER when outbox is empty
     */
    async reconcile(force = true, gen = this._generation, port = this.port) {
      if (!this._isGenerationActive(gen, port)) {
        if (force) {
          this.log('warn', 'Reconciliation requested while disconnected; ignoring');
        }
        return;
      }

      if (force) {
        this._failedAttempts.clear();
      }

      try {
        const outboxIds = await this.storage.getOutboxIds();
        if (!this._isGenerationActive(gen, port)) return;

        const ids = (Array.isArray(outboxIds) ? outboxIds : [])
          .filter(isValidMessageId)
          .slice(0, MAX_BATCH_IDS);

        // Also drain any pending receiver GET window if slots are open
        this._dispatchNextGets(gen, port);

        // If background periodic check and outbox is empty, avoid log noise
        if (!force && ids.length === 0) {
          return;
        }

        for (const id of ids) {
          if (this._offeredIds.size < MAX_BATCH_IDS) {
            this._offeredIds.add(id);
          }
        }

        this.log('info', `Reconciling: offering ${ids.length} outbox message(s)`, ids);

        const offerMsg = {
          protocol: PROTOCOL_NAME,
          version: PROTOCOL_VERSION,
          type: 'OFFER',
          ids: ids
        };

        if (this._sendToPort(offerMsg, gen, port)) {
          this.onTransfer({ direction: 'outgoing', type: 'OFFER', ids: offerMsg.ids });
        }
      } catch (err) {
        if (!this._isGenerationActive(gen, port)) return;
        this.log('error', 'Failed to retrieve outbox for OFFER', err.message);
        this.onError(err);
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
      this.onTransfer({ direction: 'incoming', type: 'OFFER', ids: offeredIds });

      // Symmetrical reconciliation: ensure our own outbox is offered in return
      if (!this._peerOfferedOnce) {
        this._peerOfferedOnce = true;
        this.reconcile(false, gen, port);
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
              alreadyAccepted.push(id);
              if (acc.ackReceipt) {
                repeatedReceipts[id] = acc.ackReceipt;
              }
            } else {
              const failCount = this._failedAttempts.get(id) || 0;
              if (failCount >= MAX_AUTO_RETRIES) {
                this.log('warn', `Skipping automatic GET for message ${id} after ${failCount} failed acceptance attempts in this session`);
                continue;
              }
              const totalOutstanding =
                this._pendingGetQueue.length +
                this._inFlightGets.size +
                this._acceptingIds.size +
                this._incomingPutQueue.length;
              if (
                !this._isGetInFlight(id) &&
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
            const ackMsg = {
              protocol: PROTOCOL_NAME,
              version: PROTOCOL_VERSION,
              type: 'ACK',
              ids: alreadyAccepted,
              receipts: repeatedReceipts
            };
            if (this._sendToPort(ackMsg, gen, port)) {
              this.onTransfer({ direction: 'outgoing', type: 'ACK', ids: alreadyAccepted, repeated: true });
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

      const activeReceives = this._inFlightGets.size + this._acceptingIds.size + this._incomingPutQueue.length;
      const availableSlots = this.maxConcurrency - activeReceives;
      if (availableSlots <= 0 || this._pendingGetQueue.length === 0) {
        return;
      }

      const toFetch = [];
      while (toFetch.length < availableSlots && this._pendingGetQueue.length > 0) {
        const nextId = this._pendingGetQueue.shift();
        if (!this._isGetInFlight(nextId) && !this._acceptingIds.has(nextId)) {
          toFetch.push(nextId);
        }
      }

      if (toFetch.length > 0) {
        const now = Date.now();
        for (const id of toFetch) {
          this._inFlightGets.set(id, now);
        }
        this._notifySyncStatus(`Requesting ${toFetch.length} unaccepted message(s)...`);
        this.log('info', `Requesting unaccepted message(s) via GET`, toFetch);
        const getMsg = {
          protocol: PROTOCOL_NAME,
          version: PROTOCOL_VERSION,
          type: 'GET',
          ids: toFetch
        };
        if (this._sendToPort(getMsg, gen, port)) {
          this.onTransfer({ direction: 'outgoing', type: 'GET', ids: toFetch });
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
      this.onTransfer({ direction: 'incoming', type: 'GET', ids: requestedIds });

      for (const id of requestedIds) {
        this._queuePut(id, gen, port);
      }
    }

    /**
     * Enqueues a message ID to be transferred as a PUT (deduplicating already queued IDs and capping queue size).
     */
    _queuePut(id, gen = this._generation, port = this.port) {
      if (!this._isGenerationActive(gen, port)) return;
      if (this._putQueue.includes(id) || this._putQueue.length >= MAX_BATCH_IDS) {
        return;
      }
      this._putQueue.push(id);
      this._notifySyncStatus(`Transfer queued for message ${id}`);
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

      this._activeSendCount++;
      const id = this._putQueue.shift();
      this._notifySyncStatus(`Sending message ${id}...`);

      try {
        this.log('info', `Preparing PUT for message ${id}`);
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
        const safePayload = (msg.payload !== undefined && msg.payload !== null) ? msg.payload : {};
        if (validateMessageSize(safePayload, msg.attachments, this.maxAttachments, this.maxMessageBytes) < 0) {
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
          payload: safePayload,
          attachments: msg.attachments,
          signature: sigStr
        };

        this.log(
          'info',
          `Sending PUT for message ${id} with ${msg.attachments.length} attachment(s)`
        );

        if (this._sendToPort(putMsg, gen, port)) {
          this.onTransfer({
            direction: 'outgoing',
            type: 'PUT',
            id: id,
            attachmentCount: msg.attachments.length
          });
        }
      } catch (err) {
        if (this._isGenerationActive(gen, port)) {
          this.log('error', `Failed to send PUT for message ${id}`, err.message);
          this.onError(err);
        }
      } finally {
        if (this._isGenerationActive(gen, port)) {
          this._activeSendCount = Math.max(0, this._activeSendCount - 1);
          this._notifySyncStatus();
          // Process next item in queue if still active
          this._processPutQueue(gen, port);
        }
      }
    }

    /**
     * Handles incoming PUT:
     * - Rule 2: Enforces receiver-controlled transfer (rejects unsolicited PUTs not in _inFlightGets).
     * - Rule 3: Complete messages only. Validates payload + attachments array and bounds before acceptance.
     * - Queues and processes incoming PUTs within maxConcurrency so receiver work is strictly bounded.
     */
    async _handlePut(put, gen = this._generation, port = this.port) {
      if (!this._isGenerationActive(gen, port) || !put || typeof put !== 'object') {
        return;
      }
      const id = put.id;
      if (
        !isValidMessageId(id) ||
        !this._isGetInFlight(id) ||
        this._acceptingIds.has(id) ||
        (this._incomingPutQueue.length + this._activeAcceptCount) >= this.maxConcurrency
      ) {
        this.log('warn', `Ignored unsolicited or duplicate in-flight PUT for message ${id}`);
        return;
      }
      this._inFlightGets.delete(id);

      // Validate wire format & bounds (Rule 3: reject malformed/incomplete envelopes before touching storage)
      const sigStr = (put.signature !== undefined && put.signature !== null) ? put.signature : '';
      const safePayload = (put.payload !== undefined && put.payload !== null) ? put.payload : {};
      if (
        typeof sigStr !== 'string' ||
        sigStr.length > MAX_SIGNATURE_LEN ||
        validateMessageSize(safePayload, put.attachments, this.maxAttachments, this.maxMessageBytes) < 0
      ) {
        const fails = (this._failedAttempts.get(id) || 0) + 1;
        this._failedAttempts.set(id, fails);
        const err = new Error(`Rejected PUT for message ${id}: invalid payload/attachments or exceeded size/count bounds`);
        this.log('error', err.message);
        this.onError(err);
        this._notifySyncStatus();
        this._dispatchNextGets(gen, port);
        return;
      }

      this._acceptingIds.add(id);
      this._incomingPutQueue.push({ put, gen, port });
      this._notifySyncStatus(`Receiving message ${id} (${put.attachments.length} attachment(s))...`);
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

      const { put } = item;
      const id = put.id;
      const attachments = put.attachments;
      this._activeAcceptCount++;

      this.log(
        'info',
        `Received PUT for message ${id} with ${attachments.length} attachment(s)`
      );
      this.onTransfer({
        direction: 'incoming',
        type: 'PUT',
        id: id,
        attachmentCount: attachments.length
      });

      try {
        // Duplicate check: if already accepted, send ACK again and do not import twice
        const alreadyAcc = parseAcceptanceResult(await this.storage.isAccepted(id));
        if (!this._isGenerationActive(gen, port)) {
          return;
        }
        if (alreadyAcc.accepted) {
          this.log('info', `Message ${id} already accepted; sending ACK without re-importing`);
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
            this.onTransfer({ direction: 'outgoing', type: 'ACK', ids: [id], repeated: true });
          }
          return;
        }

        // Rule 3 & 4: Attempt atomic acceptance
        const acceptRes = parseAcceptanceResult(await this.storage.acceptMessage({
          id: id,
          payload: (put.payload !== undefined && put.payload !== null) ? put.payload : {},
          attachments: attachments,
          signature: typeof put.signature === 'string' ? put.signature : ''
        }));

        if (!this._isGenerationActive(gen, port)) {
          return;
        }

        if (acceptRes.accepted) {
          this._failedAttempts.delete(id);
          this.log('info', `Successfully accepted message ${id}. Sending ACK.`);
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
            this.onTransfer({ direction: 'outgoing', type: 'ACK', ids: [id] });
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
          this.onError(err);
        }
      } finally {
        if (this._isGenerationActive(gen, port)) {
          this._acceptingIds.delete(id);
          this._activeAcceptCount = Math.max(0, this._activeAcceptCount - 1);
          this._notifySyncStatus();
          // Request next window of GETs and process any queued PUTs
          this._dispatchNextGets(gen, port);
          this._processIncomingPutQueue(gen, port);
        }
      }
    }

    /**
     * Handles incoming ACK:
     * - Rule 6: Sender cleanup upon receiving ACK.
     * - Only acknowledges IDs that were actually offered by this sender.
     * - Removes acknowledged message from outbox.
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
      this.onTransfer({ direction: 'incoming', type: 'ACK', ids: validIds });

      if (validIds.length === 0) return;

      const receipts = Object.create(null);
      if (ack.receipts && typeof ack.receipts === 'object') {
        for (const id of validIds) {
          if (
            Object.prototype.hasOwnProperty.call(ack.receipts, id) &&
            typeof ack.receipts[id] === 'string' &&
            ack.receipts[id].length <= MAX_SIGNATURE_LEN
          ) {
            receipts[id] = ack.receipts[id];
          }
        }
      }

      this._ackingCount++;
      this._notifySyncStatus(`Acknowledging ${validIds.length} message(s)...`);
      try {
        await this.storage.onAcknowledged(validIds, receipts);
        if (!this._isGenerationActive(gen, port)) {
          return;
        }
        for (const id of validIds) {
          this._offeredIds.delete(id);
        }
        this.log('info', `Removed acknowledged message(s) from outbox:`, validIds);
      } catch (err) {
        if (this._isGenerationActive(gen, port)) {
          this.log('error', 'Error processing ACK in local storage', err.message);
          this.onError(err);
        }
      } finally {
        if (this._isGenerationActive(gen, port)) {
          this._ackingCount = Math.max(0, this._ackingCount - 1);
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
