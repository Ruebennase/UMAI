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

  /**
   * Validates a message identifier is a safe, bounded string.
   */
  function isValidMessageId(id) {
    return typeof id === 'string' && id.length > 0 && id.length <= 128;
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
   * Validates whether incoming origin matches expected origin (HTTP/HTTPS only),
   * supporting local loopback synonyms (localhost <-> 127.0.0.1 on matching port).
   */
  function isAllowedOrigin(incomingOrigin, expectedOrigin) {
    if (!incomingOrigin || !expectedOrigin) return false;
    try {
      const inc = new URL(incomingOrigin);
      const exp = new URL(expectedOrigin);
      if ((inc.protocol !== 'http:' && inc.protocol !== 'https:') ||
          (exp.protocol !== 'http:' && exp.protocol !== 'https:')) {
        return false;
      }
      if (inc.origin === exp.origin) return true;
      const isLoopback = (host) => host === 'localhost' || host === '127.0.0.1';
      if (isLoopback(inc.hostname) && isLoopback(exp.hostname) && inc.port === exp.port && inc.protocol === exp.protocol) {
        return true;
      }
    } catch (e) {
      // ignore parse errors
    }
    return false;
  }

  /**
   * Main UMAI Session Adapter.
   */
  class UmaiSession {
    /**
     * @param {Object} options
     * @param {string} options.peerOrigin Expected origin of the remote application (e.g. 'http://127.0.0.1:8081')
     * @param {string} [options.role] 'host' or 'embedded' (auto-detected if omitted)
     * @param {HTMLIFrameElement} [options.iframe] The iframe element (for 'host' role when using iframe embedding)
     * @param {Window} [options.peerWindow] Optional direct Window reference (e.g. popup from window.open or window.opener)
     * @param {Object} options.storage Handlers for reading/writing local messages:
     *   - getOutboxIds(): Promise<string[]>
     *   - getMessage(id): Promise<{ id: string, payload: any, attachments: File[] }>
     *   - isAccepted(id): Promise<boolean>
     *   - acceptMessage(msg: { id: string, payload: any, attachments: File[] }): Promise<boolean>
     *   - onAcknowledged(ids: string[]): Promise<void>
     * @param {Function} [options.onStatusChange] Callback: ({ state, detail }) => void
     * @param {Function} [options.onLog] Callback: ({ level, message, details }) => void
     * @param {Function} [options.onError] Callback: (error) => void
     * @param {Function} [options.onTransfer] Callback: ({ direction, type, id, info }) => void
     */
    constructor(options) {
      if (!options || !options.peerOrigin) {
        throw new Error('UMAI: peerOrigin is required');
      }
      if (!options.storage) {
        throw new Error('UMAI: storage interface is required');
      }

      this.peerOrigin = options.peerOrigin;
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
      this.state = 'disconnected'; // 'disconnected' | 'handshaking' | 'connected'
      this._windowListener = this._handleWindowMessage.bind(this);
      this._portListener = this._handlePortMessage.bind(this);

      // Concurrency control: only one outgoing PUT transfer at a time
      this._putQueue = [];
      this._isSendingPut = false;
      this._ackingCount = 0;

      // Track in-flight PUT requests (id -> timestampMs) to avoid redundant GETs, expire stale GETs, and reject unsolicited PUTs
      this._inFlightGets = new Map();

      // Track message IDs currently being committed in acceptMessage() to prevent overlapping imports and premature "In Sync" status
      this._acceptingIds = new Set();

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
      this.peerWindow = win || null;
      if (this.role === 'host' && this.peerWindow && !this.peerWindow.closed) {
        this._initiateHostHandshake();
      }
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
      const pendingOutgoing = this._putQueue.length + (this._isSendingPut ? 1 : 0) + this._ackingCount;
      const pendingIncoming = this._inFlightGets.size + this._acceptingIds.size;
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
      const pendingOutgoing = this._putQueue.length + (this._isSendingPut ? 1 : 0) + this._ackingCount;
      const pendingIncoming = this._inFlightGets.size + this._acceptingIds.size;
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
     */
    start() {
      if (this.state === 'connected') return;

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
     * Stop and cleanup session.
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
      if (this.port) {
        try {
          this.port.close();
        } catch (e) {
          // ignore
        }
        this.port = null;
      }
      this._peerOfferedOnce = false;
      this._putQueue = [];
      this._isSendingPut = false;
      this._ackingCount = 0;
      this._inFlightGets.clear();
      this._acceptingIds.clear();
      this._offeredIds.clear();
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

      try {
        const channel = new MessageChannel();
        this.port = channel.port1;
        this.port.onmessage = this._portListener;

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
      // Validate origin strictly (supports localhost/127.0.0.1 synonym on matching port)
      if (!isAllowedOrigin(event.origin, this.peerOrigin)) {
        return;
      }

      const data = event.data;
      if (!isValidUmaiMessage(data)) {
        return;
      }

      const expectedSource = this._getTargetWindow();

      if (this.role === 'host') {
        if (expectedSource && event.source && event.source !== expectedSource) {
          return;
        }
        if (data.type === 'READY') {
          if (!this.peerWindow && !this.iframe && event.source) {
            this.peerWindow = event.source;
          }
          this.log('info', 'Received READY from peer');
          // If peer reloaded or restarted, reset port and per-channel transfer state
          if (this.port) {
            try {
              this.port.close();
            } catch (e) {}
            this.port = null;
          }
          this._peerOfferedOnce = false;
          this._putQueue = [];
          this._isSendingPut = false;
          this._inFlightGets.clear();
          this._offeredIds.clear();
          this._setState('handshaking', 'Peer sent READY; re-establishing channel');
          this._initiateHostHandshake(event.origin);
        }
      } else if (this.role === 'embedded') {
        if (expectedSource && event.source && event.source !== expectedSource) {
          return;
        }
        if (data.type === 'INIT' && event.ports && event.ports.length > 0) {
          if (this._readyInterval) {
            clearInterval(this._readyInterval);
            this._readyInterval = null;
          }
          if (this.port) {
            try {
              this.port.close();
            } catch (e) {}
          }
          this._peerOfferedOnce = false;
          this._putQueue = [];
          this._isSendingPut = false;
          this._inFlightGets.clear();
          this._offeredIds.clear();
          this.port = event.ports[0];
          this.port.onmessage = this._portListener;
          this.log('info', 'Received MessagePort from host application');

          // Send confirmation back over the port
          this._sendToPort({
            protocol: PROTOCOL_NAME,
            version: PROTOCOL_VERSION,
            type: 'INIT_ACK'
          });

          this._onEstablished();
        }
      }
    }

    /**
     * Called once the point-to-point MessagePort is established.
     */
    _onEstablished() {
      this._setState('connected', `Connected to ${this.peerOrigin}`);
      // Rule 7: Reconnection - both sides exchange outstanding offers
      this.reconcile();
    }

    /**
     * Dedicated MessagePort event handler for all protocol messages.
     */
    async _handlePortMessage(event) {
      const data = event.data;
      if (!isValidUmaiMessage(data)) {
        this.log('warn', 'Ignored invalid protocol message on port', data);
        return;
      }

      try {
        switch (data.type) {
          case 'INIT_ACK':
            if (this.role === 'host' && this.state !== 'connected') {
              this._onEstablished();
            }
            break;

          case 'OFFER':
            await this._handleOffer(data);
            break;

          case 'GET':
            await this._handleGet(data);
            break;

          case 'PUT':
            await this._handlePut(data);
            break;

          case 'ACK':
            await this._handleAck(data);
            break;

          default:
            this.log('warn', `Unknown message type received: ${data.type}`);
        }
      } catch (err) {
        this.log('error', `Error handling ${data.type} message`, err.message);
        this.onError(err);
      }
    }

    /**
     * Sends a raw message object over the established MessagePort.
     */
    _sendToPort(msg, transferList = []) {
      if (!this.port) {
        throw new Error('UMAI: Cannot send message, MessagePort not connected');
      }
      this.port.postMessage(msg, transferList);
    }

    /**
     * Trigger reconciliation: announces all local outbox message IDs via OFFER.
     * @param {boolean} [force=true] If false, skips sending OFFER when outbox is empty
     */
    async reconcile(force = true) {
      if (this.state !== 'connected') {
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
        const ids = (Array.isArray(outboxIds) ? outboxIds : [])
          .filter(isValidMessageId)
          .slice(0, MAX_BATCH_IDS);

        // If background periodic check and outbox is empty, avoid log noise
        if (!force && ids.length === 0) {
          return;
        }

        for (const id of ids) {
          this._offeredIds.add(id);
        }

        this.log('info', `Reconciling: offering ${ids.length} outbox message(s)`, ids);

        const offerMsg = {
          protocol: PROTOCOL_NAME,
          version: PROTOCOL_VERSION,
          type: 'OFFER',
          ids: ids
        };

        this._sendToPort(offerMsg);
        this.onTransfer({ direction: 'outgoing', type: 'OFFER', ids: offerMsg.ids });
      } catch (err) {
        this.log('error', 'Failed to retrieve outbox for OFFER', err.message);
        this.onError(err);
      }
    }

    /**
     * Handles incoming OFFER:
     * - Partitions IDs into already accepted vs. not accepted.
     * - Rule 5: For already accepted IDs, sends repeated ACK immediately!
     * - Rule 2: For unaccepted IDs, sends GET.
     */
    async _handleOffer(offer) {
      const offeredIds = (Array.isArray(offer.ids) ? offer.ids : [])
        .filter(isValidMessageId)
        .slice(0, MAX_BATCH_IDS);
      this.log('info', `Received OFFER with ${offeredIds.length} message(s)`, offeredIds);
      this.onTransfer({ direction: 'incoming', type: 'OFFER', ids: offeredIds });

      // Symmetrical reconciliation: ensure our own outbox is offered in return
      if (!this._peerOfferedOnce) {
        this._peerOfferedOnce = true;
        this.reconcile(false);
      }

      if (offeredIds.length === 0) return;

      this._pruneExpiredGets();

      const alreadyAccepted = [];
      const repeatedReceipts = Object.create(null);
      const toFetch = [];

      for (const id of offeredIds) {
        const accResult = await this.storage.isAccepted(id);
        if (accResult) {
          this._failedAttempts.delete(id);
          alreadyAccepted.push(id);
          if (typeof accResult === 'string' && accResult.length > 0) {
            repeatedReceipts[id] = accResult;
          } else if (typeof accResult === 'object' && accResult.ackReceipt) {
            repeatedReceipts[id] = accResult.ackReceipt;
          }
        } else {
          const failCount = this._failedAttempts.get(id) || 0;
          if (failCount >= MAX_AUTO_RETRIES) {
            this.log('warn', `Skipping automatic GET for message ${id} after ${failCount} failed acceptance attempts in this session`);
            continue;
          }
          // If not currently in-flight or being committed by acceptMessage
          if (!this._isGetInFlight(id) && !this._acceptingIds.has(id)) {
            toFetch.push(id);
          }
        }
      }

      // Rule 5: Repeated acknowledgements
      // If any offered message was already accepted, ACK it immediately again!
      if (alreadyAccepted.length > 0) {
        this.log('info', `Rule 5: Sending repeated ACK for already accepted ID(s)`, alreadyAccepted);
        const ackMsg = {
          protocol: PROTOCOL_NAME,
          version: PROTOCOL_VERSION,
          type: 'ACK',
          ids: alreadyAccepted,
          receipts: repeatedReceipts
        };
        this._sendToPort(ackMsg);
        this.onTransfer({ direction: 'outgoing', type: 'ACK', ids: alreadyAccepted, repeated: true });
      }

      // Rule 2: Receiver-controlled transfer
      // Request only messages that have not been accepted yet
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
        this._sendToPort(getMsg);
        this.onTransfer({ direction: 'outgoing', type: 'GET', ids: toFetch });
      }
    }

    /**
     * Handles incoming GET:
     * Queues outgoing PUT messages strictly for IDs that were previously offered by this sender.
     */
    async _handleGet(get) {
      const rawIds = (Array.isArray(get.ids) ? get.ids : [])
        .filter(isValidMessageId)
        .slice(0, MAX_BATCH_IDS);
      const requestedIds = rawIds.filter(id => this._offeredIds.has(id));
      if (requestedIds.length !== rawIds.length) {
        this.log('warn', `Ignored GET for unoffered ID(s)`, rawIds.filter(id => !this._offeredIds.has(id)));
      }
      this.log('info', `Received GET request for ${requestedIds.length} message(s)`, requestedIds);
      this.onTransfer({ direction: 'incoming', type: 'GET', ids: requestedIds });

      for (const id of requestedIds) {
        this._queuePut(id);
      }
    }

    /**
     * Enqueues a message ID to be transferred as a PUT (deduplicating already queued IDs).
     */
    _queuePut(id) {
      if (this._putQueue.includes(id)) {
        return;
      }
      this._putQueue.push(id);
      this._notifySyncStatus(`Transfer queued for message ${id}`);
      this._processPutQueue();
    }

    /**
     * Serialized transfer worker: sends one PUT at a time per direction.
     */
    async _processPutQueue() {
      if (this._isSendingPut || this._putQueue.length === 0 || this.state !== 'connected') {
        return;
      }

      this._isSendingPut = true;
      const id = this._putQueue.shift();
      this._notifySyncStatus(`Sending message ${id}...`);

      try {
        this.log('info', `Preparing PUT for message ${id}`);
        const msg = await this.storage.getMessage(id);
        if (!msg) {
          this.log('warn', `Message ${id} not found in outbox, skipping PUT`);
          this._isSendingPut = false;
          this._processPutQueue();
          return;
        }

        // Attachments must be native File/Blob objects
        const attachments = Array.isArray(msg.attachments) ? msg.attachments : [];
        const safePayload = (msg.payload !== undefined && msg.payload !== null) ? msg.payload : {};
        const putMsg = {
          protocol: PROTOCOL_NAME,
          version: PROTOCOL_VERSION,
          type: 'PUT',
          id: msg.id,
          payload: safePayload,
          attachments: attachments,
          signature: msg.signature || ''
        };

        this.log(
          'info',
          `Sending PUT for message ${id} with ${attachments.length} attachment(s)`
        );

        this._sendToPort(putMsg);
        this.onTransfer({
          direction: 'outgoing',
          type: 'PUT',
          id: msg.id,
          attachmentCount: attachments.length
        });
      } catch (err) {
        this.log('error', `Failed to send PUT for message ${id}`, err.message);
        this.onError(err);
      } finally {
        this._isSendingPut = false;
        this._notifySyncStatus();
        // Process next item in queue
        this._processPutQueue();
      }
    }

    /**
     * Handles incoming PUT:
     * - Rule 2: Enforces receiver-controlled transfer (rejects unsolicited PUTs not in _inFlightGets).
     * - Rule 3: Complete messages only. Either accepts entire message or rejects.
     * - Checks duplicate: if already accepted, sends ACK again without re-importing.
     * - Stores payload and all attachments atomically on receiver server.
     * - Rule 4: Sends ACK only after successful acceptance.
     */
    async _handlePut(put) {
      const id = put.id;
      if (!isValidMessageId(id) || !this._inFlightGets.has(id) || this._acceptingIds.has(id)) {
        this.log('warn', `Ignored unsolicited or duplicate in-flight PUT for message ${id}`);
        return;
      }
      this._inFlightGets.delete(id);
      this._acceptingIds.add(id);

      const attachments = Array.isArray(put.attachments) ? put.attachments : [];
      this._notifySyncStatus(`Receiving message ${id} (${attachments.length} attachment(s))...`);
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
        const alreadyAccepted = await this.storage.isAccepted(id);
        if (alreadyAccepted) {
          this.log('info', `Message ${id} already accepted; sending ACK without re-importing`);
          const receipts = Object.create(null);
          if (typeof alreadyAccepted === 'string' && alreadyAccepted.length > 0) {
            receipts[id] = alreadyAccepted;
          } else if (typeof alreadyAccepted === 'object' && alreadyAccepted.ackReceipt) {
            receipts[id] = alreadyAccepted.ackReceipt;
          }
          const ackMsg = {
            protocol: PROTOCOL_NAME,
            version: PROTOCOL_VERSION,
            type: 'ACK',
            ids: [id],
            receipts: receipts
          };
          this._sendToPort(ackMsg);
          this.onTransfer({ direction: 'outgoing', type: 'ACK', ids: [id], repeated: true });
          return;
        }

        // Rule 3 & 4: Attempt atomic acceptance
        const result = await this.storage.acceptMessage({
          id: put.id,
          payload: (put.payload !== undefined && put.payload !== null) ? put.payload : {},
          attachments: attachments,
          signature: typeof put.signature === 'string' ? put.signature : ''
        });

        if (result) {
          this._failedAttempts.delete(id);
          this.log('info', `Successfully accepted message ${id}. Sending ACK.`);
          const receipts = Object.create(null);
          if (typeof result === 'string' && result.length > 0) {
            receipts[id] = result;
          } else if (typeof result === 'object' && result.ackReceipt) {
            receipts[id] = result.ackReceipt;
          }
          const ackMsg = {
            protocol: PROTOCOL_NAME,
            version: PROTOCOL_VERSION,
            type: 'ACK',
            ids: [id],
            receipts: receipts
          };
          this._sendToPort(ackMsg);
          this.onTransfer({ direction: 'outgoing', type: 'ACK', ids: [id] });
        } else {
          const fails = (this._failedAttempts.get(id) || 0) + 1;
          this._failedAttempts.set(id, fails);
          this.log('error', `Acceptance rejected by local storage for message ${id} (attempt ${fails}/${MAX_AUTO_RETRIES}); NO ACK sent`);
        }
      } catch (err) {
        // Transfer failure or storage error: do not send ACK
        const fails = (this._failedAttempts.get(id) || 0) + 1;
        this._failedAttempts.set(id, fails);
        this.log('error', `Failed to accept message ${id} (attempt ${fails}/${MAX_AUTO_RETRIES}): ${err.message}; NO ACK sent`);
        this.onError(err);
      } finally {
        this._acceptingIds.delete(id);
        this._notifySyncStatus();
      }
    }

    /**
     * Handles incoming ACK:
     * - Rule 6: Sender cleanup upon receiving ACK.
     * - Only acknowledges IDs that were actually offered by this sender.
     * - Removes acknowledged message from outbox.
     */
    async _handleAck(ack) {
      const rawIds = (Array.isArray(ack.ids) ? ack.ids : [])
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
          if (Object.prototype.hasOwnProperty.call(ack.receipts, id) && typeof ack.receipts[id] === 'string') {
            receipts[id] = ack.receipts[id];
          }
        }
      }

      this._ackingCount++;
      this._notifySyncStatus(`Acknowledging ${validIds.length} message(s)...`);
      try {
        await this.storage.onAcknowledged(validIds, receipts);
        for (const id of validIds) {
          this._offeredIds.delete(id);
        }
        this.log('info', `Removed acknowledged message(s) from outbox:`, validIds);
      } catch (err) {
        this.log('error', 'Error processing ACK in local storage', err.message);
        this.onError(err);
      } finally {
        this._ackingCount = Math.max(0, this._ackingCount - 1);
        this._notifySyncStatus();
      }
    }
  }

  // Export to global scope / CommonJS
  if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
      UmaiSession,
      PROTOCOL_NAME,
      PROTOCOL_VERSION,
      isValidUmaiMessage
    };
  } else {
    global.UMAI = {
      UmaiSession,
      PROTOCOL_NAME,
      PROTOCOL_VERSION,
      isValidUmaiMessage
    };
  }
})(typeof window !== 'undefined' ? window : this);
