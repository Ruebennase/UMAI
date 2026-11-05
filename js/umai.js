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
   * Validates whether incoming origin matches expected origin,
   * supporting local loopback synonyms (localhost <-> 127.0.0.1 on matching port).
   */
  function isAllowedOrigin(incomingOrigin, expectedOrigin) {
    if (!incomingOrigin || !expectedOrigin) return false;
    if (incomingOrigin === expectedOrigin) return true;
    try {
      const inc = new URL(incomingOrigin);
      const exp = new URL(expectedOrigin);
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
     * @param {HTMLIFrameElement} [options.iframe] The iframe element (required for 'host' role)
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
      this.onLog = options.onLog || (() => {});
      this.onError = options.onError || (() => {});
      this.onTransfer = options.onTransfer || (() => {});

      this.iframe = options.iframe || null;
      this.role = options.role || (typeof window !== 'undefined' && window.parent !== window ? 'embedded' : 'host');

      this.port = null;
      this.state = 'disconnected'; // 'disconnected' | 'handshaking' | 'connected'
      this._windowListener = this._handleWindowMessage.bind(this);
      this._portListener = this._handlePortMessage.bind(this);

      // Concurrency control: only one outgoing PUT transfer at a time
      this._putQueue = [];
      this._isSendingPut = false;

      // Track in-flight PUT requests to avoid redundant GETs
      this._inFlightGets = new Set();
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
    }

    /**
     * Start the UMAI adapter and initiate handshake with peer.
     */
    start() {
      if (this.state === 'connected') return;

      this._setState('handshaking', `Starting as ${this.role}`);
      if (typeof window !== 'undefined' && window.addEventListener) {
        window.addEventListener('message', this._windowListener);
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
        this._readyInterval = setInterval(() => {
          if (this.state === 'connected') {
            clearInterval(this._readyInterval);
            return;
          }
          this._sendReadySignal();
        }, 1000);
      } else {
        // Host role: if iframe is already loaded, we can initiate
        if (this.iframe && this.iframe.contentWindow) {
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
      if (typeof window !== 'undefined' && window.removeEventListener) {
        window.removeEventListener('message', this._windowListener);
      }
      if (this.port) {
        try {
          this.port.close();
        } catch (e) {
          // ignore
        }
        this.port = null;
      }
      this._putQueue = [];
      this._isSendingPut = false;
      this._inFlightGets.clear();
      this._setState('disconnected');
    }

    /**
     * Send READY signal from embedded window to parent.
     */
    _sendReadySignal() {
      if (window.parent && window.parent !== window) {
        try {
          window.parent.postMessage(
            { protocol: PROTOCOL_NAME, version: PROTOCOL_VERSION, type: 'READY' },
            this.peerOrigin
          );
        } catch (err) {
          this.log('error', 'Failed to send READY signal', err.message);
        }
      }
    }

    /**
     * Host initializes MessageChannel and posts port2 to embedded iframe.
     */
    _initiateHostHandshake(targetOrigin = null) {
      if (!this.iframe || !this.iframe.contentWindow) {
        this.log('warn', 'Cannot initiate handshake: iframe or contentWindow missing');
        return;
      }

      const destOrigin = targetOrigin || this.peerOrigin;

      try {
        const channel = new MessageChannel();
        this.port = channel.port1;
        this.port.onmessage = this._portListener;

        this.iframe.contentWindow.postMessage(
          { protocol: PROTOCOL_NAME, version: PROTOCOL_VERSION, type: 'INIT' },
          destOrigin,
          [channel.port2]
        );

        this.log('info', `Sent INIT and MessagePort to embedded application (${destOrigin})`);
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

      if (this.role === 'host') {
        if (data.type === 'READY') {
          this.log('info', 'Received READY from embedded peer');
          this._initiateHostHandshake(event.origin);
        }
      } else if (this.role === 'embedded') {
        if (data.type === 'INIT' && event.ports && event.ports.length > 0) {
          if (this._readyInterval) {
            clearInterval(this._readyInterval);
            this._readyInterval = null;
          }
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

      try {
        const outboxIds = await this.storage.getOutboxIds();
        const ids = Array.isArray(outboxIds) ? outboxIds : [];

        // If background periodic check and outbox is empty, avoid log noise
        if (!force && ids.length === 0) {
          return;
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
      const offeredIds = Array.isArray(offer.ids) ? offer.ids : [];
      this.log('info', `Received OFFER with ${offeredIds.length} message(s)`, offeredIds);
      this.onTransfer({ direction: 'incoming', type: 'OFFER', ids: offeredIds });

      // Symmetrical reconciliation: ensure our own outbox is offered in return
      if (!this._peerOfferedOnce) {
        this._peerOfferedOnce = true;
        this.reconcile(false);
      }

      if (offeredIds.length === 0) return;

      const alreadyAccepted = [];
      const toFetch = [];

      for (const id of offeredIds) {
        const isAcc = await this.storage.isAccepted(id);
        if (isAcc) {
          alreadyAccepted.push(id);
        } else {
          // If not currently in-flight
          if (!this._inFlightGets.has(id)) {
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
          ids: alreadyAccepted
        };
        this._sendToPort(ackMsg);
        this.onTransfer({ direction: 'outgoing', type: 'ACK', ids: alreadyAccepted, repeated: true });
      }

      // Rule 2: Receiver-controlled transfer
      // Request only messages that have not been accepted yet
      if (toFetch.length > 0) {
        for (const id of toFetch) {
          this._inFlightGets.add(id);
        }
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
     * Queues outgoing PUT messages for the requested IDs.
     */
    async _handleGet(get) {
      const requestedIds = Array.isArray(get.ids) ? get.ids : [];
      this.log('info', `Received GET request for ${requestedIds.length} message(s)`, requestedIds);
      this.onTransfer({ direction: 'incoming', type: 'GET', ids: requestedIds });

      for (const id of requestedIds) {
        this._queuePut(id);
      }
    }

    /**
     * Enqueues a message ID to be transferred as a PUT.
     */
    _queuePut(id) {
      this._putQueue.push(id);
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
        const putMsg = {
          protocol: PROTOCOL_NAME,
          version: PROTOCOL_VERSION,
          type: 'PUT',
          id: msg.id,
          payload: msg.payload || {},
          attachments: attachments
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
        // Process next item in queue
        this._processPutQueue();
      }
    }

    /**
     * Handles incoming PUT:
     * - Rule 3: Complete messages only. Either accepts entire message or rejects.
     * - Checks duplicate: if already accepted, sends ACK again without re-importing.
     * - Stores payload and all attachments atomically on receiver server.
     * - Rule 4: Sends ACK only after successful acceptance.
     */
    async _handlePut(put) {
      const id = put.id;
      this._inFlightGets.delete(id);

      const attachments = Array.isArray(put.attachments) ? put.attachments : [];
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

      // Duplicate check: if already accepted, send ACK again and do not import twice
      const alreadyAccepted = await this.storage.isAccepted(id);
      if (alreadyAccepted) {
        this.log('info', `Message ${id} already accepted; sending ACK without re-importing`);
        const ackMsg = {
          protocol: PROTOCOL_NAME,
          version: PROTOCOL_VERSION,
          type: 'ACK',
          ids: [id]
        };
        this._sendToPort(ackMsg);
        this.onTransfer({ direction: 'outgoing', type: 'ACK', ids: [id], repeated: true });
        return;
      }

      // Rule 3 & 4: Attempt atomic acceptance
      try {
        const success = await this.storage.acceptMessage({
          id: put.id,
          payload: put.payload,
          attachments: attachments
        });

        if (success) {
          this.log('info', `Successfully accepted message ${id}. Sending ACK.`);
          const ackMsg = {
            protocol: PROTOCOL_NAME,
            version: PROTOCOL_VERSION,
            type: 'ACK',
            ids: [id]
          };
          this._sendToPort(ackMsg);
          this.onTransfer({ direction: 'outgoing', type: 'ACK', ids: [id] });
        } else {
          this.log('error', `Acceptance rejected by local storage for message ${id}; NO ACK sent`);
        }
      } catch (err) {
        // Transfer failure or storage error: do not send ACK
        this.log('error', `Failed to accept message ${id}: ${err.message}; NO ACK sent`);
        this.onError(err);
      }
    }

    /**
     * Handles incoming ACK:
     * - Rule 6: Sender cleanup upon receiving ACK.
     * - Removes acknowledged message from outbox.
     */
    async _handleAck(ack) {
      const ids = Array.isArray(ack.ids) ? ack.ids : [];
      this.log('info', `Received ACK confirming acceptance of ${ids.length} message(s)`, ids);
      this.onTransfer({ direction: 'incoming', type: 'ACK', ids: ids });

      if (ids.length === 0) return;

      try {
        await this.storage.onAcknowledged(ids);
        this.log('info', `Removed acknowledged message(s) from outbox:`, ids);
      } catch (err) {
        this.log('error', 'Error processing ACK in local storage', err.message);
        this.onError(err);
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
