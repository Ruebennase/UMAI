/**
 * UMAI JavaScript Library Unit and Protocol Verification Tests
 * Runs under Node.js without any dependencies.
 */

const assert = require('assert');
const { UmaiSession, PROTOCOL_NAME, PROTOCOL_VERSION, isValidUmaiMessage, isValidMessageId } = require('../js/umai.js');

console.log('--- Running UMAI JavaScript Tests ---');

// Test 1: Message & ID Validation (C4 & D2)
{
  assert.strictEqual(isValidUmaiMessage(null), null);
  assert.strictEqual(isValidUmaiMessage({}), false);
  assert.strictEqual(isValidUmaiMessage({ protocol: 'OTHER', version: 1, type: 'OFFER' }), false);
  assert.strictEqual(isValidUmaiMessage({ protocol: PROTOCOL_NAME, version: 2, type: 'OFFER' }), false);
  assert.strictEqual(isValidUmaiMessage({ protocol: PROTOCOL_NAME, version: 1, type: 'OFFER' }), true);
  assert.strictEqual(isValidMessageId('msg-123.ok_1'), true);
  assert.strictEqual(isValidMessageId('_underscore-start'), true);
  assert.strictEqual(isValidMessageId('-hyphen-start'), true);
  assert.strictEqual(isValidMessageId('.leading-dot-ok'), true);
  assert.strictEqual(isValidMessageId('.'), false);
  assert.strictEqual(isValidMessageId('..'), false);
  assert.strictEqual(isValidMessageId('../outside'), false, 'Traversal ID must be rejected (C4)');
  assert.strictEqual(isValidMessageId('a..b'), false, 'Double-dot ID must be rejected (C4)');
  console.log('✓ Test 1: isValidUmaiMessage and isValidMessageId validation passed');
}

// Mock MessagePort for testing
class MockPort {
  constructor() {
    this.sent = [];
    this.peer = null;
    this.onmessage = null;
  }
  postMessage(msg, transfer) {
    this.sent.push(msg);
    if (this.peer && this.peer.onmessage) {
      setTimeout(() => {
        this.peer.onmessage({ data: msg });
      }, 0);
    }
  }
  close() {}
}

function createMockChannel() {
  const p1 = new MockPort();
  const p2 = new MockPort();
  p1.peer = p2;
  p2.peer = p1;
  return { port1: p1, port2: p2 };
}

// Helper to build a simple getAcceptance(ids) function from a predicate or map
function makeBatchAcceptance(fn) {
  return async (ids) => {
    const out = Object.create(null);
    for (const id of ids) {
      out[id] = await fn(id);
    }
    return out;
  };
}

// Test 2: Handshake & Reconnection Reconcile
(async () => {
  const channel = createMockChannel();

  const outboxA = ['msg-001', 'msg-002'];
  const acceptedB = new Set(['msg-001']); // B has already accepted msg-001 in past

  let ackReceivedOnA = [];
  let getReceivedOnA = [];

  const sessionA = new UmaiSession({
    peerOrigin: 'http://peer.example',
    role: 'host',
    storage: {
      getOutboxIds: async () => outboxA,
      getMessage: async (id) => ({ id, payload: { title: 'Test' }, attachments: [] }),
      getAcceptance: makeBatchAcceptance(() => ({ accepted: false })),
      acceptMessage: async () => true,
      onAcknowledged: async (ids) => { ackReceivedOnA.push(...ids); }
    }
  });

  const sessionB = new UmaiSession({
    peerOrigin: 'http://host.example',
    role: 'embedded',
    storage: {
      getOutboxIds: async () => [],
      getMessage: async (id) => null,
      getAcceptance: makeBatchAcceptance((id) => ({ accepted: acceptedB.has(id) })),
      acceptMessage: async (msg) => {
        acceptedB.add(msg.id);
        return true;
      },
      onAcknowledged: async () => {}
    }
  });

  // Attach mock ports directly
  sessionA.port = channel.port1;
  channel.port1.onmessage = sessionA._portListener;
  sessionA.state = 'connected';

  sessionB.port = channel.port2;
  channel.port2.onmessage = sessionB._portListener;
  sessionB.state = 'connected';

  // Session A reconciles (sends OFFER for msg-001 and msg-002)
  await sessionA.reconcile();

  // Wait for async port dispatch
  await new Promise(r => setTimeout(r, 50));

  // Verify:
  // 1. Session B should have recognized msg-001 as already accepted and sent repeated ACK!
  // 2. Session B should have requested msg-002 via GET.
  // 3. Session A received ACK for msg-001 and cleaned it.
  // 4. Session A received GET for msg-002, sent PUT.
  // 5. Session B accepted msg-002, sent ACK for msg-002.
  // 6. Session A received ACK for msg-002.
  await new Promise(r => setTimeout(r, 50));

  assert.ok(ackReceivedOnA.includes('msg-001'), 'A should have received repeated ACK for msg-001');
  assert.ok(ackReceivedOnA.includes('msg-002'), 'A should have received ACK for msg-002');
  assert.ok(acceptedB.has('msg-002'), 'B should have accepted msg-002');

  console.log('✓ Test 2: Symmetric MessagePort exchange with repeated-ACK (Rule 5) passed');

  // Test 3: Security — Unsolicited PUT is dropped, Unoffered GET cannot poison _offeredIds, & Unoffered ACK IDs are ignored
  let unsolicitedAccepted = false;
  let unofferedGetFetched = false;
  let unofferedAcked = [];

  const secSession = new UmaiSession({
    peerOrigin: 'http://peer.example',
    role: 'embedded',
    storage: {
      getOutboxIds: async () => ['msg-real-100'],
      getMessage: async (id) => {
        if (id === 'msg-never-offered') unofferedGetFetched = true;
        return { id, payload: {}, attachments: [] };
      },
      getAcceptance: makeBatchAcceptance(() => ({ accepted: false })),
      acceptMessage: async () => {
        unsolicitedAccepted = true;
        return true;
      },
      onAcknowledged: async (ids) => {
        unofferedAcked.push(...ids);
      }
    }
  });

  const secChannel = createMockChannel();
  secSession.port = secChannel.port1;
  secChannel.port1.onmessage = secSession._portListener;
  secSession.state = 'connected';

  // Offer msg-real-100 so only msg-real-100 is in _offeredIds
  await secSession.reconcile();

  // Attempt GET for an unoffered ID ('msg-never-offered') to verify it cannot fetch or poison _offeredIds
  await secSession._handleGet({
    protocol: PROTOCOL_NAME,
    version: PROTOCOL_VERSION,
    type: 'GET',
    ids: ['msg-never-offered']
  });
  await new Promise(r => setTimeout(r, 20));
  assert.strictEqual(unofferedGetFetched, false, 'Unoffered GET must not invoke storage.getMessage');

  // Send unsolicited PUT (not in _inFlightGets)
  await secSession._handlePut({
    protocol: PROTOCOL_NAME,
    version: PROTOCOL_VERSION,
    type: 'PUT',
    id: 'msg-unsolicited-999',
    payload: {},
    attachments: []
  });
  assert.strictEqual(unsolicitedAccepted, false, 'Unsolicited PUT must be dropped without calling acceptMessage');

  // Send ACK containing unoffered IDs ('msg-not-offered', 'msg-never-offered') alongside the offered ID ('msg-real-100')
  await secSession._handleAck({
    protocol: PROTOCOL_NAME,
    version: PROTOCOL_VERSION,
    type: 'ACK',
    ids: ['msg-not-offered', 'msg-never-offered', 'msg-real-100']
  });
  assert.deepStrictEqual(unofferedAcked, ['msg-real-100'], 'Only offered IDs should be passed to onAcknowledged');

  console.log('✓ Test 3: State-machine security (unsolicited PUT, unoffered GET, & unoffered ACK rejection) passed');

  // Test 4: Poison-pill retry backoff (stops auto-GET after MAX_AUTO_RETRIES=3 failed acceptMessage attempts, resets on reconcile(true))
  let poisonAttempts = 0;
  const poisonChannel = createMockChannel();
  const senderPoison = new UmaiSession({
    peerOrigin: 'http://peer.example',
    role: 'host',
    storage: {
      getOutboxIds: async () => ['msg-poison-1'],
      getMessage: async (id) => ({ id, payload: { bad: true }, attachments: [] }),
      getAcceptance: makeBatchAcceptance(() => ({ accepted: false })),
      acceptMessage: async () => true,
      onAcknowledged: async () => {}
    }
  });
  const receiverPoison = new UmaiSession({
    peerOrigin: 'http://host.example',
    role: 'embedded',
    storage: {
      getOutboxIds: async () => [],
      getMessage: async () => null,
      getAcceptance: makeBatchAcceptance(() => ({ accepted: false })),
      acceptMessage: async () => {
        poisonAttempts++;
        return { accepted: false }; // Reject acceptance via structured object
      },
      onAcknowledged: async () => {}
    }
  });
  senderPoison.port = poisonChannel.port1;
  poisonChannel.port1.onmessage = senderPoison._portListener;
  senderPoison.state = 'connected';
  receiverPoison.port = poisonChannel.port2;
  poisonChannel.port2.onmessage = receiverPoison._portListener;
  receiverPoison.state = 'connected';

  for (let i = 0; i < 5; i++) {
    await senderPoison.reconcile(false);
    await new Promise(r => setTimeout(r, 30));
  }
  assert.strictEqual(poisonAttempts, 3, 'Poison-pill message should back off after 3 failed automatic acceptance attempts');

  // Manual reconcile(true) on receiver resets failure counter
  await receiverPoison.reconcile(true);
  await senderPoison.reconcile(false);
  await new Promise(r => setTimeout(r, 30));
  assert.strictEqual(poisonAttempts, 4, 'Manual reconcile(true) should reset failure counter and allow retry');

  console.log('✓ Test 4: Poison-pill retry backoff and manual reconcile reset passed');

  // Test 5: Concurrent OFFER deduplication while acceptMessage is pending (F4),
  // accurate getSyncStatus().isSyncing during acceptMessage (F8), and READY reload / expired GET recovery (F3)
  let acceptCallsForSlowMsg = 0;
  let releaseAcceptPromise = null;
  let slowMsgAccepted = false;
  const slowChannel = createMockChannel();

  let ackReceiptsOnSenderSlow = {};
  const senderSlow = new UmaiSession({
    peerOrigin: 'http://peer.example',
    role: 'host',
    storage: {
      getOutboxIds: async () => ['msg-slow-1'],
      getMessage: async (id) => ({ id, payload: false, attachments: [] }),
      getAcceptance: makeBatchAcceptance(() => ({ accepted: false })),
      acceptMessage: async () => ({ accepted: true }),
      onAcknowledged: async (ids, receipts) => {
        if (receipts) Object.assign(ackReceiptsOnSenderSlow, receipts);
      }
    }
  });

  const receiverSlow = new UmaiSession({
    peerOrigin: 'http://host.example',
    role: 'embedded',
    storage: {
      getOutboxIds: async () => [],
      getMessage: async () => null,
      getAcceptance: makeBatchAcceptance(() => ({ accepted: slowMsgAccepted, ackReceipt: slowMsgAccepted ? 'receipt-slow-1' : '' })),
      acceptMessage: async (msg) => {
        acceptCallsForSlowMsg++;
        assert.strictEqual(msg.payload, false, 'Falsy scalar payload (false) must be preserved');
        await new Promise((resolve) => {
          releaseAcceptPromise = resolve;
        });
        slowMsgAccepted = true;
        return { accepted: true, ackReceipt: 'receipt-slow-1' };
      },
      onAcknowledged: async () => {}
    }
  });

  senderSlow.port = slowChannel.port1;
  slowChannel.port1.onmessage = senderSlow._portListener;
  senderSlow.state = 'connected';
  receiverSlow.port = slowChannel.port2;
  slowChannel.port2.onmessage = receiverSlow._portListener;
  receiverSlow.state = 'connected';

  // Trigger initial OFFER -> GET -> PUT, which pauses inside receiverSlow's acceptMessage
  await senderSlow.reconcile(false);
  await new Promise(r => setTimeout(r, 30));
  assert.strictEqual(acceptCallsForSlowMsg, 1, 'First PUT should have entered acceptMessage');
  assert.strictEqual(receiverSlow.getSyncStatus().isSyncing, true, 'isSyncing must remain true while acceptMessage is still running (F8)');
  assert.strictEqual(receiverSlow.getSyncStatus().pendingIncoming, 1, 'pendingIncoming must be 1 while acceptMessage is still running');

  // While acceptMessage is still running, another OFFER arrives — must NOT trigger a second GET or second acceptMessage (F4)
  await senderSlow.reconcile(false);
  await new Promise(r => setTimeout(r, 30));
  assert.strictEqual(acceptCallsForSlowMsg, 1, 'Concurrent OFFER while acceptMessage is in-flight must not trigger duplicate acceptMessage (F4)');

  // Complete acceptMessage
  releaseAcceptPromise();
  await new Promise(r => setTimeout(r, 30));
  assert.strictEqual(receiverSlow.getSyncStatus().isSyncing, false, 'isSyncing must become false after acceptMessage finishes');
  assert.strictEqual(ackReceiptsOnSenderSlow['msg-slow-1'], 'receipt-slow-1', 'Structured { accepted: true, ackReceipt } must propagate receipt in ACK');

  // Verify expired GET reservation demotion (F3): expired _inFlightGets entry frees its active slot and moves to _expiredGets
  receiverSlow._inFlightGets.set('msg-expired-get', Date.now() - 130000);
  receiverSlow._pruneExpiredGets();
  assert.strictEqual(receiverSlow._inFlightGets.has('msg-expired-get'), false, 'Expired GET reservation must free active _inFlightGets slot (F3)');
  assert.strictEqual(receiverSlow._expiredGets.has('msg-expired-get'), true, 'Expired GET reservation must move to bounded _expiredGets');

  senderSlow.stop();
  receiverSlow.stop();
  console.log('✓ Test 5: Concurrent acceptMessage deduplication (F4), sync status accuracy (F8), falsy payload (F6), and GET expiry (F3) passed');

  // Test 6: Top-level companion/popup window binding via options.peerWindow (no iframe required)
  let popupPortReceived = false;
  const mockPopupWindow = {
    closed: false,
    postMessage(msg, targetOrigin, transfer) {
      assert.strictEqual(msg.type, 'INIT', 'Host should send INIT to peerWindow');
      assert.strictEqual(targetOrigin, 'http://companion.example', 'Host should pin targetOrigin on peerWindow');
      if (transfer && transfer.length > 0) {
        popupPortReceived = true;
      }
    }
  };

  const hostPopupSession = new UmaiSession({
    peerOrigin: 'http://companion.example',
    role: 'host',
    peerWindow: mockPopupWindow,
    storage: {
      getOutboxIds: async () => [],
      getMessage: async () => null,
      getAcceptance: makeBatchAcceptance(() => ({ accepted: false })),
      acceptMessage: async () => true,
      onAcknowledged: async () => {}
    }
  });

  hostPopupSession._handleWindowMessage({
    origin: 'http://companion.example',
    source: mockPopupWindow,
    data: { protocol: PROTOCOL_NAME, version: PROTOCOL_VERSION, type: 'READY' }
  });
  assert.strictEqual(popupPortReceived, true, 'Host session must complete handshake with top-level peerWindow without an iframe');

  // Verify fail-closed window binding:
  // 1) A different window from the same peerOrigin must be rejected
  popupPortReceived = false;
  const rogueSameOriginWindow = {
    closed: false,
    postMessage() {
      popupPortReceived = true;
    }
  };
  hostPopupSession._handleWindowMessage({
    origin: 'http://companion.example',
    source: rogueSameOriginWindow,
    data: { protocol: PROTOCOL_NAME, version: PROTOCOL_VERSION, type: 'READY' }
  });
  assert.strictEqual(popupPortReceived, false, 'Handshake must reject READY from a different Window of the same peerOrigin');

  // 2) An unbound host session (no iframe, no peerWindow) must fail closed and NEVER auto-adopt event.source
  const unboundHostSession = new UmaiSession({
    peerOrigin: 'http://companion.example',
    role: 'host',
    storage: {
      getOutboxIds: async () => [],
      getMessage: async () => null,
      getAcceptance: makeBatchAcceptance(() => ({ accepted: false })),
      acceptMessage: async () => true,
      onAcknowledged: async () => {}
    }
  });
  unboundHostSession._handleWindowMessage({
    origin: 'http://companion.example',
    source: rogueSameOriginWindow,
    data: { protocol: PROTOCOL_NAME, version: PROTOCOL_VERSION, type: 'READY' }
  });
  assert.strictEqual(unboundHostSession.peerWindow, null, 'Unbound host session must not auto-adopt event.source on READY');
  assert.strictEqual(popupPortReceived, false, 'Unbound host session must not send INIT');
  unboundHostSession.stop();
  hostPopupSession.stop();
  console.log('✓ Test 6: Top-level companion/popup window binding (peerWindow) & fail-closed source check passed');

  // Test 7: Core Hardening — Wildcard origin rejection (C3), Generation isolation across channel replacement/stop (C1),
  // Bounded GET/PUT concurrency (C2), and Strict attachment/boolean validation (C4)
  {
    // C3: Wildcard and non-HTTP(S) origins must be rejected at construction
    assert.throws(() => new UmaiSession({ peerOrigin: '*', storage: {} }), /wildcards are forbidden/);
    assert.throws(() => new UmaiSession({ peerOrigin: 'null', storage: {} }), /valid concrete http/);
    assert.throws(() => new UmaiSession({ peerOrigin: 'javascript:alert(1)', storage: {} }), /valid concrete http/);

    // C1: Pending getMessage() from an old channel must NOT leak onto a replacement channel,
    // and stop() during getAcceptance() must NOT invoke acceptMessage()
    let releaseOldGetMessage = null;
    const oldChan = createMockChannel();
    const newChan = createMockChannel();
    const genSender = new UmaiSession({
      peerOrigin: 'http://peer.example',
      role: 'host',
      storage: {
        getOutboxIds: async () => ['msg-gen-old'],
        getMessage: async (id) => {
          await new Promise(r => { releaseOldGetMessage = r; });
          return { id, payload: { secret: 'old-account' }, attachments: [] };
        },
        getAcceptance: makeBatchAcceptance(() => ({ accepted: false })),
        acceptMessage: async () => true,
        onAcknowledged: async () => {}
      }
    });
    genSender.port = oldChan.port1;
    oldChan.port1.onmessage = genSender._portListener;
    genSender.state = 'connected';
    await genSender.reconcile();
    genSender._handleGet({ protocol: PROTOCOL_NAME, version: PROTOCOL_VERSION, type: 'GET', ids: ['msg-gen-old'] });
    await new Promise(r => setTimeout(r, 10));
    assert.strictEqual(typeof releaseOldGetMessage, 'function', 'Old getMessage should be pending');

    // Simulate channel replacement (e.g. READY handshake / account switch) before old getMessage resolves
    genSender._resetChannelState();
    genSender.port = newChan.port1;
    newChan.port1.onmessage = genSender._portListener;
    genSender.state = 'connected';
    releaseOldGetMessage();
    await new Promise(r => setTimeout(r, 20));
    const leakedPuts = newChan.port1.sent.filter(m => m.type === 'PUT');
    assert.strictEqual(leakedPuts.length, 0, 'Pending getMessage from old generation must NOT transmit over replacement channel (C1)');
    genSender.stop();

    // Also verify stop() during getAcceptance() prevents acceptMessage() from being called (C1)
    let releaseGetAcceptance = null;
    let acceptCalledAfterStop = false;
    const stopRecChan = createMockChannel();
    const stopReceiver = new UmaiSession({
      peerOrigin: 'http://host.example',
      role: 'embedded',
      storage: {
        getOutboxIds: async () => [],
        getMessage: async () => null,
        getAcceptance: async (ids) => {
          await new Promise(r => { releaseGetAcceptance = r; });
          const out = {};
          for (const id of ids) out[id] = { accepted: false };
          return out;
        },
        acceptMessage: async () => {
          acceptCalledAfterStop = true;
          return { accepted: true };
        },
        onAcknowledged: async () => {}
      }
    });
    stopReceiver.port = stopRecChan.port1;
    stopRecChan.port1.onmessage = stopReceiver._portListener;
    stopReceiver.state = 'connected';
    stopReceiver._inFlightGets.set('msg-stop-1', Date.now());
    stopReceiver._handlePut({
      protocol: PROTOCOL_NAME,
      version: PROTOCOL_VERSION,
      type: 'PUT',
      id: 'msg-stop-1',
      payload: {},
      attachments: []
    });
    await new Promise(r => setTimeout(r, 10));
    stopReceiver.stop();
    releaseGetAcceptance();
    await new Promise(r => setTimeout(r, 20));
    assert.strictEqual(acceptCalledAfterStop, false, 'acceptMessage must not be called after stop() (C1)');

    // C2: Offer of 12 messages with default maxConcurrency=1 runs at most 1 acceptMessage at a time
    const batchIds = Array.from({ length: 12 }, (_, i) => `msg-batch-${i + 1}`);
    let currentConcurrentAccepts = 0;
    let maxObservedConcurrentAccepts = 0;
    const acceptedBatch = new Set();
    const batchChan = createMockChannel();

    const batchSender = new UmaiSession({
      peerOrigin: 'http://peer.example',
      role: 'host',
      storage: {
        getOutboxIds: async () => batchIds.filter(id => !acceptedBatch.has(id)),
        getMessage: async (id) => ({ id, payload: { n: id }, attachments: [] }),
        getAcceptance: makeBatchAcceptance(() => ({ accepted: false })),
        acceptMessage: async () => true,
        onAcknowledged: async () => {}
      }
    });
    const batchReceiver = new UmaiSession({
      peerOrigin: 'http://host.example',
      role: 'embedded',
      maxConcurrency: 1,
      storage: {
        getOutboxIds: async () => [],
        getMessage: async () => null,
        getAcceptance: makeBatchAcceptance((id) => ({ accepted: acceptedBatch.has(id) })),
        acceptMessage: async (msg) => {
          currentConcurrentAccepts++;
          if (currentConcurrentAccepts > maxObservedConcurrentAccepts) {
            maxObservedConcurrentAccepts = currentConcurrentAccepts;
          }
          await new Promise(r => setTimeout(r, 5));
          acceptedBatch.add(msg.id);
          currentConcurrentAccepts--;
          return { accepted: true };
        },
        onAcknowledged: async () => {}
      }
    });
    batchSender.port = batchChan.port1;
    batchChan.port1.onmessage = batchSender._portListener;
    batchSender.state = 'connected';
    batchReceiver.port = batchChan.port2;
    batchChan.port2.onmessage = batchReceiver._portListener;
    batchReceiver.state = 'connected';

    await batchSender.reconcile();
    await new Promise(r => setTimeout(r, 250));
    assert.strictEqual(acceptedBatch.size, 12, 'All 12 offered messages must be accepted sequentially');
    assert.strictEqual(maxObservedConcurrentAccepts, 1, 'maxConcurrency=1 must bound concurrent acceptMessage calls to 1 (C2)');
    batchSender.stop();
    batchReceiver.stop();

    // C4: Malformed non-array attachments and truthy non-boolean { accepted: "false" } must be rejected
    let badPutAccepted = false;
    let stringFalseAckSent = false;
    const c4Chan = createMockChannel();
    const c4Receiver = new UmaiSession({
      peerOrigin: 'http://host.example',
      role: 'embedded',
      storage: {
        getOutboxIds: async () => [],
        getMessage: async () => null,
        getAcceptance: makeBatchAcceptance(() => ({ accepted: false })),
        acceptMessage: async (msg) => {
          if (msg.id === 'msg-bad-att') badPutAccepted = true;
          return { accepted: 'false' }; // Invalid string instead of boolean true
        },
        onAcknowledged: async () => {}
      }
    });
    c4Receiver.port = c4Chan.port1;
    c4Chan.port1.onmessage = c4Receiver._portListener;
    c4Receiver.state = 'connected';

    c4Receiver._inFlightGets.set('msg-bad-att', Date.now());
    await c4Receiver._handlePut({
      protocol: PROTOCOL_NAME,
      version: PROTOCOL_VERSION,
      type: 'PUT',
      id: 'msg-bad-att',
      payload: {},
      attachments: 'not-an-array'
    });
    assert.strictEqual(badPutAccepted, false, 'Malformed non-array attachments must be rejected before acceptMessage (C4)');

    c4Receiver._inFlightGets.set('msg-str-false', Date.now());
    await c4Receiver._handlePut({
      protocol: PROTOCOL_NAME,
      version: PROTOCOL_VERSION,
      type: 'PUT',
      id: 'msg-str-false',
      payload: {},
      attachments: []
    });
    stringFalseAckSent = c4Chan.port1.sent.some(m => m.type === 'ACK' && m.ids.includes('msg-str-false'));
    assert.strictEqual(stringFalseAckSent, false, '{ accepted: "false" } must NOT produce an ACK (C4)');

    // Plain object attachment (not a Blob/File) must be rejected (C4)
    let plainObjAccepted = false;
    c4Receiver._inFlightGets.set('msg-plain-att', Date.now());
    await c4Receiver._handlePut({
      protocol: PROTOCOL_NAME,
      version: PROTOCOL_VERSION,
      type: 'PUT',
      id: 'msg-plain-att',
      payload: {},
      attachments: [{ name: 'fake.bin', size: 10 }]
    });
    assert.strictEqual(plainObjAccepted, false, 'Plain non-Blob object in attachments must be rejected (C4)');

    // Oversized JSON payload exceeding maxMessageBytes must be rejected (C2)
    let oversizedPayloadAccepted = false;
    const smallLimitReceiver = new UmaiSession({
      peerOrigin: 'http://host.example',
      role: 'embedded',
      maxMessageBytes: 64,
      storage: {
        getOutboxIds: async () => [],
        getMessage: async () => null,
        getAcceptance: makeBatchAcceptance(() => ({ accepted: false })),
        acceptMessage: async () => {
          oversizedPayloadAccepted = true;
          return { accepted: true };
        },
        onAcknowledged: async () => {}
      }
    });
    const smallChan = createMockChannel();
    smallLimitReceiver.port = smallChan.port1;
    smallChan.port1.onmessage = smallLimitReceiver._portListener;
    smallLimitReceiver.state = 'connected';
    smallLimitReceiver._inFlightGets.set('msg-big-json', Date.now());
    await smallLimitReceiver._handlePut({
      protocol: PROTOCOL_NAME,
      version: PROTOCOL_VERSION,
      type: 'PUT',
      id: 'msg-big-json',
      payload: { data: 'x'.repeat(200) },
      attachments: []
    });
    assert.strictEqual(oversizedPayloadAccepted, false, 'JSON payload exceeding maxMessageBytes must be rejected (C2)');
    smallLimitReceiver.stop();
    c4Receiver.stop();
  }
  console.log('✓ Test 7: Generation isolation (C1), bounded concurrency & payload size (C2), wildcard origin rejection (C3), and strict validation (C4) passed');

  // Test 8: Reviewer Follow-Up Regressions:
  //   8a) 100 ACK flood coalescing + receipt upgrade + failed-receipt retry
  //   8b) Strict JSON payload validation (nested Blob / TypedArray / Date rejection)
  //   8c) >1,000-entry outbox reordering, active transfer protection, stale retirement, & serialized reconcile()
  //   8d) Lifecycle-aware callback stop() & exception safety
  //   8e) getTimeoutMs expiry, non-blocking slot reuse, busy-slot deferral, & late PUT admission
  {
    // --- 8a: Bounded ACK coalescing & receipt upgrade ---
    let concurrentAckCalls = 0;
    let maxConcurrentAckCalls = 0;
    let totalAckCalls = 0;
    let acceptedReceiptOnSender = null;

    const ackSender = new UmaiSession({
      peerOrigin: 'http://peer.example',
      role: 'host',
      storage: {
        getOutboxIds: async () => (acceptedReceiptOnSender ? [] : ['msg-ack-flood']),
        getMessage: async (id) => ({ id, payload: {}, attachments: [] }),
        getAcceptance: makeBatchAcceptance(() => ({ accepted: false })),
        acceptMessage: async () => true,
        onAcknowledged: async (ids, receipts) => {
          totalAckCalls++;
          concurrentAckCalls++;
          if (concurrentAckCalls > maxConcurrentAckCalls) {
            maxConcurrentAckCalls = concurrentAckCalls;
          }
          await new Promise(r => setTimeout(r, 25));
          concurrentAckCalls--;
          const r = receipts && receipts['msg-ack-flood'];
          if (r !== 'valid-receipt-sig') {
            throw new Error('Invalid or missing receipt');
          }
          acceptedReceiptOnSender = r;
        }
      }
    });
    const ackChan = createMockChannel();
    ackSender.port = ackChan.port1;
    ackChan.port1.onmessage = ackSender._portListener;
    ackSender.state = 'connected';
    await ackSender.reconcile();

    // Fire 100 ACK frames concurrently: 1st has bad receipt, next 50 have empty receipts, last 49 have valid receipt
    const ackPromises = [];
    for (let i = 0; i < 100; i++) {
      const rec = i === 0 ? { 'msg-ack-flood': 'bad-receipt' } : (i <= 50 ? {} : { 'msg-ack-flood': 'valid-receipt-sig' });
      ackPromises.push(ackSender._handleAck({
        protocol: PROTOCOL_NAME,
        version: PROTOCOL_VERSION,
        type: 'ACK',
        ids: ['msg-ack-flood'],
        receipts: rec
      }));
    }
    await Promise.all(ackPromises);
    await new Promise(r => setTimeout(r, 60));

    assert.strictEqual(maxConcurrentAckCalls, 1, '100 simultaneous ACK frames must never run >1 concurrent onAcknowledged()');
    assert.strictEqual(totalAckCalls, 2, '100 ACK frames (1st bad, 99 coalesced) must execute at most 2 onAcknowledged() calls');
    assert.strictEqual(acceptedReceiptOnSender, 'valid-receipt-sig', 'Earlier empty/bad receipts must not suppress later valid receipt');
    assert.strictEqual(ackSender._offeredIds.has('msg-ack-flood'), false, 'Acknowledged ID must be removed from _offeredIds after valid receipt');
    ackSender.stop();

    // --- 8b: Nested Blob / non-JSON structured-clone types in payload must be rejected ---
    let nestedBlobAccepted = false;
    let nestedBlobSent = false;
    const blobChan = createMockChannel();
    const blobReceiver = new UmaiSession({
      peerOrigin: 'http://host.example',
      role: 'embedded',
      maxMessageBytes: 64,
      storage: {
        getOutboxIds: async () => ['msg-out-blob'],
        getMessage: async (id) => ({
          id,
          payload: { sneaky: new Blob([new Uint8Array(1024)]) },
          attachments: []
        }),
        getAcceptance: makeBatchAcceptance(() => ({ accepted: false })),
        acceptMessage: async () => {
          nestedBlobAccepted = true;
          return true;
        },
        onAcknowledged: async () => {}
      }
    });
    blobReceiver.port = blobChan.port1;
    blobChan.port1.onmessage = blobReceiver._portListener;
    blobReceiver.state = 'connected';

    blobReceiver._inFlightGets.set('msg-in-blob', Date.now());
    await blobReceiver._handlePut({
      protocol: PROTOCOL_NAME,
      version: PROTOCOL_VERSION,
      type: 'PUT',
      id: 'msg-in-blob',
      payload: { sneaky: new Blob([new Uint8Array(1024)]) },
      attachments: []
    });
    assert.strictEqual(nestedBlobAccepted, false, 'Payload containing nested Blob must be rejected before acceptMessage');

    blobReceiver._inFlightGets.set('msg-in-date', Date.now());
    await blobReceiver._handlePut({
      protocol: PROTOCOL_NAME,
      version: PROTOCOL_VERSION,
      type: 'PUT',
      id: 'msg-in-date',
      payload: { when: new Date() },
      attachments: []
    });
    assert.strictEqual(nestedBlobAccepted, false, 'Payload containing non-JSON Date object must be rejected');

    await blobReceiver.reconcile();
    await blobReceiver._handleGet({ protocol: PROTOCOL_NAME, version: PROTOCOL_VERSION, type: 'GET', ids: ['msg-out-blob'] });
    await new Promise(r => setTimeout(r, 20));
    nestedBlobSent = blobChan.port1.sent.some(m => m.type === 'PUT' && m.id === 'msg-out-blob');
    assert.strictEqual(nestedBlobSent, false, 'Outgoing getMessage with nested Blob in payload must be rejected before PUT');
    blobReceiver.stop();

    // --- 8c: >1,000-entry outbox reordering, active transfer protection, stale retirement, & serialized reconcile ---
    let currentOutbox = Array.from({ length: 1200 }, (_, i) => `msg-large-${String(i + 1).padStart(4, '0')}`);
    let getOutboxCallCount = 0;
    let releaseFirstGetMessage = null;
    const fetchedLargeIds = [];
    const largeChan = createMockChannel();

    const largeSender = new UmaiSession({
      peerOrigin: 'http://peer.example',
      role: 'host',
      storage: {
        getOutboxIds: async () => {
          getOutboxCallCount++;
          const snapshot = currentOutbox.slice();
          if (getOutboxCallCount === 1) {
            // Simulate slow first snapshot while a newer reconcile() arrives with updated state
            await new Promise(r => setTimeout(r, 25));
          }
          return snapshot;
        },
        getMessage: async (id) => {
          fetchedLargeIds.push(id);
          if (id === 'msg-large-0001' && !releaseFirstGetMessage) {
            await new Promise(r => { releaseFirstGetMessage = r; });
          }
          return { id, payload: { id }, attachments: [] };
        },
        getAcceptance: makeBatchAcceptance(() => ({ accepted: false })),
        acceptMessage: async () => true,
        onAcknowledged: async () => {}
      }
    });
    largeSender.port = largeChan.port1;
    largeChan.port1.onmessage = largeSender._portListener;
    largeSender.state = 'connected';

    // Trigger overlapping reconcile() calls: mutate currentOutbox before 1st resolves
    const r1 = largeSender.reconcile(true);
    await new Promise(r => setTimeout(r, 5));
    const r2 = largeSender.reconcile(true);
    await Promise.all([r1, r2]);

    assert.strictEqual(largeSender._offeredIds.size, 1000, '_offeredIds must be capped at 1000');
    // Start an active PUT on msg-large-0001
    await largeSender._handleGet({ protocol: PROTOCOL_NAME, version: PROTOCOL_VERSION, type: 'GET', ids: ['msg-large-0001'] });
    await new Promise(r => setTimeout(r, 10));
    assert.strictEqual(typeof releaseFirstGetMessage, 'function', 'msg-large-0001 should be actively sending');

    // Reorder the 1,200-entry outbox so msg-large-0201..1200 come first while msg-large-0001 is still active
    currentOutbox = currentOutbox.slice(200).concat(currentOutbox.slice(0, 200));
    largeChan.port1.sent = [];
    await largeSender.reconcile(true);
    const reorderedOffer = largeChan.port1.sent.find(m => m.type === 'OFFER');
    assert.ok(reorderedOffer, 'Reordered reconcile must emit OFFER');
    assert.strictEqual(largeSender._offeredIds.has('msg-large-0001'), true, 'Actively sending ID must remain protected in _offeredIds across reorder');
    assert.strictEqual(largeSender._offeredIds.size <= 1000, true, '_offeredIds must never exceed 1000');
    // Every single advertised ID in reorderedOffer.ids MUST be present in _offeredIds and fetchable!
    for (const advId of reorderedOffer.ids) {
      assert.strictEqual(largeSender._offeredIds.has(advId), true, `Advertised ID ${advId} must be tracked in _offeredIds`);
    }
    assert.ok(reorderedOffer.ids.includes('msg-large-1001'), 'Newly rotated-in ID msg-large-1001 must be advertised and fetchable');

    releaseFirstGetMessage();
    await new Promise(r => setTimeout(r, 20));

    // Now remove all 1,200 IDs externally (as if another pooled browser session completed them) and add 1 new message
    currentOutbox = ['msg-after-pool-drain-1201'];
    largeChan.port1.sent = [];
    await largeSender.reconcile(true);
    await largeSender._handleGet({
      protocol: PROTOCOL_NAME,
      version: PROTOCOL_VERSION,
      type: 'GET',
      ids: ['msg-after-pool-drain-1201']
    });
    await new Promise(r => setTimeout(r, 20));
    assert.ok(fetchedLargeIds.includes('msg-after-pool-drain-1201'), 'New message after 1,000+ external removals must be advertised and fetchable via GET');
    largeSender.stop();

    // --- 8d: Lifecycle-aware callback guard (stop() in onTransfer on ACK; throwing callbacks) ---
    let onAckCalledAfterCallbackStop = false;
    let statusCallbackSawHandshaking = false;
    const cbChan = createMockChannel();
    const cbSession = new UmaiSession({
      peerOrigin: 'http://peer.example',
      role: 'host',
      onStatusChange: ({ state }) => {
        if (state === 'handshaking') {
          statusCallbackSawHandshaking = true;
          throw new Error('Simulated status callback throw during startup');
        }
      },
      onTransfer: ({ direction, type }) => {
        if (direction === 'incoming' && type === 'ACK') {
          cbSession.stop();
        }
      },
      storage: {
        getOutboxIds: async () => ['msg-cb-stop'],
        getMessage: async (id) => ({ id, payload: {}, attachments: [] }),
        getAcceptance: makeBatchAcceptance(() => ({ accepted: false })),
        acceptMessage: async () => true,
        onAcknowledged: async () => {
          onAckCalledAfterCallbackStop = true;
        }
      }
    });
    // start() transitions to 'handshaking' and invokes throwing onStatusChange -> must not abort startup!
    cbSession.start();
    assert.strictEqual(statusCallbackSawHandshaking, true, 'onStatusChange must run on handshaking');
    assert.strictEqual(cbSession.state, 'handshaking', 'Throwing callback during handshaking must not corrupt startup state');

    cbSession.port = cbChan.port1;
    cbChan.port1.onmessage = cbSession._portListener;
    cbSession.state = 'connected';
    await cbSession.reconcile();

    await cbSession._handleAck({
      protocol: PROTOCOL_NAME,
      version: PROTOCOL_VERSION,
      type: 'ACK',
      ids: ['msg-cb-stop']
    });
    await new Promise(r => setTimeout(r, 20));
    assert.strictEqual(onAckCalledAfterCallbackStop, false, 'storage.onAcknowledged must NOT be called if onTransfer called stop()');
    cbSession.stop();

    // --- 8e: getTimeoutMs expiry, slot reuse for waiting messages, busy-slot protection, & late PUT admission ---
    const acceptedLateSet = new Set();
    let releaseHealthyAccept = null;
    const timeoutChan = createMockChannel();

    const timeoutReceiver = new UmaiSession({
      peerOrigin: 'http://host.example',
      role: 'embedded',
      maxConcurrency: 1,
      getTimeoutMs: 60,
      storage: {
        getOutboxIds: async () => [],
        getMessage: async () => null,
        getAcceptance: makeBatchAcceptance((id) => ({ accepted: acceptedLateSet.has(id) })),
        acceptMessage: async (msg) => {
          if (msg.id === 'msg-healthy' && !releaseHealthyAccept) {
            await new Promise(r => { releaseHealthyAccept = r; });
          }
          acceptedLateSet.add(msg.id);
          return { accepted: true };
        },
        onAcknowledged: async () => {}
      }
    });
    timeoutReceiver.port = timeoutChan.port1;
    timeoutChan.port1.onmessage = timeoutReceiver._portListener;
    timeoutReceiver.state = 'connected';

    // Offer ['msg-stalled', 'msg-healthy']. With maxConcurrency=1, only GET ['msg-stalled'] is sent initially.
    await timeoutReceiver._handleOffer({
      protocol: PROTOCOL_NAME,
      version: PROTOCOL_VERSION,
      type: 'OFFER',
      ids: ['msg-stalled', 'msg-healthy']
    });
    const firstGets = timeoutChan.port1.sent.filter(m => m.type === 'GET');
    assert.strictEqual(firstGets.length, 1);
    assert.deepStrictEqual(firstGets[0].ids, ['msg-stalled']);

    // Wait for msg-stalled's 60ms GET reservation to expire automatically via timer and reuse the slot for msg-healthy!
    await new Promise(r => setTimeout(r, 95));
    const allGetsAfterTimeout = timeoutChan.port1.sent.filter(m => m.type === 'GET');
    assert.ok(
      allGetsAfterTimeout.some(m => m.ids.includes('msg-healthy')),
      'Expired GET reservation must release its slot so waiting msg-healthy is requested'
    );

    // Deliver msg-healthy PUT and hold it inside acceptMessage so the single slot is actively busy
    timeoutReceiver._handlePut({
      protocol: PROTOCOL_NAME,
      version: PROTOCOL_VERSION,
      type: 'PUT',
      id: 'msg-healthy',
      payload: { ok: 1 },
      attachments: []
    });
    await new Promise(r => setTimeout(r, 15));
    assert.strictEqual(typeof releaseHealthyAccept, 'function', 'msg-healthy should hold the active acceptance slot');

    // While msg-healthy owns the slot, late PUT for msg-stalled arrives -> must be deferred without failure penalty
    await timeoutReceiver._handlePut({
      protocol: PROTOCOL_NAME,
      version: PROTOCOL_VERSION,
      type: 'PUT',
      id: 'msg-stalled',
      payload: { slow: true },
      attachments: []
    });
    assert.strictEqual(acceptedLateSet.has('msg-stalled'), false, 'Late PUT must not exceed maxConcurrency while reused slot is busy');
    assert.strictEqual(timeoutReceiver._failedAttempts.get('msg-stalled') || 0, 0, 'Deferred late PUT must not increment _failedAttempts');

    // Now test late PUT admission when a slot IS free (slow attachment transfer completing after getTimeoutMs)
    const soloLateChan = createMockChannel();
    const soloLateReceiver = new UmaiSession({
      peerOrigin: 'http://host.example',
      role: 'embedded',
      maxConcurrency: 1,
      getTimeoutMs: 50,
      storage: {
        getOutboxIds: async () => [],
        getMessage: async () => null,
        getAcceptance: makeBatchAcceptance((id) => ({ accepted: acceptedLateSet.has(id) })),
        acceptMessage: async (msg) => {
          acceptedLateSet.add(msg.id);
          return { accepted: true };
        },
        onAcknowledged: async () => {}
      }
    });
    soloLateReceiver.port = soloLateChan.port1;
    soloLateChan.port1.onmessage = soloLateReceiver._portListener;
    soloLateReceiver.state = 'connected';

    await soloLateReceiver._handleOffer({
      protocol: PROTOCOL_NAME,
      version: PROTOCOL_VERSION,
      type: 'OFFER',
      ids: ['msg-slow-50mb']
    });
    // Let 50ms GET timeout expire (and prune), then deliver the slow PUT while no other message holds the slot
    soloLateReceiver._inFlightGets.set('msg-slow-50mb', Date.now() - 100);
    soloLateReceiver._pruneExpiredGets();
    // Clear any auto-requeued GET so slot is free when the slow response arrives
    soloLateReceiver._pendingGetQueue = [];
    await soloLateReceiver._handlePut({
      protocol: PROTOCOL_NAME,
      version: PROTOCOL_VERSION,
      type: 'PUT',
      id: 'msg-slow-50mb',
      payload: { size: 'large' },
      attachments: []
    });
    await new Promise(r => setTimeout(r, 20));
    assert.strictEqual(acceptedLateSet.has('msg-slow-50mb'), true, 'Slow valid PUT arriving after getTimeoutMs must be accepted when slot is free');

    releaseHealthyAccept();
    await new Promise(r => setTimeout(r, 20));
    assert.strictEqual(acceptedLateSet.has('msg-healthy'), true, 'msg-healthy must complete acceptance');

    soloLateReceiver.stop();
    timeoutReceiver.stop();
  }
  console.log('✓ Test 8: Bounded ACK coalescing, strict JSON payload, >1,000 outbox progress, callback stop() isolation, and late-PUT timeout handling passed');

  // Test 9: Batch getAcceptance(ids) Contract & Reviewer Section 6 Verification Suite:
  //   9a) Large initial offer (250 IDs: 100 accepted with receipts, 150 unaccepted) uses 1 batch call, emits 1 ACK with receipts, and skips already-queued/transferring IDs on repeated OFFERs
  //   9b) Missing, malformed, and failed lookup results produce no false ACKs or false GETs, and obey MAX_AUTO_RETRIES=3
  //   9c) Concurrent acceptance by another session between OFFER lookup and PUT arrival is caught by pre-acceptMessage getAcceptance([id])
  {
    const initial250 = Array.from({ length: 250 }, (_, i) => `msg-b250-${i + 1}`);
    const batchCalls = [];
    const chan9a = createMockChannel();

    const rec9a = new UmaiSession({
      peerOrigin: 'http://host.example',
      role: 'embedded',
      maxConcurrency: 2,
      storage: {
        getOutboxIds: async () => [],
        getMessage: async () => null,
        getAcceptance: async (ids) => {
          batchCalls.push(ids.slice());
          const out = Object.create(null);
          for (let i = 0; i < ids.length; i++) {
            const id = ids[i];
            const num = parseInt(id.split('-').pop(), 10);
            if (num <= 100) {
              out[id] = { accepted: true, ackReceipt: `rec-${id}` };
            } else {
              out[id] = { accepted: false };
            }
          }
          return out;
        },
        acceptMessage: async () => ({ accepted: true }),
        onAcknowledged: async () => {}
      }
    });
    rec9a.port = chan9a.port1;
    chan9a.port1.onmessage = rec9a._portListener;
    rec9a.state = 'connected';

    await rec9a._handleOffer({
      protocol: PROTOCOL_NAME,
      version: PROTOCOL_VERSION,
      type: 'OFFER',
      ids: initial250
    });

    assert.strictEqual(batchCalls.length, 1, 'Large initial offer of 250 IDs must execute exactly 1 batch getAcceptance(ids) call');
    assert.strictEqual(batchCalls[0].length, 250, 'Batch lookup must receive all 250 unique valid IDs');

    const sentAcks = chan9a.port1.sent.filter(m => m.type === 'ACK');
    assert.strictEqual(sentAcks.length, 1, 'All 100 accepted IDs must be acknowledged in a single batched ACK');
    assert.strictEqual(sentAcks[0].ids.length, 100, 'Batched ACK must contain all 100 accepted IDs');
    assert.strictEqual(sentAcks[0].receipts['msg-b250-1'], 'rec-msg-b250-1', 'Batched ACK must preserve receipts');
    assert.strictEqual(sentAcks[0].receipts['msg-b250-100'], 'rec-msg-b250-100', 'Batched ACK must preserve all receipts');

    const sentGets = chan9a.port1.sent.filter(m => m.type === 'GET');
    assert.strictEqual(sentGets.length, 1, 'Initial GET window must be dispatched');
    assert.strictEqual(sentGets[0].ids.length, 2, 'Initial GET window must respect maxConcurrency=2');
    assert.strictEqual(rec9a._pendingGetQueue.length, 148, 'Remaining 148 unaccepted IDs must be queued in _pendingGetQueue');

    // Now send a repeated OFFER for the exact 150 unaccepted IDs (2 in _inFlightGets, 148 in _pendingGetQueue)
    await rec9a._handleOffer({
      protocol: PROTOCOL_NAME,
      version: PROTOCOL_VERSION,
      type: 'OFFER',
      ids: initial250.slice(100)
    });
    assert.strictEqual(batchCalls.length, 1, 'Repeated OFFER for IDs already queued or in-flight must be skipped before getAcceptance() (0 new lookups)');
    rec9a.stop();

    // --- 9b: Missing, malformed, and failed lookup results produce no false ACKs and no false GETs ---
    let lookupAttempts = 0;
    const chan9b = createMockChannel();
    const rec9b = new UmaiSession({
      peerOrigin: 'http://host.example',
      role: 'embedded',
      storage: {
        getOutboxIds: async () => [],
        getMessage: async () => null,
        getAcceptance: async () => {
          lookupAttempts++;
          return {
            // 'msg-missing' is omitted completely (simulating SQL WHERE IN missing-key bug)
            'msg-malformed-bool': { accepted: 'yes' },
            'msg-malformed-rec': { accepted: true, ackReceipt: 12345 },
            'msg-valid-acc': { accepted: true, ackReceipt: 'sig-ok' },
            'msg-valid-unacc': { accepted: false }
          };
        },
        acceptMessage: async () => ({ accepted: true }),
        onAcknowledged: async () => {}
      }
    });
    rec9b.port = chan9b.port1;
    chan9b.port1.onmessage = rec9b._portListener;
    rec9b.state = 'connected';

    await rec9b._handleOffer({
      protocol: PROTOCOL_NAME,
      version: PROTOCOL_VERSION,
      type: 'OFFER',
      ids: ['msg-missing', 'msg-malformed-bool', 'msg-malformed-rec', 'msg-valid-acc', 'msg-valid-unacc']
    });

    const acks9b = chan9b.port1.sent.filter(m => m.type === 'ACK');
    assert.strictEqual(acks9b.length, 1);
    assert.deepStrictEqual(acks9b[0].ids, ['msg-valid-acc'], 'Only explicitly valid accepted entry may produce ACK');
    const gets9b = chan9b.port1.sent.filter(m => m.type === 'GET');
    assert.strictEqual(gets9b.length, 1);
    assert.deepStrictEqual(gets9b[0].ids, ['msg-valid-unacc'], 'Missing or malformed entries must NOT trigger false GETs');

    // Verify bounded retry backoff (MAX_AUTO_RETRIES=3) for missing/malformed entries
    for (let i = 0; i < 5; i++) {
      await rec9b._handleOffer({
        protocol: PROTOCOL_NAME,
        version: PROTOCOL_VERSION,
        type: 'OFFER',
        ids: ['msg-missing']
      });
    }
    assert.strictEqual(lookupAttempts, 3, 'Missing/malformed getAcceptance entry must back off after MAX_AUTO_RETRIES=3');
    rec9b.stop();

    // --- 9c: Concurrent acceptance by another session between OFFER lookup and PUT arrival ---
    let acceptMessageCalledOnDup = false;
    const chan9c = createMockChannel();
    const rec9c = new UmaiSession({
      peerOrigin: 'http://host.example',
      role: 'embedded',
      storage: {
        getOutboxIds: async () => [],
        getMessage: async () => null,
        getAcceptance: async (ids) => {
          // By the time PUT arrives and checks getAcceptance([id]), another session has accepted it!
          const out = {};
          for (const id of ids) {
            out[id] = { accepted: true, ackReceipt: 'concurrent-session-receipt' };
          }
          return out;
        },
        acceptMessage: async () => {
          acceptMessageCalledOnDup = true;
          return { accepted: true };
        },
        onAcknowledged: async () => {}
      }
    });
    rec9c.port = chan9c.port1;
    chan9c.port1.onmessage = rec9c._portListener;
    rec9c.state = 'connected';
    rec9c._inFlightGets.set('msg-concurrent-tab', Date.now());
    await rec9c._handlePut({
      protocol: PROTOCOL_NAME,
      version: PROTOCOL_VERSION,
      type: 'PUT',
      id: 'msg-concurrent-tab',
      payload: { hello: 'world' },
      attachments: []
    });
    await new Promise(r => setTimeout(r, 20));
    assert.strictEqual(acceptMessageCalledOnDup, false, 'Concurrent acceptance detected by getAcceptance([id]) must skip acceptMessage');
    const acks9c = chan9c.port1.sent.filter(m => m.type === 'ACK');
    assert.strictEqual(acks9c.length, 1);
    assert.strictEqual(acks9c[0].receipts['msg-concurrent-tab'], 'concurrent-session-receipt', 'Duplicate PUT check must forward stored ackReceipt');
    rec9c.stop();
  }
  console.log('✓ Test 9: Batch getAcceptance(ids) contract, pre-lookup skip, malformed-entry safety, and concurrent session dedup passed');

  senderPoison.stop();
  receiverPoison.stop();
  secSession.stop();
  sessionA.stop();
  sessionB.stop();

  console.log('--- All JavaScript Tests Passed ---');
})();
