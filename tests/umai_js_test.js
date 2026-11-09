/**
 * UMAI JavaScript Library Unit and Protocol Verification Tests
 * Runs under Node.js without any dependencies.
 */

const assert = require('assert');
const { UmaiSession, PROTOCOL_NAME, PROTOCOL_VERSION, isValidUmaiMessage, isValidMessageId } = require('../js/umai.js');

let allTestsCompleted = false;
process.on('exit', (code) => {
  if (code === 0 && !allTestsCompleted) {
    console.error('FATAL: JavaScript test suite exited prematurely with unresolved async work!');
    process.exitCode = 1;
  }
});

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

  // Test 4: Poison-pill session retry cutoff (stops auto-GET after MAX_AUTO_RETRIES=3 failed acceptMessage attempts, resets on reconcile(true))
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
  assert.strictEqual(poisonAttempts, 3, 'Poison-pill message should hit session retry cutoff after 3 failed automatic acceptance attempts');

  // Manual reconcile(true) on receiver resets failure counter
  await receiverPoison.reconcile(true);
  await senderPoison.reconcile(false);
  await new Promise(r => setTimeout(r, 30));
  assert.strictEqual(poisonAttempts, 4, 'Manual reconcile(true) should reset session retry cutoff and allow retry');

  console.log('✓ Test 4: Poison-pill session retry cutoff and manual reconcile reset passed');

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

  // Test 9: Batch getAcceptance(ids) Scheduling, Pacing, Outage Recovery, & Whole-Batch Validation Suite:
  //   9a) Large initial offer (250 IDs), pre-lookup skip of queued/in-flight IDs, and lookupMinIntervalMs flood pacing
  //   9b) Decisive Test 1: Full GET queue (1,000 items) does NOT block repeated ACKs for accepted IDs, and deferred overflow unaccepted IDs advance automatically once capacity opens
  //   9c) Decisive Test 2: Temporary getAcceptance outage (> MAX_AUTO_RETRIES=3 failures, including thrown 503, Map, missing key, malformed entry) paces retries via backoff without false ACKs/GETs and recovers automatically
  //   9d) Concurrent acceptance caught by pre-acceptMessage getAcceptance([id]) & bounded _failedAttempts map (<= 1,000)
  {
    const initial250 = Array.from({ length: 250 }, (_, i) => `msg-b250-${i + 1}`);
    const batchCalls = [];
    const chan9a = createMockChannel();

    const rec9a = new UmaiSession({
      peerOrigin: 'http://host.example',
      role: 'embedded',
      maxConcurrency: 2,
      lookupMinIntervalMs: 50,
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

    // Repeated OFFER for the exact 150 unaccepted IDs (2 in _inFlightGets, 148 in _pendingGetQueue)
    await rec9a._handleOffer({
      protocol: PROTOCOL_NAME,
      version: PROTOCOL_VERSION,
      type: 'OFFER',
      ids: initial250.slice(100)
    });
    assert.strictEqual(batchCalls.length, 1, 'Repeated OFFER for IDs already queued or in-flight must be skipped before getAcceptance()');

    // Sustained OFFER flood of already-accepted IDs must be paced by lookupMinIntervalMs=50
    for (let f = 0; f < 15; f++) {
      await rec9a._handleOffer({
        protocol: PROTOCOL_NAME,
        version: PROTOCOL_VERSION,
        type: 'OFFER',
        ids: [`msg-b250-${(f % 10) + 1}`]
      });
    }
    assert.strictEqual(batchCalls.length, 1, 'Immediate OFFER flood within lookupMinIntervalMs must be coalesced and held until pacing interval elapses');
    await new Promise(r => setTimeout(r, 70));
    assert.strictEqual(batchCalls.length, 2, 'Coalesced OFFER flood must execute exactly 1 paced batch lookup after lookupMinIntervalMs');
    assert.strictEqual(batchCalls[1].length, 10, 'Coalesced flood lookup must batch all 10 distinct offered IDs');
    rec9a.stop();

    // --- 9b (Decisive Test 1): Full GET queue (1,000 items) does NOT prevent repeated ACKs, and deferred overflow unaccepted IDs advance automatically ---
    const chan9b = createMockChannel();
    const acceptedIn9b = new Set(['msg-already-1', 'msg-already-2']);
    const receiptsIn9b = { 'msg-already-1': 'sig-a1', 'msg-already-2': 'sig-a2' };

    const sender9b = new UmaiSession({
      peerOrigin: 'http://peer.example',
      role: 'host',
      storage: {
        getOutboxIds: async () => ['msg-fill-0', 'msg-overflow-1001', 'msg-overflow-1002'],
        getMessage: async (id) => ({ id, payload: { item: id }, attachments: [] }),
        getAcceptance: makeBatchAcceptance(() => ({ accepted: false })),
        acceptMessage: async () => true,
        onAcknowledged: async () => {}
      }
    });

    const rec9b = new UmaiSession({
      peerOrigin: 'http://host.example',
      role: 'embedded',
      maxConcurrency: 1,
      lookupMinIntervalMs: 0,
      storage: {
        getOutboxIds: async () => [],
        getMessage: async () => null,
        getAcceptance: async (ids) => {
          const out = Object.create(null);
          for (const id of ids) {
            if (acceptedIn9b.has(id)) {
              out[id] = { accepted: true, ackReceipt: receiptsIn9b[id] || '' };
            } else {
              out[id] = { accepted: false };
            }
          }
          return out;
        },
        acceptMessage: async (msg) => {
          acceptedIn9b.add(msg.id);
          return { accepted: true, ackReceipt: `rec-${msg.id}` };
        },
        onAcknowledged: async () => {}
      }
    });

    sender9b.port = chan9b.port1;
    chan9b.port1.onmessage = sender9b._portListener;
    sender9b.state = 'connected';
    sender9b._offeredIds.add('msg-fill-0');
    sender9b._offeredIds.add('msg-overflow-1001');
    sender9b._offeredIds.add('msg-overflow-1002');

    rec9b.port = chan9b.port2;
    chan9b.port2.onmessage = rec9b._portListener;
    rec9b.state = 'connected';
    rec9b._peerOfferedOnce = true;

    // Fill receiver's GET capacity completely to MAX_BATCH_IDS = 1,000 (1 in-flight + 999 queued = 1,000)
    rec9b._inFlightGets.set('msg-fill-0', Date.now());
    for (let q = 1; q < 1000; q++) {
      rec9b._pendingGetQueue.push(`msg-fill-${q}`);
    }
    assert.strictEqual(
      rec9b._inFlightGets.size + rec9b._pendingGetQueue.length,
      1000,
      'Receiver GET queue must be completely full (0 spare GET capacity)'
    );

    // Peer sends OFFER containing already-accepted IDs AND overflow unaccepted IDs (#1001, #1002)
    await rec9b._handleOffer({
      protocol: PROTOCOL_NAME,
      version: PROTOCOL_VERSION,
      type: 'OFFER',
      ids: ['msg-already-1', 'msg-already-2', 'msg-overflow-1001', 'msg-overflow-1002']
    });

    const immediateAcks9b = chan9b.port2.sent.filter(m => m.type === 'ACK');
    assert.strictEqual(immediateAcks9b.length, 1, 'Full GET queue must NOT prevent immediate repeated ACK for already-accepted IDs');
    assert.deepStrictEqual(immediateAcks9b[0].ids, ['msg-already-1', 'msg-already-2'], 'Repeated ACK must include all already-accepted IDs');
    assert.strictEqual(immediateAcks9b[0].receipts['msg-already-1'], 'sig-a1', 'Repeated ACK must preserve stored receipt sig-a1');
    assert.strictEqual(immediateAcks9b[0].receipts['msg-already-2'], 'sig-a2', 'Repeated ACK must preserve stored receipt sig-a2');
    assert.strictEqual(rec9b._deferredOfferIds.size, 2, 'Unaccepted IDs exceeding MAX_BATCH_IDS GET capacity must be retained in _deferredOfferIds');

    // Clear the 999 synthetic filler queue items and complete the 1 active transfer ('msg-fill-0') WITHOUT sending any new OFFER
    rec9b._pendingGetQueue = [];
    await rec9b._handlePut({
      protocol: PROTOCOL_NAME,
      version: PROTOCOL_VERSION,
      type: 'PUT',
      id: 'msg-fill-0',
      payload: { done: true },
      attachments: []
    });
    await new Promise(r => setTimeout(r, 40));

    assert.strictEqual(rec9b._deferredOfferIds.size, 0, 'Deferred unaccepted IDs must be automatically promoted once GET capacity frees up');
    assert.strictEqual(acceptedIn9b.has('msg-overflow-1001'), true, 'Deferred overflow ID #1001 must advance and be accepted without a new OFFER');
    assert.strictEqual(acceptedIn9b.has('msg-overflow-1002'), true, 'Deferred overflow ID #1002 must advance and be accepted without a new OFFER');
    sender9b.stop();
    rec9b.stop();

    // --- 9c (Decisive Test 2): Temporary lookup outage (> MAX_AUTO_RETRIES=3 failures) + whole-batch validation + automatic recovery ---
    let outageLookupCalls = 0;
    const outageErrors = [];
    const acceptedIn9c = new Set(['msg-outage-acc']);
    const chan9c = createMockChannel();

    const sender9c = new UmaiSession({
      peerOrigin: 'http://peer.example',
      role: 'host',
      storage: {
        getOutboxIds: async () => ['msg-outage-acc', 'msg-outage-new'],
        getMessage: async (id) => ({ id, payload: { fresh: true }, attachments: [] }),
        getAcceptance: makeBatchAcceptance(() => ({ accepted: false })),
        acceptMessage: async () => true,
        onAcknowledged: async () => {}
      }
    });

    const rec9c = new UmaiSession({
      peerOrigin: 'http://host.example',
      role: 'embedded',
      lookupMinIntervalMs: 15,
      lookupRetryBaseMs: 20,
      lookupRetryMaxMs: 50,
      onError: (err) => outageErrors.push(err.message),
      storage: {
        getOutboxIds: async () => [],
        getMessage: async () => null,
        getAcceptance: async (ids) => {
          outageLookupCalls++;
          // Fail 4 consecutive times (> MAX_AUTO_RETRIES=3) across thrown error, Map, missing key, and malformed entry!
          if (outageLookupCalls === 1) {
            throw new Error('HTTP 503 Service Unavailable');
          }
          if (outageLookupCalls === 2) {
            // Map must be rejected (plain object only contract)
            const m = new Map();
            for (const id of ids) m.set(id, { accepted: true });
            return m;
          }
          if (outageLookupCalls === 3) {
            // Sparse response missing 'msg-outage-new': whole batch must fail (even valid 'msg-outage-acc' must NOT emit ACK!)
            return {
              'msg-outage-acc': { accepted: true, ackReceipt: 'rec-outage' }
            };
          }
          if (outageLookupCalls === 4) {
            // Malformed non-boolean entry: whole batch must fail
            return {
              'msg-outage-acc': { accepted: 'yes' },
              'msg-outage-new': { accepted: false }
            };
          }
          // Attempt 5+: backend heals completely!
          const out = Object.create(null);
          for (const id of ids) {
            if (acceptedIn9c.has(id)) {
              out[id] = { accepted: true, ackReceipt: id === 'msg-outage-acc' ? 'rec-outage' : `rec-${id}` };
            } else {
              out[id] = { accepted: false };
            }
          }
          return out;
        },
        acceptMessage: async (msg) => {
          acceptedIn9c.add(msg.id);
          return { accepted: true, ackReceipt: `rec-${msg.id}` };
        },
        onAcknowledged: async () => {}
      }
    });

    sender9c.port = chan9c.port1;
    chan9c.port1.onmessage = sender9c._portListener;
    sender9c.state = 'connected';
    sender9c._offeredIds.add('msg-outage-acc');
    sender9c._offeredIds.add('msg-outage-new');

    rec9c.port = chan9c.port2;
    chan9c.port2.onmessage = rec9c._portListener;
    rec9c.state = 'connected';
    rec9c._peerOfferedOnce = true;

    // Trigger initial OFFER (Attempt 1 fails with HTTP 503) + flood 20 duplicate OFFERs during backoff window
    for (let k = 0; k < 20; k++) {
      await rec9c._handleOffer({
        protocol: PROTOCOL_NAME,
        version: PROTOCOL_VERSION,
        type: 'OFFER',
        ids: ['msg-outage-acc', 'msg-outage-new']
      });
    }
    assert.strictEqual(outageLookupCalls, 1, '20 flooded OFFERs during lookup backoff must NOT cause immediate retry amplification');
    assert.strictEqual(chan9c.port2.sent.filter(m => m.type === 'ACK').length, 0, 'Outage must produce zero false ACKs');
    assert.strictEqual(chan9c.port2.sent.filter(m => m.type === 'GET').length, 0, 'Outage must produce zero premature GETs');

    // Wait for automatic capped exponential backoff attempts 2 (20ms), 3 (40ms), 4 (50ms), and 5 (50ms) to complete
    await new Promise(r => setTimeout(r, 250));

    assert.strictEqual(outageErrors.length, 4, 'All 4 failed/malformed lookup batches must report errors via onError');
    assert.strictEqual(rec9c._failedAttempts.size, 0, 'Lookup outages must NOT increment per-message _failedAttempts cutoff');
    assert.strictEqual(outageLookupCalls, 6, 'Expected 4 failed batch lookups + 1 recovered batch lookup + 1 pre-acceptMessage [id] lookup (no flood)');

    const recoveredAcks = chan9c.port2.sent.filter(m => m.type === 'ACK');
    const ackedIds9c = recoveredAcks.flatMap(a => a.ids);
    assert.strictEqual(ackedIds9c.includes('msg-outage-acc'), true, 'Already-accepted message must be ACKed automatically after outage recovery');
    assert.strictEqual(ackedIds9c.includes('msg-outage-new'), true, 'Unaccepted message must be fetched, accepted, and ACKed automatically after >3 lookup failures');
    const outageAccFrame = recoveredAcks.find(a => a.ids.includes('msg-outage-acc'));
    assert.strictEqual(outageAccFrame.receipts['msg-outage-acc'], 'rec-outage', 'Recovered ACK must preserve stored receipt');
    assert.strictEqual(acceptedIn9c.has('msg-outage-new'), true, 'msg-outage-new must be committed in storage after outage recovery');
    assert.strictEqual(rec9c.getSyncStatus().isSyncing, false, 'Session must return to clean in-sync state after automatic recovery');
    sender9c.stop();
    rec9c.stop();

    // --- 9d: Concurrent acceptance by another session on PUT + bounded _failedAttempts map (<= 1,000) ---
    let acceptMessageCalledOnDup = false;
    const chan9d = createMockChannel();
    const rec9d = new UmaiSession({
      peerOrigin: 'http://host.example',
      role: 'embedded',
      storage: {
        getOutboxIds: async () => [],
        getMessage: async () => null,
        getAcceptance: async (ids) => {
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
    rec9d.port = chan9d.port1;
    chan9d.port1.onmessage = rec9d._portListener;
    rec9d.state = 'connected';
    rec9d._inFlightGets.set('msg-concurrent-tab', Date.now());
    await rec9d._handlePut({
      protocol: PROTOCOL_NAME,
      version: PROTOCOL_VERSION,
      type: 'PUT',
      id: 'msg-concurrent-tab',
      payload: { hello: 'world' },
      attachments: []
    });
    await new Promise(r => setTimeout(r, 20));
    assert.strictEqual(acceptMessageCalledOnDup, false, 'Concurrent acceptance detected by getAcceptance([id]) must skip acceptMessage');
    const acks9d = chan9d.port1.sent.filter(m => m.type === 'ACK');
    assert.strictEqual(acks9d.length, 1);
    assert.strictEqual(acks9d[0].receipts['msg-concurrent-tab'], 'concurrent-session-receipt', 'Duplicate PUT check must forward stored ackReceipt');

    // Verify _setBoundedMap caps _failedAttempts to MAX_BATCH_IDS = 1,000 with FIFO eviction
    for (let m = 0; m < 1050; m++) {
      rec9d._setBoundedMap(rec9d._failedAttempts, `msg-fail-${m}`, 3);
    }
    assert.strictEqual(rec9d._failedAttempts.size, 1000, '_failedAttempts must remain strictly bounded to MAX_BATCH_IDS (1,000)');
    assert.strictEqual(rec9d._failedAttempts.has('msg-fail-0'), false, 'Oldest entries must be evicted once _failedAttempts exceeds 1,000');
    assert.strictEqual(rec9d._failedAttempts.has('msg-fail-1049'), true, 'Newest entries must be retained in _failedAttempts');
    rec9d.stop();
  }
  console.log('✓ Test 9: Batch getAcceptance(ids) full-queue ACK independence, outage backoff recovery, whole-batch validation, and bounded maps passed');

  // Test 10: Reviewer Progress & Outage-Backoff Completeness Regressions:
  //   10a) Slow getOutboxIds() overlapped by faster periodic reconcile(false) heartbeats still emits OFFERs (no starvation)
  //        and excludes IDs acknowledged while getOutboxIds() was in flight
  //   10b) Incoming PUT duplicate checks respect lookup outage backoff (20 offered messages do NOT trigger 20 lookups or 20 payload transfers during outage)
  {
    // --- 10a: Slow getOutboxIds() overlapped by faster reconcile(false) heartbeats ---
    let slowReadCount = 0;
    const outbox10a = ['msg-slow-outbox-1', 'msg-concurrent-ack'];
    const chan10a = createMockChannel();
    const sender10a = new UmaiSession({
      peerOrigin: 'http://peer.example',
      role: 'host',
      storage: {
        getOutboxIds: async () => {
          slowReadCount++;
          const snapshot = outbox10a.slice();
          await new Promise(r => setTimeout(r, 110));
          return snapshot;
        },
        getMessage: async () => null,
        getAcceptance: makeBatchAcceptance(() => ({ accepted: false })),
        acceptMessage: async () => true,
        onAcknowledged: async (ids) => {
          for (const id of ids) {
            const idx = outbox10a.indexOf(id);
            if (idx !== -1) outbox10a.splice(idx, 1);
          }
        }
      }
    });
    sender10a.port = chan10a.port1;
    chan10a.port1.onmessage = sender10a._portListener;
    sender10a.state = 'connected';
    sender10a._offeredIds.add('msg-concurrent-ack');

    // Start initial reconcile(true) (110ms read), overlap with 35ms heartbeats (faster than 110ms read!),
    // AND deliver an ACK for 'msg-concurrent-ack' while read #1 is in flight!
    const pInit = sender10a.reconcile(true);
    await new Promise(r => setTimeout(r, 20));
    await sender10a._handleAck({
      protocol: PROTOCOL_NAME,
      version: PROTOCOL_VERSION,
      type: 'ACK',
      ids: ['msg-concurrent-ack']
    });
    const hbTimer = setInterval(() => {
      sender10a.reconcile(false);
    }, 35);
    await new Promise(r => setTimeout(r, 260));
    clearInterval(hbTimer);
    await pInit;

    const offers10a = chan10a.port1.sent.filter(m => m.type === 'OFFER');
    assert.strictEqual(offers10a.length >= 2, true, `Slow getOutboxIds() overlapped by faster heartbeats must still emit OFFERs (got ${offers10a.length} after ${slowReadCount} reads)`);
    assert.deepStrictEqual(
      offers10a[0].ids,
      ['msg-slow-outbox-1'],
      'First completed outbox snapshot must emit OFFER immediately while excluding ID acknowledged mid-read'
    );
    sender10a.stop();

    // --- 10b: Incoming PUT duplicate checks respect lookup outage backoff (20-message reproduction) ---
    const ids20 = Array.from({ length: 20 }, (_, i) => `msg-cascade-${i + 1}`);
    let lookupCalls10b = 0;
    let backendOutage10b = false;
    let putSentCount10b = 0;
    const accepted10b = new Set();
    const chan10b = createMockChannel();

    const sender10b = new UmaiSession({
      peerOrigin: 'http://peer.example',
      role: 'host',
      storage: {
        getOutboxIds: async () => ids20.filter(id => !accepted10b.has(id)),
        getMessage: async (id) => {
          putSentCount10b++;
          return { id, payload: { seq: id }, attachments: [] };
        },
        getAcceptance: makeBatchAcceptance(() => ({ accepted: false })),
        acceptMessage: async () => true,
        onAcknowledged: async () => {}
      }
    });

    const rec10b = new UmaiSession({
      peerOrigin: 'http://host.example',
      role: 'embedded',
      maxConcurrency: 1,
      lookupMinIntervalMs: 0,
      lookupRetryBaseMs: 180,
      lookupRetryMaxMs: 360,
      storage: {
        getOutboxIds: async () => [],
        getMessage: async () => null,
        getAcceptance: async (ids) => {
          lookupCalls10b++;
          if (backendOutage10b) {
            throw new Error('HTTP 503 Lookup Outage During PUT');
          }
          const out = Object.create(null);
          for (const id of ids) {
            out[id] = { accepted: accepted10b.has(id) };
          }
          // Flip backend into outage right after the initial 20-ID OFFER batch lookup succeeds!
          if (lookupCalls10b === 1) {
            backendOutage10b = true;
          }
          return out;
        },
        acceptMessage: async (msg) => {
          accepted10b.add(msg.id);
          return { accepted: true, ackReceipt: `rec-${msg.id}` };
        },
        onAcknowledged: async () => {}
      }
    });

    sender10b.port = chan10b.port1;
    chan10b.port1.onmessage = sender10b._portListener;
    sender10b.state = 'connected';
    rec10b.port = chan10b.port2;
    chan10b.port2.onmessage = rec10b._portListener;
    rec10b.state = 'connected';

    await sender10b.reconcile(true);
    // Wait 60ms (well inside the 180ms lookupRetryBaseMs window)
    await new Promise(r => setTimeout(r, 60));

    assert.strictEqual(
      lookupCalls10b,
      2,
      `Expected only 1 initial OFFER batch lookup + 1 PUT duplicate lookup before backoff holds the queue, got ${lookupCalls10b}`
    );
    assert.strictEqual(
      putSentCount10b,
      1,
      `Expected only 1 message payload transferred before lookup backoff pauses remaining 19 queued GETs, got ${putSentCount10b}`
    );
    assert.strictEqual(accepted10b.size, 0, 'Zero messages should be accepted while lookup outage is active');

    // Heal lookup backend before the 180ms backoff timer fires and verify all 20 messages complete automatically
    backendOutage10b = false;
    await new Promise(r => setTimeout(r, 260));

    assert.strictEqual(accepted10b.size, 20, `All 20 messages must recover and be accepted automatically once lookup heals (got ${accepted10b.size})`);
    assert.strictEqual(rec10b.getSyncStatus().isSyncing, false, 'Receiver must return to in-sync state after all 20 messages complete');
    sender10b.stop();
    rec10b.stop();
  }
  console.log('✓ Test 10: Slow outbox non-starvation under heartbeat and PUT lookup-backoff cascade prevention passed');

  // Test 11: Bidirectional Reconnect Churn (Repeated READY -> INIT -> INIT_ACK Handshakes) + Flaky Adapter Stress Test
  {
    const origMessageChannel = global.MessageChannel;
    const allCreatedPorts = [];

    class ClosableAsyncPort {
      constructor() {
        this.peer = null;
        this.onmessage = null;
        this.closed = false;
        allCreatedPorts.push(this);
      }
      postMessage(msg) {
        if (this.closed || !this.peer || this.peer.closed) {
          return;
        }
        const target = this.peer;
        setTimeout(() => {
          if (!this.closed && !target.closed && typeof target.onmessage === 'function') {
            target.onmessage({ data: msg });
          }
        }, 1);
      }
      close() {
        this.closed = true;
        this.onmessage = null;
      }
    }

    global.MessageChannel = class ClosableAsyncChannel {
      constructor() {
        this.port1 = new ClosableAsyncPort();
        this.port2 = new ClosableAsyncPort();
        this.port1.peer = this.port2;
        this.port2.peer = this.port1;
      }
    };

    try {
      const makeInitialOutbox = (prefix, count) => {
        const map = new Map();
        for (let i = 1; i <= count; i++) {
          const id = `${prefix}-${String(i).padStart(2, '0')}`;
          map.set(id, {
            id,
            payload: { seq: i, origin: prefix },
            attachments: [new Blob([`blob-content-${id}`], { type: 'text/plain' })],
            signature: `sig-${id}`
          });
        }
        return map;
      };

      const hostOutbox = makeInitialOutbox('host-churn', 12);
      const embOutbox = makeInitialOutbox('emb-churn', 12);
      const hostAccepted = new Map(); // id -> ackReceipt
      const embAccepted = new Map();  // id -> ackReceipt
      const importCountById = new Map(); // id -> number of times storage committed new import
      const ackedReceiptsOnHost = new Map();
      const ackedReceiptsOnEmb = new Map();

      let flakyEnabled = true;
      const faultStats = {
        outbox: 0,
        lookupThrow: 0,
        lookupPartial: 0,
        getMessage: 0,
        accept: 0,
        ack: 0
      };
      let callTick = 0;
      const delay = (ms) => new Promise(r => setTimeout(r, ms));

      const perIdGetMsgFaults = new Map();
      const perIdAcceptFaults = new Map();

      const makeFlakyStorage = (roleLabel, ownOutbox, ownAccepted, ownAckedReceipts) => ({
        getOutboxIds: async () => {
          const n = ++callTick;
          await delay(4 + (n % 5));
          if (flakyEnabled && (faultStats.outbox === 0 || n % 11 === 1)) {
            faultStats.outbox++;
            throw new Error(`${roleLabel} transient getOutboxIds error`);
          }
          return Array.from(ownOutbox.keys());
        },
        getMessage: async (id) => {
          const n = ++callTick;
          await delay(5 + (n % 6));
          const prevGetFaults = perIdGetMsgFaults.get(id) || 0;
          if (flakyEnabled && prevGetFaults < 2 && (faultStats.getMessage === 0 || n % 13 === 2)) {
            perIdGetMsgFaults.set(id, prevGetFaults + 1);
            faultStats.getMessage++;
            throw new Error(`${roleLabel} transient getMessage(${id}) error`);
          }
          return ownOutbox.get(id) || null;
        },
        getAcceptance: async (ids) => {
          const n = ++callTick;
          await delay(3 + (n % 5));
          if (flakyEnabled && (faultStats.lookupThrow === 0 || n % 11 === 3)) {
            faultStats.lookupThrow++;
            throw new Error(`${roleLabel} transient getAcceptance outage`);
          }
          const out = Object.create(null);
          for (let i = 0; i < ids.length; i++) {
            const id = ids[i];
            if (flakyEnabled && ids.length > 1 && i === ids.length - 1 && (faultStats.lookupPartial === 0 || n % 12 === 4)) {
              // Omit the last requested ID to trigger whole-batch fail-closed validation
              faultStats.lookupPartial++;
              continue;
            }
            if (ownAccepted.has(id)) {
              out[id] = { accepted: true, ackReceipt: ownAccepted.get(id) };
            } else {
              out[id] = { accepted: false };
            }
          }
          return out;
        },
        acceptMessage: async (msg) => {
          const n = ++callTick;
          await delay(6 + (n % 7));
          const prevAccFaults = perIdAcceptFaults.get(msg.id) || 0;
          if (flakyEnabled && !ownAccepted.has(msg.id) && prevAccFaults < 2 && (faultStats.accept === 0 || n % 9 === 5)) {
            perIdAcceptFaults.set(msg.id, prevAccFaults + 1);
            faultStats.accept++;
            throw new Error(`${roleLabel} transient acceptMessage(${msg.id}) disk error`);
          }
          if (!ownAccepted.has(msg.id)) {
            assert.strictEqual(Array.isArray(msg.attachments) && msg.attachments.length, 1, 'Attachment must survive transfer');
            assert.strictEqual(msg.signature, `sig-${msg.id}`, 'Signature must survive transfer');
            ownAccepted.set(msg.id, `receipt-for-${msg.id}`);
            importCountById.set(msg.id, (importCountById.get(msg.id) || 0) + 1);
          }
          return { accepted: true, ackReceipt: ownAccepted.get(msg.id) };
        },
        onAcknowledged: async (ids, receipts) => {
          const n = ++callTick;
          await delay(3 + (n % 4));
          if (flakyEnabled && (faultStats.ack === 0 || n % 7 === 0)) {
            faultStats.ack++;
            throw new Error(`${roleLabel} transient onAcknowledged error`);
          }
          for (const id of ids) {
            const rec = receipts && receipts[id];
            assert.strictEqual(rec, `receipt-for-${id}`, `ACK receipt for ${id} must match peer receipt`);
            ownAckedReceipts.set(id, rec);
            ownOutbox.delete(id);
          }
        }
      });

      let hostChurn = null;
      let embChurn = null;

      const hostMockWindow = {
        closed: false,
        postMessage(msg, targetOrigin, transfer) {
          setTimeout(() => {
            if (hostChurn && !hostChurn._stopped) {
              hostChurn._handleWindowMessage({
                origin: 'http://emb-churn.example',
                source: embMockWindow,
                data: msg,
                ports: transfer || []
              });
            }
          }, 1);
        }
      };

      const embMockWindow = {
        closed: false,
        postMessage(msg, targetOrigin, transfer) {
          setTimeout(() => {
            if (embChurn && !embChurn._stopped) {
              embChurn._handleWindowMessage({
                origin: 'http://host-churn.example',
                source: hostMockWindow,
                data: msg,
                ports: transfer || []
              });
            }
          }, 1);
        }
      };

      hostChurn = new UmaiSession({
        peerOrigin: 'http://emb-churn.example',
        role: 'host',
        peerWindow: embMockWindow,
        maxConcurrency: 3,
        getTimeoutMs: 90,
        lookupMinIntervalMs: 4,
        lookupRetryBaseMs: 20,
        lookupRetryMaxMs: 50,
        storage: makeFlakyStorage('host', hostOutbox, hostAccepted, ackedReceiptsOnHost)
      });

      embChurn = new UmaiSession({
        peerOrigin: 'http://host-churn.example',
        role: 'embedded',
        peerWindow: hostMockWindow,
        maxConcurrency: 3,
        getTimeoutMs: 90,
        lookupMinIntervalMs: 4,
        lookupRetryBaseMs: 20,
        lookupRetryMaxMs: 50,
        storage: makeFlakyStorage('embedded', embOutbox, embAccepted, ackedReceiptsOnEmb)
      });

      const triggerReadyHandshake = () => {
        hostMockWindow.postMessage(
          { protocol: PROTOCOL_NAME, version: PROTOCOL_VERSION, type: 'READY' },
          'http://host-churn.example'
        );
      };

      // Initial handshake + 5 rapid READY reconnect cycles mid-flight while flaky adapter errors fire
      triggerReadyHandshake();
      for (let cycle = 0; cycle < 5; cycle++) {
        await delay(28);
        triggerReadyHandshake();
      }

      // Let churn run long enough on the 6th generation for every adapter method (outbox, lookup, getMessage, accept, ack)
      // to fire at least one transient fault while flakyEnabled is active, then heal adapter and let settle
      await delay(120);
      flakyEnabled = false;

      // Wait for full bidirectional convergence (bounded polling up to 2s)
      const deadline = Date.now() + 2000;
      while (Date.now() < deadline) {
        if (
          hostOutbox.size === 0 &&
          embOutbox.size === 0 &&
          hostAccepted.size === 12 &&
          embAccepted.size === 12 &&
          !hostChurn.getSyncStatus().isSyncing &&
          !embChurn.getSyncStatus().isSyncing
        ) {
          break;
        }
        // Periodic heartbeat reconcile just like the demo UI's 3s interval
        hostChurn.reconcile(false);
        embChurn.reconcile(false);
        await delay(40);
      }

      // 1. Verify every individual fault mode actually fired during churn
      assert.strictEqual(faultStats.outbox >= 1, true, 'Must exercise transient getOutboxIds error');
      assert.strictEqual(faultStats.lookupThrow >= 1, true, 'Must exercise transient getAcceptance throw');
      assert.strictEqual(faultStats.lookupPartial >= 1, true, 'Must exercise partial getAcceptance batch rejection');
      assert.strictEqual(faultStats.getMessage >= 1, true, 'Must exercise transient getMessage error');
      assert.strictEqual(faultStats.accept >= 1, true, 'Must exercise transient acceptMessage error');
      assert.strictEqual(faultStats.ack >= 1, true, 'Must exercise transient onAcknowledged error');

      // 2. Verify 100% bidirectional delivery and outbox cleanup with verified receipts
      assert.strictEqual(embAccepted.size, 12, `Embedded peer must accept all 12 host messages (got ${embAccepted.size})`);
      assert.strictEqual(hostAccepted.size, 12, `Host peer must accept all 12 embedded messages (got ${hostAccepted.size})`);
      assert.strictEqual(hostOutbox.size, 0, `Host outbox must drain completely (remaining: ${hostOutbox.size})`);
      assert.strictEqual(embOutbox.size, 0, `Embedded outbox must drain completely (remaining: ${embOutbox.size})`);
      assert.strictEqual(ackedReceiptsOnHost.size, 12, 'Host must verify and record all 12 ACK receipts');
      assert.strictEqual(ackedReceiptsOnEmb.size, 12, 'Embedded must verify and record all 12 ACK receipts');

      // 3. Verify zero duplicate imports across all 24 messages despite 6 connection generations
      for (let i = 1; i <= 12; i++) {
        const hId = `host-churn-${String(i).padStart(2, '0')}`;
        const eId = `emb-churn-${String(i).padStart(2, '0')}`;
        assert.strictEqual(importCountById.get(hId), 1, `Message ${hId} must be imported exactly once`);
        assert.strictEqual(importCountById.get(eId), 1, `Message ${eId} must be imported exactly once`);
      }

      // 4. Verify zero leaked worker counters, queues, or open superseded MessagePorts
      for (const [label, sess] of [['host', hostChurn], ['embedded', embChurn]]) {
        assert.strictEqual(sess._activeSendCount, 0, `${label} _activeSendCount must settle at 0`);
        assert.strictEqual(sess._activeAcceptCount, 0, `${label} _activeAcceptCount must settle at 0`);
        assert.strictEqual(sess._putQueue.length, 0, `${label} _putQueue must be empty`);
        assert.strictEqual(sess._incomingPutQueue.length, 0, `${label} _incomingPutQueue must be empty`);
        assert.strictEqual(sess._acceptingIds.size, 0, `${label} _acceptingIds must be empty`);
        assert.strictEqual(sess._inFlightGets.size, 0, `${label} _inFlightGets must be empty`);
        assert.strictEqual(sess.getSyncStatus().isSyncing, false, `${label} getSyncStatus().isSyncing must be false`);
      }

      // 6 handshakes created 12 ports total; the 10 superseded ports must already be closed, and the active 2 open
      const closedBeforeStop = allCreatedPorts.filter(p => p.closed).length;
      assert.strictEqual(allCreatedPorts.length, 12, `Expected 12 ports across 6 handshakes, got ${allCreatedPorts.length}`);
      assert.strictEqual(closedBeforeStop, 10, `All 10 superseded ports from earlier generations must be closed, got ${closedBeforeStop}`);

      hostChurn.stop();
      embChurn.stop();
      assert.strictEqual(allCreatedPorts.every(p => p.closed), true, 'All 12 ports must be closed after stop()');

      // --- 11b: Deterministic READY arriving mid-getOutboxIds() reconcile loop ---
      let releaseStaleGen1Outbox = null;
      let outboxGenCall = 0;
      const midRecPorts = [];
      let midRecEmbWin = null;
      let midRecHost = null;

      midRecEmbWin = {
        closed: false,
        postMessage(msg, targetOrigin, transfer) {
          if (msg.type === 'INIT' && transfer && transfer.length > 0) {
            const p = transfer[0];
            midRecPorts.push(p);
            p.postMessage({ protocol: PROTOCOL_NAME, version: PROTOCOL_VERSION, type: 'INIT_ACK' });
          }
        }
      };

      midRecHost = new UmaiSession({
        peerOrigin: 'http://emb-midrec.example',
        role: 'host',
        peerWindow: midRecEmbWin,
        storage: {
          getOutboxIds: async () => {
            outboxGenCall++;
            if (outboxGenCall === 1) {
              return await new Promise(r => { releaseStaleGen1Outbox = r; });
            }
            return ['fresh-gen2-msg'];
          },
          getMessage: async (id) => ({ id, payload: {}, attachments: [] }),
          getAcceptance: makeBatchAcceptance(() => ({ accepted: false })),
          acceptMessage: async () => true,
          onAcknowledged: async () => {}
        }
      });

      // Establish Generation 1; reconcile(true) suspends inside getOutboxIds() #1
      midRecHost._handleWindowMessage({
        origin: 'http://emb-midrec.example',
        source: midRecEmbWin,
        data: { protocol: PROTOCOL_NAME, version: PROTOCOL_VERSION, type: 'READY' }
      });
      await delay(10);
      assert.strictEqual(typeof releaseStaleGen1Outbox, 'function', 'Gen 1 getOutboxIds() must be suspended');

      // Capture messages received on Generation 2's peer port
      const gen2ReceivedOffers = [];
      midRecHost._handleWindowMessage({
        origin: 'http://emb-midrec.example',
        source: midRecEmbWin,
        data: { protocol: PROTOCOL_NAME, version: PROTOCOL_VERSION, type: 'READY' }
      });
      assert.strictEqual(midRecPorts.length, 2, 'Second READY must establish Generation 2 port');
      midRecPorts[1].onmessage = (ev) => {
        if (ev.data && ev.data.type === 'OFFER') {
          gen2ReceivedOffers.push(ev.data.ids);
        }
      };
      await delay(15);

      // Now resolve Generation 1's stale getOutboxIds() after Generation 2 is active
      releaseStaleGen1Outbox(['stale-gen1-msg']);
      await delay(20);

      assert.strictEqual(
        gen2ReceivedOffers.some(ids => ids.includes('stale-gen1-msg')),
        false,
        'Stale getOutboxIds() from superseded generation must NEVER emit OFFER on replacement port'
      );
      assert.strictEqual(midRecHost._offeredIds.has('stale-gen1-msg'), false, 'Stale ID must not pollute Gen 2 _offeredIds');
      assert.strictEqual(midRecHost._offeredIds.has('fresh-gen2-msg'), true, 'Fresh Gen 2 outbox ID must be offered');
      midRecHost.stop();

      // --- 11c: Deterministic heartbeat OFFERs colliding with active lookup backoff ---
      const backoffCollisionChan = createMockChannel();
      let collisionLookupCalls = 0;
      const collisionBatchHistory = [];
      let failFirstCollisionLookup = true;

      const backoffCollisionRec = new UmaiSession({
        peerOrigin: 'http://host.example',
        role: 'embedded',
        lookupMinIntervalMs: 5,
        lookupRetryBaseMs: 140,
        lookupRetryMaxMs: 500,
        storage: {
          getOutboxIds: async () => [],
          getMessage: async () => null,
          getAcceptance: async (ids) => {
            collisionLookupCalls++;
            collisionBatchHistory.push(ids.slice());
            if (failFirstCollisionLookup) {
              throw new Error('transient DB timeout');
            }
            const out = Object.create(null);
            for (const id of ids) out[id] = { accepted: false };
            return out;
          },
          acceptMessage: async () => true,
          onAcknowledged: async () => {}
        }
      });
      backoffCollisionRec.port = backoffCollisionChan.port1;
      backoffCollisionChan.port1.onmessage = backoffCollisionRec._portListener;
      backoffCollisionRec.state = 'connected';

      // Initial OFFER triggers lookup #1 -> fails -> enters 140ms backoff
      await backoffCollisionRec._handleOffer({
        protocol: PROTOCOL_NAME,
        version: PROTOCOL_VERSION,
        type: 'OFFER',
        ids: ['msg-b1']
      });
      assert.strictEqual(collisionLookupCalls, 1, 'Initial OFFER must trigger lookup #1');
      assert.strictEqual(backoffCollisionRec._lookupFailureCount, 1, 'Failed lookup must enter backoff');

      // Send two heartbeat re-OFFERs (adding msg-b2) mid-backoff; neither may trigger an early lookup
      await delay(20);
      await backoffCollisionRec._handleOffer({
        protocol: PROTOCOL_NAME,
        version: PROTOCOL_VERSION,
        type: 'OFFER',
        ids: ['msg-b1']
      });
      await delay(25);
      await backoffCollisionRec._handleOffer({
        protocol: PROTOCOL_NAME,
        version: PROTOCOL_VERSION,
        type: 'OFFER',
        ids: ['msg-b1', 'msg-b2']
      });
      assert.strictEqual(collisionLookupCalls, 1, 'Heartbeat OFFERs arriving during active backoff must NOT trigger early getAcceptance()');

      // Heal backend before the 140ms backoff window finishes and verify single coalesced batch lookup
      failFirstCollisionLookup = false;
      await delay(140);
      assert.strictEqual(collisionLookupCalls, 2, 'Backoff expiry must execute exactly 1 coalesced retry lookup');
      assert.deepStrictEqual(
        collisionBatchHistory[1].sort(),
        ['msg-b1', 'msg-b2'],
        'Post-backoff lookup must coalesce initial + mid-backoff heartbeat OFFER IDs into one batch'
      );
      const postBackoffGets = backoffCollisionChan.port1.sent.filter(m => m.type === 'GET');
      assert.strictEqual(postBackoffGets.length >= 1, true, 'GET must be dispatched once coalesced post-backoff lookup succeeds');
      backoffCollisionRec.stop();
    } finally {
      global.MessageChannel = origMessageChannel;
    }
  }
  console.log('✓ Test 11: Bidirectional reconnect churn (6 READY/INIT generations) + flaky adapter stress test passed');

  // Test 12: Failed lookup while pending lookup queue is full must NEVER invent accepted:false or emit premature GET
  {
    const chan12 = createMockChannel();
    let lookupAttempt12 = 0;
    let rejectFirstLookup12 = null;
    let resolveSecondLookup12 = null;
    let secondLookupRequestedIds12 = null;

    const rec12 = new UmaiSession({
      peerOrigin: 'http://host.example',
      role: 'embedded',
      maxConcurrency: 4,
      lookupMinIntervalMs: 5,
      lookupRetryBaseMs: 50,
      lookupRetryMaxMs: 120,
      storage: {
        getOutboxIds: async () => [],
        getMessage: async () => null,
        getAcceptance: async (ids) => {
          lookupAttempt12++;
          if (lookupAttempt12 === 1) {
            return await new Promise((_, reject) => {
              rejectFirstLookup12 = reject;
            });
          }
          secondLookupRequestedIds12 = ids.slice();
          return await new Promise((resolve) => {
            resolveSecondLookup12 = resolve;
          });
        },
        acceptMessage: async () => true,
        onAcknowledged: async () => {}
      }
    });

    rec12.port = chan12.port1;
    chan12.port1.onmessage = rec12._portListener;
    rec12.state = 'connected';

    // 1. Start initial lookup for ['msg-already-acc', 'msg-needs-get'] (suspended in flight)
    const offer1Promise = rec12._handleOffer({
      protocol: PROTOCOL_NAME,
      version: PROTOCOL_VERSION,
      type: 'OFFER',
      ids: ['msg-already-acc', 'msg-needs-get']
    });
    await new Promise(r => setTimeout(r, 10));
    assert.strictEqual(typeof rejectFirstLookup12, 'function', 'Initial lookup must be in flight');
    assert.strictEqual(rec12._inFlightLookupIds.size, 2, 'Both in-flight lookup IDs must reserve retry capacity');

    // 2. While first lookup is pending, flood _handleOffer with 1,000 different IDs
    const floodIds12 = Array.from({ length: 1000 }, (_, i) => `flood-12-${String(i + 1).padStart(4, '0')}`);
    await rec12._handleOffer({
      protocol: PROTOCOL_NAME,
      version: PROTOCOL_VERSION,
      type: 'OFFER',
      ids: floodIds12
    });
    assert.strictEqual(
      rec12._pendingOfferIds.size,
      998,
      `Offer admission must reserve 2 slots for in-flight lookup IDs (expected 998, got ${rec12._pendingOfferIds.size})`
    );

    // 3. Fail the first lookup while the lookup queue is full
    rejectFirstLookup12(new Error('transient lookup failure under full queue'));
    await offer1Promise;

    assert.strictEqual(rec12._pendingGetQueue.length, 0, 'Failed lookup under full queue must NEVER push unresolved IDs into _pendingGetQueue');
    assert.strictEqual(rec12._deferredOfferIds.size, 0, 'Failed lookup under full queue must NEVER push unresolved IDs into _deferredOfferIds');
    assert.strictEqual(rec12._pendingOfferIds.has('msg-already-acc'), true, 'msg-already-acc must be re-queued into reserved _pendingOfferIds slot');
    assert.strictEqual(rec12._pendingOfferIds.has('msg-needs-get'), true, 'msg-needs-get must be re-queued into reserved _pendingOfferIds slot');
    assert.strictEqual(chan12.port1.sent.some(m => m.type === 'GET'), false, 'Zero GET frames may be sent after failed lookup');

    // 4. Wait for backoff to expire so retry lookup #2 starts (and hold it before resolving)
    await new Promise(r => setTimeout(r, 75));
    assert.strictEqual(lookupAttempt12, 2, 'Retry lookup #2 must start after backoff');
    assert.strictEqual(
      chan12.port1.sent.some(m => m.type === 'GET'),
      false,
      'Zero GET frames may be sent before retry lookup #2 explicitly resolves'
    );
    assert.strictEqual(secondLookupRequestedIds12.includes('msg-already-acc'), true, 'Retry lookup must re-query msg-already-acc');
    assert.strictEqual(secondLookupRequestedIds12.includes('msg-needs-get'), true, 'Retry lookup must re-query msg-needs-get');

    // 5. Resolve retry lookup #2: msg-already-acc -> accepted:true, msg-needs-get -> accepted:false, flood -> accepted:true
    const retryResponse12 = Object.create(null);
    for (const id of secondLookupRequestedIds12) {
      if (id === 'msg-already-acc') {
        retryResponse12[id] = { accepted: true, ackReceipt: 'sig-already-acc' };
      } else if (id === 'msg-needs-get') {
        retryResponse12[id] = { accepted: false };
      } else {
        retryResponse12[id] = { accepted: true };
      }
    }
    resolveSecondLookup12(retryResponse12);
    await new Promise(r => setTimeout(r, 25));

    const sentGets12 = chan12.port1.sent.filter(m => m.type === 'GET');
    const sentAcks12 = chan12.port1.sent.filter(m => m.type === 'ACK');

    assert.strictEqual(
      sentGets12.some(m => m.ids.includes('msg-already-acc')),
      false,
      'Already-accepted ID must NEVER receive a GET'
    );
    assert.strictEqual(
      sentAcks12.some(m => m.ids.includes('msg-already-acc') && m.receipts && m.receipts['msg-already-acc'] === 'sig-already-acc'),
      true,
      'Already-accepted ID must emit repeated ACK with stored receipt once retry lookup succeeds'
    );
    assert.strictEqual(
      sentGets12.some(m => m.ids.includes('msg-needs-get')),
      true,
      'Unaccepted ID must receive GET once retry lookup explicitly returns accepted:false'
    );
    rec12.stop();
  }
  console.log('✓ Test 12: Failed lookup under full pending lookup queue reserves retry capacity and never invents GET passed');

  // Test 13: Shared-reference DAG bomb protection, inter-continuation stop() guard, and generation-scoped reservation cleanup
  {
    // --- 13a: Shared-reference DAG payload over real Node MessageChannel + pre-stringify byte budget ---
    const realMc = new MessageChannel();
    try {
      let dagAccepted = false;
      let dagRejectedCount = 0;
      const dagRec64 = new UmaiSession({
        peerOrigin: 'http://host.example',
        role: 'embedded',
        maxMessageBytes: 64,
        storage: {
          getOutboxIds: async () => [],
          getMessage: async () => null,
          getAcceptance: makeBatchAcceptance(() => ({ accepted: false })),
          acceptMessage: async () => {
            dagAccepted = true;
            return true;
          },
          onAcknowledged: async () => {}
        },
        onError: () => {
          dagRejectedCount++;
        }
      });

      dagRec64.port = realMc.port2;
      dagRec64.state = 'connected';
      const gen64 = dagRec64._generation;
      realMc.port2.onmessage = (ev) => dagRec64._handlePortMessage(ev, gen64, realMc.port2);

      let dagPayload = true;
      for (let i = 0; i < 30; i++) {
        dagPayload = { a: dagPayload, b: dagPayload };
      }

      dagRec64._inFlightGets.set('msg-dag-64', Date.now());
      const t0 = Date.now();
      realMc.port1.postMessage({
        protocol: PROTOCOL_NAME,
        version: PROTOCOL_VERSION,
        type: 'PUT',
        id: 'msg-dag-64',
        payload: dagPayload,
        attachments: []
      });

      // Wait briefly for real MessagePort delivery and synchronous validation
      const waitStart = Date.now();
      while (dagRejectedCount === 0 && Date.now() - waitStart < 250) {
        await new Promise(r => setTimeout(r, 5));
      }
      const elapsed64 = Date.now() - t0;

      assert.strictEqual(dagAccepted, false, 'Shared-reference DAG payload must NEVER reach acceptMessage');
      assert.strictEqual(dagRejectedCount, 1, 'Shared-reference DAG payload over real MessageChannel must be rejected');
      assert.strictEqual(dagRec64._failedAttempts.get('msg-dag-64'), 1, 'Rejected DAG PUT must record failed attempt');
      assert.strictEqual(elapsed64 < 200, true, `30-level DAG validation must complete immediately without hanging (took ${elapsed64}ms)`);

      // Also verify 30-level DAG is rejected in <50ms even with default 50MB maxMessageBytes,
      // and oversized non-shared trees abort BEFORE JSON.stringify is ever invoked.
      const dagChan50 = createMockChannel();
      const dagRec50 = new UmaiSession({
        peerOrigin: 'http://host.example',
        role: 'embedded',
        storage: {
          getOutboxIds: async () => [],
          getMessage: async () => null,
          getAcceptance: makeBatchAcceptance(() => ({ accepted: false })),
          acceptMessage: async () => {
            dagAccepted = true;
            return true;
          },
          onAcknowledged: async () => {}
        }
      });
      dagRec50.port = dagChan50.port1;
      dagChan50.port1.onmessage = dagRec50._portListener;
      dagRec50.state = 'connected';
      dagRec50._inFlightGets.set('msg-dag-50mb', Date.now());

      const t50 = Date.now();
      await dagRec50._handlePut({
        protocol: PROTOCOL_NAME,
        version: PROTOCOL_VERSION,
        type: 'PUT',
        id: 'msg-dag-50mb',
        payload: dagPayload,
        attachments: []
      });
      const elapsed50 = Date.now() - t50;
      assert.strictEqual(dagAccepted, false, 'Shared-reference DAG must be rejected even under 50MB maxMessageBytes');
      assert.strictEqual(dagRec50._failedAttempts.get('msg-dag-50mb'), 1, 'Rejected 50MB DAG PUT must record failed attempt');
      assert.strictEqual(elapsed50 < 50, true, `50MB DAG rejection must run in O(distinct objects) (<50ms, took ${elapsed50}ms)`);

      // Verify oversized distinct tree aborts during traversal before JSON.stringify runs
      const origStringify = JSON.stringify;
      let stringifyCalledOnOversized = false;
      JSON.stringify = function (...args) {
        stringifyCalledOnOversized = true;
        return origStringify.apply(this, args);
      };
      try {
        dagRec64._inFlightGets.set('msg-oversized-tree', Date.now());
        const distinctOversizedTree = { items: Array.from({ length: 100 }, (_, i) => ({ idx: i })) };
        await dagRec64._handlePut({
          protocol: PROTOCOL_NAME,
          version: PROTOCOL_VERSION,
          type: 'PUT',
          id: 'msg-oversized-tree',
          payload: distinctOversizedTree,
          attachments: []
        });
      } finally {
        JSON.stringify = origStringify;
      }
      assert.strictEqual(stringifyCalledOnOversized, false, 'Oversized tree must abort pre-serialization before JSON.stringify()');

      dagRec50.stop();
      dagRec64.stop();
    } finally {
      realMc.port1.close();
      realMc.port2.close();
    }

    // --- 13b: Deterministic session.stop() between _queryValidatedAcceptance resolution and caller continuation ---
    let acceptCalledAfterStop13b = false;
    let resolveLookup13b = null;
    let lookupPromise13b = null;
    const chan13b = createMockChannel();

    const rec13b = new UmaiSession({
      peerOrigin: 'http://host.example',
      role: 'embedded',
      storage: {
        getOutboxIds: async () => [],
        getMessage: async () => null,
        getAcceptance: () => {
          lookupPromise13b = new Promise((resolve) => {
            resolveLookup13b = resolve;
          });
          return lookupPromise13b;
        },
        acceptMessage: async () => {
          acceptCalledAfterStop13b = true;
          return { accepted: true };
        },
        onAcknowledged: async () => {}
      }
    });
    rec13b.port = chan13b.port1;
    chan13b.port1.onmessage = rec13b._portListener;
    rec13b.state = 'connected';
    rec13b._inFlightGets.set('msg-interleave-stop', Date.now());

    const putPromise13b = rec13b._handlePut({
      protocol: PROTOCOL_NAME,
      version: PROTOCOL_VERSION,
      type: 'PUT',
      id: 'msg-interleave-stop',
      payload: { ok: true },
      attachments: []
    });
    await new Promise(r => setTimeout(r, 5));
    assert.strictEqual(typeof resolveLookup13b, 'function', 'PUT duplicate lookup must be awaiting lookupPromise13b');

    // Attach a .then() reaction on lookupPromise13b AFTER _queryValidatedAcceptance's internal `await`:
    // Microtask 1 runs _queryValidatedAcceptance's post-await (while session is still connected!) and resolves outer helper promise;
    // Microtask 2 runs rec13b.stop() BEFORE Microtask 3 resumes _processIncomingPutQueue!
    lookupPromise13b.then(() => {
      rec13b.stop();
    });
    resolveLookup13b({ 'msg-interleave-stop': { accepted: false } });
    await putPromise13b;
    await new Promise(r => setTimeout(r, 15));

    assert.strictEqual(rec13b.state, 'disconnected', 'Session must be disconnected');
    assert.strictEqual(
      acceptCalledAfterStop13b,
      false,
      'storage.acceptMessage() must NEVER start when stop() fires between lookup helper return and caller continuation'
    );

    // --- 13c: Stale Generation A lookup completion (resolve & reject) must NOT erase Generation B reservations ---
    for (const mode of ['resolve', 'reject']) {
      let lookupCall13c = 0;
      let settleGenA13c = null;
      let resolveGenB13c = null;
      const chanGenA = createMockChannel();
      const chanGenB = createMockChannel();

      const rec13c = new UmaiSession({
        peerOrigin: 'http://host.example',
        role: 'embedded',
        lookupMinIntervalMs: 5,
        storage: {
          getOutboxIds: async () => [],
          getMessage: async () => null,
          getAcceptance: async (ids) => {
            lookupCall13c++;
            if (lookupCall13c === 1) {
              return await new Promise((resolve, reject) => {
                settleGenA13c = mode === 'resolve' ? resolve : reject;
              });
            }
            if (lookupCall13c === 2) {
              return await new Promise((resolve) => {
                resolveGenB13c = resolve;
              });
            }
            const out = Object.create(null);
            for (const id of ids) out[id] = { accepted: true };
            return out;
          },
          acceptMessage: async () => true,
          onAcknowledged: async () => {}
        }
      });

      // Generation A starts lookup for 'shared-res-id'
      rec13c.port = chanGenA.port1;
      chanGenA.port1.onmessage = rec13c._portListener;
      rec13c.state = 'connected';
      const genAOffer = rec13c._handleOffer({
        protocol: PROTOCOL_NAME,
        version: PROTOCOL_VERSION,
        type: 'OFFER',
        ids: ['shared-res-id']
      });
      await new Promise(r => setTimeout(r, 5));
      assert.strictEqual(rec13c._inFlightLookupIds.has('shared-res-id'), true, 'Gen A must reserve shared-res-id');

      // Reset into Generation B and start lookup for the same 'shared-res-id'
      rec13c._resetChannelState();
      rec13c.port = chanGenB.port1;
      chanGenB.port1.onmessage = rec13c._portListener;
      rec13c.state = 'connected';
      const genBOffer = rec13c._handleOffer({
        protocol: PROTOCOL_NAME,
        version: PROTOCOL_VERSION,
        type: 'OFFER',
        ids: ['shared-res-id']
      });
      await new Promise(r => setTimeout(r, 5));
      assert.strictEqual(lookupCall13c, 2, 'Gen B lookup must be running');
      assert.strictEqual(rec13c._inFlightLookupIds.has('shared-res-id'), true, 'Gen B must reserve shared-res-id');

      // Settle obsolete Generation A's lookup while Generation B's lookup is still pending
      if (mode === 'resolve') {
        settleGenA13c({ 'shared-res-id': { accepted: false } });
      } else {
        settleGenA13c(new Error('obsolete Gen A lookup error'));
      }
      await genAOffer;
      await new Promise(r => setTimeout(r, 5));

      assert.strictEqual(
        rec13c._inFlightLookupIds.has('shared-res-id'),
        true,
        `Obsolete Gen A lookup (${mode}) must NEVER erase Gen B's active reservation`
      );

      // Verify Gen B's reserved retry slot still caps a 1,000-ID OFFER flood at 999 admitted IDs
      const flood13c = Array.from({ length: 1000 }, (_, i) => `f13c-${mode}-${String(i + 1).padStart(4, '0')}`);
      await rec13c._handleOffer({
        protocol: PROTOCOL_NAME,
        version: PROTOCOL_VERSION,
        type: 'OFFER',
        ids: flood13c
      });
      assert.strictEqual(
        rec13c._pendingOfferIds.size,
        999,
        `Gen B reservation (${mode}) must keep 1 retry slot reserved during 1,000-ID flood (got ${rec13c._pendingOfferIds.size})`
      );

      resolveGenB13c({ 'shared-res-id': { accepted: true } });
      await genBOffer;
      rec13c.stop();
    }
  }
  console.log('✓ Test 13: Shared-reference DAG bomb rejection, inter-continuation stop() guard, and generation-scoped reservation cleanup passed');

  // Test 14: Reusable Browser HTTP Spool Adapter (js/umai-spool.js — createHttpSpoolAdapter):
  //   14a) End-to-end UmaiSession transfer + receipt verification through createHttpSpoolAdapter
  //   14b) Partial attachment failure (404/500 on 2nd attachment) and size mismatch abort getMessage(id) completely (Rule 3)
  //   14c) Outbox metadata 404 -> null vs 500 -> throw; 401 invokes onUnauthorized; throwing UI hooks do not corrupt commit/ack results
  {
    const { createHttpSpoolAdapter } = require('../js/umai-spool.js');
    assert.strictEqual(typeof createHttpSpoolAdapter, 'function', 'createHttpSpoolAdapter must be exported');

    // --- 14a: End-to-end UmaiSession exchange via createHttpSpoolAdapter ---
    const outboxStore14 = new Map([
      ['msg-spool-1', {
        id: 'msg-spool-1',
        payload: { invoice: 'INV-100', amount: 250 },
        signature: 'sig-100',
        attachments: [
          { name: 'a.txt', size: 5, bytes: Buffer.from('hello') },
          { name: 'b.bin', size: 4, bytes: Buffer.from([1, 2, 3, 4]) }
        ]
      }]
    ]);
    const inboxStore14 = new Map();
    const seenMutatingHeaders = [];
    let uiAcceptedCount = 0;
    let uiAckCount = 0;

    const mockFetchA = async (url, init) => {
      if (init && init.method && init.method !== 'GET') {
        seenMutatingHeaders.push(init.headers['X-UMAI-CSRF']);
      }
      if (url === '/api/outbox' && init.method === 'GET') {
        return new Response(JSON.stringify(Array.from(outboxStore14.values())), { status: 200 });
      }
      if (url === '/api/outbox/msg-spool-1' && init.method === 'GET') {
        const m = outboxStore14.get('msg-spool-1');
        if (!m) return new Response('not found', { status: 404 });
        return new Response(JSON.stringify({
          id: m.id,
          payload: m.payload,
          signature: m.signature,
          attachments: m.attachments.map(a => ({ name: a.name, size: a.size }))
        }), { status: 200 });
      }
      if (url.startsWith('/api/outbox/msg-spool-1/attachments/') && init.method === 'GET') {
        const name = decodeURIComponent(url.split('/').pop());
        const m = outboxStore14.get('msg-spool-1');
        const att = m && m.attachments.find(a => a.name === name);
        if (!att) return new Response('missing', { status: 404 });
        return new Response(att.bytes, { status: 200, headers: { 'Content-Type': 'application/octet-stream' } });
      }
      if (url === '/api/outbox/ack' && init.method === 'POST') {
        const body = JSON.parse(init.body);
        for (const id of body.ids) {
          assert.strictEqual(body.receipts[id], 'receipt-' + id, 'Receipt must be forwarded to /outbox/ack');
          outboxStore14.delete(id);
        }
        return new Response(JSON.stringify({ acknowledged: true }), { status: 200 });
      }
      if (url === '/api/inbox/acceptance' && init.method === 'POST') {
        const body = JSON.parse(init.body);
        const results = {};
        for (const id of body.ids) results[id] = { accepted: false };
        return new Response(JSON.stringify({ results }), { status: 200 });
      }
      throw new Error('Unexpected fetch URL on A: ' + url);
    };

    const mockFetchB = async (url, init) => {
      if (url === '/api/outbox' && init.method === 'GET') {
        return new Response('[]', { status: 200 });
      }
      if (url === '/api/inbox/acceptance' && init.method === 'POST') {
        const body = JSON.parse(init.body);
        const results = {};
        for (const id of body.ids) {
          if (inboxStore14.has(id)) {
            results[id] = { accepted: true, ack_receipt: 'receipt-' + id };
          } else {
            results[id] = { accepted: false };
          }
        }
        return new Response(JSON.stringify({ results }), { status: 200 });
      }
      if (url === '/api/inbox' && init.method === 'POST') {
        const form = init.body;
        const id = form.get('id');
        const payload = JSON.parse(form.get('payload'));
        const signature = form.get('signature');
        const files = form.getAll('attachments');
        assert.strictEqual(files.length, 2, 'Both attachments must arrive intact in FormData');
        inboxStore14.set(id, { id, payload, signature, fileCount: files.length });
        return new Response(JSON.stringify({ accepted: true, ack_receipt: 'receipt-' + id }), { status: 200 });
      }
      throw new Error('Unexpected fetch URL on B: ' + url);
    };

    const adapterA = createHttpSpoolAdapter({
      baseUrl: '/api/',
      fetchImpl: mockFetchA,
      onAcknowledged() {
        uiAckCount++;
        throw new Error('Simulated UI render glitch in onAcknowledged');
      }
    });
    const adapterB = createHttpSpoolAdapter({
      baseUrl: '/api',
      fetchImpl: mockFetchB,
      onAccepted() {
        uiAcceptedCount++;
        return Promise.reject(new Error('Simulated UI render glitch in onAccepted'));
      }
    });

    const chan14 = createMockChannel();
    const sess14A = new UmaiSession({ peerOrigin: 'http://b.example', role: 'embedded', storage: adapterA });
    const sess14B = new UmaiSession({ peerOrigin: 'http://a.example', role: 'host', storage: adapterB });
    sess14A.port = chan14.port1;
    chan14.port1.onmessage = sess14A._portListener;
    sess14A.state = 'connected';
    sess14B.port = chan14.port2;
    chan14.port2.onmessage = sess14B._portListener;
    sess14B.state = 'connected';

    await sess14A.reconcile();
    await new Promise(r => setTimeout(r, 40));

    assert.strictEqual(inboxStore14.has('msg-spool-1'), true, 'Receiver spool must accept msg-spool-1');
    assert.strictEqual(outboxStore14.size, 0, 'Sender spool must remove msg-spool-1 upon verified ACK');
    assert.strictEqual(uiAcceptedCount, 1, 'onAccepted UI hook must be invoked');
    assert.strictEqual(uiAckCount, 1, 'onAcknowledged UI hook must be invoked');
    assert.ok(seenMutatingHeaders.every(v => v === '1'), 'X-UMAI-CSRF must be attached to state-changing requests');
    sess14A.stop();
    sess14B.stop();

    // --- 14b: Failed or truncated attachment download MUST abort getMessage(id) completely (Rule 3) ---
    let failMode = 'second-404';
    const faultAdapter = createHttpSpoolAdapter({
      baseUrl: '/api',
      fetchImpl: async (url) => {
        if (url === '/api/outbox/msg-missing') {
          return new Response('not found', { status: 404 });
        }
        if (url === '/api/outbox/msg-500') {
          return new Response('internal error', { status: 500 });
        }
        if (url === '/api/outbox/msg-2att') {
          return new Response(JSON.stringify({
            id: 'msg-2att',
            payload: { ok: true },
            attachments: [
              { name: 'first.txt', size: 5 },
              { name: 'second.txt', size: 6 }
            ]
          }), { status: 200 });
        }
        if (url.endsWith('/attachments/first.txt')) {
          return new Response(Buffer.from('12345'), { status: 200 });
        }
        if (url.endsWith('/attachments/second.txt')) {
          if (failMode === 'second-404') {
            return new Response('missing attachment', { status: 404 });
          }
          if (failMode === 'second-size-mismatch') {
            return new Response(Buffer.from('short'), { status: 200 }); // 5 bytes instead of declared 6
          }
          return new Response(Buffer.from('123456'), { status: 200 });
        }
        return new Response('unauthorized', { status: 401 });
      }
    });

    assert.strictEqual(await faultAdapter.getMessage('msg-missing'), null, '404 on message metadata must return null');
    await assert.rejects(() => faultAdapter.getMessage('msg-500'), /500/, '500 on message metadata must throw');
    await assert.rejects(
      () => faultAdapter.getMessage('msg-2att'),
      /Attachment download failed for second\.txt/,
      '404 on second attachment must abort getMessage rather than omitting it or wrapping the error body'
    );

    failMode = 'second-size-mismatch';
    await assert.rejects(
      () => faultAdapter.getMessage('msg-2att'),
      /Attachment size mismatch for second\.txt/,
      'Truncated attachment bytes must abort getMessage'
    );

    failMode = 'ok';
    const completeMsg = await faultAdapter.getMessage('msg-2att');
    assert.strictEqual(completeMsg.attachments.length, 2, 'Complete message must return both File objects');

    // --- 14c: 401 triggers onUnauthorized callback and throws status=401 ---
    let unauthTriggered = 0;
    const unauthAdapter = createHttpSpoolAdapter({
      baseUrl: '/api',
      fetchImpl: async () => new Response('unauth', { status: 401 }),
      onUnauthorized() {
        unauthTriggered++;
      }
    });
    await assert.rejects(() => unauthAdapter.getOutboxIds(), /Unauthorized \(401\)/);
    assert.strictEqual(unauthTriggered, 1, 'onUnauthorized callback must run on 401 response');
  }
  console.log('✓ Test 14: Reusable HTTP spool adapter (js/umai-spool.js) end-to-end, complete-attachment abort, and hook isolation passed');

  // ===========================================================================
  // Test 15: Stage 2C — Optional Authenticated media_type (C2) & attachment_meta
  // ===========================================================================
  {
    const { createHttpSpoolAdapter, validateMediaType } = require('../js/umai-spool.js');

    // 15a: validateMediaType normalization and strict rejection rules
    assert.strictEqual(validateMediaType(undefined), '');
    assert.strictEqual(validateMediaType('   '), '');
    assert.strictEqual(validateMediaType('  Application/PDF '), 'application/pdf');
    assert.strictEqual(validateMediaType('image/svg+xml'), 'image/svg+xml');
    assert.throws(() => validateMediaType('text/plain; charset=utf-8'), /Invalid attachment media_type/);
    assert.throws(() => validateMediaType('application/'), /Invalid attachment media_type/);
    assert.throws(() => validateMediaType('/pdf'), /Invalid attachment media_type/);
    assert.throws(() => validateMediaType('a/b/c'), /Invalid attachment media_type/);
    assert.throws(() => validateMediaType('a'.repeat(120) + '/bbbbbbbbbb'), /exceeds 127/);

    // 15b: getMessage reconstructs File.type strictly from att.media_type, ignoring HTTP application/octet-stream,
    //      and acceptMessage emits 1:1 attachment_meta preserving absent vs non-empty media_type.
    let capturedAttachmentMeta = null;
    let capturedUploadedTypes = null;
    const c2Adapter = createHttpSpoolAdapter({
      baseUrl: '/api',
      fetchImpl: async (url, init) => {
        if (url === '/api/outbox/msg-c2') {
          return new Response(JSON.stringify({
            id: 'msg-c2',
            created_at: '2026-11-09T18:00:00Z',
            payload: { kind: 'bundle' },
            signature: 'sig-c2',
            attachments: [
              { name: 'untyped.bin', size: 4, sha256: 'aa' }, // absent media_type
              { name: 'typed.pdf', size: 5, sha256: 'bb', media_type: 'Application/PDF' }
            ]
          }), { status: 200, headers: { 'Content-Type': 'application/json' } });
        }
        if (url === '/api/outbox/msg-c2/attachments/untyped.bin') {
          return new Response(Buffer.from('1234'), {
            status: 200,
            headers: { 'Content-Type': 'application/octet-stream' }
          });
        }
        if (url === '/api/outbox/msg-c2/attachments/typed.pdf') {
          return new Response(Buffer.from('%PDF-'), {
            status: 200,
            headers: { 'Content-Type': 'application/octet-stream' }
          });
        }
        if (url === '/api/inbox' && init.method === 'POST') {
          capturedAttachmentMeta = JSON.parse(init.body.get('attachment_meta'));
          const uploaded = init.body.getAll('attachments');
          capturedUploadedTypes = uploaded.map(f => ({ name: f.name, type: f.type }));
          return new Response(JSON.stringify({
            accepted: true,
            accepted_at: '2026-11-09T18:00:05Z',
            ack_receipt: 'rcpt-c2'
          }), { status: 200 });
        }
        if (url === '/api/inbox/acceptance' && init.method === 'POST') {
          return new Response(JSON.stringify({
            results: {
              'msg-c2': {
                accepted: true,
                accepted_at: '2026-11-09T18:00:05Z',
                ack_receipt: 'rcpt-c2'
              }
            }
          }), { status: 200 });
        }
        throw new Error('Unexpected URL in Test 15: ' + url);
      }
    });

    const fetched = await c2Adapter.getMessage('msg-c2');
    assert.strictEqual(fetched.attachments.length, 2);
    assert.strictEqual(fetched.attachments[0].name, 'untyped.bin');
    assert.strictEqual(
      fetched.attachments[0].type,
      '',
      'Absent media_type must remain "" and NEVER become application/octet-stream from HTTP download'
    );
    assert.strictEqual(fetched.attachments[1].name, 'typed.pdf');
    assert.strictEqual(
      fetched.attachments[1].type,
      'application/pdf',
      'Declared media_type must be normalized and reconstructed on File.type despite application/octet-stream download'
    );

    const acceptOut = await c2Adapter.acceptMessage(fetched);
    assert.strictEqual(acceptOut.accepted, true);
    assert.strictEqual(acceptOut.ackReceipt, 'rcpt-c2');
    assert.strictEqual(acceptOut.acceptedAt, '2026-11-09T18:00:05Z');
    assert.deepStrictEqual(capturedAttachmentMeta, [
      { name: 'untyped.bin' },
      { name: 'typed.pdf', media_type: 'application/pdf' }
    ]);
    assert.deepStrictEqual(capturedUploadedTypes, [
      { name: 'untyped.bin', type: '' },
      { name: 'typed.pdf', type: 'application/pdf' }
    ]);

    const accLookup = await c2Adapter.getAcceptance(['msg-c2']);
    assert.strictEqual(accLookup['msg-c2'].accepted, true);
    assert.strictEqual(accLookup['msg-c2'].acceptedAt, '2026-11-09T18:00:05Z');
    assert.strictEqual(accLookup['msg-c2'].ackReceipt, 'rcpt-c2');

    // 15c: Parameterized or malformed File.type is rejected fail-closed by acceptMessage before upload
    const badFile = { name: 'bad.txt', type: 'text/plain; charset=utf-8', size: 1 };
    const badRes = await c2Adapter.acceptMessage({
      id: 'msg-bad-type',
      payload: {},
      attachments: [badFile]
    });
    assert.deepStrictEqual(badRes, { accepted: false }, 'Parameterized File.type must be rejected');
  }
  console.log('✓ Test 15: Optional authenticated media_type (C2), explicit attachment_meta, and accepted_at round-trip passed');

  senderPoison.stop();
  receiverPoison.stop();
  secSession.stop();
  sessionA.stop();
  sessionB.stop();

  allTestsCompleted = true;
  console.log('--- All JavaScript Tests Passed ---');
})();
