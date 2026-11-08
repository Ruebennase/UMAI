/**
 * UMAI JavaScript Library Unit and Protocol Verification Tests
 * Runs under Node.js without any dependencies.
 */

const assert = require('assert');
const { UmaiSession, PROTOCOL_NAME, PROTOCOL_VERSION, isValidUmaiMessage } = require('../js/umai.js');

console.log('--- Running UMAI JavaScript Tests ---');

// Test 1: Message Validation
{
  assert.strictEqual(isValidUmaiMessage(null), null);
  assert.strictEqual(isValidUmaiMessage({}), false);
  assert.strictEqual(isValidUmaiMessage({ protocol: 'OTHER', version: 1, type: 'OFFER' }), false);
  assert.strictEqual(isValidUmaiMessage({ protocol: PROTOCOL_NAME, version: 2, type: 'OFFER' }), false);
  assert.strictEqual(isValidUmaiMessage({ protocol: PROTOCOL_NAME, version: 1, type: 'OFFER' }), true);
  console.log('✓ Test 1: isValidUmaiMessage envelope validation passed');
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
      isAccepted: async () => false,
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
      isAccepted: async (id) => acceptedB.has(id),
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
      isAccepted: async () => false,
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
      isAccepted: async () => false,
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
      isAccepted: async () => false,
      acceptMessage: async () => {
        poisonAttempts++;
        return false; // Reject acceptance
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

  const senderSlow = new UmaiSession({
    peerOrigin: 'http://peer.example',
    role: 'host',
    storage: {
      getOutboxIds: async () => ['msg-slow-1'],
      getMessage: async (id) => ({ id, payload: false, attachments: [] }),
      isAccepted: async () => false,
      acceptMessage: async () => true,
      onAcknowledged: async () => {}
    }
  });

  const receiverSlow = new UmaiSession({
    peerOrigin: 'http://host.example',
    role: 'embedded',
    storage: {
      getOutboxIds: async () => [],
      getMessage: async () => null,
      isAccepted: async () => slowMsgAccepted,
      acceptMessage: async (msg) => {
        acceptCallsForSlowMsg++;
        assert.strictEqual(msg.payload, false, 'Falsy scalar payload (false) must be preserved');
        await new Promise((resolve) => {
          releaseAcceptPromise = resolve;
        });
        slowMsgAccepted = true;
        return 'receipt-slow-1';
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

  // Verify expired GET reservation recovery (F3): if an ID is in _inFlightGets with an expired timestamp, next OFFER re-requests it
  receiverSlow._inFlightGets.set('msg-expired-get', Date.now() - 20000);
  assert.strictEqual(receiverSlow._isGetInFlight('msg-expired-get'), false, 'Expired GET reservation must be pruned and allow retry (F3)');

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
      isAccepted: async () => false,
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
      isAccepted: async () => false,
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

  senderPoison.stop();
  receiverPoison.stop();
  secSession.stop();
  sessionA.stop();
  sessionB.stop();

  console.log('--- All JavaScript Tests Passed ---');
})();
