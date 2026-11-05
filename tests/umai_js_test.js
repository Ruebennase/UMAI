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

  secSession.stop();
  sessionA.stop();
  sessionB.stop();

  console.log('--- All JavaScript Tests Passed ---');
})();
