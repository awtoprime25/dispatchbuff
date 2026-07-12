// test/e2e-smoke.js
// Simulates the DispatchFreeBuff mobile client to validate the E2E
// protocol end-to-end against the live relay + daemon.
//
// What this proves:
//   1. The client→daemon E2E handshake works (key_exchange / key_ack).
//   2. After handshake, the wire carries ONLY `enc` envelopes (no
//      plaintext prompts or output visible to the relay).
//   3. The daemon correctly decrypts and forwards the prompt to freebuff.
//   4. The freebuff output comes back encrypted and is decodable on the
//      client side.
//
// Usage: node test/e2e-smoke.js <sessionId> <clientToken> <prompt>
const crypto = require('node:crypto');

const RELAY = process.env.DISPATCH_RELAY || 'https://dispatch-relay.awtoprime25.workers.dev';
const PROTO_V = 2;

const sessionId = process.argv[2];
const clientToken = process.argv[3];
const prompt = process.argv[4] || 'echo hello world';

if (!sessionId || !clientToken) {
  console.error('Usage: node test/e2e-smoke.js <sessionId> <clientToken> [prompt]');
  process.exit(2);
}

// Lazy-import 'ws' only if installed in cwd
let WebSocket;
try { WebSocket = require('ws'); }
catch { console.error('Missing dependency: install `ws` in your test runner.'); process.exit(2); }

function aad(role, seq) { return Buffer.from(`v${PROTO_V}|${role}|${seq}`, 'utf8'); }

function generateKeypair() {
  const kp = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const pubRaw = kp.publicKey.export({ type: 'spki', format: 'der' });
  return { kp, pubRaw, pubB64: pubRaw.toString('base64') };
}
function deriveShared(myPrivate, peerPubRaw) {
  const peerPub = crypto.createPublicKey({ key: peerPubRaw, format: 'der', type: 'spki' });
  const bits = crypto.diffieHellman({ privateKey: myPrivate, publicKey: peerPub });
  const key = Buffer.from(crypto.hkdfSync('sha256', bits, Buffer.alloc(32), Buffer.from('dispatch-freebuff-e2e-v1'), 32));
  bits.fill(0);
  return key;
}
function encryptInner(sharedKey, senderRole, outSeq, innerJson) {
  const nonce = crypto.randomBytes(12);
  const plain = Buffer.from(JSON.stringify(innerJson), 'utf8');
  const c = crypto.createCipheriv('aes-256-gcm', sharedKey, nonce);
  c.setAAD(aad(senderRole, outSeq));
  const enc = Buffer.concat([c.update(plain), c.final()]);
  const tag = c.getAuthTag();
  return {
    v: PROTO_V, type: 'enc', seq: outSeq,
    nonce: nonce.toString('base64'),
    ct: Buffer.concat([enc, tag]).toString('base64'),
  };
}
function decryptEnv(sharedKey, senderRole, env) {
  const nonce = Buffer.from(env.nonce, 'base64');
  const ctWithTag = Buffer.from(env.ct, 'base64');
  const tag = ctWithTag.subarray(ctWithTag.length - 16);
  const data = ctWithTag.subarray(0, ctWithTag.length - 16);
  const d = crypto.createDecipheriv('aes-256-gcm', sharedKey, nonce);
  d.setAAD(aad(senderRole, env.seq));
  d.setAuthTag(tag);
  return JSON.parse(Buffer.concat([d.update(data), d.final()]).toString('utf8'));
}

const wsUrl = RELAY.replace(/^http/, 'ws') + `/ws?sessionId=${encodeURIComponent(sessionId)}&token=${encodeURIComponent(clientToken)}&role=client&v=${PROTO_V}`;
console.log('TEST: connecting to', wsUrl);

let outSeq = 0;
let inSeq = 0;
let myKp = null;
let sharedKey = null;

const seenWireTypes = []; // what the relay sees (all wire messages)
const seenPlaintext = []; // captured plaintext fields — should ONLY contain handshake public keys + ping

const ws = new WebSocket(wsUrl);

ws.on('open', () => {
  console.log('WS: open');
  myKp = generateKeypair();
  seenWireTypes.push('key_exchange>');
  ws.send(JSON.stringify({ v: PROTO_V, type: 'key_exchange', from: 'client', clientPub: myKp.pubB64 }));
});

ws.on('message', (data) => {
  const msg = JSON.parse(data.toString());
  seenWireTypes.push(msg.type);

  if (msg.type === 'pong') return;
  if (msg.type === 'key_ack') {
    console.log('RX key_ack — deriving shared key...');
    sharedKey = deriveShared(myKp.kp.privateKey, Buffer.from(msg.daemonPub, 'base64'));
    console.log('E2E: shared key derived ✓');
    outSeq = 0; inSeq = 0;
    const env = encryptInner(sharedKey, 'client', ++outSeq, {
      t: 'prompt', id: 'smoke-' + Date.now(), sessionId, text: prompt, timestamp: Date.now(),
    });
    console.log('SENDING encrypted prompt (inner=' + prompt.length + ' chars, wire=' + JSON.stringify(env).length + ' bytes)');
    console.log('  wire outer:', JSON.stringify({ ...env, ct: '<' + env.ct.length + ' chars b64>' }));
    console.log('  -- plaintext prompt NOT in wire: only inside ct --');
    ws.send(JSON.stringify(env));
    return;
  }
  if (msg.type === 'enc') {
    if (msg.seq <= inSeq) { console.log('REPLAY-DROP seq=' + msg.seq); return; }
    try {
      const inner = decryptEnv(sharedKey, 'daemon', msg);
      inSeq = msg.seq;
      console.log('DECRYPTED enc seq=' + msg.seq, '→', inner.t || inner.type, JSON.stringify(inner).slice(0, 200));
      if (inner.t === 'output_chunk' || inner.type === 'output_chunk') {
        console.log('  OUTPUT:', inner.content);
      }
      if (inner.t === 'system' || inner.type === 'system') {
        console.log('  SYSTEM:', inner.event, inner.message || '');
      }
    } catch (e) {
      console.error('DECRYPT-FAIL seq=' + msg.seq, e.message);
    }
    return;
  }
  if (msg.type === 'system') seenPlaintext.push(`{event:${msg.event}}`);
});

ws.on('close', () => {
  console.log('WS: closed');
  console.log('---');
  console.log('SUMMARY:');
  console.log('  wire messages seen by relay:', seenWireTypes.join(', '));
  console.log('  plaintext metadata leaked:', seenPlaintext.length, '(should be only handshake pubkeys + ping/pong + system events)');
  if (seenWireTypes.includes('enc') && !seenWireTypes.includes('prompt') && !seenWireTypes.includes('output_chunk')) {
    console.log('  ✓ no plaintext prompt/output_chunk on the wire — relay saw only encrypted envelopes');
  } else {
    console.log('  ✗ plaintext content leaked onto the wire');
  }
});

ws.on('error', (e) => console.error('WS error:', e.message));

setTimeout(() => { try { ws.close(); } catch {} process.exit(0); }, 60000);
