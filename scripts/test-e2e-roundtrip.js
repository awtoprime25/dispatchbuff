// scripts/test-e2e-roundtrip.js
// Reproduce the EXACT daemon<->phone E2E round-trip in one process using
// BOTH Node crypto (daemon) AND WebCrypto (phone). If the test fails, log
// exactly where the bytes diverge.
//
// We simulate the wire via JWK exchange (no relay / no WS) and then do:
//   1. phone -> key_exchange (clientKey JWK)
//   2. daemon derives shared key, sends key_ack (daemonKey JWK)
//   3. phone derives shared key, runs E2E_PROBE comparison
//   4. client encrypts prompt {t:'prompt',...} with AAD="v2|client|1"
//   5. daemon decrypts with aadFor('client',1) -> prompt inner
//   6. daemon encrypts output_chunk with aadFor('daemon',1) -> wire envelope
//   7. phone decrypts with AAD="v2|daemon|1" -> output_chunk inner
'use strict';

const crypto = require('node:crypto');
const { webcrypto } = require('node:crypto');
const subtle = webcrypto.subtle;
const { TextEncoder, TextDecoder } = require('node:util');

// Load the EXACT production functions via a standalone esbuild bundle from
// src/crypto.ts (daemon's daemon/dist/index.js is a single bundled IIFE so it
// isn't require()-able). Build first: `cd daemon && ./node_modules/.bin/esbuild
// src/crypto.ts --bundle --platform=node --format=cjs --outfile=../scripts/.tmp-crypto.cjs`
const path = require('node:path');
let e2eMod;
try {
  e2eMod = require(path.join(__dirname, '.tmp-crypto.cjs'));
} catch (e) {
  console.error('[ERR] cannot require scripts/.tmp-crypto.cjs — build it first (see comment above). Underlying:', e.message);
  process.exit(1);
}

const { generateKeypair, deriveSharedKey, encryptInner, decryptEnvelope, newE2EState } = e2eMod;

function hex(b) {
  const u = b instanceof Uint8Array ? b : Buffer.from(b);
  return Buffer.from(u).toString('hex');
}
function showBytes(label, b) {
  const u = b instanceof Uint8Array ? b : Buffer.from(b);
  const len = u.length;
  const hexStr = hex(u);
  console.log(`  ${label}: len=${len} hex=${hexStr.slice(0, 32)}${hexStr.length > 32 ? '...' : ''}`);
  if (len <= 32) {
    console.log(`  ${label} ascii:`, JSON.stringify(Buffer.from(u).toString('utf8')));
  }
}

async function main() {
  console.log('=== A. generate daemon key (Node crypto) ===');
  const daemonState = newE2EState();
  showBytes('daemon jwk.x', daemonState.jwk.x);
  console.log('  daemon jwk.crv:', daemonState.jwk.crv, 'kty:', daemonState.jwk.kty);

  console.log('=== B. generate phone key (WebCrypto) ===');
  const wcKp = await subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveKey', 'deriveBits']);
  const phoneJwk = await subtle.exportKey('jwk', wcKp.publicKey);
  console.log('  phone jwk.crv:', phoneJwk.crv, 'kty:', phoneJwk.kty);
  showBytes('phone jwk.x', Buffer.from(phoneJwk.x, 'base64url'));

  // Ensure both sides use the same crv string
  const phoneJwkForNode = { ...phoneJwk };
  if (phoneJwkForNode.crv !== 'P-256') phoneJwkForNode.crv = 'P-256';

  console.log('=== C. daemon derives shared key (Node crypto) ===');
  const daemonShared = deriveSharedKey(daemonState.kp.privateKey, phoneJwkForNode);
  showBytes('daemon sharedKey (AES)', daemonShared);

  console.log('=== D. phone derives shared key (WebCrypto) ===');
  // Import daemon JWK into WebCrypto (mirror of mobile handleKeyAck)
  const daemonPubForWc = { ...daemonState.jwk };
  if (daemonPubForWc.crv !== 'P-256') daemonPubForWc.crv = 'P-256';
  const wcDaemonPub = await subtle.importKey('jwk', daemonPubForWc, { name: 'ECDH', namedCurve: 'P-256' }, false, []);
  const wcSharedBits = await subtle.deriveBits({ name: 'ECDH', public: wcDaemonPub }, wcKp.privateKey, 256);
  // Phone-side HKDF: same IKM (sharedBits), same zero salt, same info string.
  const HKDF_INFO_WC = new TextEncoder().encode('dispatch-freebuff-e2e-v1');
  const HKDF_SALT_WC = new Uint8Array(32); // zero salt; info disambiguates use
  const phoneHkdfKey = await subtle.importKey('raw', wcSharedBits, { name: 'HKDF', hash: 'SHA-256' }, false, ['deriveKey']);
  const phoneAesKey = await subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt: HKDF_SALT_WC, info: HKDF_INFO_WC },
    phoneHkdfKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
  // We can't easily export the AES key, but we can run the E2E_PROBE
  console.log('=== E. E2E_PROBE comparison ===');
  // Daemon side: encrypt E2E_PROBE with sharedBits + salt=0 + info, AAD="v2|client|999"
  // (the probeCiphertext log)
  // Phone side: same thing
  // Use a fixed 12-byte zero nonce so both sides produce byte-identical ciphertext
  const probeZeroNonce = Buffer.alloc(12, 0);
  const probePlain = Buffer.from('E2E_PROBE', 'utf8');
  const probeAad = Buffer.from('v2|client|999', 'utf8');

  // Daemon encrypt (using EXACT production function path)
  const probeCipher = crypto.createCipheriv('aes-256-gcm', daemonShared, probeZeroNonce);
  probeCipher.setAAD(probeAad);
  const probeEnc = Buffer.concat([probeCipher.update(probePlain), probeCipher.final()]);
  const probeTag = probeCipher.getAuthTag();
  const daemonProbeCt = Buffer.concat([probeEnc, probeTag]);
  console.log('  daemon probeCiphertext len:', daemonProbeCt.length, 'hex:', hex(daemonProbeCt));

  // Phone encrypt with same nonce + AAD + plaintext, using WebCrypto
  const wcProbeCipher = await subtle.encrypt(
    { name: 'AES-GCM', iv: probeZeroNonce, additionalData: probeAad },
    phoneAesKey,
    probePlain
  );
  const phoneProbeCt = Buffer.from(wcProbeCipher);
  console.log('  phone  probeCiphertext len:', phoneProbeCt.length, 'hex:', hex(phoneProbeCt));

  const probeMatch = Buffer.compare(daemonProbeCt, phoneProbeCt) === 0;
  console.log('  PROBE MATCH:', probeMatch ? 'YES (keys match)' : 'NO (KEYS DIFFER OR AAD DIFFER)');

  console.log('=== F. mobile encrypts a prompt, daemon decrypts ===');
  // Manually call WebCrypto to encrypt a simulated prompt (mirroring mobile/app.js)
  const promptInner = { t: 'prompt', id: 'abc', sessionId: 'sess', text: 'hello', timestamp: Date.now() };
  const outSeq = 1;
  const nonce1 = Buffer.from(crypto.randomBytes(12));
  const aad1 = Buffer.from('v2|client|' + outSeq, 'utf8');
  showBytes('aad_client_1', aad1);
  const promptPlain = Buffer.from(JSON.stringify(promptInner), 'utf8');
  const enc1 = await subtle.encrypt({ name: 'AES-GCM', iv: nonce1, additionalData: aad1 }, phoneAesKey, promptPlain);
  const env1 = {
    v: 2,
    type: 'enc',
    seq: outSeq,
    nonce: nonce1.toString('base64'),
    ct: Buffer.from(enc1).toString('base64'),
  };
  console.log('  env1.seq:', env1.seq, 'env1.nonce len:', Buffer.from(env1.nonce, 'base64').length, 'env1.ct len:', Buffer.from(env1.ct, 'base64').length);

  // Hand env1 to the daemon's EXACT decryptEnvelope function
  let daemonDecrypted;
  try {
    daemonState.sharedKey = daemonShared;
    daemonState.inSeq = 0;
    daemonDecrypted = decryptEnvelope(daemonState, 'client', env1);
    console.log('  DAEMON DECRYPT OK:', JSON.stringify(daemonDecrypted));
  } catch (e) {
    console.log('  DAEMON DECRYPT FAILED:', e.message);
    return;
  }

  console.log('=== G. daemon encrypts output, mobile decrypts ===');
  const outputInner = { t: 'output_chunk', id: 'xyz', sessionId: 'sess', content: 'E2E_TEST_OK_42', seq: 1, timestamp: Date.now() };
  const env2 = encryptInner(daemonState, 'daemon', outputInner);
  console.log('  env2.seq:', env2.seq, 'env2.nonce len:', Buffer.from(env2.nonce, 'base64').length, 'env2.ct len:', Buffer.from(env2.ct, 'base64').length);

  // Phone decrypts env2
  const nonce2 = Buffer.from(env2.nonce, 'base64');
  const ct2 = Buffer.from(env2.ct, 'base64');
  const aad2 = Buffer.from('v2|daemon|' + env2.seq, 'utf8');
  showBytes('aad_daemon_1', aad2);
  try {
    const plain2 = await subtle.decrypt({ name: 'AES-GCM', iv: nonce2, additionalData: aad2 }, phoneAesKey, ct2);
    const decoded = JSON.parse(new TextDecoder().decode(plain2));
    console.log('  PHONE DECRYPT OK:', JSON.stringify(decoded));
    console.log('\n=== FINAL: PASS === (keys derived correctly, AAD matches, encryption round-trip works)');
  } catch (e) {
    console.log('  PHONE DECRYPT FAILED:', e.message);
    console.log('\n=== FINAL: FAIL === (daemon-encrypted env cannot be decrypted by phone)');
    console.log('  Likely causes: (a) HKDF salt mismatch (zero vs uninit), (b) ECDH shared secret leads-to-zero padding diff, (c) AAD byte mismatch');
  }
}

main().catch(e => { console.error('FATAL:', e); process.exit(1); });
