// scripts/verify-ecdh-leading-zero.js
// Compare shared-secret length between Node crypto.diffieHellman and WebCrypto
// deriveBits for many random ECDH P-256 keypairs. If Node strips leading
// zeros (a long-standing Node crypto quirk), HKDF IKM lengths will diverge
// and the AES key will NOT match what the browser derives.
//
// We simulate: Node Alice (sender) + Node Bob (recipient). Both compute the
// shared secret via their respective APIs and run HKDF to get the AES key.
// If the AES keys match -> no bug. If they only match AFTER right-padding the
// Node shared secret to 32 bytes -> bug confirmed + fix validated.
'use strict';

const crypto = require('node:crypto');
const { webcrypto } = require('node:crypto');
const subtle = webcrypto.subtle;

const HKDF_INFO = Buffer.from('dispatch-freebuff-e2e-v1', 'utf8');
const HKDF_SALT = Buffer.alloc(32, 0);
const TOTAL = 200;

function rightPad(src, len = 32) {
  if (src.length === len) return src;
  const dst = Buffer.alloc(len, 0);
  src.copy(dst, len - src.length);
  return dst;
}

(async () => {
  const nodeLens = new Map();
  const wcLens = new Map();
  const nodeAesMismatches = [];
  let paddedFixes = 0;
  let i = 0;

  while (i < TOTAL) {
    i++;
    const alice = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    const bob = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });

    // Node side
    const nodeShared = crypto.diffieHellman({ privateKey: alice.privateKey, publicKey: bob.publicKey });
    const nodeAes = Buffer.from(crypto.hkdfSync('sha256', nodeShared, HKDF_SALT, HKDF_INFO, 32));
    nodeLens.set(nodeShared.length, (nodeLens.get(nodeShared.length) || 0) + 1);

    // WebCrypto side: import both as JWK, derive bits
    const wcAliceJwk = { ...alice.privateKey.export({ format: 'jwk' }), crv: 'P-256' };
    const wcBobJwk = { ...bob.publicKey.export({ format: 'jwk' }), crv: 'P-256' };
    const wcAliceKey = await subtle.importKey('jwk', wcAliceJwk, { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
    const wcBobPub = await subtle.importKey('jwk', wcBobJwk, { name: 'ECDH', namedCurve: 'P-256' }, false, []);
    const wcShared = new Uint8Array(await subtle.deriveBits({ name: 'ECDH', public: wcBobPub }, wcAliceKey, 256));
    wcLens.set(wcShared.length, (wcLens.get(wcShared.length) || 0) + 1);
    const wcHmacKey = await subtle.importKey('raw', wcShared, { name: 'HKDF' }, false, ['deriveBits']);
    const wcAes = Buffer.from(await subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt: HKDF_SALT, info: HKDF_INFO }, wcHmacKey, 256));

    if (Buffer.compare(nodeAes, wcAes) !== 0) {
      const paddedNodeAes = Buffer.from(crypto.hkdfSync('sha256', rightPad(nodeShared), HKDF_SALT, HKDF_INFO, 32));
      const paddingFixes = Buffer.compare(paddedNodeAes, wcAes) === 0;
      if (paddingFixes) paddedFixes++;
      nodeAesMismatches.push({
        trial: i,
        nodeLen: nodeShared.length,
        wcLen: wcShared.length,
        xCoordHiHex: nodeShared.length < 32 ? nodeShared.toString('hex').slice(0, 4) + '...' : '>0x7f',
        nodeAesPrefix: nodeAes.toString('hex').slice(0, 16),
        wcAesPrefix: wcAes.toString('hex').slice(0, 16),
        paddingFixes,
      });
    }
  }

  console.log('=== Result summary (', TOTAL, 'random P-256 keypairs) ===');
  console.log('Node  sharedBits length distribution:', Object.fromEntries(nodeLens));
  console.log('WebCrypto sharedBits length distribution:', Object.fromEntries(wcLens));
  console.log('AES key mismatches (node != wc, no padding):', nodeAesMismatches.length, '/', TOTAL);
  console.log('Of those, FIXED by right-padding node sharedBits to 32 bytes:', paddedFixes, '/', nodeAesMismatches.length);
  if (nodeAesMismatches.length > 0) {
    console.log('First 3 mismatches (with x-coord hi byte and AES prefixes):');
    console.log(JSON.stringify(nodeAesMismatches.slice(0, 3), null, 2));
  } else {
    console.log('No mismatches: Node + WebCrypto agree on shared secrets for all', TOTAL, 'trials. Hypothesis RULED OUT.');
  }
  console.log('\nVerdict:', nodeAesMismatches.length === 0 ? 'NO BUG HERE' : (paddedFixes === nodeAesMismatches.length ? 'BUG CONFIRMED + PADDING FIX VALIDATED' : 'BUG PARTIAL: padding does not fully fix'));
})().catch(e => { console.error('FATAL:', e); process.exit(1); });
