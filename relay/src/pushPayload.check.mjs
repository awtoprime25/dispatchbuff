// Self-check: exercise buildPushPayload() the same way relay-do.ts's
// sendPush() does — a synthetic "client" ECDH keypair stands in for a real
// browser subscription's p256dh/auth, confirming the VAPID+encryption
// pipeline (RFC 8291/8292) actually produces a well-formed request without
// needing a live push service to hit.
import { buildPushPayload } from '@block65/webcrypto-web-push';
import assert from 'node:assert';

const { subtle } = globalThis.crypto;
function b64url(buf) { return Buffer.from(buf).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); }

// Throwaway VAPID keypair, generated fresh per run — never the real deploy
// secret. See README's "Push notifications" section for generating that one.
const vapidKp = await subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
const vapid = {
  subject: 'mailto:test@example.com',
  publicKey: b64url(await subtle.exportKey('raw', vapidKp.publicKey)),
  privateKey: (await subtle.exportKey('jwk', vapidKp.privateKey)).d,
};

// Synthetic client keypair — stands in for a browser's PushSubscription.keys.
const clientKp = await subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
const p256dh = b64url(await subtle.exportKey('raw', clientKp.publicKey));
const auth = b64url(crypto.getRandomValues(new Uint8Array(16)));

const subscription = {
  endpoint: 'https://web.push.apple.com/fake-endpoint-for-payload-shape-check',
  expirationTime: null,
  keys: { p256dh, auth },
};

const message = { data: JSON.stringify({ title: 'DispatchFreeBuff', body: 'freebuff finished' }), options: { ttl: 300 } };

const payload = await buildPushPayload(message, subscription, vapid);

assert.ok(payload.body instanceof Uint8Array && payload.body.length > 0, 'body must be non-empty bytes');
assert.ok(payload.headers.authorization.startsWith('WebPush '), 'authorization header must be a WebPush JWT');
assert.ok(payload.headers['crypto-key'].includes(vapid.publicKey), 'crypto-key must carry the VAPID public key');
assert.ok(['aes128gcm', 'aesgcm'].includes(payload.headers['content-encoding']), 'must use a Web Push content encoding');
assert.strictEqual(payload.method.toUpperCase(), 'POST');

console.log('PASS — buildPushPayload() produced a well-formed encrypted request');
console.log('  body bytes:', payload.body.length, '| ttl:', payload.headers.ttl, '| encoding:', payload.headers['content-encoding']);
