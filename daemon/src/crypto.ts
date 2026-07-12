// daemon/src/crypto.ts
// E2E encryption layer for the DispatchFreeBuff daemon.
// Used during a live WebSocket connection to encrypt outgoing messages
// (output_chunk, system) and decrypt incoming ones (prompt, sync_request).
//
// Wire format (see shared/protocol.ts):
//   plaintext:  {v:2, type:"key_exchange"|"key_ack"|"rekey_required"|"enc"|"ping"|...}
//   encrypted:  {v:2, type:"enc", seq, nonce:<b64 12B>, ct:<b64 ciphertext+16B tag>}
//
// Crypto primitives:
//   - ECDH P-256 (secp256r1) for key agreement
//   - HKDF-SHA-256 to derive a 32-byte AES key
//   - AES-256-GCM for authenticated encryption with 12-byte random nonce
//   - AAD = "v2|<senderRole>|<seq>" to bind ciphertext to wire metadata
//
// Nonce policy: 12 random bytes per message (96-bit nonce, collision-resistant
// up to ~2^32 messages per key — well beyond session length).
//
// Persistence: NONE. The daemon regenerates its keypair on every `start`.
// The phone re-exchanges on every reconnect. This keeps the threat model
// simple: a stolen token + daemon pubkey (from a logged session) is not enough
// to decrypt future sessions.
import crypto from 'node:crypto';
import { aadFor, type Role, type EncryptedInner, type EncryptedEnvelope } from '../../shared/protocol';

const HKDF_INFO = Buffer.from('dispatch-freebuff-e2e-v1', 'utf8');
const HKDF_SALT = Buffer.alloc(32, 0); // all-zero salt; info string disambiguates use
const CURVE = 'prime256v1';
/**
 * Public keys are exchanged as JWK objects (RFC 7517). Each JWK has
 * `{ kty: 'EC', crv: 'P-256', x: <base64url X>, y: <base64url Y> }`. This format
 * is natively supported by both Node's `crypto.createPublicKey({format:'jwk'})` and
 * Web Crypto's `crypto.subtle.importKey('jwk', ...)`, eliminating the need for any
 * SPKI/raw byte-level conversions that caused silent interop failures.
 */

export interface E2EState {
  /** Our private+public keypair. Public half is exported as JWK for the wire. */
  kp: crypto.KeyPairKeyObjectResult;
  /** Public key as a JWK object (RFC 7517): {kty:'EC', crv:'P-256', x, y}. */
  jwk: crypto.JsonWebKey;
  /** Public key, JSON-stringified JWK — what we put on the wire. */
  jwkJson: string;
  /** Derived 32-byte AES key, or null until key_exchange completes. */
  sharedKey: Buffer | null;
  /** Outbound seq (we increment for every encrypted message we send). */
  outSeq: number;
  /** Highest inbound seq we've accepted (replay window). */
  inSeq: number;
}

/**
 * Generate a fresh P-256 keypair. `jwk` and `jwkJson` are the public key in JWK
 * format (RFC 7517) — natively compatible with both Node and Web Crypto.
 */
export function generateKeypair(): { kp: crypto.KeyPairKeyObjectResult; jwk: crypto.JsonWebKey; jwkJson: string } {
  const kp = crypto.generateKeyPairSync('ec', { namedCurve: CURVE });
  const jwk = kp.publicKey.export({ format: 'jwk' });
  // Ensure crv is the Web-Crypto name (P-256) regardless of Node's local naming.
  if (jwk.crv !== 'P-256') jwk.crv = 'P-256';
  return { kp, jwk, jwkJson: JSON.stringify(jwk) };
}

/** Build a fresh E2E state (no shared key yet — must be set after key_exchange). */
export function newE2EState(): E2EState {
  const { kp, jwk, jwkJson } = generateKeypair();
  return { kp, jwk, jwkJson, sharedKey: null, outSeq: 0, inSeq: 0 };
}

/**
 * Derive the shared AES-256 key from our ECDH private key and the peer's
 * JWK public key. Throws on bad input.
 */
export function deriveSharedKey(myPrivate: crypto.KeyObject, peerJwk: crypto.JsonWebKey): Buffer {
  // Normalize the JWK to use the Web-Crypto curve name so Node is happy.
  if (peerJwk.crv !== 'P-256') peerJwk.crv = 'P-256';
  const peerPub = crypto.createPublicKey({ key: peerJwk, format: 'jwk' });
  // Node returns the shared secret as a Buffer (length = 32 for P-256).
  const sharedBits: Buffer = crypto.diffieHellman({ privateKey: myPrivate, publicKey: peerPub });
  // HKDF-SHA-256 → 32 bytes for AES-256.
  const key = crypto.hkdfSync('sha256', sharedBits, HKDF_SALT, HKDF_INFO, 32);
  // Zero out the raw shared secret — it's no longer needed and we don't want
  // it sitting on the heap.
  sharedBits.fill(0);
  return Buffer.from(key);
}

/** Encrypt an inner payload into an EncryptedEnvelope. Increments outSeq. */
export function encryptInner(state: E2EState, senderRole: Role, inner: EncryptedInner): EncryptedEnvelope {
  if (!state.sharedKey) throw new Error('E2E: cannot encrypt before key exchange');
  state.outSeq += 1;
  const nonce = crypto.randomBytes(12);
  const aad = aadFor(senderRole, state.outSeq);
  const plain = Buffer.from(JSON.stringify(inner), 'utf8');
  const cipher = crypto.createCipheriv('aes-256-gcm', state.sharedKey, nonce);
  cipher.setAAD(aad);
  const enc = Buffer.concat([cipher.update(plain), cipher.final()]);
  const tag = cipher.getAuthTag();
  return {
    v: 2,
    type: 'enc',
    seq: state.outSeq,
    nonce: nonce.toString('base64'),
    // ciphertext + 16-byte auth tag (node convention)
    ct: Buffer.concat([enc, tag]).toString('base64'),
  };
}

/** Decrypt an EncryptedEnvelope. Returns the inner payload.
 *  Returns null if the envelope is a replay (seq <= last seen) or fails
 *  auth. Throws on protocol-level errors. */
export function decryptEnvelope(state: E2EState, senderRole: Role, env: EncryptedEnvelope): EncryptedInner | null {
  if (env.v !== 2 || env.type !== 'enc') throw new Error('E2E: not an enc envelope');
  if (!state.sharedKey) throw new Error('E2E: cannot decrypt before key exchange');
  if (!Number.isInteger(env.seq) || env.seq <= 0) throw new Error('E2E: bad seq');
  if (env.seq <= state.inSeq) return null; // replay
  const nonce = Buffer.from(env.nonce, 'base64');
  const ctWithTag = Buffer.from(env.ct, 'base64');
  if (ctWithTag.length < 17) throw new Error('E2E: ct too short');
  const tag = ctWithTag.subarray(ctWithTag.length - 16);
  const data = ctWithTag.subarray(0, ctWithTag.length - 16);
  const aad = aadFor(senderRole, env.seq);
  const decipher = crypto.createDecipheriv('aes-256-gcm', state.sharedKey, nonce);
  decipher.setAAD(aad);
  decipher.setAuthTag(tag);
  const plain = Buffer.concat([decipher.update(data), decipher.final()]);
  state.inSeq = env.seq; // accept only AFTER successful decrypt
  return JSON.parse(plain.toString('utf8')) as EncryptedInner;
}

/** Wipe the shared key (e.g. on rekey). Keeps the keypair (we keep ours,
 *  the peer's was already public). */
export function clearSharedKey(state: E2EState): void {
  if (state.sharedKey) state.sharedKey.fill(0);
  state.sharedKey = null;
  state.inSeq = 0;
  state.outSeq = 0;
}

/** Wipe everything (e.g. on socket close). */
export function destroyE2E(state: E2EState): void {
  clearSharedKey(state);
  // Note: KeyObject doesn't expose a wipe API in Node; the private key bytes
  // are still in the JS heap. For a hardened build we'd mlock the process and
  // use a sidecar (e.g. ssh-agent). For v1, this is good enough.
}
