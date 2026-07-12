// relay/src/pair.ts
// Pair-code mint (POST /pair/code) → 6-char code, 5-minute TTL, single use.
// Pair-code redeem (POST /pair/redeem) → exchanges a code for a long-lived
// 30-day token with a role ('daemon' or 'client') bound to the session.
//
// Tokens are stored as DO storage entries with built-in expiration so they
// auto-purge. DO storage operations are serialized per DO, so the
// GET-THEN-DELETE redeem is atomic in practice.

export interface PairCodeRecord {
  code: string;
  sessionId: string;
  createdAt: number;
  expiresAt: number;
}

export interface TokenRecord {
  token: string;
  sessionId: string;
  role: 'daemon' | 'client';
  createdAt: number;
  expiresAt: number;
}

const CODE_TTL_MS = 5 * 60 * 1000;
const TOKEN_TTL_MS = 30 * 24 * 60 * 60 * 1000;
const CODE_CHARSET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';

export async function createPairCode(storage: DurableObjectStorage, sessionId: string): Promise<PairCodeRecord> {
  const code = randomCode(6);
  const rec: PairCodeRecord = {
    code, sessionId, createdAt: Date.now(), expiresAt: Date.now() + CODE_TTL_MS,
  };
  await storage.put(`code:${code}`, rec, { expiration: new Date(rec.expiresAt) });
  return rec;
}

export async function redeemPairCode(
  storage: DurableObjectStorage,
  code: string,
  role: 'daemon' | 'client',
  sessionId: string,
  relayUrl: string,
): Promise<{ token: string; expiresAt: number; relayUrl: string } | null> {
  const rec = (await storage.get(`code:${code}`)) as PairCodeRecord | null;
  if (!rec) return null;
  if (rec.expiresAt < Date.now()) {
    await storage.delete(`code:${code}`);
    return null;
  }
  if (rec.sessionId !== sessionId) return null;

  // Single-use: delete before minting
  await storage.delete(`code:${code}`);

  const token = randomToken();
  const tr: TokenRecord = {
    token, sessionId, role, createdAt: Date.now(), expiresAt: Date.now() + TOKEN_TTL_MS,
  };
  await storage.put(`token:${token}`, tr, { expiration: new Date(tr.expiresAt) });
  return { token, expiresAt: tr.expiresAt, relayUrl };
}

function randomCode(n: number): string {
  const bytes = new Uint8Array(n);
  crypto.getRandomValues(bytes);
  let s = '';
  for (const b of bytes) s += CODE_CHARSET[b % CODE_CHARSET.length];
  return s;
}
function randomToken(): string {
  const b = new Uint8Array(32);
  crypto.getRandomValues(b);
  return Array.from(b).map(x => x.toString(16).padStart(2, '0')).join('');
}
