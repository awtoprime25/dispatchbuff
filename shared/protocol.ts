// shared/protocol.ts
// Wire format for DispatchFreeBuff over WebSocket + HTTP.
// Source of truth for daemon ↔ relay ↔ mobile. Mirror in each component if
// you split the repo.
//
// v2 (current): adds E2E encryption (ECDH P-256 + AES-GCM-256). The relay is a
// dumb pipe for `enc` envelopes — it cannot read content. Handshake messages
// (key_exchange, key_ack, rekey_required), relay-emitted system events, and
// pings remain plaintext so the relay can route and observe.
//
// v1 (legacy): kept exported for type-compat with older daemons; new code uses
// v2 only. The relay will accept v=1 clients but they get plaintext service.

/**
 * Protocol version string. Used in the AES-GCM AAD format
 * `${PROTOCOL_VERSION}|${senderRole}|${seq}` and in relay HTTP routes.
 * NOTE: this is a STRING ('v2') and must be the Web Crypto / PWA-style
 * prefix. The PWA hardcodes its AAD prefixes as `'v2|client|'` and
 * `'v2|daemon|'` (mobile/app.js) and rejects any AAD byte difference with
 * `Unsupported state or unable to authenticate data` on AES-GCM decrypt.
 * If you change this, update the AAD_PREFIX constants in mobile/app.js too.
 */
export const PROTOCOL_VERSION = 'v2';

export type SessionId = string;
export type Token = string;
export type MessageId = string;
export type Role = 'daemon' | 'client' | 'viewer';

// ------------------------- WebSocket messages ---------------------------

// ---- v2 E2E handshake (plaintext) ----
export interface KeyExchangeMessage {
  v: 2;
  type: 'key_exchange';
  from: 'client';
  /** base64 of raw SubjectPublicKeyInfo (65 bytes for P-256). */
  clientPub: string;
}
export interface KeyAckMessage {
  v: 2;
  type: 'key_ack';
  from: 'daemon';
  /** base64 of raw SubjectPublicKeyInfo (65 bytes for P-256). */
  daemonPub: string;
}
export interface RekeyRequiredMessage {
  v: 2;
  type: 'rekey_required';
  from: 'daemon';
}
export type E2EHandshake = KeyExchangeMessage | KeyAckMessage | RekeyRequiredMessage;

// ---- v2 Encrypted envelope (outer is plaintext, inner is AES-GCM ciphertext) ----
export interface EncryptedEnvelope {
  v: 2;
  type: 'enc';
  /** Monotonic per-sender sequence for replay protection. */
  seq: number;
  /** base64 of 12-byte AES-GCM nonce. */
  nonce: string;
  /** base64 of ciphertext + 16-byte auth tag, in that order. */
  ct: string;
}
/**
 * Raw navigation keys — for arrow-key/Enter-driven menus a full-screen TUI
 * shows (freebuff has no way to answer those from typed text). Sent as a
 * literal escape sequence straight into the pty; see daemon/src/index.ts.
 */
export type ControlKey = 'up' | 'down' | 'left' | 'right' | 'enter' | 'escape';

/** Inner payload of an `enc` envelope. JSON-stringified then encrypted. */
export type EncryptedInner =
  | { t: 'prompt'; id: MessageId; sessionId: SessionId; text: string; timestamp: number }
  | { t: 'key'; sessionId: SessionId; key: ControlKey; timestamp: number }
  | { t: 'output_chunk'; id: MessageId; sessionId: SessionId; content: string; seq: number; timestamp: number; mode?: OutputMode }
  | { t: 'system'; sessionId: SessionId; event: 'crashed' | 'restarted'; message?: string; timestamp: number }
  | { t: 'sync_request'; sessionId: SessionId; sinceSeq: number; timestamp: number };

/**
 * 'line'   — one scrolled line of normal-buffer output; client appends a bubble.
 * 'screen' — a full-screen (alternate-buffer) TUI snapshot; client replaces the
 *            current live-terminal view instead of appending. Emitted when the
 *            child CLI is a full-screen app (cursor-addressed redraws, e.g.
 *            Ink-based TUIs) — see daemon/src/index.ts screenTerm handling.
 */
export type OutputMode = 'line' | 'screen';

// ---- v1 legacy types (plaintext, no encryption) ----
export interface PromptMessage {
  v?: 1;
  type: 'prompt';
  id: MessageId;
  sessionId: SessionId;
  text: string;
  timestamp: number;
}
export interface OutputChunk {
  v?: 1;
  type: 'output_chunk';
  id: MessageId;
  sessionId: SessionId;
  /** Freebuff output, ANSI-stripped and line-batched. */
  content: string;
  /** Monotonic per-session sequence for dedupe + replay on iOS resume. */
  seq: number;
  timestamp: number;
  /** See OutputMode. Absent = 'line' (legacy/default). */
  mode?: OutputMode;
}
export interface SystemMessage {
  v?: 1 | 2;
  type: 'system';
  sessionId: SessionId;
  event:
    | 'ready'
    | 'daemon_connected'
    | 'daemon_disconnected'
    | 'client_connected'
    | 'client_disconnected'
    | 'client_prompt'   // relay → viewer only: "client sent a prompt" (not the prompt itself)
    | 'crashed'
    | 'restarted'
    | 'rate_limited'
    | 'revoked';
  message?: string;
  timestamp: number;
}
export interface SyncRequest {
  v?: 1 | 2;
  type: 'sync_request';
  sessionId: SessionId;
  sinceSeq: number;
  timestamp: number;
}
export interface PingMessage { v?: 1 | 2; type: 'ping'; ts: number }
export interface PongMessage { v?: 1 | 2; type: 'pong'; ts: number }

/**
 * Daemon → relay only. Plaintext and relay-visible by design (like ping) —
 * it carries no session content, just "send a push to this session's
 * subscribed devices". Emitted when freebuff goes idle after producing
 * output (see daemon/src/index.ts idle-timer in `start`).
 */
export interface NotifyMessage { v: 2; type: 'notify'; event: 'idle' }

// ---- v2 unions ----
export type V2ClientMessage = E2EHandshake | EncryptedEnvelope | SyncRequest | PingMessage;
export type V2ServerMessage = E2EHandshake | EncryptedEnvelope | OutputChunk | SystemMessage | PongMessage | NotifyMessage;

// ---- v1 unions (legacy) ----
export type V1ClientMessage = PromptMessage | SyncRequest | PingMessage;
export type V1ServerMessage = OutputChunk | SystemMessage | PongMessage;

// ---- back-compat aliases (existing code uses these names) ----
export type AnyClientMessage = V1ClientMessage | V2ClientMessage;
export type AnyServerMessage = V1ServerMessage | V2ServerMessage;
export type AnyMessage = AnyClientMessage | AnyServerMessage;

// ------------------------------- /pair API ------------------------------

export interface PairCodeRequest  { sessionId: SessionId }
export interface PairCodeResponse {
  code: string;
  expiresAt: number;
}

export interface PairRedeemRequest {
  sessionId: SessionId;
  code: string;
  role: 'daemon' | 'client';
  v?: 2;
  /** Optional v2 client public key (base64 raw SPKI). If present, the daemon
   *  will use it on first connect to skip a round-trip. */
  clientPub?: string;
}
export interface PairRedeemResponse {
  token: Token;
  expiresAt: number;
  relayUrl: string;
}

export interface RevokeRequest { sessionId: SessionId; token: Token }

// ------------------------------- /push API -------------------------------
// Web Push (RFC 8030/8291/8292) for the "freebuff went idle" notification.
// The relay holds the VAPID keypair; the daemon never sees it — it just
// sends a plaintext `notify` over the existing WS (see NotifyMessage above).

export interface WebPushKeys { p256dh: string; auth: string }
/** Shape of `PushSubscription.toJSON()` from the browser's Push API. */
export interface WebPushSubscriptionJSON {
  endpoint: string;
  expirationTime: number | null;
  keys: WebPushKeys;
}
export interface PushSubscribeRequest {
  sessionId: SessionId;
  token: Token;
  subscription: WebPushSubscriptionJSON;
}
export interface VapidPublicKeyResponse { publicKey: string }

// ---------------------------- Rate limiting -----------------------------

export const RATE_LIMITS = {
  promptsPerMinutePerToken: 60,
  syncRequestsPerMinutePerToken: 30,
} as const;

// ------------------------- AAD (AEAD binding) ---------------------------
// AES-GCM AAD format: `${PROTOCOL_VERSION}|${senderRole}|${seq}`
// Binds the ciphertext to the wire-level metadata so the relay cannot mix
// envelopes between sessions or reorder them. Both sides must use this exact
// format or decryption will fail.
export function aadFor(senderRole: Role, seq: number): Buffer | Uint8Array {
  return new TextEncoder().encode(`${PROTOCOL_VERSION}|${senderRole}|${seq}`);
}
