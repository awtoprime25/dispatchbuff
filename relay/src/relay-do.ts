// relay/src/relay-do.ts
// One Durable Object per Dispatch session. Holds WebSocket connections from
// the PC daemon + the phone clients. Routes messages by tag.
//
// - Tags: 'daemon' | 'client' | 'viewer' (used for Hibernatable WebSockets)
// - state.acceptWebSocket + getWebSockets('tag') is the Hibernatable API.
// - Pairing + token expiry use the storage API with built-in TTL.
//
// Message flow:
//   daemon --prompt--> relay --> client (write)
//   client --prompt--> relay --> daemon (forward) + viewer (system event)
//   daemon --output_chunk--> relay --> client + viewer (forward)
import { createPairCode, redeemPairCode } from './pair.js';
import { buildPushPayload, type VapidKeys, type PushSubscription as WebPushSubscription } from '@block65/webcrypto-web-push';
import type { Env } from './index.js';

const TAGS = ['daemon', 'client', 'viewer'] as const;
type Tag = typeof TAGS[number];

export class RelayDO {
  constructor(private state: DurableObjectState, private env: Env) {}

  async fetch(req: Request): Promise<Response> {
    const url = new URL(req.url);

    if (url.pathname === '/pair/code' && req.method === 'POST') {
      const body = await safeJson(req);
      if (!body?.sessionId) return json({ error: 'sessionId required' }, 400);
      const rec = await createPairCode(this.state.storage, body.sessionId);
      return json(rec, 200);
    }

    if (url.pathname === '/pair/redeem' && req.method === 'POST') {
      const body = await safeJson(req);
      if (!body?.code || !body?.role || !body?.sessionId) {
        return json({ error: 'code, role, sessionId required' }, 400);
      }
      if (body.role !== 'daemon' && body.role !== 'client') {
        return json({ error: 'role must be daemon|client' }, 400);
      }
      const relayUrl = url.origin; // the Worker URL the phone is talking to
      const result = await redeemPairCode(this.state.storage, body.code, body.role, body.sessionId, relayUrl);
      if (!result) return json({ error: 'invalid or expired code' }, 400);
      return json(result, 200);
    }

    if (url.pathname === '/push/subscribe' && req.method === 'POST') {
      const body = await safeJson(req);
      if (!body?.token || !body?.subscription?.endpoint) return json({ error: 'token, subscription required' }, 400);
      const rec = (await this.state.storage.get(`token:${body.token}`)) as { sessionId: string; role: Tag; expiresAt: number } | null;
      if (!rec || rec.expiresAt < Date.now()) return json({ error: 'invalid or expired token' }, 403);
      // Keyed by token (one subscription per paired device). DO storage has
      // no built-in TTL — cleared explicitly on /revoke, and lazily on a
      // 404/410 push response (subscription gone) in sendPush() below.
      await this.state.storage.put(`push:${body.token}`, body.subscription);
      return json({ ok: true }, 200);
    }

    if (url.pathname === '/revoke' && req.method === 'POST') {
      const body = await safeJson(req);
      if (!body?.token) return json({ error: 'token required' }, 400);
      await this.state.storage.delete(`token:${body.token}`);
      await this.state.storage.delete(`push:${body.token}`);
      this.broadcastAll(JSON.stringify({
        type: 'system', sessionId: body.sessionId ?? '',
        event: 'revoked', message: 'token revoked', timestamp: Date.now(),
      }));
      return json({ ok: true }, 200);
    }

    if (req.headers.get('Upgrade') === 'websocket') {
      return await this.handleWebSocket(req, url);
    }

    return json({ error: 'bad request' }, 400);
  }

  private async handleWebSocket(req: Request, url: URL): Promise<Response> {
    const sessionId = url.searchParams.get('sessionId') ?? '';
    const token = url.searchParams.get('token') ?? '';
    const role = (url.searchParams.get('role') as Tag) ?? 'client';

    if (!sessionId || !token) return new Response('sessionId + token required', { status: 400 });
    if (!TAGS.includes(role)) return new Response('bad role', { status: 400 });

    const rec = (await this.state.storage.get(`token:${token}`)) as { sessionId: string; role: Tag; expiresAt: number } | null;
    if (!rec) return new Response('invalid token', { status: 403 });
    if (rec.expiresAt < Date.now()) {
      await this.state.storage.delete(`token:${token}`);
      return new Response('expired token', { status: 403 });
    }
    if (rec.role !== role) return new Response('role mismatch', { status: 403 });
    if (rec.sessionId !== sessionId) return new Response('session mismatch', { status: 403 });

    const pair = new WebSocketPair();
    const client = pair[0];
    const server = pair[1];
    this.state.acceptWebSocket(server, [role, rec.sessionId]);

    try { server.send(JSON.stringify({ type: 'system', sessionId: rec.sessionId, event: 'ready', timestamp: Date.now() })); } catch {}
    this.announce(role, rec.sessionId, role === 'daemon' ? 'daemon_connected' : 'client_connected');

    return new Response(null, { status: 101, webSocket: client });
  }

  async webSocketMessage(ws: WebSocket, message: string | ArrayBuffer): Promise<void> {
    if (typeof message !== 'string') return;
    let msg: any;
    try { msg = JSON.parse(message); } catch { return; }

    if (msg.type === 'ping') {
      try { ws.send(JSON.stringify({ type: 'pong', ts: msg.ts ?? Date.now() })); } catch {}
      return;
    }

    const tags = this.state.getTags(ws) as string[];
    const role = tags.find(t => (TAGS as readonly string[]).includes(t)) as Tag | undefined;
    if (!role) return;

    if (role === 'viewer') return; // viewer is read-only (only ping is allowed above)

    if (role === 'daemon' && msg.type === 'notify' && msg.event === 'idle') {
      // Relay-internal trigger, not forwarded over WS — see sendPush().
      await this.sendPush();
      return;
    }

    if (role === 'daemon') {
      // Forward output + system events from daemon to clients + viewers
      for (const peer of this.state.getWebSockets('client')) if (peer !== ws) try { peer.send(message); } catch {}
      for (const peer of this.state.getWebSockets('viewer')) if (peer !== ws) try { peer.send(message); } catch {}
      return;
    }

    if (role === 'client') {
      // Forward prompts + sync requests from client to daemon
      for (const peer of this.state.getWebSockets('daemon')) try { peer.send(message); } catch {}
      // Tell viewers a prompt was forwarded (so the PC-side `dispatch watch`
      // observer sees activity, not the prompt text itself)
      const sessionId = tags.find(t => !(TAGS as readonly string[]).includes(t)) ?? '';
      const sys = JSON.stringify({ type: 'system', sessionId, event: 'client_prompt', message: 'prompt forwarded to daemon', timestamp: Date.now() });
      for (const peer of this.state.getWebSockets('viewer')) try { peer.send(sys); } catch {}
      return;
    }
  }

  async webSocketClose(ws: WebSocket, code: number): Promise<void> {
    const tags = this.state.getTags(ws) as string[];
    const role = tags.find(t => (TAGS as readonly string[]).includes(t)) as Tag | undefined;
    const sessionId = tags.find(t => !(TAGS as readonly string[]).includes(t)) ?? '';
    try { ws.close(code, 'bye'); } catch {}
    if (role) this.announce(role, sessionId, role === 'daemon' ? 'daemon_disconnected' : 'client_disconnected');
  }

  async webSocketError(ws: WebSocket): Promise<void> {
    try { ws.close(1011, 'error'); } catch {}
  }

  private announce(origin: Tag, sessionId: string, event: string) {
    const sys = JSON.stringify({ type: 'system', sessionId, event, timestamp: Date.now() });
    this.broadcastAll(sys, origin);
  }

  /**
   * Send `msg` to every connected socket except those tagged `exclude`.
   * Used for system announcements: when daemon disconnects, every client and
   * viewer should know; when a client disconnects, only the daemon (and other
   * viewers, who see the activity) should know.
   */
  private broadcastAll(msg: string, exclude?: Tag) {
    for (const tag of TAGS) {
      if (tag === exclude) continue;
      for (const peer of this.state.getWebSockets(tag)) {
        try { peer.send(msg); } catch {}
      }
    }
  }

  /** Push "freebuff is idle" to every subscribed device for this session. */
  private async sendPush() {
    if (!this.env.VAPID_PUBLIC_KEY || !this.env.VAPID_PRIVATE_KEY) return; // not configured
    const vapid: VapidKeys = {
      subject: this.env.VAPID_SUBJECT ?? 'mailto:dispatch@example.com',
      publicKey: this.env.VAPID_PUBLIC_KEY,
      privateKey: this.env.VAPID_PRIVATE_KEY,
    };
    const entries = await this.state.storage.list({ prefix: 'push:' });
    const message = {
      data: JSON.stringify({ title: 'DispatchFreeBuff', body: 'freebuff terminou — a resposta está pronta' }),
      // 300s (the previous value) meant a phone asleep/backgrounded for more
      // than 5 minutes when freebuff finished never got the notification at
      // all -- Apple's push relay drops anything past its TTL rather than
      // holding it for the next time the device wakes. A few hours is still
      // "this is worth telling you" without going stale.
      options: { ttl: 6 * 60 * 60 },
    };
    console.log(`[push] sending to ${entries.size} subscription(s)`);
    for (const [key, subscription] of entries) {
      try {
        const payload = await buildPushPayload(message, subscription as WebPushSubscription, vapid);
        // payload.body is a Uint8Array — a valid fetch() BodyInit at runtime;
        // the mismatch is @block65's own Uint8Array<T> vs workers-types' lib.
        const res = await fetch((subscription as WebPushSubscription).endpoint, payload as RequestInit);
        if (res.status === 404 || res.status === 410) {
          console.log(`[push] ${key} gone (${res.status}) — deleting subscription`);
          await this.state.storage.delete(key);
        } else if (!res.ok) {
          console.error(`[push] ${key} failed: ${res.status} ${await res.text().catch(() => '')}`);
        } else {
          console.log(`[push] ${key} delivered`);
        }
      } catch (e) {
        console.error(`[push] ${key} threw: ${(e as Error).message}`);
      }
    }
  }
}

async function safeJson(req: Request): Promise<any> { try { return await req.json(); } catch { return null; } }
function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      'content-type': 'application/json',
      'access-control-allow-origin': '*',
      'access-control-allow-headers': 'content-type',
      'access-control-allow-methods': 'POST,OPTIONS,GET',
    },
  });
}
