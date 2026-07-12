// relay/src/index.ts
// Cloudflare Worker entry. Single deploy: serves the relay API + the iOS PWA
// from the same origin (via the [assets] binding in wrangler.toml).
//
//   /pair/code, /pair/redeem, /revoke  → DO (per sessionId)
//   /ws                                  → DO (WebSocket upgrade, per sessionId)
//   /health                              → 200 JSON
//   everything else                      → env.ASSETS (mobile PWA static)
import { RelayDO } from './relay-do.js';

export { RelayDO };

export interface Env {
  RELAY_DO: DurableObjectNamespace;
  ASSETS?: Fetcher; // populated by [assets] binding in wrangler.toml
  ALLOWED_ORIGINS?: string;
  // Web Push (see /push/* routes + relay-do.ts sendPush). Secrets — set via
  // `wrangler secret put`, not checked in. Push is silently disabled (no
  // route 500s, subscribe just no-ops) when these are unset.
  VAPID_PUBLIC_KEY?: string;
  VAPID_PRIVATE_KEY?: string;
  VAPID_SUBJECT?: string; // e.g. "mailto:you@example.com"
}

const CORS_HEADERS: Record<string, string> = {
  'access-control-allow-origin': '*',
  'access-control-allow-headers': 'content-type',
  'access-control-allow-methods': 'POST, OPTIONS, GET',
  'access-control-max-age': '86400',
};

function corsOk() { return new Response(null, { status: 204, headers: CORS_HEADERS }); }

function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status, headers: { 'content-type': 'application/json', ...CORS_HEADERS },
  });
}

async function getSessionId(req: Request, url: URL): Promise<string | null> {
  let sessionId = url.searchParams.get('sessionId');
  if (sessionId) return sessionId;
  if (req.method === 'POST') {
    try { const b = await req.clone().json() as any; if (b?.sessionId) return b.sessionId; } catch {}
  }
  return null;
}

export default {
  async fetch(req: Request, env: Env): Promise<Response> {
    const url = new URL(req.url);

    if (req.method === 'OPTIONS') return corsOk();

    // Health
    if (url.pathname === '/health' && req.method === 'GET') {
      return json({ ok: true, name: 'dispatch-relay', version: '2', e2e: true });
    }

    // Public VAPID key — safe to expose, it's the applicationServerKey the
    // PWA passes to pushManager.subscribe(). Worker-level, not per-session.
    if (url.pathname === '/push/vapid-public-key' && req.method === 'GET') {
      if (!env.VAPID_PUBLIC_KEY) return json({ error: 'push not configured' }, 503);
      return json({ publicKey: env.VAPID_PUBLIC_KEY });
    }

    // Per-session DO routes
    const doRoutes = ['/pair/code', '/pair/redeem', '/revoke', '/ws', '/push/subscribe'];
    if (doRoutes.includes(url.pathname)) {
      const sessionId = await getSessionId(req, url);
      if (!sessionId) return new Response('sessionId required', { status: 400, headers: CORS_HEADERS });
      const id = env.RELAY_DO.idFromName(sessionId);
      const stub = env.RELAY_DO.get(id);
      return stub.fetch(req);
    }

    // Static PWA fallback
    if (env.ASSETS) {
      // Try the asset fetch as-is first
      let res = await env.ASSETS.fetch(req);
      if (res.status === 404) {
        // Friendly fallbacks for the two non-.html routes the PWA uses
        let fallback: string | null = null;
        if (url.pathname === '/' || url.pathname === '') fallback = '/index.html';
        else if (url.pathname === '/pair') fallback = '/pair.html';
        if (fallback) {
          const u = new URL(fallback + url.search, url.origin);
          res = await env.ASSETS.fetch(new Request(u.toString(), req));
        }
      }
      return res;
    }

    return new Response('not found', { status: 404, headers: CORS_HEADERS });
  },
} satisfies ExportedHandler<Env>;
