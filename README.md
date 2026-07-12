# DispatchFreeBuff

> **Send prompts from your phone to your PC terminal running Freebuff — from anywhere in the world.**

A self-hosted alternative to Claude Dispatch for the Freebuff AI CLI. Open the Freebuff terminal on your PC, scan a QR code with your iPhone, and from anywhere (commute, café, holiday) you keep chatting with Freebuff over your phone — output streams back live.

```
   📱 iPhone (PWA)             ☁️ Cloudflare Worker           🖥️ PC (Linux/Mac/Windows)
   ┌─────────────┐    wss://    ┌──────────────────────┐    wss://    ┌──────────────────┐
   │  Chat UI    │ ◄──────────► │  Durable Object      │ ◄──────────► │  Node.js daemon  │
   │  (Tailwind) │              │  tags: daem/clnt/vwr │              │  node-pty term   │
   │             │              │  + token auth        │              │  ws reconnect    │
   │  iOS Safari │              │  + pair codes (5min) │              │  ANSI strip+line │
   └─────────────┘              │  + ASSETS → PWA      │              │  buffer          │
                                └──────────────────────┘              │     └────────────┤
                                                                       │       freebuff   │
                                                                       └──────────────────┘
```

The Cloudflare Worker is the **single deploy** — it serves both the WebSocket relay (Durable Object) and the iOS PWA (via the `[assets]` binding in `wrangler.toml`). One `wrangler deploy`, one URL, one TLS certificate.

## Requirements

- **PC**: Node.js 20+, npm, and the `freebuff` CLI on your `PATH` (or pass `--command`)
  - Linux/macOS: `node-pty` builds out of the box with `make`/`gcc` (Xcode CLT on macOS).
  - Windows 10+: `node-pty` prebuilds are bundled; no Visual Studio required.
- **Phone**: iOS 14+ Safari (for "Add to Home Screen") — or any modern browser.
- **Cloudflare account** (free tier is enough).

## Install (single deploy)

```bash
# 1. Clone
git clone <repo> DispatchFreeBuff && cd DispatchFreeBuff

# 2. Deploy the relay + PWA (one command — `predeploy` syncs mobile/* into public/)
cd relay
npm install
npm run deploy                # wrangler login + push
#  → outputs e.g. https://dispatch-relay.<your-subdomain>.workers.dev

# 3. Install + build the PC daemon
cd ../daemon
npm install
npm run build                 # esbuild → dist/index.js (the `dispatch` bin)

# 4. Initialise a session on the PC
npx dispatch init --relay https://dispatch-relay.<your-subdomain>.workers.dev
#  → saves sessionId + daemonToken to ~/.dispatch/config.json (chmod 600)

# 5. Generate a pairing QR
npx dispatch pair
#  → prints a 6-char code + ASCII QR + local scan page on http://127.0.0.1:13737

# 6. Run the daemon
npx dispatch start
#  → spawns freebuff in a PTY, relays to the Cloudflare Worker over WSS
```

On the iPhone: scan the QR (or open the URL from the QR) → `/pair` page → enter the 6-letter code → tap **Share → Add to Home Screen** → use the app icon from your home screen.

## Security model

| Layer | Mechanism |
|-------|-----------|
| Transport | TLS 1.3 (Cloudflare edge) — daemon + phone both initiate outbound |
| Pairing code | 32-bit random, **5-min TTL, single-use**, deleted on redeem |
| Daemon token | 256-bit random, **30-day TTL**, stored `chmod 600` in `~/.dispatch/config.json` |
| Client token | 256-bit random, **30-day TTL**, stored in iOS PWA localStorage (per-app isolated) |
| Revocation | `dispatch revoke` rotates sessionId + tokens locally. Old tokens remain valid in the relay until expiry — wipe them via `POST /revoke { token }` (TODO CLI hook). |
| Pairing scan page | Listens on `127.0.0.1` only — never reachable from outside |
| iOS cold-resume | `visibilitychange` + `pageshow` reconnect; daemon replays last 200 chunks on `sync_request` |

**Threat model assumptions (MVP)**: you trust your phone, your PC, and Cloudflare's free-tier infrastructure. The relay sees prompt text and AI output in cleartext. If you need E2E encryption, see the roadmap at the bottom.

> ⚠️ **Re-deploying the relay wipes DO storage** (sessions, codes, tokens). If you `wrangler deploy` after a session is in use, the daemon will need to re-pair.

## Message protocol

JSON over WebSocket. All messages have a discriminator `type`. See [`shared/protocol.ts`](shared/protocol.ts).

- **`prompt`** (client → daemon) — text the user typed on phone
- **`output_chunk`** (daemon → clients) — line of stripped Freebuff output, with a monotonic `seq`
- **`sync_request`** (client → daemon) — phone reconnects after iOS background; asks for replay of chunks `seq > sinceSeq`
- **`system`** (any → any) — `daemon_connected`, `daemon_disconnected`, `crashed`, `restarted`, `revoked`
- **`ping` / `pong`** — keepalive every 25 s

## Directory layout

```
DispatchFreeBuff/
├── shared/protocol.ts          ← canonical wire schema
├── daemon/                     ← Node.js PC side
│   ├── src/index.ts            ← CLI: init / pair / start / status / ask / revoke
│   ├── package.json
│   └── tsconfig.json
├── relay/                      ← Cloudflare Worker + PWA in one
│   ├── src/index.ts            ← Worker fetch router
│   ├── src/relay-do.ts         ← Hibernatable Durable Object
│   ├── src/pair.ts             ← pair code mint/redeem + token storage
│   ├── public/                 ← PWA static (synced from ../../mobile by sync-assets)
│   ├── scripts/sync-assets.mjs ← copies mobile/* → public/ on prepublish
│   ├── wrangler.toml           ← [assets] + Durable Object binding
│   └── package.json
└── mobile/                     ← PWA source of truth (dev)
    ├── index.html  pair.html  manifest.json
    ├── app.js  pair.js  styles.css  sw.js
    └── icon.svg  icon-180.png  icon-512.png
```

## Usage

| Command                              | Effect |
|--------------------------------------|--------|
| `dispatch init --relay <URL>`        | Create a session in `~/.dispatch/config.json` |
| `dispatch init --command <cmd>`      | Use a custom CLI instead of `freebuff` |
| `dispatch pair`                      | Print QR + 6-char code, open scan page on 127.0.0.1 |
| `dispatch pair --once`               | Same, but print-and-exit (no local server) — for scripting |
| `dispatch start`                     | Run daemon in foreground |
| `dispatch start --no-watchdog`       | Disable auto-restart on Freebuff crash |
| `dispatch start --max-restarts 0`    | Same as above |
| `dispatch status`                    | Show config + ping the relay |
| `dispatch ask "fix the login bug"`   | One-shot prompt locally, no relay (debug aid) |
| `dispatch revoke`                    | Rotate sessionId + tokens; force re-pairing |

On the **iOS PWA**: tap the home-screen icon to open the chat. Type your prompt at the bottom and hit **Send**. Status indicator in the header shows `● connected` / `● offline` / `◐ syncing`.

### One-click start (Windows)

`daemon/dispatch-start.bat` chains the usual restart routine into one double-click: prints the pairing QR, opens the pretty HTML fallback in your browser, then runs `dispatch start`. Needs `dispatch init` to have run once already (persists in `~/.dispatch/config.json` across reboots — you don't redo it every time).

To get it on your desktop with the Terminal Messenger icon (same one as the phone app), run once:

```powershell
cd daemon
powershell -File create-shortcut.ps1
```

This creates `DispatchFreeBuff.lnk` on your Desktop, pointed at `dispatch-start.bat` with `dispatch-icon.ico`. Re-run it any time to recreate the shortcut (e.g. after moving the repo).

## Push notifications ("freebuff is done")

The daemon watches pty output for a 2.5s idle gap after a prompt and tells the relay to push a "freebuff finished" notification — so you don't have to keep the app open and watch it.

**PWA only.** iOS only delivers Web Push to a PWA added to the home screen via Safari (16.4+). The sideloaded native `ios-app` shell is a plain WKWebView — it can't receive Web Push, and real APNs push (`@capacitor/push-notifications`) needs an Apple Developer Program membership ($99/yr) for the Push Notifications entitlement, which free/personal-team sideloading (Sideloadly/AltServer) doesn't get. If you upgrade to a paid account later, that's the path for native push; until then, use the PWA for notifications.

Setup (one-time, per relay deploy):

```bash
# Generate a VAPID keypair (any P-256 ECDSA keypair in raw base64url works —
# this doesn't have to be @block65/webcrypto-web-push specifically):
node -e "
const {subtle}=globalThis.crypto;
const b64url=b=>Buffer.from(b).toString('base64').replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},true,['sign','verify']).then(async kp=>{
  console.log('VAPID_PUBLIC_KEY='+b64url(await subtle.exportKey('raw',kp.publicKey)));
  console.log('VAPID_PRIVATE_KEY='+(await subtle.exportKey('jwk',kp.privateKey)).d);
});
"

cd relay
npx wrangler secret put VAPID_PUBLIC_KEY   # paste the value above
npx wrangler secret put VAPID_PRIVATE_KEY  # paste the value above — never commit this
```

Then edit `VAPID_SUBJECT` in `relay/wrangler.toml` (a `mailto:` contact, not secret) and redeploy. Until the secrets are set, `/push/vapid-public-key` returns 503 and the PWA just doesn't subscribe — everything else works normally.

## Developing the PWA

The PWA source of truth is `mobile/`. **Edit `mobile/`, never `relay/public/` directly** — the next `npm run deploy` will overwrite the deployed copy. To deploy changes:

```bash
cd relay
npm run sync-assets    # mobile/* → public/
npm run deploy          # or: npm run dev for local testing
```

There's no bundler — Tailwind comes from the CDN and JS is plain ESM. The service worker precaches the shell so the PWA launches offline once installed.

## Troubleshooting

### "node-pty failed to install"
`node-pty` is a native module. Linux/macOS need `make` / `gcc` / Xcode CLT. Windows 10+ ships prebuilt binaries via `prebuild-install`. If install still fails:
```bash
cd daemon && rm -rf node_modules && npm cache clean --force && npm install --verbose
```
On Debian/Ubuntu: `sudo apt install build-essential python3`. On Alpine: `apk add gcc g++ make python3`.

### "iOS PWA keeps disconnecting"
iOS Safari aggressively suspends background WebSockets. The PWA reconnects on both `visibilitychange` and `pageshow`. If chunks are missed, the daemon replays them via `sync_request` (last 200 buffered).

### "Pairing code expired"
Codes are valid for **5 minutes**. Rerun `dispatch pair`.

### "Daemon says: relay 401"
The token doesn't match what's stored in the relay DO. Either:
1. `dispatch revoke` to rotate tokens, then `dispatch pair` again.
2. If you redeployed the relay, **all previous tokens are lost** (DO storage is wiped). Re-init the daemon.

### "Freebuff isn't actually installed / different path"
```bash
dispatch init --command /full/path/to/freebuff
# or
export FREEBUFF_BIN=/full/path/to/freebuff && dispatch init --command "$FREEBUFF_BIN"
```

## Roadmap (post-MVP)

- [ ] End-to-end encryption (ECDH handshake during `pair/redeem`)
- [ ] Worker-edge rate limiting (KV-backed sliding window per token)
- [ ] Multiple phone clients per daemon (multi-tag)
- [ ] Multi-daemon dashboard
- [ ] Telegram bot mirror (no-install fallback)
- [ ] Apple Push notifications (real APN via Cloudflare Worker → APNs HTTP/2)
- [ ] Replay store upgrade (R2 + time-windowed compaction)
- [ ] WebRTC mode for LAN-only deployments (no relay needed)
- [ ] `dispatch watch` — PC-side live tail viewer

## License

MIT.
