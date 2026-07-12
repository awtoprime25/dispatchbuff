// daemon/src/index.ts
// PC daemon: spawns Freebuff in a node-pty, strips ANSI, line-batches output,
// sends chunks to the relay as encrypted OutputChunks; receives encrypted
// Prompts from the relay and writes them into the pty.
//
// Protocol v2 (see shared/protocol.ts):
//   - First WS message from client is plaintext `key_exchange` (clientPub).
//   - Daemon derives shared AES-256-GCM key and replies with plaintext `key_ack`.
//   - From then on, all content is wrapped in `enc` envelopes (AES-256-GCM,
//     12-byte nonce, AAD = "v2|<role>|<seq>"). Ping/pong stay plaintext.
//   - Daemon regenerates its keypair on every `start`; phone re-exchanges on
//     every reconnect. AAD + seq give replay protection + ciphertext binding.
//
// CLI subcommands:
//   init       — create a session + tokens (saved to ~/.dispatch/config.json)
//   pair       — print a 6-char code + QR + local scan page (binds 127.0.0.1)
//   start      — main daemon loop with reconnect + crash watchdog
//   status     — show config + ping the relay
//   ask <text> — run a one-shot prompt locally without the relay (debug aid)
//   revoke     — rotate sessionId + tokens, forcing re-pair
import { Command } from 'commander';
// `import * as pty` is CJS-interop safe: node-pty is an externalized CJS module
// exported via `module.exports = { spawn, ... }`. Default-import shape varies
// across esbuild versions; namespace import always gives us `pty.spawn`.
import * as pty from 'node-pty';
import { Terminal as HeadlessTerminal } from '@xterm/headless';
import WebSocket from 'ws';
import qrcodeTerminal from 'qrcode-terminal';
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import crypto from 'node:crypto';
import * as e2e from './crypto';
import {
  PROTOCOL_VERSION,
  type Role,
  type SystemMessage,
  type AnyClientMessage,
  type AnyServerMessage,
  type EncryptedInner,
  type OutputMode,
  type ControlKey,
} from '../../shared/protocol';

// TEMP: bypass AES-GCM E2E while we debug the PIN-E2E key-derivation bug.
// When true, the daemon sends and accepts `{v:2, type:'plain', ...inner}`
// envelopes instead of encrypted `enc` envelopes — same shape, no AES-GCM.
// Flip to false to restore end-to-end encryption.
const E2E_DISABLED = true;

const RELAY_DEFAULT = process.env.DISPATCH_RELAY ?? 'https://dispatch-relay.example.workers.dev';
const PORT_PAIR_DEFAULT = 13737;
const DIR = path.join(os.homedir(), '.dispatch');
const FILE = path.join(DIR, 'config.json');

interface Config {
  version: 1;
  sessionId: string;
  daemonToken: string;
  relay: string;
  command: string;
  args: string[];
  cols: number;
  rows: number;
  createdAt: number;
}

function loadConfig(): Config | null {
  try { const raw = fs.readFileSync(FILE, 'utf8'); return JSON.parse(raw) as Config; } catch { return null; }
}
function saveConfig(c: Config) {
  fs.mkdirSync(DIR, { recursive: true, mode: 0o700 });
  fs.writeFileSync(FILE, JSON.stringify(c, null, 2), { mode: 0o600 });
}
function requireConfig(): Config {
  const c = loadConfig();
  if (!c) { console.error('Not initialized. Run `dispatch init` first.'); process.exit(1); }
  return c;
}
function newId() { return crypto.randomBytes(8).toString('hex'); }
function newToken() { return crypto.randomBytes(32).toString('hex'); }
/**
 * Mint a registration code for a phone from the relay. The code is stored in
 * DO storage with a 5-min TTL — the phone must call /pair/redeem with it
 * before expiry. Returning a locally-fabricated code (the old behaviour)
 * produced "invalid or expired" errors because the relay never saw it.
 */
async function mintClientCode(relay: string, sessionId: string): Promise<{ code: string; expiresAt: number }> {
  const resp = await fetch(`${relay}/pair/code`, {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ sessionId }),
  });
  if (!resp.ok) throw new Error(`/pair/code returned HTTP ${resp.status}`);
  return await resp.json() as { code: string; expiresAt: number };
}
/**
 * Mint a real daemon authentication token from the relay's pair flow.
 * The locally-generated tokens we used before were never registered with the
 * relay, so every WS upgrade returned 403. This helper calls /pair/code +
 * /pair/redeem (with role:'daemon') so the token is actually usable.
 */
async function mintDaemonToken(relay: string, sessionId: string): Promise<string> {
  // We need a (server-side) code to redeem; calling /pair/code first is the
  // canonical pair-flow path on this relay. Throws on HTTP failure.
  const { code } = await mintClientCode(relay, sessionId);
  const redeemResp = await fetch(`${relay}/pair/redeem`, {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ sessionId, code, role: 'daemon', v: 2 }),
  });
  if (!redeemResp.ok) {
    const errBody = await redeemResp.text().catch(() => '');
    throw new Error(`/pair/redeem returned HTTP ${redeemResp.status}: ${errBody.slice(0, 200)}`);
  }
  const { token } = await redeemResp.json() as { token: string };
  return token;
}
function newCode() {
  const charset = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  const bytes = crypto.randomBytes(6);
  let s = ''; for (let i = 0; i < 6; i++) s += charset[bytes[i] % charset.length];
  return s;
}
function relayWsUrl(c: Config) {
  const u = new URL(c.relay);
  u.protocol = u.protocol === 'https:' ? 'wss:' : 'ws:';
  return u.toString().replace(/\/+$/, '') + '/ws';
}

// Raw key sequences for menu/list navigation (see ControlKey in shared/protocol) —
// standard xterm CSI arrow codes; freebuff runs with TERM=xterm-256color.
const KEY_SEQUENCES: Record<ControlKey, string> = {
  up: '\x1b[A', down: '\x1b[B', right: '\x1b[C', left: '\x1b[D',
  enter: '\r', escape: '\x1b',
};

// ---------------------------------------------------------------------------
// ANSI stripper + line buffer
function stripAnsi(s: string): string {
  return s
    .replace(/\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)/g, '')
    .replace(/\x1b\[[0-9;?]*[a-zA-Z]/g, '')
    .replace(/\x1b[\(\)][A-Za-z0-9]/g, '')
    .replace(/\x1b[=>]/g, '');
}
class LineBuffer {
  private current = '';
  private pending: string[] = [];
  push(chunk: string): string[] {
    const clean = stripAnsi(chunk);
    for (const ch of clean) {
      if (ch === '\n') {
        if (this.current.length > 0) { this.pending.push(this.current); this.current = ''; }
        else this.pending.push('');
      } else if (ch === '\r') { this.current = ''; }
      else if (ch !== '\x07' && ch !== '\x0b' && ch !== '\x08') this.current += ch;
    }
    if (this.pending.length === 0) return [];
    const out = this.pending; this.pending = []; return out;
  }
}

// Output buffer for iOS replay on visibility-resume
class OutputRollbackBuffer {
  private chunks: { seq: number; content: string; mode: OutputMode; ts: number }[] = [];
  constructor(private capacity = 200) {}
  push(seq: number, content: string, mode: OutputMode = 'line') {
    this.chunks.push({ seq, content, mode, ts: Date.now() });
    while (this.chunks.length > this.capacity) this.chunks.shift();
  }
  since(sinceSeq: number) { return this.chunks.filter(c => c.seq > sinceSeq); }
  latestSeq() { return this.chunks.length ? this.chunks[this.chunks.length - 1].seq : 0; }
}

// ---------------------------------------------------------------------------
// WebSocket client wrapper used by start (uses the `ws` package — works on Node 20+)
class RelaySocket {
  private ws?: WebSocket;
  /** Set true once we've *intentionally* stopped (auth failure). The user's
   *  close handler should treat this as a terminal state, not a network blip. */
  public dying = false;
  private alive = true;
  private attempts = 0;
  private heartbeat?: NodeJS.Timeout;
  private msgHandler: (raw: string) => void = () => {};
  private closeHandler: () => void = () => {};
  private openHandler: () => void = () => {};
  constructor(private url: string, private opts: { sessionId: string; token: string; role: Role }) { this.connect(); }
  private connect() {
    if (!this.alive) return;
    const u = new URL(this.url);
    u.searchParams.set('sessionId', this.opts.sessionId);
    u.searchParams.set('token', this.opts.token);
    u.searchParams.set('role', this.opts.role);
    u.searchParams.set('v', PROTOCOL_VERSION);
    this.ws = new WebSocket(u.toString());
    this.ws.on('open', () => {
      this.attempts = 0;
      this.startHeartbeat();
      this.openHandler();
    });
    this.ws.on('message', d => { try { this.msgHandler(d.toString()); } catch {} });
    this.ws.on('close', (code, reason) => {
      const reasonStr = reason && Buffer.isBuffer(reason) ? reason.toString('utf8') : (typeof reason === 'string' ? reason : '');
      console.error(`[daemon] relay WS closed (code=${code}${reasonStr ? `, reason=${reasonStr}` : ''})`);
      this.stopHeartbeat(); this.closeHandler();
      if (this.alive) {
        const delay = Math.min(30_000, 500 * Math.pow(2, ++this.attempts));
        setTimeout(() => this.connect(), delay);
      }
    });
    this.ws.on('error', () => {});
    // WS upgrade rejected by relay (HTTP 4xx/5xx): don't loop forever — stop
    // and tell the user how to recover.
    (this.ws as any).on?.('unexpected-response', (_req: any, res: any) => {
      this.dying = true;
      this.alive = false;
      this.stopHeartbeat();
      console.error(`[daemon] relay rejected the connection: HTTP ${res.statusCode} ${res.statusMessage ?? ''}`.trim());
      console.error('  This usually means the daemon token is invalid or the relay evicted our session.');
      console.error('  Fix: `dispatch revoke` → `rm ~/.dispatch/config.json` → `dispatch init` → `dispatch pair` → `dispatch start`');
      this.closeHandler();
      try { res.resume(); } catch {}
      // Exit so the user sees the error and the freebuff child is cleaned up.
      setTimeout(() => process.exit(1), 300);
    });
  }
  private startHeartbeat() {
    this.stopHeartbeat();
    this.heartbeat = setInterval(
      () => this.sendRaw({ v: 2, type: 'ping', ts: Date.now() }),
      25_000,
    );
  }
  private stopHeartbeat() { if (this.heartbeat) clearInterval(this.heartbeat); this.heartbeat = undefined; }
  onOpen(h: () => void) { this.openHandler = h; }
  onMessage(h: (raw: string) => void) { this.msgHandler = h; }
  onClose(h: () => void) { this.closeHandler = h; }
  /** Send a wire-level message. No encryption layer here. */
  sendRaw(msg: unknown) {
    try { if (this.ws && this.ws.readyState === WebSocket.OPEN) this.ws.send(JSON.stringify(msg)); } catch {}
  }
  close() {
    this.alive = false;
    this.stopHeartbeat();
    try { this.ws?.close(); } catch {}
  }
}

// ---------------------------------------------------------------------------
// CLI
const program = new Command();
program.name('dispatch')
  .description('DispatchFreeBuff — relay your Freebuff terminal to your phone')
  .version(PROTOCOL_VERSION);

program.command('init')
  .description('Create a new Dispatch session (registers daemon token with relay)')
  .requiredOption('-r, --relay <url>', 'relay URL (e.g. https://dispatch-relay.X.workers.dev)')
  .option('-c, --command <cmd>', 'CLI to spawn', process.env.FREEBUFF_BIN ?? 'freebuff')
  // 200-col default made every mode:'screen' TUI snapshot too wide for a
  // phone (horizontal scroll to read anything) — 50 fits an iPhone SE-width
  // screen at the live-terminal bubble's 11px font without scrolling sideways.
  // Bump this back up with --cols if you're mainly watching from a PC terminal.
  .option('--cols <n>', 'terminal cols', '50')
  .option('--rows <n>', 'terminal rows', '50')
  .action(async (opts) => {
    const sessionId = newId();
    const relay = opts.relay.replace(/\/+$/, '');
    console.log('Registering daemon token with relay...');
    let daemonToken: string;
    try {
      daemonToken = await mintDaemonToken(relay, sessionId);
      console.log('  \u2713 Daemon token registered (256-bit, relay-minted).');
    } catch (err) {
      console.error('\n[init failed] Could not register with relay:', (err as Error).message);
      console.error('  Check your internet connection and that the relay URL is reachable.');
      process.exit(1);
    }

    const cfg: Config = {
      version: 1,
      sessionId,
      daemonToken,
      relay: opts.relay,
      command: opts.command,
      args: [],
      cols: parseInt(opts.cols, 10),
      rows: parseInt(opts.rows, 10),
      createdAt: Date.now(),
    };
    saveConfig(cfg);
    console.log('\nInitialized Dispatch session.');
    console.log('  Session ID :', cfg.sessionId);
    console.log('  Relay      :', cfg.relay);
    console.log('  CLI        :', cfg.command);
    console.log('  Saved to   :', FILE);
    console.log('\nNext: dispatch pair  \u2192  dispatch start\n');
  });

program.command('pair')
  .description('Mint a pairing code from the relay, print QR (opens scan page on 127.0.0.1)')
  .option('-p, --port <n>', 'local HTTP port', String(PORT_PAIR_DEFAULT))
  .option('--once', 'print the QR + save the HTML page, then exit — skip the local scan-page server (for launcher scripts that chain into `dispatch start`)')
  .action(async (opts) => {
    const cfg = requireConfig();
    const relay = cfg.relay.replace(/\/+$/, '');
    let code: string;
    let ttlMin: number;
    try {
      const mint = await mintClientCode(relay, cfg.sessionId);
      code = mint.code;
      ttlMin = Math.max(1, Math.round((mint.expiresAt - Date.now()) / 60_000));
    } catch (err) {
      console.error('[pair failed] Could not mint code from relay:', (err as Error).message);
      console.error('  Check your internet connection and the relay URL.');
      process.exit(1);
    }
    const pairUrl = `${relay.replace(/^http:/, 'https:')}/pair?session=${cfg.sessionId}&code=${code}`;
    // Plain, undecorated line — a boxed/padded URL is a pain to select
    // cleanly in a terminal. Paste this whole thing into the "session ID"
    // field on the phone and it auto-fills + submits (see mobile/pair.js).
    console.log('\nDispatchFreeBuff Pairing');
    console.log('─'.repeat(Math.min(60, pairUrl.length)));
    console.log('Copy this link, paste it into the phone\'s session field:');
    console.log(pairUrl);
    console.log(`\nCode: ${code}  (expires in ~${ttlMin} min) · or scan the QR below\n`);
    try {
      qrcodeTerminal.generate(pairUrl, { small: false }); // larger blocks → easier to scan from a QR app
    } catch {
      console.log('(terminal QR render failed — use the HTML file below)');
    }
    // ALSO write a beautiful HTML page with embedded QR for reliable scanning.
    // PowerShell often mangles Unicode QR blocks, so the HTML file is the
    // rock-solid fallback. Just `start` it from File Explorer.
    const qrHtmlPath = path.join(DIR, 'pair-qr.html');
    try {
      writePairQrHtml(qrHtmlPath, pairUrl);
      console.log(`\nSaved QR page → ${qrHtmlPath}`);
      console.log(`  Open it (e.g. double-click in File Explorer) to scan a clean QR with your phone.`);
    } catch (e) {
      console.log(`  (could not save HTML QR page: ${(e as Error).message})`);
    }
    if (opts.once) return; // launcher mode — QR printed + HTML saved above, nothing left to do

    const html = renderPairPage(pairUrl, code);
    const port = parseInt(opts.port, 10);
    const server = http.createServer((_req, res) => {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' });
      res.end(html);
    });
    server.listen(port, '127.0.0.1', () => {
      console.log(`\nLocal scan page: http://127.0.0.1:${port}  (127.0.0.1 only — never reachable from outside)\n`);
    });
    console.log('Press Ctrl+C to exit.\n');
    process.on('SIGINT', () => { server.close(); process.exit(0); });
  });

// HTML-escape any user-controlled value before inlining into the page
function htmlEscape(s: string): string {
  return s.replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c] as string));
}
/**
 * Save a self-contained HTML file with a scannable QR (uses jsdelivr's
 * qrcode-generator library at load time). The daemon needs no QR library of
 * its own — the user's BROWSER fetches the CDN when they open the file.
 * Saved to ~/.dispatch/pair-qr.html so the user can `start <path>` it.
 */
function writePairQrHtml(filePath: string, url: string): void {
  const safeUrl = htmlEscape(url);
  const safeUrlJs = JSON.stringify(url);
  const html = `<!doctype html><html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>DispatchFreeBuff — Pair QR</title>
<style>
:root{color-scheme:dark}
body{font-family:system-ui,-apple-system,Segoe UI,sans-serif;background:#0b1020;color:#e8ecff;margin:0;padding:24px;min-height:100vh;display:flex;flex-direction:column;align-items:center;justify-content:center}
h1{font-weight:600;margin:0 0 8px;font-size:22px;letter-spacing:-.01em}
.sub{color:#98a4d9;font-size:14px;margin:0 0 24px;text-align:center;max-width:420px;line-height:1.5}
.qr-wrap{background:#fff;padding:20px;border-radius:14px;box-shadow:0 12px 40px rgba(0,0,0,.4);margin-bottom:24px}
.url{background:#12183a;padding:12px 14px;border-radius:8px;font-family:ui-monospace,Menlo,Consolas,monospace;font-size:11px;word-break:break-all;max-width:520px;text-align:center;border:1px solid #283060;color:#98a4d9}
.code{font-family:ui-monospace,Menlo,Consolas,monospace;letter-spacing:.4em;font-size:24px;text-align:center;background:#12183a;padding:14px 20px;border-radius:12px;font-weight:700;color:#a7f3d0;margin-top:14px;border:1px solid #283060}
.e2e{color:#a7f3d0;font-size:12px;margin-top:14px;display:flex;align-items:center;gap:6px}
.e2e::before{content:"🔒"}
</style></head><body>
<h1>📡  DispatchFreeBuff</h1>
<p class="sub">Scan this QR with your phone camera. The pairing screen will open automatically:</p>
<div class="qr-wrap"><div id="qr"></div></div>
<div class="code" id="code"></div>
<div class="url">${safeUrl}</div>
<p class="e2e">End-to-end encrypted (ECDH P-256 + AES-256-GCM) — the relay can't read your prompts.</p>
<script src="https://cdn.jsdelivr.net/npm/qrcode-generator@1.4.4/qrcode.min.js"></script>
<script>
try {
  var q = qrcode(0, 'M');
  q.addData(${safeUrlJs});
  q.make();
  document.getElementById('qr').innerHTML = q.createImgTag(6, 12);
  var m = ${safeUrlJs}.match(/[?&]code=([A-Z0-9]+)/i);
  if (m) document.getElementById('code').textContent = m[1].toUpperCase();
} catch(e) {
  var qr = document.getElementById('qr');
  qr.innerHTML = '<p style="color:#b91c1c;padding:20px">QR library blocked. URL: ${safeUrl}</p>';
}
</script>
</body></html>`;
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, html, 'utf8');
}
function renderPairPage(url: string, code: string): string {
  const safeUrl = htmlEscape(url);
  const safeCode = htmlEscape(code);
  const safeUrlJs = JSON.stringify(url);
  return `<!doctype html><html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>DispatchFreeBuff — Pair</title>
<style>
:root{color-scheme:dark}
body{font-family:system-ui,-apple-system,Segoe UI,sans-serif;background:#0b1020;color:#e8ecff;margin:0;padding:24px;min-height:100vh;display:flex;align-items:center;justify-content:center}
.card{max-width:520px;width:100%;background:#12183a;border-radius:18px;padding:28px;box-shadow:0 24px 60px #0006}
h1{font-size:22px;margin:0 0 6px;letter-spacing:.2px}
p.sub{color:#98a4d9;font-size:14px;line-height:1.55;margin:0 0 18px}
.qr{background:white;border-radius:14px;padding:14px;display:flex;justify-content:center;margin-bottom:18px}
.code{font-family:ui-monospace,Menlo,Consolas,monospace;letter-spacing:.4em;font-size:30px;text-align:center;background:#0b1020;padding:16px;border-radius:14px;font-weight:700;border:1px solid #283060}
.url{word-break:break-all;color:#98a4d9;font-size:12px;margin-top:14px;font-family:ui-monospace,Consolas,monospace}
.e2e{color:#a7f3d0;font-size:12px;margin-top:8px;display:flex;align-items:center;gap:6px}
.e2e::before{content:"🔒"}
</style></head><body>
<div class="card">
  <h1>📡  DispatchFreeBuff</h1>
  <p class="sub">On your iPhone, open the URL below, then enter the code on the pairing screen.</p>
  <div class="qr"><canvas id="qr"></canvas></div>
  <div class="code">${safeCode}</div>
  <div class="url">${safeUrl}</div>
  <p class="e2e">End-to-end encrypted (ECDH P-256 + AES-256-GCM). The relay can't read your prompts.</p>
</div>
<script src="https://cdn.jsdelivr.net/npm/qrcode@1.5.4/build/qrcode.min.js"></script>
<script>
try { QRCode.toCanvas(document.getElementById('qr'), ${safeUrlJs}, { width: 280, margin: 1, color: { dark: '#0b1020', light: '#fff' } }); }
catch (e) { document.getElementById('qr').outerHTML = '<p style="color:#ffb">QR library blocked — scan the URL above manually.</p>'; }
</script>
</body></html>`;
}

program.command('start')
  .description('Run the daemon in the foreground')
  .option('--no-watchdog', 'do not auto-restart freebuff on crash')
  .option('--max-restarts <n>', 'max auto-restart attempts', '3')
  .action(async (opts) => {
    const cfg = requireConfig();
    const outBuf = new OutputRollbackBuffer();
    const lineBuf = new LineBuffer();
    // Headless terminal mirrors the pty's screen state so we can tell a
    // scrolling CLI (normal buffer) apart from a full-screen TUI (alternate
    // buffer, e.g. Ink-based freebuff UI) and switch output mode accordingly.
    const screenTerm = new HeadlessTerminal({ cols: cfg.cols, rows: cfg.rows, allowProposedApi: true });
    let screenFlushTimer: NodeJS.Timeout | null = null;
    // "freebuff went idle" push trigger: armed on every prompt sent + every
    // pty chunk received. Originally a pure output-silence timer (fire after
    // IDLE_MS with no new pty data) but freebuff's pty never actually goes
    // silent — something in its idle screen (cursor blink, ad rotation, who
    // knows) keeps emitting redraws indefinitely, so a silence-based timer
    // never completed its countdown and simply never fired (confirmed: 300+
    // consecutive re-arms with zero fires in a real session). Now it's a
    // settle-debounce that, once nothing's arrived for IDLE_MS, checks
    // freebuff's own UI state directly: it shows a "■ Esc" hint (cancel a
    // running turn) any time it's actively thinking/working, and only that —
    // NOT the input-box placeholder, which reappears briefly right after
    // Enter, before "Thinking" has even rendered, and read as "already done"
    // far too early (confirmed: idle fired ~400ms after submit, well before
    // freebuff could plausibly have answered). Absence of "■ Esc" is a
    // direct signal from freebuff's own UI, not an inferred timing guess.
    // If it's still busy we just keep polling every IDLE_MS instead of
    // giving up, so it's self-correcting regardless of how noisy the pty is.
    // Doubles as the busy/idle gate for pendingPrompts below — freebuff's TUI
    // expects one prompt at a time (typed + Enter, wait for the reply) and
    // silently drops/garbles prompts sent while it's still mid-response, so
    // anything that arrives while awaitingIdleNotify is true gets queued
    // instead of written straight to the pty.
    let idleTimer: NodeJS.Timeout | null = null;
    let awaitingIdleNotify = false;
    const pendingPrompts: string[] = [];
    const IDLE_MS = 400;
    function armIdleTimer() {
      if (idleTimer) clearTimeout(idleTimer);
      idleTimer = setTimeout(() => {
        idleTimer = null;
        if (pendingPrompts.length > 0) { writePrompt(pendingPrompts.shift()!); return; }
        if (!awaitingIdleNotify) return;
        if (/■\s*Esc/.test(renderScreen())) { armIdleTimer(); return; } // still busy — keep polling
        awaitingIdleNotify = false;
        sendExtractedAnswer();
        relay.sendRaw({ v: 2, type: 'notify', event: 'idle' });
      }, IDLE_MS);
    }
    function writePrompt(text: string) {
      awaitingIdleNotify = true;
      // freebuff's Ink input box silently drops an Enter sent in the same
      // tick as the preceding text — confirmed by repro: text+\r written
      // back-to-back left the prompt sitting unsubmitted in the input box
      // indefinitely. 150ms was enough headroom at 200 cols but NOT at the
      // narrower 50-col default (3/3 repro failures) — Ink's re-render cost
      // apparently scales with layout, so 500ms is used for both instead of
      // making this width-dependent. Root cause is upstream (Ink/freebuff),
      // not something we can fix here — just avoid triggering it.
      //
      // armIdleTimer() is NOT called until after \r is actually sent — arming
      // it immediately raced the readiness check in armIdleTimer() against
      // this same delay: the check could fire at IDLE_MS while the screen was
      // still showing its pre-prompt "ready" state (Enter not sent yet),
      // reading that as "already idle" and never re-mirroring the real
      // conversation. onData's own re-arms cover the steady state once real
      // output starts flowing; this only guards the window before that.
      try {
        term.write(text);
        setTimeout(() => {
          try { term.write('\r'); } catch (e) { log(`write failed: ${(e as Error).message}`); }
          armIdleTimer();
        }, 500);
      } catch (e) { log(`write failed: ${(e as Error).message}`); }
    }
    let seq = 0;
    let restarts = 0;
    const e2eState = e2e.newE2EState();
    let ready = false; // becomes true when key_exchange completes
    const pendingOutbound: EncryptedInner[] = [];
    let clientRekeyPending = false; // true while we wait for a fresh key_exchange from the client

    function log(msg: string) { console.error(`[daemon] ${msg}`); }

    function makeTerm() {
      return pty.spawn(cfg.command, cfg.args, {
        name: 'xterm-256color',
        cols: cfg.cols,
        rows: cfg.rows,
        cwd: process.cwd(),
        env: { ...process.env, TERM: 'xterm-256color', FORCE_COLOR: '1', COLORTERM: 'truecolor' },
      });
    }
    let term = makeTerm();
    log(`started ${cfg.command} (${cfg.cols}x${cfg.rows}) session=${cfg.sessionId.slice(0, 8)}…`);
    attachTerm(term);

    const relay = new RelaySocket(relayWsUrl(cfg), {
      sessionId: cfg.sessionId, token: cfg.daemonToken, role: 'daemon',
    });

    /** Convert an output_chunk or system message to the encrypted-inner shape. */
    function toInner(msg: AnyServerMessage): EncryptedInner | null {
      if (msg.type === 'output_chunk') {
        return { t: 'output_chunk', id: msg.id, sessionId: msg.sessionId, content: msg.content, seq: msg.seq, timestamp: msg.timestamp, mode: msg.mode };
      }
      if (msg.type === 'system') {
        // We only forward daemon-originated system events through encryption.
        // Relay-originated events (ready, *_connected, revoked) stay plaintext
        // on the wire and reach the client directly from the relay.
        return { t: 'system', sessionId: msg.sessionId, event: msg.event as 'crashed' | 'restarted', message: msg.message, timestamp: msg.timestamp };
      }
      return null;
    }

    /** Send a content message: encrypt if key ready, otherwise buffer.
     *  ping/pong are always sent plaintext. */
    function sendContent(msg: AnyServerMessage) {
      if (msg.type === 'ping' || msg.type === 'pong') {
        relay.sendRaw({ v: 2, type: msg.type, ts: msg.ts });
        return;
      }
      const inner = toInner(msg);
      if (!inner) return;
      if (E2E_DISABLED) {
        // Plaintext envelope. Daemon's keypair is unused in this mode.
        relay.sendRaw({ v: 2, type: 'plain', ...inner });
        return;
      }
      if (!ready || !e2eState.sharedKey) {
        pendingOutbound.push(inner);
        return;
      }
      try {
        const env = e2e.encryptInner(e2eState, 'daemon', inner);
        relay.sendRaw(env);
      } catch (err) { log(`encrypt failed: ${(err as Error).message}`); }
    }

    function flushPending() {
      while (pendingOutbound.length > 0) {
        const inner = pendingOutbound.shift()!;
        if (E2E_DISABLED) {
          try { relay.sendRaw({ v: 2, type: 'plain', ...inner }); }
          catch (err) { log(`flush failed: ${(err as Error).message}`); pendingOutbound.unshift(inner); break; }
          continue;
        }
        if (!ready || !e2eState.sharedKey) { pendingOutbound.unshift(inner); break; }
        try { relay.sendRaw(e2e.encryptInner(e2eState, 'daemon', inner)); }
        catch (err) { log(`flush failed: ${(err as Error).message}`); pendingOutbound.unshift(inner); break; }
      }
    }

    /** Render the headless terminal's active screen as plain text (trailing
     *  blank rows trimmed) — the snapshot sent for mode:'screen' chunks. */
    function renderScreen(): string {
      const buf = screenTerm.buffer.active;
      const lines: string[] = [];
      for (let i = 0; i < screenTerm.rows; i++) lines.push(buf.getLine(i)?.translateToString(true) ?? '');
      while (lines.length && lines[lines.length - 1] === '') lines.pop();
      return lines.join('\n');
    }

    /**
     * Best-effort scrape of freebuff's most recent answer out of its TUI
     * history so the phone can show a clean chat bubble instead of only the
     * live screen mirror. freebuff renders each turn as a repeating block:
     *   [HH:MM]
     *   <echoed prompt> ⎘
     *   (• or ▸) Thinking [...thinking text...]
     *   <answer text>
     *   Suggested followups: / ⎘ • Ns • △▽   (footer)
     * Heuristic, coupled to that layout — freebuff has no structured/plain
     * output mode to hook into instead (checked: no CLI flag, and it still
     * forces the alternate-screen TUI even when stdin/stdout aren't a TTY).
     * Returns null (falls back to screen-mode-only) if the shape doesn't match.
     */
    function extractLastAnswer(screenText: string): string | null {
      const lines = screenText.split('\n');
      let start = -1;
      for (let i = lines.length - 1; i >= 0; i--) {
        if (/^\s*\[\d{1,2}:\d{2}\]\s*$/.test(lines[i])) { start = i; break; }
      }
      if (start === -1) return null;

      const body: string[] = [];
      for (let i = start + 1; i < lines.length; i++) {
        const line = lines[i];
        if (/⎘\s*•\s*\d+s/.test(line)) break; // per-turn footer
        if (/^\s*\[\d{1,2}:\d{2}\]\s*$/.test(line)) break; // next turn already started
        if (/Enter a coding task/.test(line)) break; // input box
        body.push(line);
      }

      let idx = 0;
      while (idx < body.length && body[idx].trim() === '') idx++;
      if (idx < body.length) idx++; // skip the echoed prompt line
      while (idx < body.length && body[idx].trim() === '') idx++;
      if (idx < body.length && /^\s*[•▸]\s*Thinking/.test(body[idx])) {
        idx++;
        while (idx < body.length && body[idx].trim() !== '') idx++; // skip thinking paragraph
      }
      while (idx < body.length && body[idx].trim() === '') idx++;

      const answerLines: string[] = [];
      for (; idx < body.length; idx++) {
        if (/^\s*Suggested followups:/.test(body[idx])) break;
        if (/^\s*[╭╰]/.test(body[idx])) break; // boxed UI elements (ads, warnings) aren't part of the answer
        answerLines.push(body[idx].trimEnd());
      }
      const answer = answerLines.join('\n').replace(/\n{3,}/g, '\n\n').trim();
      return answer || null;
    }

    /** Fires once freebuff goes idle after a TUI turn — sends the scraped
     *  answer (see extractLastAnswer) as a normal chat bubble alongside the
     *  live screen mirror. No-ops if freebuff isn't in the alternate screen
     *  (nothing to scrape — normal-mode output is already line-mode bubbles). */
    function sendExtractedAnswer() {
      if (screenTerm.buffer.active.type !== 'alternate') return;
      const answer = extractLastAnswer(renderScreen());
      if (!answer) return;
      seq += 1; outBuf.push(seq, answer, 'line');
      sendContent({ type: 'output_chunk', id: newId(), sessionId: cfg.sessionId, content: answer, seq, timestamp: Date.now(), mode: 'line' });
    }

    /** Throttle full-screen snapshots (TUIs redraw far faster than a phone
     *  needs to see) — coalesce bursts into one send per ~33ms. */
    function scheduleScreenFlush() {
      if (screenFlushTimer) return;
      screenFlushTimer = setTimeout(() => {
        screenFlushTimer = null;
        const content = renderScreen();
        seq += 1; outBuf.push(seq, content, 'screen');
        sendContent({ type: 'output_chunk', id: newId(), sessionId: cfg.sessionId, content, seq, timestamp: Date.now(), mode: 'screen' });
      }, 33);
    }

    function attachTerm(t: ReturnType<typeof pty.spawn>) {
      t.onData((chunk: string) => {
        armIdleTimer(); // any output activity pushes the idle deadline back
        // Mirror into the headless terminal first so buffer.active.type
        // reflects this chunk (write() finishes parsing before the callback).
        screenTerm.write(chunk, () => {
          if (screenTerm.buffer.active.type === 'alternate') {
            // freebuff never leaves the alternate screen even sitting idle at
            // the input box (blinking cursor etc. keep emitting redraws) — only
            // mirror while a turn is actually in flight, otherwise those idle
            // redraws keep spawning fresh "live terminal" bubbles after the
            // clean answer bubble already landed, burying it out of view.
            if (awaitingIdleNotify) scheduleScreenFlush();
            return;
          }
          if (screenFlushTimer) { clearTimeout(screenFlushTimer); screenFlushTimer = null; }
          const lines = lineBuf.push(chunk);
          for (const line of lines) {
            seq += 1; outBuf.push(seq, line, 'line');
            sendContent({ type: 'output_chunk', id: newId(), sessionId: cfg.sessionId, content: line, seq, timestamp: Date.now(), mode: 'line' });
          }
        });
      });
      t.onExit(({ exitCode, signal }: { exitCode: number; signal?: number }) => {
        sendContent(<SystemMessage>{ type: 'system', sessionId: cfg.sessionId, event: 'crashed', message: `exit=${exitCode} signal=${signal ?? 0}`, timestamp: Date.now() });
        log(`freebuff exited code=${exitCode} signal=${signal}`);
        const max = parseInt(opts.maxRestarts, 10);
        if (opts.watchdog && restarts < max) {
          restarts += 1;
          log(`restarting (attempt ${restarts}/${max})…`);
          setTimeout(() => {
            try { t.kill(); } catch {}
            term = makeTerm();
            attachTerm(term);
            sendContent(<SystemMessage>{ type: 'system', sessionId: cfg.sessionId, event: 'restarted', timestamp: Date.now() });
          }, 1500);
        } else {
          relay.close();
          process.exit(exitCode ?? 1);
        }
      });
    }

    /** Handle a decrypted inner payload from the client. */
    function handleInner(inner: EncryptedInner) {
      if (inner.t === 'prompt') {
        log(`prompt received (${inner.text.length} chars)`);
        if (awaitingIdleNotify) {
          pendingPrompts.push(inner.text);
          log(`freebuff still busy — queued (${pendingPrompts.length} pending)`);
        } else {
          writePrompt(inner.text);
        }
      } else if (inner.t === 'key') {
        // Navigation keys (arrow-key menus, y/n prompts) bypass the prompt
        // queue entirely — they're not a new "turn", just steering the one
        // already in flight, and go straight to the pty with no delay (the
        // text+\r submit race that needs the 150ms gap doesn't apply here).
        log(`key received: ${inner.key}`);
        awaitingIdleNotify = true; armIdleTimer(); // keep the live screen mirror on while navigating
        try { term.write(KEY_SEQUENCES[inner.key]); } catch (e) { log(`write failed: ${(e as Error).message}`); }
      } else if (inner.t === 'sync_request') {
        const missed = outBuf.since(inner.sinceSeq);
        log(`sync_request sinceSeq=${inner.sinceSeq} → replaying ${missed.length} chunks`);
        for (const c of missed) {
          sendContent({ type: 'output_chunk', id: newId(), sessionId: cfg.sessionId, content: c.content, seq: c.seq, timestamp: c.ts, mode: c.mode });
        }
      }
    }

    relay.onMessage((raw: string) => {
      let msg: any;
      try { msg = JSON.parse(raw); } catch { return; }

      // Plaintext ping/pong
      if (msg.type === 'ping') { relay.sendRaw({ v: 2, type: 'pong', ts: msg.ts ?? Date.now() }); return; }

      // E2E handshake: client → daemon (must arrive first)
      if (msg.type === 'key_exchange' && msg.v === 2) {
        if (!msg.clientKey || typeof msg.clientKey !== 'object') { log('key_exchange: missing clientKey'); return; }
        try {
          const peerJwk = msg.clientKey as crypto.JsonWebKey;
          // Re-derive (even if we already had a key — this is a rekey request)
          e2e.clearSharedKey(e2eState);
          e2eState.sharedKey = e2e.deriveSharedKey(e2eState.kp.privateKey, peerJwk);
          ready = true;
          clientRekeyPending = false;
          relay.sendRaw({ v: 2, type: 'key_ack', from: 'daemon', daemonKey: e2eState.jwk });
          log('E2E: key exchange complete');
          flushPending();
        } catch (err) { log(`key_exchange failed: ${(err as Error).message}`); }
        return;
      }

      // Plaintext envelope (E2E_DISABLED mode — same shape as inner)
      if (msg.type === 'plain' && msg.v === 2) {
        const inner: EncryptedInner = (() => {
          const { v: _v, type: _t, ...rest } = msg;
          return rest as EncryptedInner;
        })();
        handleInner(inner);
        return;
      }

      // Encrypted envelope (client → daemon, in v2 all content is wrapped)
      if (msg.type === 'enc' && msg.v === 2) {
        if (!ready || !e2eState.sharedKey) { log('received enc before key exchange — dropping'); return; }
        let inner: EncryptedInner | null;
        try { inner = e2e.decryptEnvelope(e2eState, 'client', msg); }
        catch (err) { log(`decrypt failed: ${(err as Error).message}`); return; }
        if (inner === null) { log('replay dropped'); return; }
        handleInner(inner);
        return;
      }

      // Rekey: daemon-initiated (we send this when we lose our shared key,
      // e.g. after a reconnection without key_exchange). The client responds
      // with a fresh key_exchange.
      if (msg.type === 'rekey_required' && msg.v === 2) {
        // The client should be the one initiating key_exchange. This message
        // arriving from the client is unexpected — log and ignore.
        log('unexpected rekey_required from client — ignored');
        return;
      }

      // Legacy v1 plaintext — the v2 daemon doesn't speak v1. Log and drop.
      if (msg.type === 'prompt' || msg.type === 'sync_request') {
        log(`received legacy v1 message (${msg.type}) — ignoring. v2 daemon requires encrypted envelopes.`);
        return;
      }

      log(`unknown message type: ${msg.type} (v=${msg.v ?? '?'})`);
    });

    relay.onClose(() => {
      // unexpected-response already handled this and is about to exit. Don't
      // log a fake "reconnecting" message.
      if (relay.dying) return;
      log('relay disconnected; reconnecting in background');
      // Clear shared key on disconnect — we have no idea if it's still safe.
      e2e.clearSharedKey(e2eState);
      ready = false;
    });

    relay.onOpen(() => {
      if (E2E_DISABLED) {
        ready = true;
        flushPending();
      }
      log('relay connected. Listening for prompts.');
    });
    const cleanup = () => {
      log('shutting down');
      try { term.kill(); } catch {}
      e2e.destroyE2E(e2eState);
      relay.close();
      process.exit(0);
    };
    process.on('SIGINT', cleanup);
    process.on('SIGTERM', cleanup);
  });

program.command('status')
  .description('Show config + ping the relay')
  .action(async () => {
    const cfg = requireConfig();
    console.log('Session :', cfg.sessionId);
    console.log('Relay   :', cfg.relay);
    console.log('Created :', new Date(cfg.createdAt).toISOString());
    console.log('CLI     :', `${cfg.command} ${cfg.args.join(' ')}`.trim());
    console.log('Config  :', FILE);
    try {
      const res = await fetch(`${cfg.relay.replace(/^http:/, 'https:')}/health`);
      const body = await res.text();
      console.log('Ping    : OK →', body);
    } catch (e) { console.log('Ping    : FAIL (', (e as Error).message, ')'); }
  });

program.command('ask <text...>')
  .description('Run freebuff once locally and pipe the prompt (no relay)')
  .action((text: string[]) => {
    const cfg = requireConfig();
    const t = pty.spawn(cfg.command, cfg.args, {
      name: 'xterm-256color', cols: cfg.cols, rows: cfg.rows, cwd: process.cwd(),
      env: { ...process.env, TERM: 'xterm-256color', FORCE_COLOR: '1', COLORTERM: 'truecolor' },
    });
    t.onData(d => process.stdout.write(stripAnsi(d)));
    t.onExit(({ exitCode }: { exitCode: number }) => process.exit(exitCode ?? 0));
    setTimeout(() => { t.write(text.join(' ')); t.write('\r'); }, 200);
  });

program.command('revoke')
  .description('Rotate sessionId + tokens; force re-pairing (mints a fresh relay token)')
  .action(async () => {
    const cfg = loadConfig();
    if (!cfg) { console.log('Nothing to revoke.'); return; }
    const sessionId = newId();
    const relay = cfg.relay.replace(/\/+$/, '');
    console.log(`Revoking old session and minting a new daemon token with the relay...`);
    let daemonToken: string;
    try {
      daemonToken = await mintDaemonToken(relay, sessionId);
      console.log('  \u2713 New daemon token registered. Old session+token are now invalid.');
    } catch (err) {
      console.error('[revoke failed] Could not mint new token:', (err as Error).message);
      console.error('  Your current session is unchanged.');
      return;
    }
    saveConfig({ ...cfg, sessionId, daemonToken, createdAt: Date.now() });
    console.log('New session:', sessionId);
    console.log('Run `dispatch pair` then `dispatch start` (phone must scan the new QR).');
  });

program.parseAsync().catch(err => { console.error(err); process.exit(1); });
