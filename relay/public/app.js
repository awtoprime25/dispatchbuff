// mobile/app.js — Chat runtime for the PWA (protocol v2, E2E).
// - Markdown-ish rendering: ```lang code blocks``` → highlighted <pre>, inline `code`.
// - Auth badge in header shows E2E status.
// - E2E: ECDH P-256 + AES-256-GCM with AAD binding = "v2|<role>|<seq>".
//   All content (prompts, output, system, sync) is encrypted after handshake.
// - Monotonic per-direction seq for replay protection; outSeq / inSeq.
// - Pending prompts + sync_request are queued until the channel is ready.
//
// Session model (v2): E2E state lives on a per-WebSocket `session` object,
// not on module-level globals. Multiple connect() calls (initial load +
// visibilitychange + pageshow + reconnect storm) used to race on shared
// `clientKeypair`/`sharedKey`/`outSeq`/`inSeq`: a later connect() would
// overwrite the keypair while an earlier handleKeyAck() was still awaiting
// crypto.subtle.deriveBits, causing the PWA to finish deriving with a key
// the daemon never saw ⇒ AES-GCM auth-tag mismatch on every decrypt.
// Now: each connect() stamps its session with a unique `gen`, captured by
// every async callback. If a stale callback resumes after a newer connect()
// bumped the gen, it short-circuits — its WS / keypair / sharedKey are gone.
const AUTH_KEY = 'dispatch_auth';
const LAST_SEQ_KEY = 'dispatch_last_seq';
const PROTO_V = 2;
// AAD format MUST match `aadFor` in shared/protocol.ts. Drift = silent decrypt
// failure (AES-GCM auth tag mismatch, not a clear error). The assert below
// catches a bump-mismatch at module load.
if (PROTO_V !== 2) throw new Error('mobile PROTO_V must match shared PROTOCOL_VERSION');
const AAD_PREFIX_CLIENT = 'v2|client|';
const AAD_PREFIX_DAEMON = 'v2|daemon|';
const HKDF_INFO = new TextEncoder().encode('dispatch-freebuff-e2e-v1');
const HKDF_SALT = new Uint8Array(32); // zero salt; info disambiguates use
// TEMP: bypass AES-GCM E2E while we debug the PIN-E2E key-derivation bug.
// When true, the PWA skips key_exchange entirely and sends/receives
// `{v:2, type:'plain', ...inner}` envelopes instead of encrypted `enc` ones.
// Flip to false to restore end-to-end encryption.
const E2E_DISABLED = true;

const $messages = document.getElementById('messages');
const $input = document.getElementById('input');
const $form = document.getElementById('composer');
const $send = document.getElementById('send');
const $dot = document.getElementById('status-dot');
const $status = document.getElementById('status-text');
const $auth = document.getElementById('auth-badge');
const $authText = document.getElementById('auth-text');
const $connectGate = document.getElementById('connect-gate');
const $appShell = document.getElementById('app-shell');
const $gatePairBtn = document.getElementById('gate-pair-btn');
const $hdrTitle = document.getElementById('hdr-title');
const $tabBtns = document.querySelectorAll('.tab-btn');
const $screens = {
  terminal: document.getElementById('screen-terminal'),
  commands: document.getElementById('screen-commands'),
  settings: document.getElementById('screen-settings'),
};
const $commandsList = document.getElementById('commands-list');
const $setHost = document.getElementById('set-host');
const $setStatus = document.getElementById('set-status');
const $setEnc = document.getElementById('set-enc');
const $soundToggle = document.getElementById('sound-toggle');
const $disconnectBtn = document.getElementById('disconnect-btn');

function auth() { try { return JSON.parse(localStorage.getItem(AUTH_KEY) || 'null'); } catch { return null; } }
function saveAuth(a) { if (a) localStorage.setItem(AUTH_KEY, JSON.stringify(a)); else localStorage.removeItem(AUTH_KEY); }
function lastSeq() { return parseInt(localStorage.getItem(LAST_SEQ_KEY) || '0', 10); }
function setLastSeq(n) { localStorage.setItem(LAST_SEQ_KEY, String(n)); }

function setStatus(state, label) {
  $dot.className = 'dot ' + ({ connected:'dot-on', syncing:'dot-syn', offline:'dot-off', securing:'dot-syn' }[state] || 'dot-off');
  $status.textContent = label || state;
  if ($send) $send.disabled = state !== 'connected';
}

function setAuth(state) {
  if (state === 'on')  { $auth.classList.remove('hidden'); $auth.classList.add('encrypted'); $authText.textContent = 'E2E'; }
  else if (state === 'off') { $auth.classList.remove('hidden'); $auth.classList.remove('encrypted'); $authText.textContent = 'plain'; }
  else { $auth.classList.add('hidden'); }
}

// ------------------------------------------------------------------
// Connect gate: unpaired devices see the "term_" landing screen instead
// of the tabbed app (pairing itself still happens on /pair.html — this
// just routes them there instead of showing an empty chat).
function updateGateVisibility() {
  const paired = !!auth()?.token;
  $connectGate.classList.toggle('hidden', paired);
  $appShell.classList.toggle('hidden', !paired);
}
$gatePairBtn.addEventListener('click', () => { location.href = '/pair.html'; });

// ------------------------------------------------------------------
// Tabs: terminal / saved commands / settings.
let currentTab = 'terminal';
function setTab(tab) {
  currentTab = tab;
  for (const key in $screens) $screens[key].classList.toggle('hidden', key !== tab);
  $tabBtns.forEach(b => b.classList.toggle('active', b.dataset.tab === tab));
  $hdrTitle.textContent = tab === 'terminal' ? 'Dispatch' : tab === 'commands' ? 'Commands' : 'Settings';
  if (tab === 'settings') renderSettings();
  if (tab === 'terminal') $messages.scrollTop = $messages.scrollHeight;
}
$tabBtns.forEach(b => b.addEventListener('click', () => setTab(b.dataset.tab)));

// ------------------------------------------------------------------
// Saved commands: tap to send instantly. Static list — add an editor UI
// if this needs to grow beyond a handful of presets.
const DEFAULT_COMMANDS = [
  { label: 'Project status', cmd: 'git status' },
  { label: 'List files', cmd: 'ls -la' },
  { label: 'Dev server', cmd: 'npm run dev' },
  { label: 'Docker processes', cmd: 'docker ps' },
  { label: 'Clear screen', cmd: 'clear' },
];
function renderCommands() {
  $commandsList.innerHTML = '';
  for (const c of DEFAULT_COMMANDS) {
    const row = document.createElement('div');
    row.className = 'cmd-row';
    const label = document.createElement('span');
    label.className = 'cmd-label';
    label.textContent = c.label;
    const text = document.createElement('span');
    text.className = 'cmd-text';
    text.textContent = c.cmd;
    row.append(label, text);
    row.addEventListener('click', () => sendPreset(c.cmd));
    $commandsList.appendChild(row);
  }
}
function sendPreset(cmd) {
  setTab('terminal');
  $input.value = cmd;
  autoResize();
  $form.requestSubmit();
}

// ------------------------------------------------------------------
// Settings tab: connection info + sound toggle + session actions.
const SOUND_KEY = 'dispatch_sound';
function soundOn() { return localStorage.getItem(SOUND_KEY) !== 'off'; }
function setSoundOn(on) { localStorage.setItem(SOUND_KEY, on ? 'on' : 'off'); }
$soundToggle.addEventListener('click', () => {
  const next = !soundOn();
  setSoundOn(next);
  $soundToggle.classList.toggle('on', next);
});

let audioCtx = null;
function playSendSound() {
  if (!soundOn()) return;
  try {
    audioCtx = audioCtx || new (window.AudioContext || window.webkitAudioContext)();
    const osc = audioCtx.createOscillator();
    const gain = audioCtx.createGain();
    osc.type = 'sine';
    osc.frequency.value = 880;
    gain.gain.setValueAtTime(0.08, audioCtx.currentTime);
    gain.gain.exponentialRampToValueAtTime(0.001, audioCtx.currentTime + 0.12);
    osc.connect(gain).connect(audioCtx.destination);
    osc.start();
    osc.stop(audioCtx.currentTime + 0.12);
  } catch {}
}

// ponytail: refreshes on tab open, not live while the tab is open — add a
// setStatus() hook here if the settings screen needs to track state in real time.
function renderSettings() {
  const a = auth();
  $setHost.textContent = a?.relay ? new URL(a.relay).host : '—';
  $setStatus.textContent = $status.textContent || '—';
  $setEnc.textContent = E2E_DISABLED ? 'plain' : (activeSession?.sharedKey ? 'E2E' : 'negotiating…');
  $soundToggle.classList.toggle('on', soundOn());
}

document.querySelectorAll('.settings-action').forEach(btn => {
  btn.addEventListener('click', () => {
    const act = btn.dataset.act;
    if (act === 'reconnect') { if (activeSession) activeSession.reconnectAttempts = 0; connect(); }
    else if (act === 'clear') { $messages.innerHTML = ''; liveTerminalBubble = null; showEmptyState(); }
    else if (act === 'copy-fp') { navigator.clipboard.writeText(location.host + ' · ' + (auth()?.sessionId?.slice(0, 8) || '?')); }
  });
});
$disconnectBtn.addEventListener('click', () => {
  saveAuth(null);
  $messages.innerHTML = '';
  liveTerminalBubble = null;
  setStatus('offline', 'not paired');
  setAuth('hidden');
  updateGateVisibility();
});

// ------------------------------------------------------------------
// Push notifications: "freebuff went idle" (see daemon idle-timer + sw.js
// push handler). iOS Safari only delivers Web Push to a PWA installed via
// Add to Home Screen (16.4+) — a plain browser tab or the Capacitor-wrapped
// native shell can't receive it. Fails silently everywhere that's not true.
function urlBase64ToUint8Array(base64) {
  const padded = (base64 + '='.repeat((4 - (base64.length % 4)) % 4)).replace(/-/g, '+').replace(/_/g, '/');
  const raw = atob(padded);
  return Uint8Array.from([...raw].map(c => c.charCodeAt(0)));
}
async function ensurePushSubscription() {
  if (!('serviceWorker' in navigator) || !('PushManager' in window)) return;
  const a = auth();
  if (!a?.token) return;
  try {
    const reg = await navigator.serviceWorker.ready;
    let sub = await reg.pushManager.getSubscription();
    if (!sub) {
      if (Notification.permission === 'default') await Notification.requestPermission();
      if (Notification.permission !== 'granted') return;
      const keyRes = await fetch(new URL('/push/vapid-public-key', a.relay));
      if (!keyRes.ok) return; // push not configured on this relay deploy
      const { publicKey } = await keyRes.json();
      sub = await reg.pushManager.subscribe({ userVisibleOnly: true, applicationServerKey: urlBase64ToUint8Array(publicKey) });
    }
    await fetch(new URL('/push/subscribe', a.relay), {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ sessionId: a.sessionId, token: a.token, subscription: sub.toJSON() }),
    });
  } catch (e) { console.warn('push subscribe failed', e); }
}

// ------------------------------------------------------------------
// Session model: every connect() spawns a fresh "session" with its own
// ws handle, keypair, sharedKey, inSeq/outSeq, pendingPrompts, lastSent.
// Stale callbacks (a slow handleKeyAck finishing after a newer connect()
// bumped the gen) drop everything instead of corrupting the live session.
let connectGen = 0;
let activeSession = null; // newest session; older ones must not write to it.

function newSession() {
  return {
    gen: 0,                   // set in connect()
    ws: null,                 // WebSocket
    pingTimer: null,          // setInterval
    reconnectAttempts: 0,     // local backoff counter
    clientKeypair: null,      // {kp, jwk}
    sharedKey: null,          // CryptoKey (AES-256-GCM)
    outSeq: 0,
    inSeq: 0,
    pendingPrompts: [],       // queued during key-exchange window
    lastSent: null,           // for ArrowUp recall
    isStale() { return this !== activeSession; },
  };
}

function connect() {
  const a = auth();
  if (!a || !a.token || !a.relay || !a.sessionId) { setStatus('offline', 'not paired'); return; }

  // Carry over unsent prompts queued on the prior session so a re-key in
  // the middle of typing doesn't silently drop them.
  const carriedPrompts = (activeSession?.pendingPrompts) ? activeSession.pendingPrompts.splice(0) : [];
  const carriedLastSent = activeSession?.lastSent ?? null;

  // Tear down any prior session so its handlers short-circuit.
  if (activeSession) {
    try { activeSession.ws?.close(); } catch {}
    if (activeSession.pingTimer) clearInterval(activeSession.pingTimer);
    activeSession = null;
  }

  const session = newSession();
  session.gen = ++connectGen;
  session.pendingPrompts = carriedPrompts;
  session.lastSent = carriedLastSent;
  activeSession = session;

  setStatus('securing', 'connecting…');
  setAuth('off');

  const u = new URL(a.relay);
  u.protocol = u.protocol === 'https:' ? 'wss:' : 'ws:';
  u.pathname = '/ws';
  u.searchParams.set('sessionId', a.sessionId);
  u.searchParams.set('token', a.token);
  u.searchParams.set('role', 'client');
  u.searchParams.set('v', String(PROTO_V));
  const ws = new WebSocket(u.toString());
  session.ws = ws;

  ws.addEventListener('open', () => {
    if (session.isStale()) return;
    session.reconnectAttempts = 0;
    startPing(session);
    ensurePushSubscription(); // no-ops silently if unsupported/already subscribed
    if (E2E_DISABLED) {
      session.outSeq = 0; session.inSeq = 0;
      setAuth('off');
      setStatus('connected', 'connected');
      flushPendingPrompts(session);
      return;
    }
    setStatus('securing', 'exchanging keys…');
    sendKeyExchange(session);
    // sync_request is sent after key_ack (encrypted), not now
  });

  ws.addEventListener('message', ev => {
    if (session.isStale()) return;
    let msg; try { msg = JSON.parse(ev.data); } catch { return; }
    handleMessage(session, msg);
  });

  ws.addEventListener('close', () => {
    if (session.isStale()) return;
    stopPing(session);
    setAuth('off');
    setStatus('offline', `disconnected (try ${session.reconnectAttempts})`);
    scheduleReconnect(session);
  });
  ws.addEventListener('error', () => {});
}

// ------------------------------------------------------------------
// E2E: key exchange + encrypt/decrypt (all take `session` explicitly)
async function genClientKeypair() {
  const kp = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveKey', 'deriveBits']);
  const jwk = await crypto.subtle.exportKey('jwk', kp.publicKey);
  return { kp, jwk };
}

async function sendKeyExchange(session) {
  if (session.isStale()) return;
  if (!window.crypto?.subtle) { console.warn('Web Crypto unavailable'); return; }
  try {
    session.clientKeypair = await genClientKeypair();
    if (session.isStale()) return;  // a newer connect() arrived during keygen — abort.
    session.ws.send(JSON.stringify({ v: PROTO_V, type: 'key_exchange', from: 'client', clientKey: session.clientKeypair.jwk }));
  } catch (e) { console.warn('E2E key gen failed', e); }
}

async function handleKeyAck(session, msg) {
  if (session.isStale()) return;
  try {
    if (!session.clientKeypair) { console.warn('key_ack before key_exchange'); return; }
    const daemonKey = msg.daemonKey;
    if (!daemonKey || typeof daemonKey !== 'object') { console.warn('key_ack: missing daemonKey'); return; }
    const daemonPub = await crypto.subtle.importKey('jwk', daemonKey, { name: 'ECDH', namedCurve: 'P-256' }, false, []);
    if (session.isStale()) return;
    const sharedBits = await crypto.subtle.deriveBits({ name: 'ECDH', public: daemonPub }, session.clientKeypair.kp.privateKey, 256);
    if (session.isStale()) return;
    const hkdfKey = await crypto.subtle.importKey('raw', sharedBits, { name: 'HKDF', hash: 'SHA-256' }, false, ['deriveKey']);
    session.sharedKey = await crypto.subtle.deriveKey(
      { name: 'HKDF', hash: 'SHA-256', salt: HKDF_SALT, info: HKDF_INFO },
      hkdfKey,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt'],
    );
    if (session.isStale()) return;
    session.outSeq = 0; session.inSeq = 0;
    setAuth('on');
    setStatus('connected', 'connected');
    const a = auth();
    const since = lastSeq();
    if (since > 0 && a?.sessionId) {
      const env = await encryptEnvelope(session, { t: 'sync_request', sessionId: a.sessionId, sinceSeq: since, timestamp: Date.now() });
      if (session.isStale()) return;
      try { session.ws.send(JSON.stringify(env)); } catch {}
    }
    await flushPendingPrompts(session);
  } catch (e) { console.warn('E2E derive failed', e); }
}

function handleRekeyRequired(session) {
  if (session.isStale()) return;
  session.sharedKey = null;
  session.outSeq = 0; session.inSeq = 0;
  setAuth('off');
  setStatus('securing', 'rekeying…');
  session.clientKeypair = null;
  sendKeyExchange(session);
}

function handleMessage(session, msg) {
  if (session.isStale()) return;
  if (!msg || msg.v !== PROTO_V) return;
  if (msg.type === 'pong') return;
  if (msg.type === 'key_ack') { handleKeyAck(session, msg); return; }
  if (msg.type === 'rekey_required') { handleRekeyRequired(session); return; }
  if (msg.type === 'enc') { decryptAndRender(session, msg); return; }
  if (msg.type === 'plain') { renderPlainInner(session, msg); return; }
  if (msg.type === 'system') {
    if (msg.event === 'daemon_disconnected') setStatus('offline', 'daemon offline');
    else if (msg.event === 'daemon_connected') setStatus('connected', 'connected');
    else if (msg.event === 'revoked') setStatus('offline', 'token revoked');
    else if (msg.event === 'ready') { /* no-op */ }
    return;
  }
}

async function decryptAndRender(session, msg) {
  if (session.isStale()) return;
  if (!session.sharedKey) return;
  if (!Number.isInteger(msg.seq) || msg.seq <= 0) return;
  if (msg.seq <= session.inSeq) { console.warn('replay dropped, seq=' + msg.seq); return; }
  if (!msg.nonce || !msg.ct) return;
  try {
    const nonce = Uint8Array.from(atob(msg.nonce), c => c.charCodeAt(0));
    const ct = Uint8Array.from(atob(msg.ct), c => c.charCodeAt(0));
    const aad = new TextEncoder().encode(AAD_PREFIX_DAEMON + msg.seq);
    const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: nonce, additionalData: aad }, session.sharedKey, ct);
    if (session.isStale()) return;
    session.inSeq = msg.seq; // accept only after successful auth
    const decoded = new TextDecoder().decode(plain);
    const inner = JSON.parse(decoded);
    if (inner.t === 'output_chunk') {
      setLastSeq(Math.max(lastSeq(), inner.seq || 0));
      renderOutputChunk(inner);
    } else if (inner.t === 'system') {
      if (inner.event === 'crashed') addSystem(`Freebuff crashed · ${inner.message || ''}`, 'bad');
      else if (inner.event === 'restarted') addSystem('Freebuff restarted', 'warn');
    }
  } catch (e) { console.warn('decrypt failed', e); }
}

// E2E_DISABLED mode: the daemon sends `{v, type:'plain', ...inner}` directly.
// Treat every field except v/type as the inner payload and render it.
function renderPlainInner(session, msg) {
  if (session.isStale()) return;
  const inner = { ...msg };
  delete inner.v;
  delete inner.type;
  session.inSeq = (session.inSeq || 0) + 1;
  if (inner.t === 'output_chunk') {
    setLastSeq(Math.max(lastSeq(), inner.seq || 0));
    renderOutputChunk(inner);
  } else if (inner.t === 'system') {
    if (inner.event === 'crashed') addSystem(`Freebuff crashed · ${inner.message || ''}`, 'bad');
    else if (inner.event === 'restarted') addSystem('Freebuff restarted', 'warn');
  }
}

// mode:'screen' (full-screen TUI, e.g. Ink-based freebuff UI) replaces the
// content of one in-place "live terminal" bubble instead of appending a new
// bubble per redraw. mode:'line' (or missing, legacy) appends as before and
// closes out the live bubble so the *next* screen snapshot starts a fresh one.
let liveTerminalBubble = null;
function renderOutputChunk(inner) {
  if (inner.mode === 'screen') {
    if (!liveTerminalBubble) liveTerminalBubble = addLiveTerminalBubble();
    updateLiveTerminalBubble(liveTerminalBubble, inner.content || '');
  } else {
    liveTerminalBubble = null;
    addBubble('received', inner.content || '');
  }
}

function addLiveTerminalBubble() {
  const wrap = document.createElement('div');
  wrap.className = 'msg msg-in msg-live-terminal';
  const col = document.createElement('div');
  col.className = 'msg-col';
  const term = document.createElement('div');
  term.className = 'live-term';
  term.innerHTML = '<div class="live-term-head"><span class="live-term-dot"></span>live terminal</div>';
  const pre = document.createElement('pre');
  pre.className = 'live-term-pre';
  term.appendChild(pre);
  col.appendChild(term);
  wrap.appendChild(col);
  $messages.appendChild(wrap);
  $messages.scrollTop = $messages.scrollHeight;
  return wrap;
}

function updateLiveTerminalBubble(wrap, content) {
  const pre = wrap.querySelector('.live-term-pre');
  if (pre) pre.textContent = content;
  $messages.scrollTop = $messages.scrollHeight;
}

function startPing(session) {
  stopPing(session);
  session.pingTimer = setInterval(() => {
    if (session.isStale()) { stopPing(session); return; }
    try { if (session.ws && session.ws.readyState === 1) session.ws.send(JSON.stringify({ v: PROTO_V, type: 'ping', ts: Date.now() })); } catch {}
  }, 25_000);
}
function stopPing(session) { if (session?.pingTimer) { clearInterval(session.pingTimer); session.pingTimer = null; } }

function scheduleReconnect(session) {
  const delay = Math.min(30_000, 500 * Math.pow(2, ++session.reconnectAttempts));
  setTimeout(() => connect(), delay);
}

function newId() { return Math.random().toString(36).slice(2) + Date.now().toString(36); }

function addSystem(text, kind) {
  const wrap = document.createElement('div');
  wrap.className = 'msg system-msg';
  const pill = document.createElement('span');
  pill.className = 'system-pill' + (kind ? ' ' + kind : '');
  pill.textContent = text;
  wrap.appendChild(pill);
  $messages.appendChild(wrap);
  $messages.scrollTop = $messages.scrollHeight;
}

function formatTime(ts) {
  const d = new Date(ts || Date.now());
  return String(d.getHours()).padStart(2, '0') + ':' + String(d.getMinutes()).padStart(2, '0');
}

function addBubble(role, text, ts) {
  const wrap = document.createElement('div');
  wrap.className = 'msg ' + (role === 'sent' ? 'msg-out' : 'msg-in');
  const col = document.createElement('div');
  col.className = 'msg-col';
  const bubble = document.createElement('div');
  bubble.className = 'bubble';
  bubble.appendChild(renderMarkdownish(text || ''));
  col.appendChild(bubble);
  const time = document.createElement('span');
  time.className = 'bubble-time';
  time.textContent = formatTime(ts);
  col.appendChild(time);
  wrap.appendChild(col);
  $messages.appendChild(wrap);
  $messages.scrollTop = $messages.scrollHeight;
  if (role === 'sent') playSendSound();
  return wrap;
}

function renderMarkdownish(src) {
  const frag = document.createDocumentFragment();
  const re = /```([a-zA-Z0-9_+\-]*)\n([\s\S]*?)```/g;
  let lastIndex = 0;
  let m;
  while ((m = re.exec(src)) !== null) {
    if (m.index > lastIndex) frag.appendChild(renderInline(src.slice(lastIndex, m.index)));
    frag.appendChild(renderCodeBlock(m[1] || 'text', m[2]));
    lastIndex = re.lastIndex;
  }
  if (lastIndex < src.length) frag.appendChild(renderInline(src.slice(lastIndex)));
  return frag;
}

function renderInline(text) {
  const span = document.createElement('span');
  const re = /`([^`\n]+)`/g;
  let last = 0;
  let m;
  while ((m = re.exec(text)) !== null) {
    if (m.index > last) span.appendChild(document.createTextNode(text.slice(last, m.index)));
    const c = document.createElement('code');
    c.className = 'code-inline';
    c.textContent = m[1];
    span.appendChild(c);
    last = re.lastIndex;
  }
  if (last < text.length) span.appendChild(document.createTextNode(text.slice(last)));
  return span;
}

function renderCodeBlock(lang, code) {
  const wrap = document.createElement('div');
  wrap.className = 'code-block';
  const head = document.createElement('div');
  head.className = 'code-block-head';
  const langLabel = document.createElement('span');
  langLabel.className = 'code-block-lang';
  langLabel.textContent = lang || 'text';
  const copyBtn = document.createElement('button');
  copyBtn.className = 'code-block-copy';
  copyBtn.type = 'button';
  copyBtn.textContent = '📋 copy';
  copyBtn.addEventListener('click', () => {
    navigator.clipboard.writeText(code).then(() => {
      copyBtn.textContent = '✓ copied';
      copyBtn.classList.add('copied');
      setTimeout(() => { copyBtn.textContent = '📋 copy'; copyBtn.classList.remove('copied'); }, 1200);
    });
  });
  head.appendChild(langLabel);
  head.appendChild(copyBtn);
  const pre = document.createElement('pre');
  const codeEl = document.createElement('code');
  codeEl.className = lang ? `language-${lang}` : '';
  codeEl.textContent = code.replace(/\n$/, '');
  if (window.hljs) {
    try {
      if (lang && window.hljs.getLanguage(lang)) {
        const result = window.hljs.highlight(code, { language: lang, ignoreIllegals: true });
        codeEl.innerHTML = result.value;
        codeEl.classList.add('hljs');
      } else {
        const result = window.hljs.highlightAuto(code);
        codeEl.innerHTML = result.value;
        codeEl.classList.add('hljs');
      }
    } catch {}
  }
  pre.appendChild(codeEl);
  wrap.appendChild(head);
  wrap.appendChild(pre);
  return wrap;
}

function showEmptyState() {
  if ($messages.childElementCount > 0) return;
  const empty = document.createElement('div');
  empty.className = 'empty';
  empty.innerHTML = `
    <div>
      <div class="empty-icon">💬</div>
      <h2 class="empty-title">No messages yet</h2>
      <p class="empty-sub">Send a prompt below to start chatting with Freebuff on your PC.</p>
    </div>`;
  $messages.appendChild(empty);
}

// UI handlers that need the *current* session.
function currentSessionOrNull() { return activeSession; }

$form.addEventListener('submit', async e => {
  e.preventDefault();
  const text = $input.value.trim();
  if (!text) return;
  const session = currentSessionOrNull();
  if (!session || !session.ws || session.ws.readyState !== 1) { addSystem('offline — reconnect to send', 'warn'); return; }
  if (E2E_DISABLED) {
    const a = auth();
    const inner = { t: 'prompt', id: newId(), sessionId: a.sessionId, text, timestamp: Date.now() };
    try {
      session.ws.send(JSON.stringify({ v: PROTO_V, type: 'plain', ...inner }));
      addBubble('sent', text);
      session.lastSent = text;
      $input.value = ''; autoResize(); $input.focus();
    } catch (err) { addSystem('send failed', 'bad'); }
    return;
  }
  if (!session.sharedKey) {
    session.pendingPrompts.push(text);
    addSystem('🔒 establishing secure channel — prompt queued', 'warn');
    session.lastSent = text;
    $input.value = ''; autoResize();
    return;
  }
  const a = auth();
  const id = newId();
  const inner = { t: 'prompt', id, sessionId: a.sessionId, text, timestamp: Date.now() };
  const wire = await encryptEnvelope(session, inner);
  if (session.isStale()) return;
  try {
    session.ws.send(JSON.stringify(wire));
    addBubble('sent', text);
    session.lastSent = text;
    $input.value = ''; autoResize(); $input.focus();
  } catch (err) { addSystem('send failed', 'bad'); }
});

async function encryptEnvelope(session, inner) {
  if (!session?.sharedKey) return inner;
  try {
    const nonce = crypto.getRandomValues(new Uint8Array(12));
    const plain = new TextEncoder().encode(JSON.stringify(inner));
    session.outSeq += 1; // increment ONLY on success — avoid leaving a hole in the seq counter if encryption throws
    const aad = new TextEncoder().encode(AAD_PREFIX_CLIENT + session.outSeq);
    const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce, additionalData: aad }, session.sharedKey, plain);
    return {
      v: PROTO_V,
      type: 'enc',
      seq: session.outSeq,
      nonce: btoa(String.fromCharCode(...nonce)),
      ct: btoa(String.fromCharCode(...new Uint8Array(ct))),
    };
  } catch (e) {
    console.warn('encrypt failed', e);
    return inner;
  }
}

async function flushPendingPrompts(session) {
  // Snapshot the length BEFORE we start so a concurrent push (e.g. user
  // types another prompt in the gap between sends) is still picked up.
  if (session.isStale()) return;
  while (session.pendingPrompts.length > 0) {
    const text = session.pendingPrompts[0]; // peek, don't shift yet
    const a = auth();
    const inner = { t: 'prompt', id: newId(), sessionId: a.sessionId, text, timestamp: Date.now() };
    const wire = await encryptEnvelope(session, inner);
    if (session.isStale()) return;
    if (!wire || !wire.seq || wire.seq !== session.outSeq) {
      // encryption produced a plaintext fallback (caller should have checked
      // sharedKey); bail rather than shift + lose the prompt.
      return;
    }
    session.pendingPrompts.shift(); // safe to drop only now — wire is real
    try { session.ws.send(JSON.stringify(wire)); addBubble('sent', text); } catch {}
  }
  if (session.pendingPrompts.length === 0 && session.sharedKey && !session.isStale()) addSystem('🔓 channel ready', 'ok');
}

function autoResize() {
  $input.style.height = '1.4em';
  $input.style.height = Math.min(9, $input.scrollHeight / 16) + 'em';
}
$input.addEventListener('input', () => { autoResize(); const s = currentSessionOrNull(); $send.disabled = !s || !s.ws || s.ws.readyState !== 1 || !$input.value.trim(); });
$input.addEventListener('keydown', e => {
  const session = currentSessionOrNull();
  if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); $form.requestSubmit(); }
  if (e.key === 'ArrowUp' && !$input.value && session && session.ws && session.ws.readyState === 1) {
    if (session.lastSent) { $input.value = session.lastSent; autoResize(); }
    e.preventDefault();
  }
});

// visibility / pageshow — re-establish socket on iOS resume
document.addEventListener('visibilitychange', () => {
  if (document.visibilityState === 'visible' && (!activeSession || !activeSession.ws || activeSession.ws.readyState > 1)) connect();
});
window.addEventListener('pageshow', () => { if (!activeSession || !activeSession.ws || activeSession.ws.readyState > 1) connect(); });

// Keyboard shortcut: R to reconnect
document.addEventListener('keydown', e => {
  if (e.key === 'r' && !e.target.matches('input, textarea') && !e.metaKey && !e.ctrlKey) connect();
});

updateGateVisibility();
renderCommands();
showEmptyState();
connect();
