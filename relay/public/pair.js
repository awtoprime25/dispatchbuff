// mobile/pair.js — Pairing flow (protocol v2).
// - Generates an ephemeral ECDH P-256 keypair and sends clientPub in the
//   redeem body so the daemon can derive a shared AES-256-GCM key on first
//   connect (saves one round-trip).
// - The keypair is NOT persisted — we re-generate on every reconnect. The
//   daemon also re-generates on every start, so a stolen token + stale key
//   material is useless.
const AUTH_KEY = 'dispatch_auth';
const RELAY_KEY = 'dispatch_relay_host';
const SESSION_KEY = 'dispatch_last_session';

const params = new URL(location.href).searchParams;
const urlSessionId = params.get('session') || '';
// We accept the code from the URL (e.g. when the user scanned the QR) so
// they don't have to type it manually. Up to 6 chars, A-Z 0-9 (relay charset).
const urlCode = (params.get('code') || '').trim().toUpperCase().slice(0, 6);
const wantScan = params.has('scan');

const $form = document.getElementById('manual');
const $session = document.getElementById('session');
const $code = document.getElementById('code');
const $status = document.getElementById('status');
const $video = document.getElementById('cam');

function relayBase() { return localStorage.getItem(RELAY_KEY) || location.origin; }
function setStatus(s, kind) {
  $status.textContent = s;
  $status.classList.remove('err', 'ok');
  if (kind === 'err') $status.classList.add('err');
  if (kind === 'ok') $status.classList.add('ok');
}

async function genClientPub() {
  if (!window.crypto?.subtle) return null;
  try {
    const kp = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveKey', 'deriveBits']);
    const raw = await crypto.subtle.exportKey('raw', kp.publicKey);
    return btoa(String.fromCharCode(...new Uint8Array(raw)));
  } catch { return null; }
}

$form.addEventListener('submit', async e => {
  e.preventDefault();
  const sessionId = ($session.value || '').trim();
  const code = ($code.value || '').trim().toUpperCase();
  if (!sessionId || !code) { setStatus('Error: missing session or code', 'err'); $code.classList.add('error'); setTimeout(() => $code.classList.remove('error'), 280); return; }
  localStorage.setItem(SESSION_KEY, sessionId);
  setStatus('Generating encryption keys…');
  const clientPub = await genClientPub();
  setStatus('Pairing…');
  try {
    const res = await fetch(`${relayBase()}/pair/redeem`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ sessionId, code, role: 'client', v: 2, clientPub }),
    });
    const data = await res.json().catch(() => null);
    if (!res.ok || !data || !data.token) throw new Error((data && data.error) || `HTTP ${res.status}`);
    localStorage.setItem(AUTH_KEY, JSON.stringify({
      sessionId, token: data.token, relay: relayBase(), pairedAt: Date.now(),
      e2e: !!clientPub,
    }));
    setStatus('Paired! Opening chat…', 'ok');
    setTimeout(() => { location.href = '/'; }, 400);
  } catch (err) { setStatus('Error: ' + (err.message || err), 'err'); $code.classList.add('error'); setTimeout(() => $code.classList.remove('error'), 280); }
});

async function startCamera() {
  try {
    const { default: jsQR } = await import('https://cdn.jsdelivr.net/npm/jsqr@1.4.0/+esm');
    const stream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: 'environment' }, audio: false });
    $video.srcObject = stream; await $video.play();
    tick(jsQR);
  } catch (err) { setStatus('Camera unavailable: ' + (err.message || err) + '. Type the code manually.'); }
}
function tick(jsQR) {
  if (!$video.videoWidth) { requestAnimationFrame(() => tick(jsQR)); return; }
  const c = document.createElement('canvas');
  c.width = $video.videoWidth; c.height = $video.videoHeight;
  const ctx = c.getContext('2d', { willReadFrequently: true });
  ctx.drawImage($video, 0, 0);
  const img = ctx.getImageData(0, 0, c.width, c.height);
  const code = jsQR(img.data, img.width, img.height);
  if (code && code.data) {
    const m = String(code.data).match(/[?&]code=([A-Z0-9]+)/i);
    if (m) {
      $code.value = m[1].toUpperCase();
      try { $video.srcObject && $video.srcObject.getTracks().forEach(t => t.stop()); } catch {}
      $form.requestSubmit();
      return;
    }
  }
  requestAnimationFrame(() => tick(jsQR));
}

// Paste-the-whole-link shortcut: if what lands in the session field is a
// full pairing URL (copied straight from the PC's `dispatch pair` output),
// pull session+code out of it and submit — no need to juggle two fields.
function tryAutoFillFromPastedLink() {
  const val = ($session.value || '').trim();
  if (!/^https?:\/\//i.test(val)) return false;
  let parsed;
  try { parsed = new URL(val); } catch { return false; }
  const s = parsed.searchParams.get('session') || '';
  const c = (parsed.searchParams.get('code') || '').trim().toUpperCase();
  if (!s || !/^[A-Z0-9]{6}$/.test(c)) return false;
  $session.value = s;
  $code.value = c;
  $code.classList.add('auto-filled');
  setStatus('Link recognised — pairing…');
  $form.requestSubmit();
  return true;
}
$session.addEventListener('input', tryAutoFillFromPastedLink);

// Session ID: URL param (QR/manual link) wins, else the last one typed here.
$session.value = urlSessionId || localStorage.getItem(SESSION_KEY) || '';

// Pre-fill the code field from the URL so scanning the QR is one tap, not two.
if (urlCode && /^[A-Z0-9]{6}$/.test(urlCode)) {
  $code.value = urlCode;
  $code.classList.add('auto-filled');
  setStatus(`Code pre-filled. Tap Pair to confirm.`);
} else if ($session.value) {
  setStatus('Enter the 6-letter code from your PC terminal.');
} else {
  setStatus('Enter the session ID and code from your PC terminal.');
}

if (wantScan) startCamera();
