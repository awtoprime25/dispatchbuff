// mobile/sw.js — offline shell + cached CDN deps.
const CACHE = 'dispatch-v8';
const SHELL = [
  '/', '/index.html', '/pair.html',
  '/styles.css', '/app.js', '/pair.js',
  '/manifest.json', '/icon.svg',
];
const CDN = [
  'https://cdn.jsdelivr.net/npm/highlight.js@11.10.0/lib/core.min.js',
  'https://cdn.jsdelivr.net/npm/highlight.js@11.10.0/styles/atom-one-dark.min.css',
  'https://cdn.jsdelivr.net/npm/highlight.js@11.10.0/languages/javascript.min.js',
  'https://cdn.jsdelivr.net/npm/highlight.js@11.10.0/languages/typescript.min.js',
  'https://cdn.jsdelivr.net/npm/highlight.js@11.10.0/languages/python.min.js',
  'https://cdn.jsdelivr.net/npm/highlight.js@11.10.0/languages/bash.min.js',
  'https://cdn.jsdelivr.net/npm/highlight.js@11.10.0/languages/json.min.js',
  'https://cdn.jsdelivr.net/npm/highlight.js@11.10.0/languages/xml.min.js',
  'https://cdn.jsdelivr.net/npm/highlight.js@11.10.0/languages/css.min.js',
  'https://cdn.jsdelivr.net/npm/highlight.js@11.10.0/languages/markdown.min.js',
];

self.addEventListener('install', (e) => {
  e.waitUntil(Promise.all([
    caches.open(CACHE).then(c => c.addAll(SHELL).catch(() => {})),
    caches.open(`${CACHE}-cdn`).then(c => c.addAll(CDN).catch(() => {})),
  ]));
  self.skipWaiting();
});

self.addEventListener('activate', (e) => {
  e.waitUntil(
    caches.keys().then(keys => Promise.all(
      keys.filter(k => k !== CACHE && k !== `${CACHE}-cdn`).map(k => caches.delete(k))
    ))
  );
  self.clients.claim();
});

self.addEventListener('fetch', (e) => {
  const url = new URL(e.request.url);
  if (e.request.method !== 'GET') return;
  if (url.pathname.startsWith('/pair/') || url.pathname === '/ws') return; // never cache API/WS
  if (url.hostname === 'cdn.jsdelivr.net' || url.hostname === 'cdnjs.cloudflare.com') {
    e.respondWith(
      caches.open(`${CACHE}-cdn`).then(c => c.match(e.request).then(r => r ?? fetch(e.request)))
    );
    return;
  }
  e.respondWith(
    caches.open(CACHE).then(c => c.match(e.request).then(r => r ?? fetch(e.request).catch(() => c.match('/'))))
  );
});
