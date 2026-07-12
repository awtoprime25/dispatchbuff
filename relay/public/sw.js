// mobile/sw.js — offline shell + cached CDN deps + push notifications.
const CACHE = 'dispatch-v10';
const SHELL = [
  '/', '/index.html', '/pair.html',
  '/styles.css', '/app.js', '/pair.js',
  '/manifest.json', '/icon.svg', '/icon-180.png',
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

// "freebuff went idle" push (see daemon idle-timer -> relay sendPush()).
// Skip the system notification if a tab is already open and visible — the
// in-app UI is enough, no need to double-notify.
self.addEventListener('push', (e) => {
  let data = {};
  try { data = e.data ? e.data.json() : {}; } catch {}
  e.waitUntil(
    self.clients.matchAll({ type: 'window', includeUncontrolled: true }).then(clients => {
      if (clients.some(c => c.visibilityState === 'visible')) return;
      return self.registration.showNotification(data.title || 'DispatchFreeBuff', {
        body: data.body || 'freebuff finished',
        icon: '/icon-180.png',
        badge: '/icon-180.png',
        tag: 'dispatch-idle',
      });
    })
  );
});

self.addEventListener('notificationclick', (e) => {
  e.notification.close();
  e.waitUntil(
    self.clients.matchAll({ type: 'window', includeUncontrolled: true }).then(clients => {
      for (const c of clients) if ('focus' in c) return c.focus();
      if (self.clients.openWindow) return self.clients.openWindow('/');
    })
  );
});
