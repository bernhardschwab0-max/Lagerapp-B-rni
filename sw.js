const CACHE_NAME = 'lager-rezeptur-v4';

const APP_SHELL = [
  './',
  './index.html',
  './manifest.json',
  './icon-192.png',
  './icon-512.png',
];

const CDN_ASSETS = [
  'https://cdnjs.cloudflare.com/ajax/libs/react/18.2.0/umd/react.production.min.js',
  'https://cdnjs.cloudflare.com/ajax/libs/react-dom/18.2.0/umd/react-dom.production.min.js',
  'https://cdnjs.cloudflare.com/ajax/libs/babel-standalone/7.24.7/babel.min.js',
  'https://cdn.tailwindcss.com',
  'https://cdnjs.cloudflare.com/ajax/libs/qrcode-generator/1.4.4/qrcode.min.js',
  'https://cdn.jsdelivr.net/npm/tesseract.js@5/dist/tesseract.min.js',
  'https://cdn.jsdelivr.net/npm/xlsx@0.18.5/dist/xlsx.full.min.js',
];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => {
      const shellReqs = APP_SHELL.map((url) => new Request(url, { cache: 'reload' }));
      const cdnReqs = CDN_ASSETS.map((url) => new Request(url, { mode: 'no-cors' }));
      return Promise.all(
        [...shellReqs, ...cdnReqs].map((req) =>
          fetch(req).then((res) => cache.put(req, res)).catch(() => {})
        )
      );
    }).then(() => self.skipWaiting())
  );
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(keys.filter((k) => k !== CACHE_NAME).map((k) => caches.delete(k)))
    ).then(() => self.clients.claim())
  );
});

// Cache-first, mit Hintergrund-Aktualisierung (stale-while-revalidate) und Netzwerk-Fallback.
self.addEventListener('fetch', (event) => {
  if (event.request.method !== 'GET') return;
  // Online-Speicher und QR-Codes nie aus dem Cache – sonst sieht man alte Daten
  if (event.request.url.includes('api.jsonbin.io') || event.request.url.includes('api.qrserver.com')) return;

  event.respondWith(
    caches.match(event.request).then((cached) => {
      const fetchPromise = fetch(event.request)
        .then((networkRes) => {
          caches.open(CACHE_NAME).then((cache) => cache.put(event.request, networkRes.clone()));
          return networkRes;
        })
        .catch(() => cached);

      return cached || fetchPromise;
    })
  );
});
