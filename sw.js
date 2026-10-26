const CACHE_NAME = 'lager-rezeptur-v12';

const APP_SHELL = [
  './',
  './index.html',
  './manifest.json',
  './icon-192.png',
  './icon-512.png',
];

// Bibliotheken, die mit crossorigin/integrity geladen werden. Sie MÜSSEN als CORS-Antwort im Speicher
// liegen – eine "no-cors"-Antwort (opaque) lehnt der Browser dafür ab und die App bleibt bei
// "Lade die App …" hängen.
const CDN_ASSETS = [
  'https://cdnjs.cloudflare.com/ajax/libs/react/18.2.0/umd/react.production.min.js',
  'https://cdnjs.cloudflare.com/ajax/libs/react-dom/18.2.0/umd/react-dom.production.min.js',
  'https://cdnjs.cloudflare.com/ajax/libs/babel-standalone/7.24.7/babel.min.js',
  'https://cdnjs.cloudflare.com/ajax/libs/qrcode-generator/1.4.4/qrcode.min.js',
  'https://cdn.jsdelivr.net/npm/tesseract.js@5/dist/tesseract.min.js',
  'https://cdn.jsdelivr.net/npm/xlsx@0.18.5/dist/xlsx.full.min.js',
];

const brauchbar = (res) => res && res.ok && res.type !== 'opaque';

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) =>
      Promise.all([
        ...APP_SHELL.map((url) =>
          fetch(new Request(url, { cache: 'reload' })).then((res) => brauchbar(res) && cache.put(url, res)).catch(() => {})
        ),
        ...CDN_ASSETS.map((url) =>
          fetch(new Request(url, { mode: 'cors', credentials: 'omit' })).then((res) => brauchbar(res) && cache.put(url, res)).catch(() => {})
        ),
      ])
    ).then(() => self.skipWaiting())
  );
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(keys.filter((k) => k !== CACHE_NAME).map((k) => caches.delete(k)))
    ).then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', (event) => {
  const req = event.request;
  if (req.method !== 'GET') return;
  // Online-Speicher nie aus dem Cache – sonst sieht man alte Daten
  if (req.url.includes('api.jsonbin.io') || req.url.includes('api.qrserver.com')) return;

  // Eine opaque-Antwort darf nur an eine no-cors-Anfrage gehen (z.B. <script> ohne crossorigin)
  const passt = (res) => res && !(res.type === 'opaque' && req.mode !== 'no-cors');
  const speichern = (res) => {
    if (res && (res.ok || (res.type === 'opaque' && req.mode === 'no-cors'))) {
      const kopie = res.clone();
      caches.open(CACHE_NAME).then((cache) => cache.put(req, kopie));
    }
    return res;
  };

  // Die Seite selbst: zuerst aus dem Netz (immer die neueste Version), offline aus dem Speicher
  if (req.mode === 'navigate') {
    event.respondWith(
      fetch(req)
        .then(speichern)
        .catch(() => caches.match(req).then((c) => c || caches.match('./index.html')))
    );
    return;
  }

  // Alles andere: aus dem Speicher, im Hintergrund aktualisieren
  event.respondWith(
    caches.match(req).then((cached) => {
      const netz = fetch(req).then(speichern);
      if (passt(cached)) {
        netz.catch(() => {});
        return cached;
      }
      return netz.catch(() => Response.error());
    })
  );
});
