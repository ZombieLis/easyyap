// EasyYap Service Worker
const CACHE = 'easyyap-v1';

// Files to cache for offline use
const PRECACHE = [
  '/',
  '/index.html',
  '/manifest.json'
];

// Install — cache core files
self.addEventListener('install', e => {
  e.waitUntil(
    caches.open(CACHE).then(c => c.addAll(PRECACHE))
  );
  self.skipWaiting();
});

// Activate — clean up old caches
self.addEventListener('activate', e => {
  e.waitUntil(
    caches.keys().then(keys =>
      Promise.all(keys.filter(k => k !== CACHE).map(k => caches.delete(k)))
    )
  );
  self.clients.claim();
});

// Fetch — network first, fall back to cache
self.addEventListener('fetch', e => {
  // Don't intercept API calls or Supabase — always go to network for those
  if(e.request.url.includes('/api/') || e.request.url.includes('supabase.co')) {
    return;
  }
  e.respondWith(
    fetch(e.request)
      .then(res => {
        // Cache a copy of successful responses
        const copy = res.clone();
        caches.open(CACHE).then(c => c.put(e.request, copy));
        return res;
      })
      .catch(() => caches.match(e.request))
  );
});
