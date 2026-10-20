'use strict';
// No cache of pages, identities, CSRF tokens, ceremonies or federation messages.
self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', event => event.waitUntil(self.clients.claim()));
self.addEventListener('fetch', event => {
  if (event.request.mode !== 'navigate' || event.request.method !== 'GET') return;
  event.respondWith(fetch(event.request).catch(() => new Response(
    '<!doctype html><html lang="sv"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>openID · offline</title><h1>Anslut för att använda ditt test-ID</h1><p>Registrering, inloggning och spärr kräver kontakt med servern. Ingen offlineinloggning görs.</p><a href="/wallet/">Försök igen</a></html>',
    {status: 503, headers: {'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store',
      'Content-Security-Policy': "default-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"}})));
});
