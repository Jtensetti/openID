'use strict';
const form = document.querySelector('#complete');
const status = document.querySelector('#status');
let stopped = false, failures = 0, controller;
function finish(title, message) {
  stopped = true;
  document.querySelector('#heading').textContent = title;
  status.textContent = message;
  for (const selector of ['.qr', '#control-code', '#open-app', '#complete', '#cancel']) document.querySelector(selector).hidden = true;
  document.querySelector('#restart').hidden = false;
}
async function post(path, body) {
  const current = new AbortController(); controller = current;
  const timeout = setTimeout(() => current.abort(), 8000);
  try {
    return await fetch(path, { method: 'POST', body, credentials: 'same-origin', cache: 'no-store', signal: current.signal });
  } finally { clearTimeout(timeout); }
}
async function poll() {
  if (stopped) return;
  try {
    const response = await post('/phone/poll', new URLSearchParams(new FormData(form)));
    if (stopped) return;
    if (!response.ok) {
      if (response.status >= 500 || response.status === 429) throw Error();
      finish('Inloggningen kunde inte slutföras', 'Begäran är inte längre tillgänglig eller ditt ID kunde inte kontrolleras. Kontrollera status under Mitt ID i appen och starta sedan en ny inloggning.'); return;
    }
    const { state } = await response.json();
    if (stopped) return;
    failures = 0;
    if (state === 'APPROVED') { stopped = true; status.textContent = 'Godkännandet är mottaget. Slutför inloggningen…'; form.requestSubmit(); return; }
    if (state === 'REJECTED') { finish('Du nekade legitimeringen', 'Du har inte loggats in. Om du vill försöka igen, starta en ny inloggning.'); return; }
    if (state === 'CANCELLED') { finish('Inloggningen avbröts', 'Begäran har avslutats. Starta en ny inloggning när du vill försöka igen.'); return; }
    if (state === 'EXPIRED') { finish('QR-koden har gått ut', 'Tiden för att godkänna är slut. Starta en ny inloggning och skanna den nya QR-koden med openID-appen.'); return; }
    if (state !== 'PENDING') { finish('Begäran har avslutats', 'Den här QR-koden kan inte användas igen. Starta en ny inloggning.'); return; }
    status.textContent = 'Väntar på ditt godkännande i openID-appen.';
    setTimeout(poll, 1500);
  } catch {
    if (stopped) return;
    if (++failures < 3) { status.textContent = 'Anslutningen avbröts. Försöker hämta status igen…'; setTimeout(poll, 1500); }
    else finish('Kunde inte hämta inloggningens status', 'Kontrollera anslutningen. Om du redan godkänt, kontrollera Aktivitet i appen innan du startar en ny inloggning.');
  }
}
document.querySelector('#cancel').addEventListener('submit', async event => {
  event.preventDefault(); stopped = true; controller?.abort();
  const body = new URLSearchParams(new FormData(event.currentTarget));
  document.querySelector('#cancel button').disabled = true;
  try {
    const response = await post('/phone/cancel', body);
    if (!response.ok) throw Error();
    finish('Inloggningen avbröts', 'Begäran har avslutats. Starta en ny inloggning när du vill försöka igen.');
  } catch {
    finish('Avbrottet kunde inte bekräftas', 'Godkänn inte den gamla begäran i appen. Kontrollera Aktivitet om du redan godkänt. Du kan sedan starta en ny inloggning.');
  }
});
window.addEventListener('pagehide', () => { stopped = true; controller?.abort(); });
poll();
