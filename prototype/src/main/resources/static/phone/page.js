'use strict';
const form = document.querySelector('#complete');
const status = document.querySelector('#status');
const signing = document.querySelector('main')?.dataset?.kind === 'sign';
const words = signing
  ? { flow: 'underskriften', Flow: 'Underskriften', start: 'starta en ny underskrift', Start: 'Starta en ny underskrift' }
  : { flow: 'inloggningen', Flow: 'Inloggningen', start: 'starta en ny inloggning', Start: 'Starta en ny inloggning' };
let stopped = false, failures = 0, controller, completionTimer, completing = false;
function completionFailed() {
  completing = false; clearTimeout(completionTimer);
  finish('Återgången till tjänsten kunde inte slutföras', 'Appens godkännande togs emot, men tjänstens resultat kunde inte visas. Starta ett nytt test från tjänstens testsida.');
}
// back: the service is told the user stopped (SAML status cancel) instead of a local dead end.
function finish(title, message, back = false) {
  stopped = true;
  document.querySelector('#heading').textContent = title;
  status.textContent = message;
  for (const selector of ['.qr', '#control-code', '#open-app', '#complete', '#cancel', '.sign-message']) {
    const node = document.querySelector(selector); if (node) node.hidden = true;
  }
  const back_ = document.querySelector('#return');
  if (back && back_) back_.hidden = false;
  else document.querySelector('#restart').hidden = false;
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
      finish(`${words.Flow} kunde inte slutföras`, `Begäran är inte längre tillgänglig eller ditt ID kunde inte kontrolleras. Kontrollera status under Mitt ID i appen och ${words.start} sedan.`); return;
    }
    const { state } = await response.json();
    if (stopped) return;
    failures = 0;
    if (state === 'APPROVED') {
      stopped = true; completing = true;
      status.textContent = `Godkännandet är mottaget. Slutför ${words.flow}…`;
      completionTimer = setTimeout(completionFailed, 15000);
      try { form.requestSubmit(); } catch { completionFailed(); }
      return;
    }
    if (state === 'REJECTED') { finish(signing ? 'Du avböjde underskriften' : 'Du nekade legitimeringen', signing ? 'Ingenting har skrivits under. Tjänsten får besked om att du avböjde.' : 'Du har inte loggats in. Om du vill försöka igen, starta en ny inloggning.', true); return; }
    if (state === 'CANCELLED') { finish(`${words.Flow} avbröts`, `Begäran har avslutats. ${words.Start} när du vill försöka igen.`); return; }
    if (state === 'EXPIRED') { finish('QR-koden har gått ut', `Tiden för att godkänna är slut. ${words.Start} och skanna den nya QR-koden med openID-appen.`); return; }
    if (state !== 'PENDING') { finish('Begäran har avslutats', `Den här QR-koden kan inte användas igen. ${words.Start}.`); return; }
    status.textContent = 'Väntar på ditt godkännande i openID-appen.';
    setTimeout(poll, 1500);
  } catch {
    if (stopped) return;
    if (++failures < 3) { status.textContent = 'Anslutningen avbröts. Försöker hämta status igen…'; setTimeout(poll, 1500); }
    else finish(signing ? 'Kunde inte hämta underskriftens status' : 'Kunde inte hämta inloggningens status', `Kontrollera anslutningen. Om du redan godkänt, kontrollera Aktivitet i appen innan du ${words.start}.`);
  }
}
document.querySelector('#cancel').addEventListener('submit', async event => {
  event.preventDefault(); stopped = true; controller?.abort();
  const body = new URLSearchParams(new FormData(event.currentTarget));
  document.querySelector('#cancel button').disabled = true;
  try {
    const response = await post('/phone/cancel', body);
    if (!response.ok) throw Error();
    finish(`${words.Flow} avbröts`, 'Begäran har avslutats. Tjänsten får besked om att du avbröt.', true);
  } catch {
    finish('Avbrottet kunde inte bekräftas', `Godkänn inte den gamla begäran i appen. Kontrollera Aktivitet om du redan godkänt. Du kan sedan ${words.start}.`);
  }
});
document.addEventListener('securitypolicyviolation', event => {
  if (completing && event.effectiveDirective === 'form-action') completionFailed();
});
window.addEventListener('pagehide', () => { stopped = true; completing = false; clearTimeout(completionTimer); controller?.abort(); });
poll();
