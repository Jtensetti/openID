'use strict';
const form = document.querySelector('#complete');
const status = document.querySelector('#status');
let stopped = false;
async function poll() {
  try {
    const response = await fetch('/phone/poll', { method: 'POST', body: new URLSearchParams(new FormData(form)), credentials: 'same-origin', cache: 'no-store' });
    if (!response.ok) throw Error();
    const { state } = await response.json();
    if (state === 'APPROVED') { stopped = true; form.requestSubmit(); return; }
    if (state !== 'PENDING') throw Error();
    if (!stopped) setTimeout(poll, 1500);
  } catch {
    stopped = true; status.textContent = 'Inloggningen har avslutats. Börja om i tjänsten.';
  }
}
window.addEventListener('pagehide', () => { stopped = true; });
poll();
