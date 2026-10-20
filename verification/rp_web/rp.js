'use strict';
const byId = id => document.getElementById(id);
const panels = ['loading', 'ready', 'pending', 'authenticated', 'unavailable', 'offline'];
let csrf = null, current = 'LOADING', timer = null, generation = 0, busy = false, deadline = 0;
const titles = {READY:'Redo att logga in.', PENDING:'Bekräfta begäran i openID-appen.', AUTHENTICATED:'Du är inloggad.', UNAVAILABLE:'Sessionen är avslutad.', OFFLINE:'Sessionen kan inte bekräftas.'};

function stop() { clearTimeout(timer); timer = null; }
function show(state) {
  current = state;
  for (const id of panels) byId(id).hidden = id !== state.toLowerCase();
  byId('error').hidden = true;
  byId('status').textContent = titles[state] || '';
  if (state !== 'AUTHENTICATED') { byId('subject').textContent = ''; byId('session-until').textContent = ''; }
  if (state !== 'PENDING') { byId('qr').removeAttribute('src'); byId('code').textContent = ''; }
}
function connectionLost() { generation++; stop(); busy = false; csrf = null; deadline = 0; show('OFFLINE'); setBusy(false); }
function setBusy(value) { busy = value; for (const button of document.querySelectorAll('button')) button.disabled = value; }
async function api(path, body) {
  const response = await fetch(path, {method:body === undefined ? 'GET' : 'POST', credentials:'same-origin', cache:'no-store', redirect:'error',
    headers:body === undefined ? {} : {'Content-Type':'application/json','X-CSRF-Token':csrf},
    body:body === undefined ? undefined : JSON.stringify(body), signal:AbortSignal.timeout(8000)});
  const data = await response.json();
  if (!response.ok) { const error = Error(data.error || 'Begäran kunde inte slutföras.'); error.httpStatus = response.status; throw error; }
  return data;
}
function apply(data) {
  if (!['READY','PENDING','AUTHENTICATED','UNAVAILABLE'].includes(data.state) || !/^[a-f0-9]{64}$/.test(data.csrf) ||
      !Number.isFinite(data.expiresAt) || !Number.isFinite(data.serverTime)) throw Error('Ogiltigt svar.');
  if (data.state === 'PENDING' && (!data.request || !/^[a-f0-9]{64}$/.test(data.request.id) ||
      !/^\d{6}$/.test(data.request.code) || !Number.isFinite(data.request.expiresAt))) throw Error('Ogiltig begäran.');
  if (data.state === 'AUTHENTICATED' && (data.audience !== 'openid-local-demo' || data.assurance !== 'PRIVATE_PILOT' ||
      !/^[a-f0-9]{64}$/.test(data.subject))) throw Error('Ogiltig session.');
  const oldState = current;
  csrf = data.csrf;
  show(data.state);
  deadline = Date.now() + Math.max(0, data.expiresAt - data.serverTime) * 1000;
  if (data.state === 'PENDING') {
    const request = data.request;
    byId('rp-name').textContent = data.relyingParty;
    byId('code').textContent = request.code;
    if (oldState !== 'PENDING') byId('qr').src = '/qr.svg';
    deadline = Math.min(deadline, Date.now() + Math.max(0, request.expiresAt - data.serverTime) * 1000);
    byId('countdown').textContent = 'Begäran gäller i ' + Math.max(0, Math.ceil((deadline-Date.now())/1000)) + ' sekunder';
  }
  if (data.state === 'AUTHENTICATED') {
    byId('subject').textContent = data.subject;
    byId('session-until').textContent = new Date(deadline).toLocaleTimeString('sv-SE', {hour:'2-digit',minute:'2-digit'});
  }
  if (oldState !== data.state && oldState !== 'LOADING') {
    const heading = byId(data.state.toLowerCase()).querySelector('h2');
    heading.tabIndex = -1; heading.focus({preventScroll:true});
  }
  schedule();
}
function schedule() {
  stop();
  if (!document.hidden && ['PENDING','AUTHENTICATED'].includes(current)) timer = setTimeout(poll, current === 'PENDING' ? 1000 : 2000);
}
async function poll() {
  if (busy || document.hidden) return;
  const epoch = generation;
  setBusy(true);
  try { const data = await api('/poll', {}); if (epoch === generation) apply(data); }
  catch { if (epoch === generation) connectionLost(); }
  finally { if (epoch === generation) setBusy(false); }
}
async function connect() {
  const epoch = ++generation;
  stop(); show('LOADING'); setBusy(true);
  try {
    const data = await api('/session');
    if (epoch !== generation) return;
    csrf = data.csrf;
    const status = await api('/poll', {});
    if (epoch === generation) apply(status);
  } catch { if (epoch === generation) connectionLost(); }
  finally { if (epoch === generation) setBusy(false); }
}
byId('login-form').addEventListener('submit', async event => {
  event.preventDefault(); if (busy) return;
  const credentialId = byId('credential').value.trim().toLowerCase();
  if (!/^[a-f0-9]{64}$/.test(credentialId)) { byId('error').textContent = 'Referensen ska innehålla exakt 64 hextecken från appen.'; byId('error').hidden = false; return; }
  const epoch = generation; setBusy(true); stop();
  try { const data = await api('/login', {credentialId}); if (epoch === generation) apply(data); }
  catch (error) { if (epoch === generation) {
    if (!error.httpStatus) connectionLost();
    else { show('READY'); byId('error').textContent = error.message; byId('error').hidden = false; }
  } }
  finally { if (epoch === generation) setBusy(false); }
});
async function logout() {
  if (busy) return;
  const epoch = ++generation; stop(); setBusy(true);
  try { const data = await api('/logout', {}); if (epoch === generation) { byId('credential').value = ''; apply(data); } }
  catch { if (epoch === generation) connectionLost(); }
  finally { if (epoch === generation) setBusy(false); }
}
for (const id of ['logout','cancel','again']) byId(id).addEventListener('click', logout);
byId('reconnect').addEventListener('click', connect);
window.addEventListener('offline', connectionLost);
window.addEventListener('pagehide', connectionLost);
window.addEventListener('pageshow', event => { if (event.persisted) connect(); });
document.addEventListener('visibilitychange', () => { if (document.hidden) connectionLost(); else connect(); });
setInterval(() => {
  if (!deadline || !['PENDING','AUTHENTICATED'].includes(current)) return;
  const seconds = Math.max(0, Math.ceil((deadline - Date.now())/1000));
  if (current === 'PENDING') byId('countdown').textContent = 'Begäran gäller i ' + seconds + ' sekunder';
  // The browser never keeps a success screen after its displayed validity ends.
  if (seconds === 0) { stop(); generation++; show('UNAVAILABLE'); setBusy(false); }
}, 500);
connect();
