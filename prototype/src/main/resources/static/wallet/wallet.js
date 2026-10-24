'use strict';

const statusLine = document.querySelector('#status');
const tell = message => { statusLine.textContent = message; };
const decode = value => Uint8Array.from(atob(value.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
const encode = value => btoa(String.fromCharCode(...new Uint8Array(value))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
function optionsFromJson(options) {
  const key = options.publicKey;
  key.challenge = decode(key.challenge);
  if (key.user) key.user.id = decode(key.user.id);
  for (const field of ['allowCredentials', 'excludeCredentials'])
    if (key[field]) key[field] = key[field].map(item => ({...item, id: decode(item.id)}));
  return options;
}
function responseToJson(credential) {
  if (!credential) throw new Error('Ingen nyckel valdes.');
  const response = {};
  for (const field of ['clientDataJSON', 'attestationObject', 'authenticatorData', 'signature', 'userHandle'])
    if (credential.response[field] != null) response[field] = encode(credential.response[field]);
  if (credential.response.getTransports) response.transports = credential.response.getTransports();
  return JSON.stringify({id: credential.id, rawId: encode(credential.rawId), type: credential.type,
    response, clientExtensionResults: credential.getClientExtensionResults()});
}
async function post(url, form) {
  const response = await fetch(url, {method: 'POST', credentials: 'same-origin', cache: 'no-store',
    headers: {'Content-Type': 'application/x-www-form-urlencoded'}, body: form});
  if (!response.ok) throw new Error('Kontrollen nekades. Kontrollera nyckelns status och börja om.');
  return response.json();
}
function bind(id, action) {
  const form = document.querySelector(id);
  if (!form) return;
  form.addEventListener('submit', async event => {
    event.preventDefault();
    const button = form.querySelector('button');
    button.disabled = true;
    try {
      if (!window.PublicKeyCredential || !navigator.credentials || !window.isSecureContext)
        throw new Error('Webbläsaren behöver stödja WebAuthn och lita på labbens HTTPS-certifikat.');
      tell('Följ webbläsarens anvisningar för din testnyckel.');
      await action(form);
    } catch (error) {
      tell(error.name === 'NotAllowedError' ? 'Avbrutet eller tidsgränsen passerad. Börja om.' : error.message);
    } finally { button.disabled = false; }
  });
}
bind('#registration', async form => {
  const fields = new URLSearchParams(new FormData(form));
  const options = await post('/wallet/register/options', fields);
  const key = await navigator.credentials.create(optionsFromJson(options));
  fields.set('response', responseToJson(key));
  await post('/wallet/register/finish', fields);
  window.location.assign('/wallet/');
});
bind('#authentication', async form => {
  const fields = new URLSearchParams(new FormData(form));
  const options = await post('/lab/webauthn/options', fields);
  const key = await navigator.credentials.get(optionsFromJson(options));
  form.elements.response.value = responseToJson(key);
  HTMLFormElement.prototype.submit.call(form);
});
bind('#document-signature', async form => {
  const fields = new URLSearchParams(new FormData(form));
  const options = await post('/sign/options', fields);
  const key = await navigator.credentials.get(optionsFromJson(options));
  form.elements.response.value = responseToJson(key);
  HTMLFormElement.prototype.submit.call(form);
});

let installation;
const install = document.querySelector('#install');
if (install) {
  window.addEventListener('beforeinstallprompt', event => { event.preventDefault(); installation = event; install.hidden = false; });
  install.addEventListener('click', async () => {
    if (installation) { await installation.prompt(); installation = undefined; install.hidden = true; }
  });
  if ('serviceWorker' in navigator) navigator.serviceWorker.register('/wallet/sw.js', {scope: '/wallet/'})
    .catch(() => tell('Offlineinformationen kunde inte aktiveras. Webbinloggning kan fortfarande användas.'));
}
