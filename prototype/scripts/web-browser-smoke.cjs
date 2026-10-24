// WebAuthn tests with Chromium's virtual CTAP2 authenticators.
const { chromium } = require('playwright');
const { spawn, execFileSync } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const assert = require('node:assert/strict');
const root = path.resolve(__dirname, '..');
const java = process.env.JAVA_HOME ? path.join(process.env.JAVA_HOME, 'bin', 'java') : 'java';
const idp = 'https://localhost:8443', sp = 'https://localhost:8444';

async function run(transport) {
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'synthetic-web-eid-'));
  const keys = path.join(temp, 'keys');
  let app, browser;
  try {
    execFileSync(java, ['-jar', path.join(root, 'target/isolated-eid-lab.jar'), 'init', keys], {timeout: 30000});
    const cert = new crypto.X509Certificate(fs.readFileSync(path.join(keys, 'tls.crt')));
    const pin = crypto.createHash('sha256').update(cert.publicKey.export({type: 'spki', format: 'der'})).digest('base64');
    app = spawn(java, ['-jar', path.join(root, 'target/isolated-eid-lab.jar'), 'start-web', keys], {cwd: root});
    app.stderr.resume();
    await new Promise((resolve, reject) => {
      const timeout = setTimeout(() => reject(new Error('Web lab startup timed out')), 20000);
      app.stdout.on('data', bytes => { if (bytes.toString().includes('SYNTHETIC LAB ONLY')) { clearTimeout(timeout); resolve(); } });
      app.on('exit', code => { clearTimeout(timeout); reject(new Error(`Web lab exited: ${code}`)); });
      app.on('error', reject);
    });
    browser = await chromium.launch({
      ...(process.env.CHROMIUM_EXECUTABLE ? {executablePath: process.env.CHROMIUM_EXECUTABLE} : {}),
      args: ['--ignore-certificate-errors-spki-list=' + pin],
    });
    const context = await browser.newContext({viewport: {width: 390, height: 844}});
    const external = [];
    await context.route('**/*', route => {
      if ([idp, sp].includes(new URL(route.request().url()).origin)) return route.continue();
      external.push(route.request().url()); return route.abort();
    });
    const page = await context.newPage();
    const errors = [];
    page.on('pageerror', error => errors.push(error.message));
    const cdp = await context.newCDPSession(page);
    await cdp.send('WebAuthn.enable');
    await cdp.send('WebAuthn.addVirtualAuthenticator', {options: {
      protocol: 'ctap2', transport, hasResidentKey: true, hasUserVerification: true,
      isUserVerified: true, automaticPresenceSimulation: true,
    }});
    // Deliberately hold the deferred script: controls must not submit a native,
    // empty assertion before the WebAuthn handler has been installed.
    let releaseScript;
    const scriptReady = new Promise(resolve => { releaseScript = resolve; });
    await context.route(idp + '/wallet/wallet.js', async route => { await scriptReady; await route.continue(); });
    await page.goto(idp + '/wallet/', {waitUntil: 'commit'});
    const registerButton = page.getByRole('button', {name: 'Registrera testnyckel'});
    await registerButton.waitFor();
    assert.equal(await registerButton.isDisabled(), true);
    releaseScript();
    await context.unroute(idp + '/wallet/wallet.js');
    assert.equal(await page.evaluate(() => window.isSecureContext), true);
    assert.equal(await page.locator('body').evaluate(el => el.scrollWidth <= innerWidth), true);
    const manifest = await cdp.send('Page.getAppManifest');
    assert.deepEqual(manifest.errors, []);
    assert.equal(JSON.parse(manifest.data).start_url, '/wallet/');
    const installability = await cdp.send('Page.getInstallabilityErrors');
    assert.deepEqual(installability.installabilityErrors, []);
    await page.getByRole('checkbox').check();
    await page.getByRole('button', {name: 'Registrera testnyckel'}).click();
    await page.getByText('En testnyckel är registrerad.', {exact: false}).waitFor();
    assert.equal(await page.locator('#registration').count(), 0);
    await page.evaluate(async () => { await navigator.serviceWorker.ready; });
    await page.reload();
    assert.equal(await page.evaluate(() => navigator.serviceWorker.controller !== null), true);
    assert.deepEqual(await page.evaluate(() => caches.keys()), []);

    // A separate, explicit signing ceremony; a normal SAML login must not supply consent.
    await page.getByRole('link', {name: 'Skriv under ett syntetiskt testdokument'}).click();
    const documentText = await page.locator('#document').textContent();
    const documentHash = crypto.createHash('sha256').update(documentText, 'utf8').digest('hex');
    assert.equal(await page.locator('#document-digest').textContent(), documentHash);
    assert.equal(await page.locator('body').evaluate(el => el.scrollWidth <= innerWidth), true);
    await page.getByRole('checkbox').check();
    await page.getByRole('button', {name: 'Skriv under med testnyckel'}).click();
    await page.waitForURL(idp + '/sign/result');
    const downloadResponse = await page.evaluate(async () => { const r = await fetch('/sign/download'); return {status: r.status, bytes: Array.from(new Uint8Array(await r.arrayBuffer()))}; });
    assert.equal(downloadResponse.status, 200);
    const archive = path.join(temp, 'signature.zip');
    fs.writeFileSync(archive, Buffer.from(downloadResponse.bytes));
    execFileSync('python3', [path.join(root, 'scripts/verify-signature.py'), archive, '--report', path.join(temp, 'openssl.json')], {timeout: 30000});
    await page.goto(idp + '/sign/');
    await page.getByRole('button', {name: 'Avbryt utan underskrift'}).click();
    await page.waitForURL(idp + '/wallet/');
    assert.equal(await page.evaluate(async () => (await fetch('/sign/download')).status), 400);

    async function login() {
      await page.goto(sp);
      await page.getByRole('link', {name: 'Starta testinloggning'}).click();
      await page.getByRole('button', {name: 'Godkänn med testnyckel'}).click();
      await page.waitForURL(sp + '/me');
      assert.equal(await page.locator('#identity').innerText(), 'SYNTHETIC-alice');
    }
    await login();
    await page.getByRole('button', {name: 'Avsluta testsession'}).click();
    await page.waitForURL(sp + '/');
    assert.equal((await page.goto(sp + '/me')).status(), 401);
    await login();
    await page.goto(idp + '/wallet/');
    await page.getByRole('button', {name: 'Spärra SYNTHETIC-alice'}).click();
    await page.waitForURL(idp + '/lab/revoke');
    assert.equal((await page.goto(sp + '/me')).status(), 401);
    await page.goto(sp);
    await page.getByRole('link', {name: 'Starta testinloggning'}).click();
    const revokedOptions = page.waitForResponse(response =>
      response.url() === idp + '/lab/webauthn/options' && response.request().method() === 'POST');
    await page.getByRole('button', {name: 'Godkänn med testnyckel'}).click();
    assert.equal((await revokedOptions).status(), 400, 'Revoked credential options must be refused before WebAuthn');
    await page.getByRole('status').filter({hasText: 'Kontrollen nekades'}).waitFor();
    assert.equal((await page.goto(sp + '/me')).status(), 401);

    await page.goto(idp + '/wallet/');
    await context.setOffline(true);
    const offline = await page.reload();
    assert.equal(offline.status(), 503);
    assert.equal(await page.locator('form').count(), 0);
    assert.equal((await page.locator('body').innerText()).includes('SYNTHETIC-alice'), false);
    await context.setOffline(false);
    await page.goto(idp + '/wallet/');
    assert.deepEqual(await page.evaluate(() => caches.keys()), []);
    assert.deepEqual(errors, []); assert.deepEqual(external, []);
    console.log(`PASS: WebAuthn ${transport}, registration, document signature/OpenSSL, cancellation, signed/encrypted SAML, logout, revocation, manifest, mobile layout and offline refusal`);
  } finally {
    if (browser) await browser.close();
    if (app && app.exitCode === null) {
      const exited = new Promise(resolve => app.once('exit', resolve)); app.kill('SIGTERM');
      const timeout = setTimeout(() => app.kill('SIGKILL'), 10000); await exited; clearTimeout(timeout);
    }
    fs.rmSync(temp, {recursive: true, force: true});
  }
}
(async () => { for (const transport of ['usb', 'internal']) await run(transport); })()
  .catch(error => { console.error(error.message); process.exitCode = 1; });
