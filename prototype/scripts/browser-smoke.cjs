// Browser regression for real Origin, CSP, cookies and the SAML auto-POST page.
// Test TLS trust is scoped to the fresh certificate's public key; all page requests stay on loopback.
const { chromium } = require('playwright');
const { spawn, execFileSync } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const assert = require('node:assert/strict');

const root = path.resolve(__dirname, '..');
const java = process.env.JAVA_HOME ? path.join(process.env.JAVA_HOME, 'bin', 'java') : 'java';
const idp = 'https://127.0.0.1:8443';
const sp = 'https://127.0.0.1:8444';

(async () => {
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'synthetic-eid-browser-'));
  const keys = path.join(temp, 'keys');
  let app, browser;
  try {
    execFileSync(java, ['-jar', path.join(root, 'target/isolated-eid-lab.jar'), 'init', keys], {timeout: 30000});
    const cert = new crypto.X509Certificate(fs.readFileSync(path.join(keys, 'tls.crt')));
    const pin = crypto.createHash('sha256').update(cert.publicKey.export({type: 'spki', format: 'der'})).digest('base64');
    app = spawn(java, ['-jar', path.join(root, 'target/isolated-eid-lab.jar'), 'start', keys], {cwd: root});
    // Drain stderr without exposing session values or protocol bodies in CI output.
    app.stderr.resume();
    await new Promise((resolve, reject) => {
      const timeout = setTimeout(() => reject(new Error('Lab startup timed out')), 20000);
      app.stdout.on('data', bytes => {
        if (bytes.toString().includes('SYNTHETIC LAB ONLY')) { clearTimeout(timeout); resolve(); }
      });
      app.on('exit', code => { clearTimeout(timeout); reject(new Error(`Lab exited during startup: ${code}`)); });
      app.on('error', reject);
    });
    browser = await chromium.launch({
      ...(process.env.CHROMIUM_EXECUTABLE ? {executablePath: process.env.CHROMIUM_EXECUTABLE} : {}),
      args: ['--ignore-certificate-errors-spki-list=' + pin],
    });
    const page = await browser.newPage();
    await page.route('**/*', route => [idp, sp].includes(new URL(route.request().url()).origin)
      ? route.continue() : route.abort());
    const posts = [];
    page.on('request', request => {
      if (request.method() === 'POST') posts.push({path: new URL(request.url()).pathname, origin: request.headers().origin});
    });
    async function login(credential) {
      await page.goto(sp);
      await page.getByRole('link', {name: 'Starta testinloggning'}).click();
      await page.getByRole('combobox').selectOption(credential);
      await page.getByRole('checkbox').check();
      await page.getByRole('button', {name: 'Godkänn testinloggning'}).click();
    }
    await login('TEST-CREDENTIAL-alice');
    await page.waitForURL(sp + '/me');
    assert.equal(await page.locator('#identity').innerText(), 'SYNTHETIC-alice');
    assert(posts.some(p => p.path === '/lab' && p.origin === idp));
    assert(posts.some(p => p.path === '/acs' && p.origin === idp));
    await page.getByRole('button', {name: 'Avsluta testsession'}).click();
    await page.waitForURL(sp + '/');
    assert.equal((await page.goto(sp + '/me')).status(), 401);

    await login('TEST-CREDENTIAL-revoked');
    await page.waitForURL(sp + '/acs');
    assert.equal((await page.goto(sp + '/me')).status(), 401);

    await login('TEST-CREDENTIAL-alice');
    await page.waitForURL(sp + '/me');
    await page.goto(idp);
    await page.getByRole('button', {name: 'Spärra SYNTHETIC-alice i denna labbkörning'}).click();
    await page.waitForURL(idp + '/lab/revoke');
    assert.equal((await page.goto(sp + '/me')).status(), 401);
    console.log('PASS: Chromium login, real Origin headers, auto-POST, logout, rejected credential and active-session revocation');
  } finally {
    if (browser) await browser.close();
    if (app && app.exitCode === null) {
      const exited = new Promise(resolve => app.once('exit', resolve));
      app.kill('SIGTERM');
      const timeout = setTimeout(() => app.kill('SIGKILL'), 10000);
      await exited;
      clearTimeout(timeout);
    }
    fs.rmSync(temp, {recursive: true, force: true});
  }
})().catch(error => { console.error(error.message); process.exitCode = 1; });
