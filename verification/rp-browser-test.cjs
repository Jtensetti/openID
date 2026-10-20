const {chromium} = require('../prototype/node_modules/playwright');
const {spawn, spawnSync} = require('node:child_process');
const {createInterface} = require('node:readline');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

(async () => {
  const python = process.env.PROOFING_PYTHON;
  if (!python) throw Error('Set PROOFING_PYTHON to the verification virtualenv interpreter');
  const server = spawn(python, ['test_rp_fixture.py'], {cwd:__dirname});
  const lines = createInterface({input:server.stdout})[Symbol.asyncIterator]();
  let stderr = '', browser;
  server.stderr.on('data', data => { stderr += data.toString(); });
  async function receive() {
    let timer;
    try {
      const {value,done} = await Promise.race([lines.next(), new Promise((_,reject) => {
        timer = setTimeout(() => reject(Error('Fixture timed out: ' + stderr)), 15000);
      })]);
      if (done) throw Error('Fixture exited: ' + stderr);
      const data = JSON.parse(value); if (data.error) throw Error(data.error); return data;
    } finally { clearTimeout(timer); }
  }
  async function command(op, data={}) { server.stdin.write(JSON.stringify({op,...data}) + '\n'); return (await receive()).result; }
  const temporary = fs.mkdtempSync(path.join(os.tmpdir(), 'openid-rp-browser-'));
  try {
    const {origin} = await receive();
    browser = await chromium.launch(process.env.CHROMIUM_EXECUTABLE ? {executablePath:process.env.CHROMIUM_EXECUTABLE} : {});
    const context = await browser.newContext({viewport:{width:1320,height:1050}, locale:'sv-SE'});
    const page = await context.newPage(); const errors=[], external=[];
    page.on('pageerror', error => errors.push(error.message));
    await context.route('**/*', route => {
      if (new URL(route.request().url()).origin === origin) return route.continue();
      external.push(route.request().url()); return route.abort();
    });
    const visible = id => page.locator('#' + id).waitFor({state:'visible',timeout:10000});
    const cookie = async () => (await context.cookies()).find(c => c.name === 'openid_local_rp');
    async function start() {
      const {credentialId} = await command('new');
      await page.goto(origin); await visible('ready');
      await page.locator('#credential').fill(credentialId);
      await page.getByRole('button',{name:'Logga in med openID'}).click();
      await visible('pending');
      const snapshot = await command('snapshot');
      assert.equal(snapshot.requests.length,1);
      assert.equal(await page.locator('#code').textContent(), snapshot.requests[0].code);
      return snapshot.requests[0];
    }
    async function approve(request) {
      await command('approve',{requestId:request.id}); await visible('authenticated');
      assert.match(await page.locator('#subject').textContent(), /^[a-f0-9]{64}$/);
    }
    async function logout() { await page.locator('#logout').click(); await visible('ready'); }

    // Decode the rendered image to catch broken QR output.
    let request = await start(); const prelogin = await cookie();
    const qrPath = path.join(temporary,'qr.png');
    await page.locator('#qr').screenshot({path:qrPath});
    const decoded = spawnSync(python,['-c','import cv2,sys; print(cv2.QRCodeDetectorAruco().detectAndDecode(cv2.imread(sys.argv[1]))[0])',qrPath],{encoding:'utf8'});
    assert.equal(decoded.status,0,decoded.stderr);
    assert.equal(decoded.stdout.trim(),'openid://request/' + request.id);
    if (process.env.RP_SCREENSHOT) await page.screenshot({path:process.env.RP_SCREENSHOT,fullPage:true});
    const outsider = await browser.newContext(); const other = await outsider.newPage();
    await other.goto(origin); await other.locator('#ready').waitFor();
    assert.equal((await other.request.get(origin + '/qr.svg')).status(),403);
    await approve(request);
    const authenticated = await cookie();
    assert.notEqual(authenticated.value,prelogin.value); assert.equal(authenticated.httpOnly,true); assert.equal(authenticated.sameSite,'Strict');
    assert.equal(await other.locator('#authenticated').isVisible(),false);
    await outsider.close(); await logout();
    console.log('PASS: real ECDSA approval, decoded browser QR, control-code equality, session rotation, other browser isolation, logout');

    request = await start(); await command('reject',{requestId:request.id}); await visible('unavailable');
    assert.equal(await page.locator('#subject').textContent(),'');
    await page.locator('#again').click(); await visible('ready');
    request = await start(); await page.locator('#cancel').click(); await visible('ready');
    assert.equal((await command('snapshot')).requests.length,0);
    console.log('PASS: signed rejection and cancellation remove the live request');

    request = await start(); await approve(request); await command('revoke'); await visible('unavailable');
    assert.equal(await page.locator('#subject').textContent(),'');
    await page.locator('#again').click(); await visible('ready');
    request = await start(); await approve(request);
    await context.setOffline(true); await visible('offline');
    assert.equal(await page.locator('#subject').textContent(),'');
    await command('revoke'); await context.setOffline(false);
    await page.locator('#reconnect').click(); await visible('unavailable');
    await page.locator('#again').click(); await visible('ready');
    console.log('PASS: active-session revocation, network loss clears success, reconnect reads revocation');

    request = await start(); await command('advance',{seconds:121}); await visible('unavailable');
    await page.locator('#again').click(); await visible('ready');
    await page.locator('#credential').fill('0'.repeat(64));
    await page.getByRole('button',{name:'Logga in med openID'}).click(); await visible('error');
    assert.equal(await page.locator('#authenticated').isVisible(),false);
    await page.setViewportSize({width:390,height:844});
    assert.equal(await page.locator('body').evaluate(el => el.scrollWidth <= innerWidth),true);
    assert.deepEqual(await page.evaluate(() => [localStorage.length,sessionStorage.length]),[0,0]);
    assert.deepEqual(await page.evaluate(() => caches.keys()),[]);
    assert.deepEqual(await page.evaluate(() => navigator.serviceWorker.getRegistrations().then(r => r.map(v => v.scope))),[]);
    assert.deepEqual(errors,[]); assert.deepEqual(external,[]);
    console.log('PASS: expired request, unknown credential, mobile layout, no external requests or persistent browser storage');
  } finally {
    if (browser) await browser.close();
    server.stdin.end();
    const timer = setTimeout(() => server.kill('SIGTERM'), 3000); timer.unref();
    fs.rmSync(temporary,{recursive:true,force:true});
  }
})().catch(error => { console.error(error); process.exitCode = 1; });
