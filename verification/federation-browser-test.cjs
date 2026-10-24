const {chromium} = require('../prototype/node_modules/playwright');
const {spawn,spawnSync} = require('node:child_process');
const {createInterface} = require('node:readline');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const https = require('node:https');

(async () => {
  const python = process.env.PROOFING_PYTHON, java = process.env.PROOFING_JAVA;
  if (!python || !java) throw Error('Set PROOFING_PYTHON and PROOFING_JAVA');
  const temporary = fs.mkdtempSync(path.join(os.tmpdir(),'oid-fed-'));
  const jar = path.resolve(__dirname,'../prototype/target/isolated-eid-lab.jar');
  const keys = path.join(temporary,'keys'), socket = path.join(temporary,'bridge.sock');
  let browser, fixture, logs = '';
  const children = [];
  function start(command,args,options={}) {
    const child = spawn(command,args,options); children.push(child);
    child.stderr.on('data',data => { logs = (logs+data).slice(-50000); });
    return child;
  }
  async function ready(url,ca) {
    for (let i=0;i<100;i++) {
      const status = await new Promise(resolve => {
        const req = https.get(url,{ca},r => { r.resume(); resolve(r.statusCode); });
        req.on('error',() => resolve(0)); req.setTimeout(1000,() => req.destroy());
      });
      if (status === 200) return;
      await new Promise(r => setTimeout(r,200));
    }
    throw Error('Service startup failed: '+logs);
  }
  try {
    const init = spawnSync(java,['-jar',jar,'phone-init',keys],{encoding:'utf8'});
    assert.equal(init.status,0,init.stderr);
    fixture = start(python,['test_federation_fixture.py',temporary],{cwd:__dirname});
    const lines = createInterface({input:fixture.stdout})[Symbol.asyncIterator]();
    async function receive() {
      let timer;
      try {
        const {value,done} = await Promise.race([lines.next(),new Promise((_,reject) => {
          timer = setTimeout(() => reject(Error('Device fixture timeout: '+logs)),20000);
        })]);
        if (done) throw Error('Device fixture exited: '+logs);
        const data = JSON.parse(value); if (data.error) throw Error(data.error); return data;
      } finally {clearTimeout(timer);}
    }
    async function command(op,data={}) { fixture.stdin.write(JSON.stringify({op,...data})+'\n'); return (await receive()).result; }
    await receive();
    for (const mode of ['phone-idp','phone-sp']) {
      const child = start(java,['-jar',jar,mode,keys,socket]);
      child.stdout.on('data',data => {logs=(logs+data).slice(-50000);});
    }
    const ca=fs.readFileSync(path.join(keys,'tls.crt'));
    await ready('https://localhost:8444/health/ready',ca); await ready('https://localhost:8443/phone/page.css',ca);
    browser = await chromium.launch(process.env.CHROMIUM_EXECUTABLE ? {executablePath:process.env.CHROMIUM_EXECUTABLE} : {});
    const context = await browser.newContext({ignoreHTTPSErrors:true,locale:'sv-SE',viewport:{width:1100,height:1000}});
    const page = await context.newPage(), errors=[], external=[];
    page.on('pageerror',error=>errors.push(error.message));
    await context.route('**/*',route => {
      if (['https://localhost:8443','https://localhost:8444'].includes(new URL(route.request().url()).origin)) return route.continue();
      external.push(route.request().url()); return route.abort();
    });
    const cookie = async () => (await context.cookies()).find(c=>c.name==='__Host-lab-sp');
    async function begin() {
      await page.goto('https://localhost:8444/login');
      await page.locator('#code').waitFor({timeout:15000});
      const link = await page.getByRole('link',{name:'Öppna openID'}).getAttribute('href');
      assert.match(link,/^openid:\/\/request\/[a-f0-9]{64}$/);
      const requestId = link.split('/').at(-1);
      const result = await command('inspect',{requestId});
      assert.equal(result.requests[0].code,await page.locator('#code').textContent());
      assert.equal(result.requests[0].relyingParty,'openID kontotjänst');
      assert.equal(result.identity.displayName,'ALICE SYNTHETIC');
      return requestId;
    }
    async function approve(requestId) {
      await command('approve',{requestId});
      await page.waitForURL('https://localhost:8444/me',{timeout:15000});
      assert.equal(await page.locator('#identity').textContent(),'ALICE SYNTHETIC');
      assert.equal(await page.locator('#birth-date').textContent(),'900101');
      assert.equal(await page.locator('img').evaluate(el=>el.complete && el.naturalWidth>0),true);
    }
    await command('new');
    let id = await begin(), prelogin = await cookie();
    const qr = path.join(temporary,'qr.png'); await page.locator('.qr').screenshot({path:qr});
    const decoded = spawnSync(python,['-c','import cv2,sys; print(cv2.QRCodeDetectorAruco().detectAndDecode(cv2.imread(sys.argv[1]))[0])',qr],{encoding:'utf8'});
    assert.equal(decoded.status,0,decoded.stderr); assert.equal(decoded.stdout.trim(),'openid://request/'+id);
    const outsider = await browser.newContext({ignoreHTTPSErrors:true});
    assert.notEqual((await outsider.request.get('https://localhost:8443/phone/qr')).status(),200);
    assert.equal((await outsider.request.get('https://localhost:8444/portrait')).status(),401);
    assert.equal((await context.request.post('https://localhost:8443/phone/complete',{headers:{Origin:'https://localhost:8443'}})).status(),403);
    const authnId = await page.locator('#complete input[name=authnId]').inputValue();
    const csrf = await page.locator('#complete input[name=_csrf]').inputValue();
    assert.equal((await context.request.post('https://localhost:8443/phone/complete',{headers:{Origin:'https://evil.invalid'},form:{authnId,_csrf:csrf}})).status(),403);
    const acs = [];
    page.on('request',r=>{if(r.url()==='https://localhost:8444/acs') acs.push(r.postData());});
    await approve(id);
    assert.ok(acs[0]); const saml = Buffer.from(new URLSearchParams(acs[0]).get('SAMLResponse'),'base64').toString();
    assert.match(saml,/EncryptedAssertion/); assert.ok(!saml.includes('ALICE'));
    const authenticated = await cookie(); assert.notEqual(prelogin.value,authenticated.value);
    assert.equal(authenticated.secure,true); assert.equal(authenticated.httpOnly,true); assert.equal(authenticated.sameSite,'Strict');
    assert.equal((await outsider.request.post('https://localhost:8444/acs',{headers:{Origin:'https://localhost:8443','Content-Type':'application/x-www-form-urlencoded'},data:acs[0]})).status(),400);
    if (process.env.FEDERATION_SCREENSHOT) await page.screenshot({path:process.env.FEDERATION_SCREENSHOT,fullPage:true});
    await page.getByRole('button',{name:'Logga ut'}).click();
    assert.equal((await context.request.get('https://localhost:8444/portrait')).status(),401);
    console.log('PASS: signed passport → encrypted identity → signed device consent → Sweden Connect encrypted SAML → separate HTTPS SP; decoded QR, claims, session rotation, CSRF/origin, other-browser replay, logout');

    id = await begin(); await command('reject',{requestId:id});
    await page.getByRole('heading',{name:'Du nekade legitimeringen'}).waitFor();
    assert.equal((await context.request.get('https://localhost:8444/me')).status(),401);
    id = await begin(); await page.getByRole('button',{name:'Avbryt'}).click();
    assert.equal((await context.request.get('https://localhost:8444/me')).status(),401);
    id = await begin(); await command('advance',{seconds:121});
    await page.getByRole('heading',{name:'QR-koden har gått ut'}).waitFor();
    await command('advance',{seconds:-121});
    console.log('PASS: signed rejection, cancellation and expired request deny login');

    // Test console: Sweden Connect cases against the real IdP, registry and SP validation.
    async function run(name) {
      await page.goto('https://localhost:8444/test/run/'+name);
      await page.waitForURL(/\/(phone|test\/report\/)/,{timeout:15000});
    }
    async function pending() {
      await page.locator('#code').waitFor({timeout:15000});
      return (await page.getByRole('link',{name:'Öppna openID'}).getAttribute('href')).split('/').at(-1);
    }
    async function verdict(name) {
      await page.waitForURL(/\/test\/report\/[A-Za-z0-9_-]{22}$/,{timeout:20000});
      const failed = await page.locator('.checks li.fail strong').allTextContents();
      assert.deepEqual(failed,[],name+' failed checks: '+(await page.locator('.checks li.fail').allTextContents()).join(' | '));
      assert.equal(await page.locator('.verdict.ok').count(),1,name+' verdict');
    }
    const shots = process.env.FEDERATION_SCREENSHOT_DIR;
    const shot = async name => { if (shots) await page.screenshot({path:path.join(shots,name+'.png'),fullPage:true}); };
    await page.goto('https://localhost:8444/test');
    assert.equal(await page.locator('article.card').count(),15); await shot('console');
    for (const name of ['login','no-force']) { await run(name); await command('approve',{requestId:await pending()}); await verdict(name); }
    for (const name of ['passive','loa3','sign-html','sad-only']) { await run(name); await verdict(name); }
    await run('cancel'); await pending(); await page.getByRole('button',{name:'Avbryt'}).click();
    await page.getByRole('button',{name:'Tillbaka till tjänsten'}).click(); await verdict('cancel');
    await run('cancel'); await command('reject',{requestId:await pending()});
    await page.getByRole('button',{name:'Tillbaka till tjänsten'}).click(); await verdict('reject');
    await run('sign-from-service'); id = await pending();
    assert.equal(await page.locator('.sign-message').count(),0);
    const ordinary = await command('inspect',{requestId:id});
    assert.equal(ordinary.requests[0].signMessage,undefined); assert.match(ordinary.requests[0].purpose,/^Logga in/);
    await assert.rejects(command('sign',{requestId:id}));
    await command('approve',{requestId:id}); await verdict('sign-from-service');
    // Security code level: the service requires it; Face ID alone is not enough, wrong codes are counted.
    assert.equal((await command('set-pin',{newPin:'123456'})).securityCodeError,'PIN_WEAK');
    assert.equal((await command('set-pin',{newPin:'482917'})).securityCode.set,true);
    await run('login-pin'); id = await pending();
    assert.equal(await page.locator('#pin-required').count(),1);
    assert.equal((await command('inspect',{requestId:id})).requests[0].verification,'pin');
    assert.equal((await command('approve',{requestId:id})).securityCodeError,'PIN_REQUIRED');
    const wrong = await command('approve',{requestId:id,pin:'000001'});
    assert.deepEqual([wrong.securityCodeError,wrong.attemptsRemaining],['PIN_INCORRECT',4]);
    await command('approve',{requestId:id,pin:'482917'}); await verdict('login-pin');
    assert.match(await page.locator('.checks').textContent(),/passport-native:pin:v1/);
    await page.goto('https://localhost:8444/sign');
    assert.equal(await page.getByRole('link',{name:'Skriv under lånelöftet'}).count(),1);
    await run('sign-pin'); id = await pending();
    assert.match(await page.locator('#sign-message').textContent(),/Lånelöfte 250 000 kr/);
    assert.equal((await command('sign',{requestId:id})).securityCodeError,'PIN_REQUIRED');
    await command('sign',{requestId:id,pin:'482917'}); await verdict('sign-pin');
    // A Face ID level request never takes the code.
    await run('login'); id = await pending(); await assert.rejects(command('approve',{requestId:id,pin:'482917'}));
    await command('approve',{requestId:id}); await verdict('login after code level');
    for (const name of ['sign','sign-encrypted']) {
      await run(name); id = await pending();
      const shown = await page.locator('#sign-message').textContent(); if (name === 'sign') await shot('idp-sign');
      assert.match(shown,/^Jag skriver under ”Avtal om provtjänst”, dokument OID-[0-9]{6}\.\nKontrollsumma \(SHA-256\): /);
      const request = (await command('inspect',{requestId:id})).requests[0];
      assert.equal(request.signMessage,shown); assert.match(request.purpose,/^Skriv under/);
      // A login approval can never complete a signature, also not from an older app.
      await assert.rejects(command('approve',{requestId:id}));
      await command('sign',{requestId:id}); await verdict(name); if (name === 'sign') await shot('report-sign');
      const download = await context.request.get(page.url()+'/signed.pdf');
      assert.equal(download.status(),200);
      const pdf = (await download.body()).toString('latin1');
      assert.ok(pdf.startsWith('%PDF-') && pdf.includes('/ETSI.CAdES.detached') && pdf.includes('/ByteRange'));
      if (shots && name === 'sign') fs.writeFileSync(path.join(shots,'signed.pdf'),await download.body());
      const evidence = JSON.parse((await context.request.get(page.url()+'/evidence.json')).body ? (await (await context.request.get(page.url()+'/evidence.json')).text()) : '{}');
      assert.equal(evidence.signMessage,shown); assert.match(evidence.sad,/^ey/);
      assert.equal((await outsider.request.get(page.url()+'/signed.pdf')).status(),404);
    }
    console.log('PASS: test console – login, security code level (weak, missing, wrong, locked counter, Face ID level refuses code), fresh authentication, IsPassive, unsupported LoA, cancel/reject status, SignMessage+SAD, encrypted SignMessage, undisplayable text, SAD without text, non-sigservice requester; PAdES document signed');

    id = await begin(); await approve(id); await command('new');
    assert.equal((await context.request.get('https://localhost:8444/me')).status(),401);
    id = await begin(); await approve(id); await command('revoke');
    assert.equal((await context.request.get('https://localhost:8444/me')).status(),401);
    assert.equal((await context.request.get('https://localhost:8444/portrait')).status(),401);
    await command('new'); id = await begin(); await approve(id); await command('stop-bridge');
    assert.equal((await context.request.get('https://localhost:8444/me')).status(),401);
    assert.equal((await context.request.get('https://localhost:8444/health/ready')).status(),503);
    for (const endpoint of ['/lab','/wallet/','/lab/revoke']) assert.notEqual((await context.request.get('https://localhost:8443'+endpoint)).status(),200);
    assert.deepEqual(errors,[]); assert.deepEqual(external,[]);
    assert.ok(!logs.includes('ALICE') && !logs.includes('900101'), 'Identity fields leaked to service logs');
    await outsider.close();
    console.log('PASS: replacement, revocation and registry outage stop existing sessions; simulated provider unavailable');
  } catch (error) {
    console.error(logs); throw error;
  } finally {
    if(browser) await browser.close();
    if(fixture) fixture.stdin.end();
    for(const child of children) child.kill('SIGTERM');
    await Promise.all(children.map(child=>child.exitCode!==null ? Promise.resolve() : new Promise(resolve=>child.once('exit',resolve))));
    fs.rmSync(temporary,{recursive:true,force:true});
  }
})().catch(error=>{console.error(error);process.exitCode=1;});
