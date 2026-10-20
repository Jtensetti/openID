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
    const decoded = spawnSync(python,['-c','import cv2,sys; print(cv2.QRCodeDetector().detectAndDecode(cv2.imread(sys.argv[1]))[0])',qr],{encoding:'utf8'});
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
    await page.getByRole('status').filter({hasText:'Inloggningen har avslutats'}).waitFor();
    assert.equal((await context.request.get('https://localhost:8444/me')).status(),401);
    id = await begin(); await page.getByRole('button',{name:'Avbryt'}).click();
    assert.equal((await context.request.get('https://localhost:8444/me')).status(),401);
    id = await begin(); await command('advance',{seconds:121});
    await page.getByRole('status').filter({hasText:'Inloggningen har avslutats'}).waitFor();
    await command('advance',{seconds:-121});
    console.log('PASS: signed rejection, cancellation and expired request deny login');

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
