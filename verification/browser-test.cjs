const {chromium}=require('../prototype/node_modules/playwright');
const {spawn}=require('node:child_process');
const path=require('node:path');
const assert=require('node:assert/strict');

(async()=>{
  const fixtures=process.env.PROOFING_FIXTURES;
  if(!fixtures || !process.env.PROOFING_PYTHON || !process.env.PROOFING_JAVA)throw Error('Set PROOFING_FIXTURES, PROOFING_PYTHON and PROOFING_JAVA');
  const server=spawn(process.env.PROOFING_PYTHON,['server.py','--csca',path.join(fixtures,'csca.der'),'--java',process.env.PROOFING_JAVA],{cwd:__dirname});
  let browser;
  try{
    await new Promise((resolve,reject)=>{
      const timer=setTimeout(()=>reject(Error('Startup timed out')),20000);
      server.stdout.on('data',data=>{if(data.toString().includes('Verification workbench:')){clearTimeout(timer);resolve();}});
      server.on('exit',()=>{clearTimeout(timer);reject(Error('Server exited'));});
    });
    browser=await chromium.launch({...(process.env.CHROMIUM_EXECUTABLE?{executablePath:process.env.CHROMIUM_EXECUTABLE}:{}),args:['--use-fake-device-for-media-stream','--use-fake-ui-for-media-stream']});
    const context=await browser.newContext({permissions:['camera'],viewport:{width:1280,height:1100}});
    const page=await context.newPage();const errors=[],external=[];
    page.on('pageerror',e=>errors.push(e.message));
    await context.route('**/*',route=>{
      if(new URL(route.request().url()).origin==='http://localhost:8765')return route.continue();
      external.push(route.request().url());return route.abort();
    });
    await page.goto('http://localhost:8765');
    await page.getByText('Verifieraren är tillgänglig lokalt.').waitFor();
    await page.getByRole('button',{name:'Öppna kameran',exact:true}).click();
    await page.waitForFunction(()=>document.querySelector('video').videoWidth>0);
    await page.evaluate(()=>{window.testTrack=document.querySelector('video').srcObject.getVideoTracks()[0];});
    await page.getByRole('button',{name:'Stäng kameran',exact:true}).click();
    assert.equal(await page.evaluate(()=>window.testTrack.readyState),'ended');
    for(const name of ['sod','dg1','dg2'])await page.locator('#'+name).setInputFiles(path.join(fixtures,name+'.bin'));
    await page.getByRole('checkbox').check();
    await page.getByRole('button',{name:'Öppna kameran',exact:true}).click();
    await page.waitForFunction(()=>document.querySelector('video').videoWidth>0);
    await page.getByRole('button',{name:'Ta bild och verifiera underlaget'}).click();
    // Signed fixture contains deliberately invalid JPEG bytes. Real passport verification passes,
    // then real image decoding refuses it; the browser must never display a successful identity.
    await page.locator('#status').filter({hasText:'Kontrollen kunde inte slutföras'}).waitFor();
    assert.equal(await page.locator('#result').isVisible(),false);
    assert.equal(await page.evaluate(()=>document.querySelector('video').srcObject),null);
    await page.setViewportSize({width:390,height:844});
    assert.equal(await page.locator('body').evaluate(el=>el.scrollWidth<=innerWidth),true);
    assert.deepEqual(await page.evaluate(()=>({local:localStorage.length,session:sessionStorage.length,cache:[]})),{local:0,session:0,cache:[]});
    assert.deepEqual(await page.evaluate(()=>caches.keys()),[]);
    if(process.env.PROOFING_SCREENSHOT)await page.screenshot({path:process.env.PROOFING_SCREENSHOT,fullPage:true});
    assert.deepEqual(errors,[]);assert.deepEqual(external,[]);
    console.log('PASS: actual camera API, capture, camera shutdown, real Java rejection pipeline, mobile layout, no external requests or browser storage');
  }finally{if(browser)await browser.close();server.kill('SIGTERM');}
})().catch(e=>{console.error(e);process.exitCode=1;});
