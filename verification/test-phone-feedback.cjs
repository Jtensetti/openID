const assert = require('node:assert/strict');
const vm = require('node:vm');
const fs = require('node:fs');
const source = fs.readFileSync(require('node:path').join(__dirname, '../prototype/src/main/resources/static/phone/page.js'), 'utf8');
async function scenario(responses, kind='login', submitThrows=false) {
  const nodes = Object.fromEntries(['#complete','#status','#heading','.qr','#control-code','#open-app','#cancel','#restart','#return','#cancel button','main','.sign-message'].map(k => [k,{hidden:false, textContent:'', addEventListener(type,fn){this[type]=fn}, requestSubmit(){this.submitted=true}}]));
  nodes['#restart'].hidden=true; nodes['#return'].hidden=true; nodes.main.dataset={kind};
  if(submitThrows) nodes['#complete'].requestSubmit=()=>{throw Error('navigation blocked')};
  const timers=[], documentEvents={}, windowEvents={}; let calls=0;
  const context={document:{querySelector:k=>nodes[k],addEventListener:(type,fn)=>documentEvents[type]=fn},window:{addEventListener:(type,fn)=>windowEvents[type]=fn},AbortController,URLSearchParams,FormData:class{*[Symbol.iterator](){}},setTimeout(fn,ms){const t={fn,ms};timers.push(t);return t},clearTimeout(t){const i=timers.indexOf(t);if(i>=0)timers.splice(i,1)},fetch:async()=>{calls++;const value=responses.shift();if(value instanceof Error)throw value;return {ok:!value.http,status:value.http||200,json:async()=>value}}};
  vm.runInNewContext(source,context);
  const settle=async()=>{for(let i=0;i<10;i++)await Promise.resolve()};
  await settle();
  return {nodes, timers, documentEvents, windowEvents, get calls(){return calls},async tick(ms=1500){const t=timers.find(t=>t.ms===ms);assert.ok(t);timers.splice(timers.indexOf(t),1);t.fn();await settle()},async cancel(){await nodes['#cancel'].submit({preventDefault(){},currentTarget:nodes['#cancel']});await settle()}};
}
(async()=>{
  for (const [state,title,back] of [['REJECTED','Du nekade legitimeringen',true],['EXPIRED','QR-koden har gått ut',false],['CANCELLED','Inloggningen avbröts',false]]) {
    const s=await scenario([{state}]); assert.equal(s.nodes['#heading'].textContent,title);assert.equal(s.nodes['.qr'].hidden,true);assert.ok(!s.nodes['#complete'].submitted);
    // A user decision returns to the service with status cancel; other endings offer a fresh start.
    assert.equal(s.nodes['#return'].hidden,!back);assert.equal(s.nodes['#restart'].hidden,back);
  }
  const signing=await scenario([{state:'REJECTED'}],'sign');assert.equal(signing.nodes['#heading'].textContent,'Du avböjde underskriften');assert.equal(signing.nodes['.sign-message'].hidden,true);assert.match(signing.nodes['#status'].textContent,/Ingenting har skrivits under/);
  const signExpired=await scenario([{state:'EXPIRED'}],'sign');assert.match(signExpired.nodes['#status'].textContent,/ny underskrift/);
  const transient=await scenario([Error(),{state:'PENDING'},{state:'APPROVED'}]);
  assert.equal(transient.nodes['.qr'].hidden,false);await transient.tick();assert.match(transient.nodes['#status'].textContent,/Väntar/);await transient.tick();assert.equal(transient.nodes['#complete'].submitted,true);assert.equal(transient.calls,3);
  const offline=await scenario([Error(),Error(),Error()]);await offline.tick();await offline.tick();assert.equal(offline.nodes['.qr'].hidden,true);assert.match(offline.nodes['#status'].textContent,/redan godkänt/);assert.ok(!offline.nodes['#complete'].submitted);
  const denied=await scenario([{http:400}]);assert.match(denied.nodes['#status'].textContent,/Mitt ID/);assert.ok(!denied.nodes['#complete'].submitted);
  const cancel=await scenario([{state:'PENDING'},{}]);await cancel.cancel();assert.equal(cancel.nodes['#heading'].textContent,'Inloggningen avbröts');assert.equal(cancel.nodes['#return'].hidden,false);await cancel.tick();assert.equal(cancel.calls,2);
  const uncertain=await scenario([{state:'PENDING'},Error()]);await uncertain.cancel();assert.equal(uncertain.nodes['#heading'].textContent,'Avbrottet kunde inte bekräftas');assert.ok(!uncertain.nodes['#complete'].submitted);
  const timeout=await scenario([{state:'APPROVED'}]);await timeout.tick(15000);assert.match(timeout.nodes['#heading'].textContent,/Återgången/);assert.equal(timeout.calls,1);assert.equal(timeout.nodes['#restart'].hidden,false);
  const blocked=await scenario([{state:'APPROVED'}]);blocked.documentEvents.securitypolicyviolation({effectiveDirective:'form-action'});assert.match(blocked.nodes['#status'].textContent,/resultat kunde inte visas/);assert.equal(blocked.nodes['.qr'].hidden,true);
  const thrown=await scenario([{state:'APPROVED'}],'login',true);assert.match(thrown.nodes['#heading'].textContent,/Återgången/);
  const navigated=await scenario([{state:'APPROVED'}]);navigated.windowEvents.pagehide();assert.equal(navigated.timers.length,0);
  console.log('PASS 14 feedback scenarios, including blocked, failed and timed-out completion, and timer cleanup on navigation');
})().catch(e=>{console.error(e);process.exitCode=1});
