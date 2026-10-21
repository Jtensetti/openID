const assert = require('node:assert/strict');
const vm = require('node:vm');
const fs = require('node:fs');
const source = fs.readFileSync(require('node:path').join(__dirname, '../prototype/src/main/resources/static/phone/page.js'), 'utf8');
async function scenario(responses) {
  const nodes = Object.fromEntries(['#complete','#status','#heading','.qr','#control-code','#open-app','#cancel','#restart','#cancel button'].map(k => [k,{hidden:false, textContent:'', addEventListener(type,fn){this[type]=fn}, requestSubmit(){this.submitted=true}}]));
  nodes['#restart'].hidden=true;
  const timers=[]; let calls=0;
  const context={document:{querySelector:k=>nodes[k]},window:{addEventListener(){}},AbortController,URLSearchParams,FormData:class{*[Symbol.iterator](){}},setTimeout(fn,ms){const t={fn,ms};timers.push(t);return t},clearTimeout(t){timers.splice(timers.indexOf(t),1)},fetch:async()=>{calls++;const value=responses.shift();if(value instanceof Error)throw value;return {ok:!value.http,status:value.http||200,json:async()=>value}}};
  vm.runInNewContext(source,context);
  const settle=async()=>{for(let i=0;i<10;i++)await Promise.resolve()};
  await settle();
  return {nodes, get calls(){return calls},async tick(){const t=timers.find(t=>t.ms===1500);assert.ok(t);timers.splice(timers.indexOf(t),1);t.fn();await settle()},async cancel(){await nodes['#cancel'].submit({preventDefault(){},currentTarget:nodes['#cancel']});await settle()}};
}
(async()=>{
  for (const [state,title] of [['REJECTED','Du nekade legitimeringen'],['EXPIRED','QR-koden har gått ut'],['CANCELLED','Inloggningen avbröts']]) {
    const s=await scenario([{state}]); assert.equal(s.nodes['#heading'].textContent,title);assert.equal(s.nodes['.qr'].hidden,true);assert.equal(s.nodes['#restart'].hidden,false);assert.ok(!s.nodes['#complete'].submitted);
  }
  const transient=await scenario([Error(),{state:'PENDING'},{state:'APPROVED'}]);
  assert.equal(transient.nodes['.qr'].hidden,false);await transient.tick();assert.match(transient.nodes['#status'].textContent,/Väntar/);await transient.tick();assert.equal(transient.nodes['#complete'].submitted,true);assert.equal(transient.calls,3);
  const offline=await scenario([Error(),Error(),Error()]);await offline.tick();await offline.tick();assert.equal(offline.nodes['.qr'].hidden,true);assert.match(offline.nodes['#status'].textContent,/redan godkänt/);assert.ok(!offline.nodes['#complete'].submitted);
  const denied=await scenario([{http:400}]);assert.match(denied.nodes['#status'].textContent,/Mitt ID/);assert.ok(!denied.nodes['#complete'].submitted);
  const cancel=await scenario([{state:'PENDING'},{}]);await cancel.cancel();assert.equal(cancel.nodes['#heading'].textContent,'Inloggningen avbröts');await cancel.tick();assert.equal(cancel.calls,2);
  const uncertain=await scenario([{state:'PENDING'},Error()]);await uncertain.cancel();assert.equal(uncertain.nodes['#heading'].textContent,'Avbrottet kunde inte bekräftas');assert.ok(!uncertain.nodes['#complete'].submitted);
  console.log('PASS 8 feedback scenarios: rejection, expiry, cancellation, recovery, offline, invalid request, cancel button, uncertain cancel');
})().catch(e=>{console.error(e);process.exitCode=1});
