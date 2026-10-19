'use strict';
const $ = id => document.getElementById(id);
let token, stream, generation = 0, busy = false;
function closeCamera() {
  generation++;
  if (stream) stream.getTracks().forEach(track => track.stop());
  stream = undefined; $('camera').srcObject = null; $('camera').hidden = true;
  $('placeholder').hidden = false; $('close-camera').hidden = true;
  $('open-camera').disabled = false; $('camera-status').textContent = 'Kameran är avstängd.';
}
$('open-camera').addEventListener('click', async () => {
  closeCamera(); const attempt = generation;
  $('open-camera').disabled = true; $('close-camera').hidden = false;
  try {
    const acquired = await navigator.mediaDevices.getUserMedia({video:{facingMode:'user',width:{ideal:1280},height:{ideal:720}},audio:false});
    if (attempt !== generation || document.hidden) { acquired.getTracks().forEach(track => track.stop()); return; }
    stream = acquired; $('camera').srcObject = stream; $('camera').hidden = false; $('placeholder').hidden = true;
    $('camera-status').textContent = 'Redo att ta bild.';
  } catch (_) {
    if (attempt !== generation) return;
    closeCamera(); $('camera-status').textContent = 'Kameran kunde inte öppnas. Kontrollera webbläsarens behörighet.';
  }
});
$('close-camera').addEventListener('click',closeCamera);
window.addEventListener('pagehide',closeCamera);
document.addEventListener('visibilitychange',()=>{if(document.hidden)closeCamera();});
function encode(buffer) {
  const bytes = new Uint8Array(buffer); let text = '';
  for (let i=0;i<bytes.length;i+=8192) text += String.fromCharCode(...bytes.subarray(i,i+8192));
  return btoa(text);
}
$('verification').addEventListener('submit',async event=>{
  event.preventDefault(); if(busy || !token)return;
  busy=true; $('verify').disabled=true; $('result').hidden=true;
  try {
    if(!$('consent').checked || !stream || !$('camera').videoWidth) throw new Error('Öppna kameran och bekräfta bearbetningen först.');
    const data={};
    for(const [name,max] of [['sod',65536],['dg1',4096],['dg2',2000000]]) {
      const file=$(name).files[0];
      if(!file || !file.size || file.size>max)throw new Error('En chipfil saknas eller överskrider storleksgränsen.');
      data[name]=encode(await file.arrayBuffer());
    }
    const canvas=document.createElement('canvas');
    canvas.width=$('camera').videoWidth;canvas.height=$('camera').videoHeight;
    canvas.getContext('2d').drawImage($('camera'),0,0);
    data.camera=canvas.toDataURL('image/jpeg',0.9).split(',')[1];
    canvas.width=canvas.height=0;closeCamera();
    $('status').textContent='Kontrollerar…';
    const response=await fetch('/verify',{method:'POST',cache:'no-store',headers:{'Content-Type':'application/json','X-CSRF-Token':token},body:JSON.stringify(data)});
    const result=await response.json();
    if(!response.ok)throw new Error(result.error || 'Verifieringen misslyckades.');
    $('passport-result').textContent='Godkända. Certifikatspärr har inte kontrollerats.';
    $('face-result').textContent=result.faceCosineSimilarity.toFixed(4);
    $('pad-result').textContent=result.padLiveScore == null ? 'Ingen analys utförd.' : result.padLiveScore.toFixed(4);
    $('result').hidden=false; $('status').textContent='Analysen är klar.';
  } catch(error){$('status').textContent=error.message;}
  finally{busy=false;$('verify').disabled=false;}
});
fetch('/session',{cache:'no-store'}).then(async response=>{
  if(!response.ok)throw new Error();token=(await response.json()).token;
  $('verify').disabled=false;$('status').textContent='Redo.';
}).catch(()=>{$('status').textContent='Den lokala verifieraren kunde inte nås.';});
