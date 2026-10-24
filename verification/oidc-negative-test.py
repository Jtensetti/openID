"""Disposable OIDC end-to-end test; synthetic data, isolated network, verified TLS."""
import http.cookiejar, http.server, http.client, threading
from html.parser import HTMLParser
import json, os, re, ssl, subprocess, tempfile, time, base64
from pathlib import Path
import urllib.error, urllib.parse, urllib.request
from federation import FederationServer
from test_identity import document
from test_wallet import crypt
from wallet import Wallet
class Forms(HTMLParser):
 def __init__(self,html):
  super().__init__(); self.forms=[]; self.current=None; self.feed(html)
 def handle_starttag(self,tag,attrs):
  a=dict(attrs)
  if tag=='form': self.current={'action':a.get('action'),'fields':{}}; self.forms.append(self.current)
  if tag=='input' and self.current is not None and 'name' in a:self.current['fields'][a['name']]=a.get('value','')
 def handle_endtag(self,tag):
  if tag=='form': self.current=None
with tempfile.TemporaryDirectory() as tmp:
 root=Path(tmp); keys=root/'keys'; jar='/app/prototype/target/isolated-eid-lab.jar'
 subprocess.run(['java','-jar',jar,'phone-init',str(keys)],check=True,stdout=subprocess.DEVNULL)
 subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1','-subj','/CN=idp.example.test','-addext','subjectAltName=DNS:idp.example.test,DNS:sp.example.test','-keyout',str(root/'ingress.key'),'-out',str(root/'ingress.crt')],check=True,capture_output=True)
 subprocess.run(['keytool','-importcert','-noprompt','-alias','ingress','-file',str(root/'ingress.crt'),'-keystore',str(root/'trust.p12'),'-storepass','test-only-changeit'],check=True,capture_output=True)
 origins=root/'origins.json'; origins.write_text(json.dumps({'idp':'https://idp.example.test','sp':'https://sp.example.test'}))
 tls=ssl.create_default_context(cafile=str(keys/'tls.crt'))
 token_mutation=None;token_request_mutation=None
 subprocess.run(['openssl','pkcs12','-in',str(keys/'idp.p12'),'-passin','pass:test-only-changeit','-nodes','-nocerts','-out',str(root/'idp.pem')],check=True,capture_output=True)
 subprocess.run(['openssl','pkcs12','-in',str(keys/'sp.p12'),'-passin','pass:test-only-changeit','-nodes','-nocerts','-out',str(root/'sp.pem')],check=True,capture_output=True)
 used_assertion=None;used_code=None;used_verifier=None
 def b64(data):return base64.urlsafe_b64encode(data).rstrip(b'=').decode()
 class Proxy(http.server.BaseHTTPRequestHandler):
  def log_message(self,*args):pass
  def do_GET(self):self.forward()
  def do_POST(self):self.forward()
  def forward(self):
   global used_assertion,used_code,used_verifier
   host=self.headers.get('Host'); port={'idp.example.test':9443,'sp.example.test':9444}.get(host)
   if port is None:self.send_error(400);return
   c=http.client.HTTPSConnection('127.0.0.1',port,context=tls,timeout=20)
   body=self.rfile.read(int(self.headers.get('Content-Length','0')))
   if self.path=='/oidc/token' and token_request_mutation:
    fields=urllib.parse.parse_qs(body.decode())
    if token_request_mutation=='pkce':fields['code_verifier']=['A'*43]
    elif token_request_mutation=='redirect':fields['redirect_uri']=['https://sp.example.test/wrong']
    elif token_request_mutation=='client':fields.pop('client_assertion',None)
    elif token_request_mutation=='assertion_replay':fields['client_assertion']=[used_assertion]
    elif token_request_mutation=='code_replay':fields['code']=[used_code];fields['code_verifier']=[used_verifier]
    elif token_request_mutation.startswith('assertion_'):
     a,b,s=fields['client_assertion'][0].split('.')
     claims=json.loads(base64.urlsafe_b64decode(b+'='*(-len(b)%4)))
     claim=token_request_mutation.removeprefix('assertion_')
     if claim=='signature':s=b64(b'invalid-signature')
     else:
      claims[claim]=int(time.time())-60 if claim=='exp' else 'https://wrong.example.test'
      b=b64(json.dumps(claims).encode());s=b64(subprocess.run(['openssl','dgst','-sha256','-sign',str(root/'sp.pem')],input=(a+'.'+b).encode(),check=True,capture_output=True).stdout)
     fields['client_assertion']=[a+'.'+b+'.'+s]
    body=urllib.parse.urlencode(fields,doseq=True).encode();self.headers.replace_header('Content-Length',str(len(body)))
   headers={k:v for k,v in self.headers.items() if k.lower() not in ('connection','accept-encoding')}
   try:
    c.request(self.command,self.path,body=body,headers=headers);r=c.getresponse(); data=r.read()
    if self.path=='/oidc/token' and r.status==200 and token_request_mutation is None and token_mutation is None:
     exchanged=urllib.parse.parse_qs(body.decode());used_assertion=exchanged['client_assertion'][0];used_code=exchanged['code'][0];used_verifier=exchanged['code_verifier'][0]
    if self.path=='/oidc/token' and r.status==200 and token_mutation:
     payload=json.loads(data); a,b,signature=payload['id_token'].split('.')
     claims=json.loads(base64.urlsafe_b64decode(b+'='*(-len(b)%4)))
     if token_mutation=='signature':signature=b64(b'invalid-signature')
     else:
      if token_mutation=='algorithm':
       header=json.loads(base64.urlsafe_b64decode(a+'='*(-len(a)%4)));header['alg']='HS256';a=b64(json.dumps(header).encode())
      elif token_mutation=='auth_time_missing':claims.pop('auth_time',None)
      else:claims[token_mutation]={'nonce':'wrong','iss':'https://wrong.example.test','aud':'wrong-client','exp':int(time.time())-60,'acr':'http://id.elegnamnden.se/loa/1.0/loa3','auth_time':int(time.time())-600}[token_mutation]
      b=b64(json.dumps(claims).encode());signature=b64(subprocess.run(['openssl','dgst','-sha256','-sign',str(root/'idp.pem')],input=(a+'.'+b).encode(),check=True,capture_output=True).stdout)
     payload['id_token']=a+'.'+b+'.'+signature;data=json.dumps(payload).encode()
    self.send_response(r.status)
    for k,v in r.getheaders():
     if k.lower() not in ('transfer-encoding','connection','content-length'):self.send_header(k,v)
    self.send_header('Content-Length',str(len(data)));self.end_headers();self.wfile.write(data)
   except ConnectionRefusedError:self.send_error(503)
   finally:c.close()
 ingress=http.server.ThreadingHTTPServer(('127.0.0.1',443),Proxy)
 ingress_tls=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);ingress_tls.load_cert_chain(root/'ingress.crt',root/'ingress.key')
 ingress.socket=ingress_tls.wrap_socket(ingress.socket,server_side=True)
 threading.Thread(target=ingress.serve_forever,daemon=True).start()
 offset=0
 wallet=Wallet(root/'wallet.sqlite','https://localhost:8765',clock=lambda:time.time()+offset)
 bridge=FederationServer(root/'bridge.sock',wallet,audience='https://sp.example.test/sp')
 children=[];log=open(root/'service.log','w+')
 try:
  for mode in ('phone-idp','phone-sp'):
   children.append(subprocess.Popen(['java','-Xmx256m','-Djavax.net.ssl.trustStore='+str(root/'trust.p12'),'-Djavax.net.ssl.trustStorePassword=test-only-changeit','-jar',jar,mode,str(keys),str(bridge.path),str(origins)],stdout=log,stderr=log))
  public_tls=ssl.create_default_context(cafile=str(root/'ingress.crt'))
  capture_callback=False;captured_callback=None;capture_authorize=False;captured_authorize=None
  class Redirect(urllib.request.HTTPRedirectHandler):
   def redirect_request(self,req,fp,code,msg,headers,newurl):
    global captured_callback,captured_authorize
    if capture_authorize and newurl.startswith('https://idp.example.test/oidc/authorize'):
     captured_authorize=newurl;return None
    if capture_callback and newurl.startswith('https://sp.example.test/oidc/callback'):
     captured_callback=newurl;return None
    return super().redirect_request(req,fp,code,msg,headers,newurl)
  def client():return urllib.request.build_opener(Redirect(),urllib.request.ProxyHandler({}),urllib.request.HTTPSHandler(context=public_tls),urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
  def request(c,url,fields=None):
   headers={} if fields is None else {'Origin':'https://idp.example.test'}
   data=None if fields is None else urllib.parse.urlencode(fields).encode()
   try:r=c.open(urllib.request.Request(url,data=data,headers=headers),timeout=20)
   except urllib.error.HTTPError as e:r=e
   return r.status,r.read().decode(),r.url
  for host,path in [('idp.example.test','/phone/page.css'),('sp.example.test','/health/ready')]:
   for attempt in range(120):
    try:
     if request(client(),'https://'+host+path)[0]==200:break
    except Exception:pass
    time.sleep(.3)
   else:raise AssertionError('startup failed '+host)
  assert request(client(),'https://idp.example.test/sign/')[0] != 200
  key=json.loads(crypt(op='new'));ident=wallet.enroll(key['publicKey'],document())['id'];wallet.activate(ident,'REVIEW-oidc-test-001')
  def sign(action,rid):
   ch=wallet.challenge({'credentialId':ident,'action':action,'requestId':rid})
   return {'challengeId':ch['id'],'signature':crypt(op='sign',key=key['privateKey'],payload=ch['signingInput'])}
  def begin():
   c=client();status,html,url=request(c,'https://sp.example.test/oidc/login')
   assert status==200,(status,html[:1200],url)
   m=re.search(r'openid://request/([a-f0-9]{64})',html)
   assert m,(html[:1600],url)
   form=next(f for f in Forms(html).forms if f['action']=='/phone/complete')
   return c,m.group(1),form['fields']
  def complete(c,fields):return request(c,'https://idp.example.test/phone/complete',fields)
  def denied(c):assert request(c,'https://sp.example.test/oidc/me')[0]==401
  c,rid,fields=begin();wallet.execute(sign('approve',rid));status,html,url=complete(c,fields)
  assert status==200 and 'inloggad med OIDC' in html,(status,html[:1500],url)
  print('PASS OIDC positive: signed consent, code, S256 PKCE, private_key_jwt, nonce, verified TLS and session',flush=True)
  for mutation in ('nonce','iss','aud','exp','acr','auth_time','auth_time_missing','algorithm','signature'):
   c,rid,fields=begin();wallet.execute(sign('approve',rid));token_mutation=mutation
   assert complete(c,fields)[0]==400,mutation
   denied(c);token_mutation=None
  print('PASS signed wrong nonce/issuer/audience/expiry/acr, stale/missing auth_time and bad algorithm/signature rejected',flush=True)
  for mutation in ('pkce','redirect','client','assertion_aud','assertion_iss','assertion_sub','assertion_exp','assertion_signature','assertion_replay','code_replay'):
   if mutation in ('assertion_replay','code_replay'):
    fresh,rid,fields=begin();wallet.execute(sign('approve',rid));assert complete(fresh,fields)[0]==200
    claim=used_assertion.split('.')[1];assert json.loads(base64.urlsafe_b64decode(claim+'='*(-len(claim)%4)))['exp']>time.time()+5
   c,rid,fields=begin();wallet.execute(sign('approve',rid));token_request_mutation=mutation
   assert complete(c,fields)[0]==400,mutation
   denied(c);token_request_mutation=None
  print('PASS wrong PKCE/redirect, missing or invalid private_key_jwt, client assertion replay and code replay denied',flush=True)
  for mutation in ('pkce','method','redirect','client','acr'):
   c=client();capture_authorize=True;request(c,'https://sp.example.test/oidc/login');capture_authorize=False
   parsed=urllib.parse.urlsplit(captured_authorize);params=urllib.parse.parse_qs(parsed.query)
   if mutation=='pkce':params.pop('code_challenge',None);params.pop('code_challenge_method',None)
   elif mutation=='method':params['code_challenge_method']=['plain']
   elif mutation=='redirect':params['redirect_uri']=['https://sp.example.test/wrong']
   elif mutation=='client':params['client_id']=['unregistered']
   else:
    params['acr_values']=['http://id.elegnamnden.se/loa/1.0/loa3']
    params['claims']=[json.dumps({'id_token':{'acr':{'essential':True,'value':params['acr_values'][0]}}})]
   url=urllib.parse.urlunsplit(parsed._replace(query=urllib.parse.urlencode(params,doseq=True)))
   status,html,_=request(c,url);assert 'openid://request/' not in html,mutation;denied(c)
  print('PASS missing PKCE, plain challenge, wrong redirect/client and required LoA3 denied before consent',flush=True)
  c,rid,fields=begin();wallet.execute(sign('approve',rid));capture_callback=True;complete(c,fields);capture_callback=False
  assert captured_callback and 'code=' in captured_callback
  callback=captured_callback
  parsed=urllib.parse.urlsplit(callback);params=urllib.parse.parse_qs(parsed.query);params['state']=['forged']
  bad=urllib.parse.urlunsplit(parsed._replace(query=urllib.parse.urlencode(params,doseq=True)))
  assert request(c,bad)[0]==400;assert request(c,callback)[0]==400;denied(c)
  print('PASS wrong state and replay of consumed pending browser login denied',flush=True)
  c,rid,fields=begin();wallet.execute(sign('approve',rid));capture_callback=True;complete(c,fields);capture_callback=False
  assert request(c,captured_callback)[0]==200
  assert request(c,captured_callback)[0]==400;denied(c)
  print('PASS used authorization response cannot be replayed',flush=True)
  c,rid,fields=begin();wallet.execute(sign('reject',rid));complete(c,fields);denied(c)
  print('PASS rejected consent does not create OIDC session',flush=True)
  c,rid,fields=begin();offset=121;complete(c,fields);denied(c);offset=0
  print('PASS expired QR does not create OIDC session',flush=True)
  for level in range(1,5):assert request(client(),'https://sp.example.test/oidc/login?loa='+str(level))[0]==403
  assert request(client(),'https://sp.example.test/oidc/callback?code=forged&state=forged')[0]==400
  print('PASS unsupported LoA1-4 and unbound callback denied',flush=True)
  active,rid,fields=begin();wallet.execute(sign('approve',rid));assert complete(active,fields)[0]==200
  pending,rid,fields=begin();wallet.execute(sign('approve',rid));wallet.revoke(ident);complete(pending,fields);denied(pending);denied(active)
  print('PASS revoked identity blocks pending completion and existing OIDC session',flush=True)
  log.flush();log.seek(0);logs=log.read();assert 'ALICE' not in logs and '900101' not in logs
  print('PASS identity data absent from logs',flush=True)
 except Exception:
  log.flush();log.seek(0);print(log.read()[-14000:]);raise
 finally:
  for c in children:c.terminate()
  for c in children:
   try:c.wait(timeout=10)
   except subprocess.TimeoutExpired:c.kill();c.wait()
  bridge.close();ingress.shutdown();log.close()
