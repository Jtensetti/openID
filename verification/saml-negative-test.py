"""Isolated HTTP/SAML regression: synthetic identity, no pilot data mounts."""
import http.cookiejar
from html.parser import HTMLParser
import json
from pathlib import Path
import re
import ssl
import subprocess
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from federation import FederationServer
from test_identity import document
from test_wallet import crypt
from wallet import Wallet

class Forms(HTMLParser):
    def __init__(self, html):
        super().__init__(); self.forms=[]; self.current=None; self.feed(html)
    def handle_starttag(self, tag, attrs):
        a=dict(attrs)
        if tag=='form':
            self.current={'action':a.get('action'), 'fields':{}}; self.forms.append(self.current)
        if tag=='input' and self.current is not None and 'name' in a:
            self.current['fields'][a['name']]=a.get('value','')
    def handle_endtag(self, tag):
        if tag=='form': self.current=None

with tempfile.TemporaryDirectory() as tmp:
    root=Path(tmp); keys=root/'keys'; jar='/app/prototype/target/isolated-eid-lab.jar'
    subprocess.run(['java','-jar',jar,'phone-init',str(keys)],check=True,stdout=subprocess.DEVNULL)
    offset=0
    wallet=Wallet(root/'wallet.sqlite','https://localhost:8765',clock=lambda:time.time()+offset)
    bridge=FederationServer(root/'bridge.sock',wallet)
    children=[]
    log=open(root/'service.log','w+')
    try:
        for mode in ('phone-idp','phone-sp'):
            children.append(subprocess.Popen(['java','-Xmx256m','-jar',jar,mode,str(keys),str(bridge.path)],stdout=log,stderr=log))
        tls=ssl.create_default_context(cafile=str(keys/'tls.crt'))
        def client():
            return urllib.request.build_opener(urllib.request.HTTPSHandler(context=tls),urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
        def request(c,url,fields=None):
            headers={} if fields is None else {'Origin':'https://localhost:8443'}
            data=None if fields is None else urllib.parse.urlencode(fields).encode()
            try:
                r=c.open(urllib.request.Request(url,data=data,headers=headers),timeout=10)
            except urllib.error.HTTPError as e: r=e
            return r.status,r.read().decode(),r.url
        for port in (8443,8444):
            for attempt in range(100):
                try:
                    status,_,_=request(client(),f'https://localhost:{port}/'+('phone/page.css' if port==8443 else 'health/ready'))
                    if status==200: break
                except OSError: pass
                time.sleep(.3)
            else: raise AssertionError('startup failed')
        key=json.loads(crypt(op='new'))
        ident=wallet.enroll(key['publicKey'],document())['id']; wallet.activate(ident,'REVIEW-negative-test-001')
        def sign(action,rid):
            challenge=wallet.challenge({'credentialId':ident,'action':action,'requestId':rid})
            return {'challengeId':challenge['id'],'signature':crypt(op='sign',key=key['privateKey'],payload=challenge['signingInput'])}
        def begin():
            c=client(); status,html,_=request(c,'https://localhost:8444/login'); assert status==200
            rid=re.search(r'openid://request/([a-f0-9]{64})',html).group(1)
            form=next(f for f in Forms(html).forms if f['action']=='/phone/complete')
            return c,rid,form['fields']
        def denied(c):
            for path in ('me','portrait'):
                assert request(c,'https://localhost:8444/'+path)[0]==401, path
        def complete(c,fields):
            status,html,_=request(c,'https://localhost:8443/phone/complete',fields)
            for form in Forms(html).forms:
                if 'SAMLResponse' in form['fields']:
                    assert form['action']=='https://localhost:8444/acs'
                    return request(c,form['action'],form['fields'])
            return status,html,''
        def must_fail(fn):
            try: fn()
            except ValueError: return
            raise AssertionError('operation unexpectedly accepted')
        c,rid,fields=begin(); wallet.execute(sign('approve',rid)); assert complete(c,fields)[0]==200
        assert request(c,'https://localhost:8444/me')[0]==200
        print('PASS positive control: signed device consent, SAML response and protected session',flush=True)
        c,rid,fields=begin(); late=sign('approve',rid); wallet.execute(sign('reject',rid))
        assert 'APPROVED' not in request(c,'https://localhost:8443/phone/poll',fields)[1]
        must_fail(lambda:wallet.execute(late)); complete(c,fields); denied(c)
        print('PASS rejection: late approval and forced completion denied; /me and /portrait return 401',flush=True)
        c,rid,fields=begin(); late=sign('approve',rid)
        # Advance only the isolated registry clock, never the host or pilot clock.
        offset=121
        assert json.loads(request(c,'https://localhost:8443/phone/poll',fields)[1])['state']=='EXPIRED'
        must_fail(lambda:wallet.execute(late)); complete(c,fields); denied(c); offset=0
        print('PASS expired QR: +121 seconds; stale signature and forced completion denied; protected routes 401',flush=True)
        existing,rid,fields=begin(); wallet.execute(sign('approve',rid)); assert complete(existing,fields)[0]==200
        pending,rid,fields=begin(); wallet.execute(sign('approve',rid)); wallet.revoke(ident)
        must_fail(lambda:sign('approve',rid)); complete(pending,fields); denied(pending); denied(existing)
        print('PASS revoked ID: new approval denied, approved-but-unconsumed login denied, existing session and portrait denied',flush=True)
        log.flush(); log.seek(0); logs=log.read()
        assert 'ALICE' not in logs and '900101' not in logs
        print('PASS synthetic identity absent from service logs',flush=True)
    finally:
        for child in children: child.terminate()
        for child in children:
            try: child.wait(timeout=15)
            except subprocess.TimeoutExpired: child.kill(); child.wait()
        bridge.close(); log.close()
