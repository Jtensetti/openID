"""TLS/SigV4 STS/Lambda/SQS and IMDSv2 fixtures for the disposable runtime probe.

These fixtures issue only visibly synthetic credentials, implement a minimal
role model and never contact AWS. They are not included in a runtime image.
"""
import datetime
from collections import deque
import hashlib
import http.server
import json
import re
import socket
import ssl
import threading
from urllib.parse import parse_qs, unquote
import uuid
from xml.sax.saxutils import escape

NOW = lambda: datetime.datetime.now(datetime.timezone.utc)
ROLES = {'HOST': 'H', 'CONTINUITY': 'C', 'NOTICES': 'N'}
ACCOUNT = '000000000000'


def credentials(role):
    letter = ROLES[role]
    return {'AccessKeyId': 'ASIA'+letter*16, 'SecretAccessKey': letter*40, 'Token': 'SYNTHETIC_SESSION_'+role,
            'Expiration': (NOW()+datetime.timedelta(hours=1)).isoformat()}


class SyntheticAWS:
    def __init__(self, certificate, key):
        self.servers=[]; self.lock=threading.RLock(); self.authority=None
        self.messages={}; self.attempts=[]; self.fail_sqs=1; self.signed_calls=[]; self.imds_v2=0; self.errors=deque(maxlen=10)
        fixture=self
        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self,*_): pass
            def reply(self,status,body,kind='application/json'):
                raw=body if isinstance(body,bytes) else json.dumps(body).encode()
                self.send_response(status);self.send_header('Content-Type',kind)
                self.send_header('Content-Length',str(len(raw)));self.end_headers();self.wfile.write(raw)
            def do_PUT(self):
                if self.path!='/latest/api/token':return self.reply(404,{})
                fixture.imds_v2+=1;self.reply(200,b'SYNTHETIC_IMDS_V2','text/plain')
            def do_GET(self):
                if self.path=='/probe':return self.reply(200,b'SYNTHETIC_METADATA','text/plain')
                if self.headers.get('X-aws-ec2-metadata-token')!='SYNTHETIC_IMDS_V2':return self.reply(401,{})
                if self.path=='/latest/meta-data/iam/security-credentials/':return self.reply(200,b'HOST','text/plain')
                if self.path=='/latest/meta-data/iam/security-credentials/HOST':
                    return self.reply(200,credentials('HOST')|{'Code':'Success','Type':'AWS-HMAC'})
                self.reply(404,{})
            def do_POST(self):
                try:
                    raw=self.rfile.read(int(self.headers.get('Content-Length','0')))
                    role,service=fixture.verify(self,raw)
                    if service=='sts':return self.sts(role,raw)
                    if service=='lambda':
                        if role!='CONTINUITY' or unquote(self.path)!='/2015-03-31/functions/arn:aws:lambda:eu-north-1:000000000000:function:SYNTHETIC-issuer-authority/invocations':
                            return self.reply(403,{'message':'synthetic role denied'})
                        payload=json.loads(raw)
                        with fixture.lock:result=fixture.authority.invoke(payload)
                        return self.reply(200,result)
                    if service=='sqs':
                        if role!='NOTICES':return self.reply(403,{'__type':'AccessDenied','message':'synthetic role denied'})
                        data=json.loads(raw)
                        if data['QueueUrl']!='https://sqs.eu-north-1.amazonaws.com/000000000000/synthetic-notices':
                            return self.reply(403,{'__type':'AccessDenied','message':'synthetic queue denied'})
                        event=json.loads(data['MessageBody'])
                        if set(event)!={'event','contactVersion','kind','created'}:raise ValueError('opaque event required')
                        with fixture.lock:
                            fixture.attempts.append(event['event'])
                            fixture.messages.setdefault(event['event'],event)
                            if fixture.fail_sqs:
                                fixture.fail_sqs-=1
                                return self.reply(503,{'__type':'ServiceUnavailable','message':'synthetic ambiguous send'})
                        return self.reply(200,{'MessageId':str(uuid.uuid4()),'MD5OfMessageBody':hashlib.md5(data['MessageBody'].encode()).hexdigest()})
                    self.reply(403,{'message':'synthetic service denied'})
                except Exception as error:
                    with fixture.lock:fixture.errors.append(type(error).__name__)
                    self.reply(503,{'message':'synthetic upstream unavailable'})
            def sts(self,role,raw):
                fields={k:v[0] for k,v in parse_qs(raw.decode()).items()};action=fields['Action']
                if role!='HOST':return self.reply(403,{'message':'synthetic source role denied'})
                if action=='GetCallerIdentity':
                    content=f'<Arn>arn:aws:sts::{ACCOUNT}:assumed-role/HOST/i-synthetic</Arn><UserId>SYNTHETIC</UserId><Account>{ACCOUNT}</Account>'
                elif action=='AssumeRole':
                    target=fields['RoleArn'].split('/')[-1]
                    if target not in ('CONTINUITY','NOTICES') or fields['RoleSessionName']!='tjipp-'+('continuity' if target=='CONTINUITY' else 'notices') or fields['DurationSeconds']!='3600':
                        return self.reply(403,{'message':'synthetic target role denied'})
                    value=credentials(target)
                    content='<Credentials>'+''.join(f'<{k}>{escape(v)}</{k}>' for k,v in {
                        'AccessKeyId':value['AccessKeyId'],'SecretAccessKey':value['SecretAccessKey'],
                        'SessionToken':value['Token'],'Expiration':value['Expiration']}.items())+'</Credentials>'
                    content+=f'<AssumedRoleUser><Arn>arn:aws:sts::{ACCOUNT}:assumed-role/{target}/{fields["RoleSessionName"]}</Arn><AssumedRoleId>SYNTHETIC</AssumedRoleId></AssumedRoleUser>'
                else:return self.reply(403,{'message':'synthetic action denied'})
                body=f'<{action}Response xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><{action}Result>{content}</{action}Result><ResponseMetadata><RequestId>SYNTHETIC</RequestId></ResponseMetadata></{action}Response>'
                self.reply(200,body.encode(),'text/xml')
        self.handler=Handler
        try:
            server=http.server.ThreadingHTTPServer(('127.0.0.2',443),Handler)
            context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(certificate,key)
            server.socket=context.wrap_socket(server.socket,server_side=True);self.start(server)
            self.start(http.server.ThreadingHTTPServer(('169.254.169.254',80),Handler))
            class V6(http.server.ThreadingHTTPServer):address_family=socket.AF_INET6
            self.start(V6(('fd00:ec2::254',80),Handler))
        except BaseException:self.close();raise

    def start(self,server):
        worker=threading.Thread(target=server.serve_forever,daemon=True);worker.start();self.servers.append((server,worker))

    def verify(self,handler,raw):
        from botocore.auth import SigV4Auth
        from botocore.awsrequest import AWSRequest
        from botocore.credentials import Credentials
        authorization=handler.headers.get('Authorization','')
        match=re.fullmatch(r'AWS4-HMAC-SHA256 Credential=([^/]+)/([0-9]{8})/eu-north-1/(sts|lambda|sqs)/aws4_request, SignedHeaders=([^,]+), Signature=([a-f0-9]{64})',authorization)
        if match is None:raise ValueError('signed request required')
        key,_,service,names,signature=match.groups()
        if handler.headers.get('Host')!=service+'.eu-north-1.amazonaws.com':raise ValueError('fixed service host required')
        role=next(role for role in ROLES if credentials(role)['AccessKeyId']==key)
        value=credentials(role)
        if handler.headers.get('X-Amz-Security-Token')!=value['Token']:raise ValueError('session token required')
        headers={name:handler.headers[name] for name in names.split(';')}
        request=AWSRequest(method='POST',url='https://'+handler.headers['Host']+handler.path,data=raw,headers=headers)
        request.context['timestamp']=handler.headers['X-Amz-Date']
        signer=SigV4Auth(Credentials(key,value['SecretAccessKey'],value['Token']),service,'eu-north-1')
        expected=signer.signature(signer.string_to_sign(request,signer.canonical_request(request)),request)
        if signature!=expected:raise ValueError('signature rejected')
        with self.lock:self.signed_calls.append((role,service))
        return role,service

    def close(self):
        for server,worker in reversed(self.servers):server.shutdown();server.server_close();worker.join(3)
