"""Read-only applicability probes inside the exact final application image.

These observations support the reviewed data-flow decisions in runtime-policy.json;
absence of an ELF import alone is not a whole-program reachability proof.
"""
import ast
import base64
import binascii
import ctypes
import hashlib
import importlib.util
import io
import json
import mmap
import os
from pathlib import Path
import platform
import shutil
import sqlite3
import stat
import struct
import subprocess
import sys
import tempfile

ROOT = Path('/usr/share/doc/openid-runtime')
SYMBOLS = {'posix_memalign','strfmon','strfmon_l','wordexp','regcomp','regexec','glob','glob64','tdelete',
 'ns_printrr','ns_printrrf','fp_nquery','crc32_combine64','crc32_combine_gen64','gzprintf','gzvprintf','gzclearerr',
 'sqlite3changeset_apply','sqlite3changeset_apply_v2','sqlite3changeset_apply_v3',
 'sqlite3changeset_concat','sqlite3changegroup_add','XML_ParserReset',
 'fwscanf','wscanf','swscanf','vfwscanf','vwscanf','vswscanf',
 '__isoc99_fwscanf','__isoc99_wscanf','__isoc99_swscanf',
 '__isoc99_vfwscanf','__isoc99_vwscanf','__isoc99_vswscanf',
 '__isoc23_fwscanf','__isoc23_wscanf','__isoc23_swscanf',
 '__isoc23_vfwscanf','__isoc23_vwscanf','__isoc23_vswscanf',
 'CMS_encrypt','CMS_encrypt_ex','OSSL_QUIC_client_method','OSSL_QUIC_client_thread_method',
 'SSL_set1_initial_peer_addr','SSL_set_blocking_mode','SSL_handle_events',
 'EVP_CIPHER_fetch','EVP_aes_128_gcm_siv','EVP_aes_256_gcm_siv'}


def check_network_transport():
    import http.client
    from http_transport import configured_url, StrictResponse, HTTPSConnection
    from aws_client import ENDPOINTS, runtime_client
    from unittest.mock import patch
    for value in ('https://localhost\0.example', 'https://localhost:443\0',
                  'https://local\nhost', '\thttps://localhost'):
        try: configured_url(value)
        except ValueError: pass
        else: raise ValueError('network destination accepted controls')
    if configured_url('https://localhost:443').hostname != 'localhost':
        raise ValueError('ordinary network destination rejected')
    if HTTPSConnection.response_class is not StrictResponse:
        raise ValueError('strict HTTP response not wired')
    class Wire:
        def __init__(self, value): self.value=value
        def makefile(self, *args): return io.BytesIO(self.value)
    def read(headers, body):
        response=StrictResponse(Wire(b'HTTP/1.1 200 OK\r\n'+headers+b'\r\n\r\n'+body))
        response.begin();return response.read()
    for headers,body in ((b'Content-Length: +2',b'ok'),
                         (b'Content-Length: 2_0',b'ok'),
                         (b'Transfer-Encoding: chunked',b'0x2\r\nok\r\n0\r\n\r\n'),
                         (b'Transfer-Encoding: chunked',b'-2\r\nok\r\n0\r\n\r\n')):
        try: read(headers,body)
        except http.client.HTTPException: pass
        else: raise ValueError('malformed HTTP framing accepted')
    if read(b'Transfer-Encoding: chunked',b'2\r\nok\r\n0\r\n\r\n') != b'ok':
        raise ValueError('ordinary HTTP framing rejected')
    if ENDPOINTS != {s:f'https://{s}.eu-north-1.amazonaws.com' for s in ('lambda','sqs','dynamodb')}:
        raise ValueError('new AWS endpoint needs review')
    if importlib.util.find_spec('boto3'):
        with patch('boto3.client') as client:
            for service,endpoint in ENDPOINTS.items():
                runtime_client(service,read_timeout=3)
                args,kwargs=client.call_args
                if (args!=(service,) or kwargs['endpoint_url']!=endpoint
                        or kwargs['region_name']!='eu-north-1'
                        or kwargs.get('verify',True) is not True or kwargs['config'].proxies!={}):
                    raise ValueError('AWS TLS destination or proxy restriction changed')
    return ['strict_http_framing','network_origin_no_controls','aws_json_endpoints']


def check_sqlite_snapshot_boundary():
    from recovery_binding import validate_snapshot_schema, no_sqlite_sidecars
    for statement in ('CREATE VIEW unexpected AS SELECT 1',
                      'CREATE VIRTUAL TABLE unexpected USING fts3(content)',
                      'CREATE VIRTUAL TABLE unexpected USING fts5(content)',
                      'CREATE VIRTUAL TABLE unexpected USING rtree(id,x0,x1)'):
        with sqlite3.connect(':memory:') as db:
            db.execute('CREATE TABLE ordinary(x)')
            validate_snapshot_schema(db)
            db.execute(statement)
            try: validate_snapshot_schema(db)
            except ValueError: pass
            else: raise ValueError('executable snapshot schema accepted')
    with tempfile.TemporaryDirectory() as directory:
        path=Path(directory)/'wallet.sqlite'
        no_sqlite_sidecars(path)
        for suffix in ('-wal','-shm','-journal'):
            sidecar=Path(str(path)+suffix);sidecar.touch()
            try: no_sqlite_sidecars(path)
            except ValueError: pass
            else: raise ValueError('external SQLite sidecar accepted')
            sidecar.unlink()
    return ['sqlite_snapshot_schema','sqlite_no_external_wal']


def check_sts_transport():
    """Exercise the shipped client and locked parser with synthetic wire bytes."""
    import datetime
    import boto3
    import botocore
    from botocore.awsrequest import AWSResponse
    from botocore.exceptions import ClientError
    from botocore.parsers import ResponseParserError
    from unittest.mock import patch
    from aws_credential_rotate import metadata_client, STSResponseError, STS_XML_LIMIT
    if (boto3.__version__, botocore.__version__) != ('1.43.115', '1.43.115'):
        raise ValueError('STS SDK version needs review')
    expiry=(datetime.datetime.now(datetime.timezone.utc)+datetime.timedelta(hours=1)).isoformat()
    metadata={'role_name':'SYNTHETIC_HOST','access_key':'ASIA'+'A'*16,
        'secret_key':'A'*40,'token':'SYNTHETIC_TOKEN','expiry_time':expiry}
    identity=(b'<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">'
        b'<GetCallerIdentityResult><Arn>arn:aws:sts::000000000000:assumed-role/SYNTHETIC_HOST/probe</Arn>'
        b'<UserId>generated</UserId><Account>000000000000</Account></GetCallerIdentityResult>'
        b'<ResponseMetadata><RequestId>generated</RequestId></ResponseMetadata></GetCallerIdentityResponse>')
    assumed=(f'<AssumeRoleResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">'
        f'<AssumeRoleResult><Credentials><AccessKeyId>ASIA{"B"*16}</AccessKeyId>'
        f'<SecretAccessKey>{"B"*40}</SecretAccessKey><SessionToken>SYNTHETIC_TOKEN</SessionToken>'
        f'<Expiration>{expiry}</Expiration></Credentials><AssumedRoleUser>'
        f'<Arn>arn:aws:sts::000000000000:assumed-role/SYNTHETIC_TARGET/probe</Arn>'
        f'<AssumedRoleId>generated:probe</AssumedRoleId></AssumedRoleUser></AssumeRoleResult>'
        f'<ResponseMetadata><RequestId>generated</RequestId></ResponseMetadata></AssumeRoleResponse>').encode()
    denied=(b'<ErrorResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">'
        b'<Error><Type>Sender</Type><Code>AccessDenied</Code><Message>synthetic denial</Message></Error>'
        b'<RequestId>generated</RequestId></ErrorResponse>')
    dtd=(b'<!DOCTYPE GetCallerIdentityResponse [<!ENTITY generated "000000000000">]>'
        +identity.replace(b'000000000000',b'&generated;'))
    rejected=[dtd,b'\xef\xbb\xbf'+dtd,b'<!ENTITY generated "value">'+identity,
        identity.decode().encode('utf-16-le'),identity.decode().encode('utf-16-be'),
        b'<?xml version="1.0" encoding="ISO-8859-1"?>'+identity,
        b'\xff'+identity,b'\0'+identity,b'',b' '*(STS_XML_LIMIT+1)]
    class Raw:
        def __init__(self, body): self.body=body
        def stream(self, **kwargs): yield self.body
    env={k:v for k,v in os.environ.items() if not k.startswith('AWS_')}
    env.update(AWS_CONFIG_FILE='/dev/null',AWS_SHARED_CREDENTIALS_FILE='/dev/null',AWS_EC2_METADATA_DISABLED='true')
    calls=0
    with patch.dict(os.environ,env,clear=True), \
            patch('socket.socket.connect',side_effect=AssertionError('offline STS probe attempted network')), \
            patch('botocore.utils.InstanceMetadataFetcher.retrieve_iam_role_credentials',return_value=metadata):
        client=metadata_client()
        try:
            config=client.meta.config
            if (client.meta.endpoint_url!='https://sts.eu-north-1.amazonaws.com'
                    or client.meta.service_model.metadata['protocol']!='query'
                    or config.proxies!={} or config.connect_timeout!=2 or config.read_timeout!=3
                    or config.retries.get('total_max_attempts')!=1
                    or client._endpoint.http_session._verify is not True
                    or client._request_signer._credentials.method!='iam-role'):
                raise ValueError('STS endpoint, TLS or provider boundary changed')
            factory=client._endpoint._response_parser_factory
            def invoke(body, status=200, operation='get_caller_identity'):
                nonlocal calls
                calls+=1
                response=AWSResponse(client.meta.endpoint_url,status,{'content-type':'text/xml'},Raw(body))
                with patch.object(client._endpoint.http_session,'send',return_value=response):
                    if operation=='assume_role':
                        return client.assume_role(RoleArn='arn:aws:iam::000000000000:role/SYNTHETIC_TARGET',
                            RoleSessionName='probe',DurationSeconds=3600)
                    return client.get_caller_identity()
            with patch.object(factory,'create_parser',wraps=factory.create_parser) as parser:
                if invoke(identity).get('Account')!='000000000000': raise ValueError('normal STS identity failed')
                if invoke(assumed,operation='assume_role')['Credentials']['AccessKeyId']!='ASIA'+'B'*16:
                    raise ValueError('normal STS role response failed')
                if parser.call_count<2: raise ValueError('STS successes skipped real parser')
            with patch.object(factory,'create_parser',wraps=factory.create_parser) as parser:
                try: invoke(denied,403)
                except ClientError as error:
                    if error.response['Error']['Code']!='AccessDenied': raise
                else: raise ValueError('STS API denial accepted')
                if not parser.called: raise ValueError('STS error skipped real parser')
            for body in rejected:
                for status in (200,403):
                    with patch.object(factory,'create_parser',wraps=factory.create_parser) as parser:
                        try: invoke(body,status)
                        except STSResponseError: pass
                        else: raise ValueError('prohibited STS XML accepted')
                        if parser.called: raise ValueError('prohibited STS XML reached parser')
            with patch.object(factory,'create_parser',wraps=factory.create_parser) as parser:
                try: invoke(b'<broken')
                except ResponseParserError: pass
                else: raise ValueError('malformed STS XML accepted')
                if not parser.called: raise ValueError('malformed XML did not exercise SDK parser')
            if invoke(b'\xef\xbb\xbf'+identity).get('Account')!='000000000000':
                raise ValueError('normal BOM response or post-error reuse failed')
        finally:
            client.close()
    return {'protocol':'query','boto3':boto3.__version__,'botocore':botocore.__version__,
        'operations':['GetCallerIdentity','AssumeRole'],'syntheticResponses':calls,
        'rejectedBeforeParser':2*len(rejected),'parserBodyLimit':STS_XML_LIMIT,
        'checks':['aws_sts_query_transport','aws_sts_before_parse_guard','aws_sts_api_errors'],
        'limits':['Synthetic responses and credentials; no network or AWS access.',
            'The SDK already buffered the body; this is not a transport memory bound.',
            'This does not assess other XML consumers or close an advisory.']}


def elf_imports(path):
    with path.open('rb') as stream:
        if stream.read(4)!=b'\x7fELF': return None
        with mmap.mmap(stream.fileno(),0,access=mmap.ACCESS_READ) as raw:
            if raw[4:6]!=b'\x02\x01': raise ValueError('unexpected ELF format: '+str(path))
            header=struct.unpack_from('<16sHHIQQQIHHHHHH',raw)
            if header[2]!=62: raise ValueError('unexpected ELF architecture')
            offset,entrysize,count=header[6],header[11],header[12]
            if entrysize!=64 or not count: raise ValueError('missing ELF sections')
            sections=[struct.unpack_from('<IIQQQQIIQQ',raw,offset+n*64) for n in range(count)]
            imports=set()
            for sec in sections:
                if sec[1]!=11: continue
                strings=sections[sec[6]]
                start,end=strings[4],strings[4]+strings[5]
                if sec[9]!=24 or end>len(raw): raise ValueError('invalid dynamic symbols')
                for at in range(sec[4],sec[4]+sec[5],24):
                    name,info,other,index,value,size=struct.unpack_from('<IBBHQQ',raw,at)
                    if index!=0 or not name: continue
                    stop=raw.find(b'\0',start+name,end)
                    if stop<0: raise ValueError('invalid ELF symbol string')
                    symbol=raw[start+name:stop].decode('utf-8')
                    if symbol in SYMBOLS or 'from_chars' in symbol: imports.add(symbol)
            return imports


def check_sources(directory):
    count=0
    forbidden={'imaplib','poplib','xml','xmlrpc','pyexpat'}
    for path in directory.rglob('*.py'):
        tree=ast.parse(path.read_text())
        for node in ast.walk(tree):
            if isinstance(node,ast.Import):
                for item in node.names:
                    if item.name.split('.')[0] in forbidden: raise ValueError('new parser/mail entry point: '+path.name)
                    if item.name=='base64' and item.asname: raise ValueError('review base64 alias')
            if isinstance(node,ast.ImportFrom):
                module=(node.module or '').split('.')[0]
                if module in forbidden or module=='base64': raise ValueError('review parser/base64 import: '+path.name)
            if isinstance(node,ast.Call):
                name=getattr(node.func,'attr',getattr(node.func,'id',''))
                if name in {'js_output','get_data','enable_load_extension','load_extension','urlsafe_b64decode','VideoCapture','VideoWriter'}:
                    raise ValueError('new reviewed API call: '+path.name+':'+name)
                if name=='b64decode':
                    if (len(node.args)!=1 or {k.arg for k in node.keywords}!={'validate'}
                         or not isinstance(node.keywords[0].value,ast.Constant)
                         or node.keywords[0].value.value is not True):
                        raise ValueError('non-strict Base64 decoder')
                    count+=1
    if count==0: raise ValueError('no application decoder coverage')
    return count


def check_crypto_routes(directory):
    """Assert the reviewed service profile does not introduce these crypto APIs.

    Native consumers are separately bound by image hash and ELF call inventory;
    this is a change detector for the source review, not a general code sandbox.
    """
    prohibited = ('gcm-siv', 'cms_encrypt', 'ossl_quic_', 'ssl_set1_initial_peer_addr')
    for pattern in ('*.py', '*.mjs'):
        for path in directory.glob(pattern):
            source = path.read_text()
            if any(word in source.lower() for word in prohibited):
                raise ValueError('new service crypto route needs review')
            if path.suffix == '.py':
                for node in ast.walk(ast.parse(source)):
                    if (isinstance(node, ast.Constant) and isinstance(node.value, str)
                            and (node.value == 'openssl' or node.value.endswith('/openssl'))):
                        raise ValueError('service invokes OpenSSL CLI')
    import ssl
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    if any('SIV' in cipher['name'] for cipher in context.get_ciphers()):
        raise ValueError('unexpected TLS cipher profile')
    for path in (directory/'node_modules').rglob('package.json'):
        if json.loads(path.read_text()).get('name') == 'webpack-dev-middleware':
            raise ValueError('unexpected development middleware in runtime')
    return ['service_crypto_profile', 'no_webpack_dev_middleware']


def collect():
    if sys.platform!='linux' or sys.version_info[:3]!=(3,12,16) or platform.machine()!='x86_64':
        raise ValueError('unexpected runtime')
    policy=json.loads((ROOT/'runtime-policy.json').read_text())
    removal=json.loads((ROOT/'removal.json').read_text())
    if removal['format']!=1 or set(removal['packages'])!=set(policy['removedPackages']):
        raise ValueError('incomplete removal manifest')
    paths={r['path'] for r in removal['removed']}
    if len(paths)!=len(removal['removed']) or not paths: raise ValueError('invalid removal manifest')
    for path in paths:
        if Path(path).exists() or Path(path).is_symlink(): raise ValueError('removed code reappeared: '+path)
    for package,files in removal['packages'].items():
        if not set(files)<=paths: raise ValueError('unaccounted package payload')
    for name in ('imaplib','poplib','readline','_curses','pip','ensurepip'):
        if importlib.util.find_spec(name) is not None: raise ValueError('unused module remains: '+name)
    for name in ('nscd','bzip2recover','ldd','bash','sh','mount','nsenter','infocmp'):
        if shutil.which(name): raise ValueError('unused tool remains: '+name)
    decoder_count=check_sources(Path('/app/verification'))
    for raw in (b'YQ==Zg==',b'YQ==junk',b'Y Q==',b'YQ==\n'):
        try: base64.b64decode(raw,validate=True)
        except binascii.Error: pass
        else: raise ValueError('Base64 suffix accepted')
    if base64.b64decode(b'+/8=',validate=True)!=b'\xfb\xff': raise ValueError('standard alphabet broken')
    if not shutil.rmtree.avoids_symlink_attacks or hasattr(os,'chflags'):
        raise ValueError('TemporaryDirectory platform mitigation unavailable')
    with tempfile.TemporaryDirectory() as d:
        outside=Path(d)/'outside';outside.mkdir();(outside/'keep').write_text('keep')
        child=Path(d)/'child';child.mkdir();(child/'link').symlink_to(outside,target_is_directory=True)
        shutil.rmtree(child)
        if (outside/'keep').read_text()!='keep': raise ValueError('cleanup followed a symlink')
    if os.environ.get('LOCALDOMAIN')!='': raise ValueError('DNS search-list mitigation missing')
    libc=ctypes.CDLL(None)
    init=getattr(libc,'__res_init')
    if init()!=0 or init()!=0: raise ValueError('resolver initialization failed')
    import socket
    if not socket.getaddrinfo('localhost',443): raise ValueError('ordinary resolver failed')
    # Python's file API rejects arbitrary glibc fopen mode/ccs strings.
    for mode in ('r,ccs=','w,ccs=','r,ccs=UTF-8'):
        try: open('/dev/null',mode)
        except ValueError: pass
        else: raise ValueError('unvalidated libc file mode reached')
    import pyexpat
    if pyexpat.EXPAT_VERSION!='expat_2.9.0': raise ValueError('Expat version needs review')
    parser=pyexpat.ParserCreate();parser.Parse(b'<ok/>',True)
    try: parser.Parse(b'<again/>',True)
    except pyexpat.ExpatError: pass
    else: raise ValueError('XML parser reuse became available')
    if sqlite3.sqlite_version!='3.46.1': raise ValueError('SQLite version needs review')
    with sqlite3.connect(':memory:') as db:
        try: db.execute("SELECT load_extension('generated-missing')")
        except sqlite3.OperationalError as e:
            if 'not authorized' not in str(e): raise
        else: raise ValueError('SQLite extension loading enabled')
        modules={x[0] for x in db.execute('pragma module_list')}
        if not modules or 'zipfile' in modules: raise ValueError('unexpected SQLite modules')
        db.execute('CREATE TABLE t(x)');db.execute('INSERT INTO t VALUES (?)',('ok',))
        if db.execute('SELECT x FROM t').fetchone()!=('ok',): raise ValueError('ordinary SQL failed')
    # Inventory the configured JSON consumers. The shipped STS process has a
    # separate Query/XML transport probe; this is no claim that XML is absent.
    aws={}
    if importlib.util.find_spec('botocore'):
        from botocore.session import Session
        for name in ('lambda','sqs','dynamodb'):
            model=Session().get_service_model(name);aws[name]=model.metadata['protocol']
        if set(aws.values())-{'json','rest-json'}: raise ValueError('new AWS XML protocol')
    sys.path.insert(0,'/app/verification')
    sts=check_sts_transport();aws['sts']=sts['protocol']
    guards=check_network_transport()+check_sqlite_snapshot_boundary()+check_crypto_routes(Path('/app/verification'))
    guards.extend(sts['checks'])
    import locale
    if (os.environ.get('LC_ALL')!='C.UTF-8' or os.environ.get('LANGUAGE')!=''
            or locale.setlocale(locale.LC_MESSAGES) not in ('C','C.UTF-8')):
        raise ValueError('unreviewed message-catalog locale')
    guards.append('message_catalog_locale_closed')
    if any(shutil.which(name) for name in ('gcc','g++','cc','c++')) or Path('/usr/include/c++').exists():
        raise ValueError('C++ compiler or system templates in runtime')
    guards.append('gcc_runtime_only')
    if importlib.util.find_spec('cv2'):
        import cv2
        if os.environ.get('OPENCV_VIDEOIO_PRIORITY_FFMPEG')!='0' or cv2.videoio_registry.hasBackend(cv2.CAP_FFMPEG):
            raise ValueError('FFmpeg video backend enabled')
        video=cv2.VideoCapture('/tmp/generated-sequence-%d.jpg',cv2.CAP_FFMPEG)
        if video.isOpened():raise ValueError('explicit FFmpeg capture available')
        video.release();guards.append('ffmpeg_backend_disabled')
    if importlib.util.find_spec('psycopg'):
        sys.path.insert(0,'/app/verification')
        from postgres import connection_options
        opts=connection_options('host=db.example.invalid user=generated dbname=generated sslmode=verify-full gssencmode=require require_auth=gss')
        if opts['gssencmode']!='disable' or opts['require_auth']!='scram-sha-256' or opts['sslmode']!='verify-full':
            raise ValueError('database can negotiate Kerberos or skip verified TLS/SCRAM')
        guards.append('postgres_scram_only')
    imports={};native_hashes={};visited=0
    for root in (Path('/usr'),Path('/opt'),Path('/app')):
        def error(e): raise e
        for directory,dirs,files in os.walk(root,followlinks=False,onerror=error):
            dirs[:]=[d for d in dirs if not Path(directory,d).is_symlink()]
            for name in files:
                path=Path(directory,name)
                if path.is_symlink():continue
                info=path.stat()
                if not stat.S_ISREG(info.st_mode): continue
                if info.st_mode & 0o6000: raise ValueError('set-ID file remains')
                if 'security.capability' in os.listxattr(path): raise ValueError('file capabilities remain')
                found=elf_imports(path)
                if found is not None:
                    visited+=1
                    if found: imports[str(path)]=sorted(found)
                    if found:
                        with path.open('rb') as stream:
                            native_hashes[str(path)]=hashlib.file_digest(stream,'sha256').hexdigest()
    if not visited: raise ValueError('empty native-code coverage')
    return {'format':1,'python':platform.python_version(),'architecture':platform.machine(),
        'policySHA256':hashlib.sha256((ROOT/'runtime-policy.json').read_bytes()).hexdigest(),
        'removedPackages':sorted(removal['packages']),'removedPathCount':len(paths),
        'elfFiles':visited,'nativeProbeVersion':2,'sensitiveImports':imports,'nativeFileSHA256':native_hashes,'awsProtocols':aws,'awsStsTransport':sts,'strictDecoderCalls':decoder_count,
        'alignedNewProbe':subprocess.run(['/checks/aligned-new'],timeout=10).returncode==0,
        'checks':['removed_payload','mail_modules_absent','gconv_absent','no_setid_or_filecaps',
            'strict_base64','temporary_directory_safe','resolver_search_disabled','fopen_mode_validated',
            'sqlite_extension_disabled','python_xml_single_document','reviewed_source_apis','amd64']+guards,
        'limits':['Static imports are supporting evidence, not proof of whole-program reachability.',
            'Public protocol input, trusted dependency code and service configuration are reviewed separately in the version-bound policy.']}


def main():
    print(json.dumps(collect(),indent=2,sort_keys=True))


if __name__=='__main__':
    main()
