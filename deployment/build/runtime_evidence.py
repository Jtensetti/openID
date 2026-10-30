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
 'ns_printrr','ns_printrrf','fp_nquery','crc32_combine64','crc32_combine_gen64','gzprintf','gzvprintf',
 'sqlite3changeset_apply','sqlite3changeset_apply_v2','sqlite3changeset_apply_v3',
 'sqlite3changeset_concat','sqlite3changegroup_add','XML_ParserReset'}


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
                    if symbol in SYMBOLS: imports.add(symbol)
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
                if name in {'js_output','get_data','enable_load_extension','load_extension','urlsafe_b64decode'}:
                    raise ValueError('new reviewed API call: '+path.name+':'+name)
                if name=='b64decode':
                    if (len(node.args)!=1 or {k.arg for k in node.keywords}!={'validate'}
                         or not isinstance(node.keywords[0].value,ast.Constant)
                         or node.keywords[0].value.value is not True):
                        raise ValueError('non-strict Base64 decoder')
                    count+=1
    if count==0: raise ValueError('no application decoder coverage')
    return count


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
    stdlib=Path('/usr/local/lib/python3.12')
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
    # Verify the locked AWS runtime clients use JSON protocols. Archive S3/STS
    # tools are host-side operator code and are not included in these images.
    aws={}
    if importlib.util.find_spec('botocore'):
        from botocore.session import Session
        for name in ('lambda','sqs','dynamodb'):
            model=Session().get_service_model(name);aws[name]=model.metadata['protocol']
        if set(aws.values())-{'json','rest-json'}: raise ValueError('new AWS XML protocol')
    imports={};visited=0
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
    if not visited: raise ValueError('empty native-code coverage')
    return {'format':1,'python':platform.python_version(),'architecture':platform.machine(),
        'policySHA256':hashlib.sha256((ROOT/'runtime-policy.json').read_bytes()).hexdigest(),
        'removedPackages':sorted(removal['packages']),'removedPathCount':len(paths),
        'elfFiles':visited,'sensitiveImports':imports,'awsProtocols':aws,'strictDecoderCalls':decoder_count,
        'alignedNewProbe':subprocess.run(['/checks/aligned-new'],timeout=10).returncode==0,
        'checks':['removed_payload','mail_modules_absent','gconv_absent','no_setid_or_filecaps',
            'strict_base64','temporary_directory_safe','resolver_search_disabled','fopen_mode_validated',
            'sqlite_extension_disabled','python_xml_not_exposed','reviewed_source_apis','amd64'],
        'limits':['Static imports are supporting evidence, not proof of whole-program reachability.',
            'Public protocol input, trusted dependency code and service configuration are reviewed separately in the version-bound policy.']}


if __name__=='__main__':
    print(json.dumps(collect(),indent=2,sort_keys=True))
