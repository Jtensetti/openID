"""Evaluate exact-version applicability decisions; unknown or incomplete evidence blocks."""
from datetime import date
import hashlib
import json
import shlex
import subprocess
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]
POLICY=Path(__file__).with_name('runtime-policy.json')
NATIVE_GROUPS={
 'no_strfmon':{'strfmon','strfmon_l'}, 'no_tdelete':{'tdelete'},
 'no_dns_debug':{'ns_printrr','ns_printrrf','fp_nquery'}, 'no_wordexp':{'wordexp'},
 'no_native_glob':{'glob','glob64'}, 'no_posix_regex':{'regcomp','regexec'},
 'no_zlib_combine':{'crc32_combine64','crc32_combine_gen64'},
 'no_zlib_printf':{'gzprintf','gzvprintf'},
 'no_sqlite_session':{'sqlite3changeset_apply','sqlite3changeset_apply_v2','sqlite3changeset_apply_v3',
                     'sqlite3changeset_concat','sqlite3changegroup_add'},
}


def source_fingerprint(root=ROOT):
    tracked={Path(p) for p in subprocess.check_output(['git','ls-files','-z'],cwd=root,text=True).split('\0') if p}
    files=set()
    dockerfiles=('deployment/Dockerfile','deployment/cluster/Dockerfile')
    for name in dockerfiles:
        dockerfile=root/name;files.add(dockerfile)
        lines=dockerfile.read_text().replace('\\\n',' ').splitlines()
        for line in lines:
            if not line.startswith('COPY '):continue
            fields=shlex.split(line)
            if any(f.startswith('--from=') for f in fields):continue
            if any(f.startswith('--') for f in fields):raise ValueError('new COPY option needs source coverage review')
            for source in fields[1:-1]:
                matches=[p for p in tracked if p.as_posix()==source or p.as_posix().startswith(source.rstrip('/')+'/')]
                if not matches:raise ValueError('uncovered Docker COPY source: '+source)
                files.update(root/p for p in matches)
    for p in tracked:
        name=p.as_posix()
        if (name.startswith('deployment/build/') and p.suffix in ('.py','.cpp') and not p.name.startswith('test')) or name in (
                '.github/scripts/audit_image_os.py','deployment/image_bundle.py',
                'deployment/Dockerfile.dockerignore','deployment/cluster/Dockerfile.dockerignore'):
            files.add(root/p)
    # The policy contains this digest; exclude it to avoid a circular hash.
    files.discard(root/'deployment/build/runtime-policy.json')
    if not files:raise ValueError('no runtime source coverage')
    h=hashlib.sha256()
    for p in sorted(files):
        h.update(str(p.relative_to(root)).encode()+b'\0'+hashlib.sha256(p.read_bytes()).digest())
    return h.hexdigest()


def decisions(policy, evidence, findings, now, *, source_sha):
    if (policy.get('format')!=1 or evidence.get('format')!=1
            or not date.fromisoformat(policy['reviewed'])<=now.date()<date.fromisoformat(policy['reviewBefore'])
            or source_sha!=policy['sourceSHA256']):
        raise ValueError('applicability review expired or runtime source changed')
    if (evidence.get('python')!='3.12.16' or evidence.get('architecture')!='x86_64'
            or type(evidence.get('elfFiles')) is not int or evidence['elfFiles']<1
            or type(evidence.get('strictDecoderCalls')) is not int or evidence['strictDecoderCalls']<1
            or sorted(evidence['removedPackages'])!=sorted(policy['removedPackages'])
            or not evidence.get('removedPathCount')):
        raise ValueError('incomplete runtime applicability evidence')
    checks=set(evidence['checks'])
    # This is additional evidence for explicitly reviewed call paths, not a
    # generic "no symbol found therefore safe" determination.
    imported={s for values in evidence['sensitiveImports'].values() for s in values}
    for check,symbols in NATIVE_GROUPS.items():
        if not symbols & imported: checks.add(check)
    if evidence.get('alignedNewProbe') is True and 'posix_memalign' in imported: checks.add('posix_aligned_new')
    checks.update({'gcc_runtime_only','uuid_library_only'})
    if evidence.get('vendorDisputesVerified') is True: checks.add('vendor_disputed')
    rules={}
    for rule in policy['advisories']:
        key=(rule['id'],rule['package'],rule['version'])
        if (key in rules or rule['status'] not in ('fixed','not_affected') or not rule['checks']
                or not rule['reason'] or not rule['references']): raise ValueError('invalid/duplicate applicability rule')
        rules[key]=rule
    result=[]
    for finding in findings:
        key=(finding['id'],finding['package'],finding['version']);rule=rules.get(key)
        missing=sorted(set(rule['checks'])-checks) if rule else ['unreviewed_advisory_or_version']
        result.append(dict(finding,status=rule['status'] if rule and not missing else 'under_investigation',
                           missingChecks=missing,reason=rule['reason'] if rule else 'New advisory or package version requires review.'))
    return result
