"""Build and scan isolated vendor candidates; never change the runtime lock or deploy."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT/'deployment/production'))
from audit_vendors import scanner
from contract import VENDORS
from delivery_inventory import PROBE, VERSIONS, parse_inventory


def run(args, **kw):
    return subprocess.check_output(args, text=True, **kw).strip()


def main(output):
    output.mkdir(parents=True, exist_ok=False)
    context = Path(__file__).resolve().parent
    report = {'schema': 'tjipp-vendor-candidates-v1', 'productionApproved': False,
              'sourceRevision': run(['git','rev-parse','HEAD'], cwd=ROOT), 'images': {}}
    lock = json.loads(scanner.LOCK.read_text())
    (output/'scanner-lock.json').write_bytes(scanner.LOCK.read_bytes())
    with tempfile.TemporaryDirectory(prefix='vendor-candidates-') as work:
        work = Path(work); binary = scanner.install(lock, work, output)
        env = {k:v for k,v in os.environ.items() if not k.startswith('TRIVY_')}
        prefix = [str(binary),'--config','','--cache-dir',str(work/'cache'),'--timeout','8m']
        flags = ['image','--disable-telemetry','--skip-version-check','--no-progress',
                 '--module-dir',str(work/'modules'),'--db-repository',scanner.DB_REPOSITORY]
        subprocess.run(prefix+flags+['--download-db-only'], env=env, check=True)
        database = work/'cache/db'; metadata = json.loads((database/'metadata.json').read_text())
        scanner.check_database(metadata,datetime.now(timezone.utc))
        scanner.save(output/'database-metadata.json',metadata)
        report['databaseSHA256'] = scanner.digest(database/'trivy.db')
        for role, base in VENDORS.items():
            directory = output/role; directory.mkdir()
            subprocess.run(['docker','pull','--platform','linux/amd64',base['source']],check=True)
            if run(['docker','image','inspect',base['source'],'--format','{{.Id}}']) != base['id']:
                raise ValueError('upstream vendor image changed')
            tag = 'tjipp-'+role+':candidate'
            subprocess.run(['docker','build','--platform','linux/amd64',
                '--build-arg','SOURCE_DATE_EPOCH=1794484800','--provenance=false',
                '--file',str(context/('Dockerfile.'+role)),'--tag',tag,str(context)],check=True)
            info = json.loads(run(['docker','image','inspect',tag]))[0]
            scanner.save(directory/'image-inspect.json',info)
            image = info['Id']
            if info['Architecture'] != 'amd64' or info['Os'] != 'linux':
                raise ValueError('candidate architecture changed')
            command = ['docker','run','--rm','--pull','never','--network','none','--read-only',
                '--cap-drop','ALL','--security-opt','no-new-privileges','--pids-limit','64',
                '--memory','256m','--tmpfs','/tmp:size=16m,mode=1777','--entrypoint','/bin/sh',image,'-eu','-c']
            inventory = parse_inventory(run(command+[PROBE+VERSIONS[role]]).encode())
            scanner.save(directory/'inventory.json',inventory)
            removed = 'test ! -e /usr/local/bin/gosu' if role == 'postgres' else 'test ! -e /lib/libz.so.1'
            run(command+[removed])
            subprocess.run(prefix+flags+['--skip-db-update','--skip-java-db-update','--offline-scan',
                '--image-src','docker','--scanners','vuln','--pkg-types','os,library','--ignorefile','',
                '--ignore-unfixed=false','--ignore-status','','--severity','UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL',
                '--list-all-pkgs','--show-suppressed','--format','json','--exit-code','0',
                '--output',str(directory/'trivy.json'),image],env=env,check=True)
            subprocess.run(prefix+['convert','--format','cyclonedx','--output',str(directory/'sbom.cdx.json'),
                str(directory/'trivy.json')],env=env,check=True)
            scan=json.loads((directory/'trivy.json').read_text())
            report['images'][role]={'base':base['source'],'baseID':base['id'],'imageID':image,
                'findingCount':sum(len(r.get('Vulnerabilities',[])) for r in scan['Results']),
                'languageTargets':[r['Target'] for r in scan['Results'] if r['Class']=='lang-pkgs'],
                'recipeSHA256':scanner.digest(context/('Dockerfile.'+role))}
            scanner.save(output/'candidates.json',report)
    print(json.dumps(report,indent=2))
    return 0 if all(r['findingCount']==0 for r in report['images'].values()) else 1


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--output',type=Path,required=True)
    raise SystemExit(main(parser.parse_args().output.resolve()))
