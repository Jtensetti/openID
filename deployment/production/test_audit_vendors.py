"""Negative coverage tests use only synthetic image inventories and findings."""
import copy
from datetime import datetime, timedelta, timezone
import unittest

import audit_vendors as audit
from contract import VENDORS

NOW = datetime(2026, 11, 13, tzinfo=timezone.utc)


def fixture(role='postgres'):
    vendor=VENDORS[role]
    scan={'SchemaVersion':2,'ArtifactType':'container_image','Trivy':{'Version':'0.76.1'},
          'CreatedAt':NOW.isoformat(),'Metadata':{'ImageID':vendor['id'],'ImageConfig':{'architecture':'amd64'},
          'OS':{'Family':'alpine','Name':'3.24.4'}},'Results':[
          {'Class':'os-pkgs','Type':'alpine','Target':'synthetic-image','Packages':[
              {'Name':'musl','Version':'synthetic-version','Arch':'x86_64'}]},
          {'Class':'lang-pkgs','Type':'gobinary','Target':vendor['languageTargets'][0],
           'Packages':[{'Name':'stdlib','Version':'go-synthetic'}]+[{'Name':n} for n in vendor['localGoModules']]}]}
    inventory={'role':role,'imageID':vendor['id'],'source':vendor['source'],'platform':'linux/amd64',
               'inventoryComplete':True,'packageManager':'apk','osRelease':{'ID':'alpine','VERSION_ID':'3.24.4'},
               'packages':[{'name':'musl','version':'synthetic-version','architecture':'x86_64'}]}
    return scan,inventory


class VendorCoverageTests(unittest.TestCase):
    def test_empty_findings_require_both_os_and_go_coverage(self):
        for role in VENDORS:
            scan,inventory=fixture(role)
            result=audit.assess(scan,inventory,role,'0.76.1',NOW)
            self.assertTrue(result['complete']);self.assertTrue(result['passed'])
            del scan['Results'][1]
            with self.assertRaises(ValueError):audit.assess(scan,inventory,role,'0.76.1',NOW)

    def test_go_findings_block_even_when_all_os_packages_have_no_findings(self):
        scan,inventory=fixture()
        scan['Results'][1]['Vulnerabilities']=[{'VulnerabilityID':'SYNTHETIC-001','PkgName':'stdlib',
            'InstalledVersion':'go-synthetic','Severity':'LOW'}]
        result=audit.assess(scan,inventory,'postgres','0.76.1',NOW)
        self.assertTrue(result['complete']);self.assertFalse(result['passed'])
        self.assertEqual(result['unresolvedCount'],1)

    def test_changed_id_os_architecture_scanner_or_stale_scan_rejected(self):
        for mutation in ('id','os','eol','architecture','scanner','old','future','source'):
            scan,inventory=fixture()
            if mutation=='id':scan['Metadata']['ImageID']='sha256:'+'a'*64
            elif mutation=='os':scan['Metadata']['OS']['Name']='3.23.1'
            elif mutation=='eol':scan['Metadata']['OS']['EOSL']=True
            elif mutation=='architecture':scan['Metadata']['ImageConfig']['architecture']='arm64'
            elif mutation=='scanner':scan['Trivy']['Version']='different'
            elif mutation=='old':scan['CreatedAt']=(NOW-timedelta(hours=2)).isoformat()
            elif mutation=='future':scan['CreatedAt']=(NOW+timedelta(hours=2)).isoformat()
            else:inventory['source']='unverified:latest'
            with self.subTest(mutation=mutation),self.assertRaises(ValueError):audit.assess(scan,inventory,'postgres','0.76.1',NOW)

    def test_partial_duplicate_suppressed_or_unidentified_coverage_rejected(self):
        for mutation in ('missing','duplicate','suppressed','unknown_binary','unknown_module','unknown_finding'):
            scan,inventory=fixture()
            if mutation=='missing':scan['Results'][0]['Packages']=[]
            elif mutation=='duplicate':scan['Results'][0]['Packages']*=2
            elif mutation=='suppressed':scan['Results'][0]['ExperimentalModifiedFindings']=[{}]
            elif mutation=='unknown_binary':scan['Results'][1]['Target']='unreviewed/binary'
            elif mutation=='unknown_module':scan['Results'][1]['Packages'].append({'Name':'./unreviewed'})
            else:scan['Results'][0]['Vulnerabilities']=[{'VulnerabilityID':'SYNTHETIC-001','PkgName':'other',
                'InstalledVersion':'synthetic-version','Severity':'HIGH'}]
            with self.subTest(mutation=mutation),self.assertRaises(ValueError):audit.assess(scan,inventory,'postgres','0.76.1',NOW)


if __name__=='__main__':unittest.main()
