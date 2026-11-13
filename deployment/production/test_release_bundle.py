"""Synthetic bundle mutations must be rejected before any Docker load."""
import argparse
import copy
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import release_bundle as bundle
from test_delivery_inventory import runtime, IMAGE, REVISION, TREE


class BundleTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name).resolve()
        for name in bundle.FILES:
            path=self.root/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(b'synthetic')
        (self.root/'vendor-images.lock.json').write_bytes(bundle.audit_vendors.LOCK.read_bytes())
        (self.root/'canonical-runtime.json').write_text(json.dumps(runtime()))
        self.app={'source':{'revision':REVISION,'tree':TREE},
                  'image':bundle.image_record('application',{'Id':IMAGE,'Size':100},REVISION)}
        self.data={'schema':bundle.SCHEMA,'createdAt':datetime.now(timezone.utc).isoformat(),
            'source':self.app['source'],'productionApproved':False,'images':{'application':self.app['image']},
            'files':{name:{'bytes':(self.root/name).stat().st_size,'sha256':bundle.digest(self.root/name)} for name in bundle.FILES}}
        for role,vendor in bundle.VENDORS.items():
            self.data['images'][role]=bundle.image_record(role,{'Id':vendor['id'],'Size':100},REVISION)
        self.addCleanup(patch.stopall)
        self.app_verify=patch.object(bundle.application,'verify',return_value=self.app).start()
        self.vendor_verify=patch.object(bundle.audit_vendors,'verify',return_value={}).start()

    def save(self):
        path=self.root/'manifest.json';path.write_text(json.dumps(self.data));return bundle.digest(path)

    def verify(self):
        return bundle.verify(self.root,REVISION,self.save())

    def test_complete_bundle_checks_application_and_both_vendor_assessments(self):
        self.verify();self.app_verify.assert_called_once();self.assertEqual(self.vendor_verify.call_count,2)

    def test_wrong_source_id_platform_tag_and_extra_image_are_rejected(self):
        original=copy.deepcopy(self.data)
        for case in ('source','tree','id','platform','tag','size','extra','missing','approval'):
            self.data=copy.deepcopy(original)
            if case=='source':self.data['source']['revision']='d'*40
            elif case=='tree':self.data['source']['tree']='d'*40
            elif case=='id':self.data['images']['postgres']['id']=IMAGE
            elif case=='platform':self.data['images']['postgres']['platform']='linux/arm64'
            elif case=='tag':self.data['images']['postgres']['tag']='unreviewed:latest'
            elif case=='size':self.data['images']['postgres']['sizeBytes']=-1
            elif case=='extra':self.data['images']['extra']={}
            elif case=='missing':del self.data['images']['openbao']
            else:self.data['productionApproved']=True
            with self.subTest(case=case),self.assertRaises(ValueError):self.verify()

    def test_tampered_linked_missing_payload_and_path_traversal_rejected(self):
        target=self.root/'vendors/postgres/image.tar.gz';original=target.read_bytes()
        for case in ('tamper','symlink','missing','traversal'):
            self.data['files']={name:{'bytes':(self.root/name).stat().st_size,'sha256':bundle.digest(self.root/name)} for name in bundle.FILES}
            if case=='tamper':target.write_bytes(b'changed')
            elif case=='symlink':target.unlink();target.symlink_to(self.root/'application/image.tar.gz')
            elif case=='missing':target.unlink()
            else:self.data['files']['../escape']={'bytes':1,'sha256':'0'*64}
            with self.subTest(case=case),self.assertRaises((ValueError,FileNotFoundError)):self.verify()
            target.unlink(missing_ok=True);target.write_bytes(original)

    def test_stale_future_and_incomplete_runtime_evidence_rejected(self):
        original=copy.deepcopy(self.data)
        for case in ('stale','future','runtime'):
            self.data=copy.deepcopy(original)
            if case=='stale':self.data['createdAt']=(datetime.now(timezone.utc)-timedelta(days=2)).isoformat()
            elif case=='future':self.data['createdAt']=(datetime.now(timezone.utc)+timedelta(hours=1)).isoformat()
            else:
                path=self.root/'canonical-runtime.json';path.write_text('{"status":"PASS"}')
                self.data['files'][path.name]={'bytes':path.stat().st_size,'sha256':bundle.digest(path)}
            with self.subTest(case=case),self.assertRaises(ValueError):self.verify()

    def test_vendor_rejection_stops_import_before_docker(self):
        self.vendor_verify.side_effect=ValueError('unresolved vendor finding')
        args=['bundle','import','--directory',str(self.root),'--expected-revision',REVISION,
              '--expected-manifest-sha256',self.save()]
        with patch('sys.argv',args),patch.object(bundle.subprocess,'run') as run:
            with self.assertRaises(ValueError):bundle.main()
            run.assert_not_called()

    def test_insufficient_total_storage_stops_all_image_loads(self):
        with patch.object(bundle.application,'run',return_value=json.dumps({'OSType':'linux','Architecture':'amd64',
                'DockerRootDir':str(self.root)})),patch.object(bundle.shutil,'disk_usage') as disk, \
                patch.object(bundle.subprocess,'run') as run:
            disk.return_value.free=1
            with self.assertRaises(ValueError):bundle.import_images(self.root,self.data)
            run.assert_not_called()


if __name__=='__main__':unittest.main()
