from copy import deepcopy
from datetime import datetime,timezone
from pathlib import Path
import tempfile
import unittest
import runtime_policy as policy
import runtime_evidence as evidence
import runtime_hardening as hardening
import component_advisories as advisory

NOW=datetime(2026,10,30,tzinfo=timezone.utc)


class ApplicabilityTests(unittest.TestCase):
    def setUp(self):
        self.policy={'format':1,'reviewed':'2026-10-30','reviewBefore':'2026-11-30','sourceSHA256':'a'*64,
            'removedPackages':['unused'],'advisories':[{'id':'CVE-TEST','package':'pkg','version':'1',
             'status':'not_affected','checks':['removed_payload'],'reason':'code absent','references':['https://example.invalid']} ]}
        self.evidence={'format':1,'python':'3.12.16','architecture':'x86_64','elfFiles':1,'strictDecoderCalls':1,
            'removedPackages':['unused'],'removedPathCount':1,'checks':['removed_payload'],'sensitiveImports':{}}
        self.finding={'id':'CVE-TEST','package':'pkg','version':'1'}
    def evaluate(self,**kwargs):
        return policy.decisions(kwargs.get('policy',self.policy),kwargs.get('evidence',self.evidence),
            kwargs.get('findings',[self.finding]),kwargs.get('now',NOW),source_sha=kwargs.get('source_sha','a'*64))
    def test_known_version_needs_all_evidence(self):
        self.assertEqual(self.evaluate()[0]['status'],'not_affected')
        self.evidence['checks']=[]
        self.assertEqual(self.evaluate()[0]['status'],'under_investigation')
    def test_new_advisory_package_or_version_never_inherits_exception(self):
        for change in ({'id':'CVE-NEW'},{'package':'other'},{'version':'2'}):
            with self.subTest(change=change):
                self.assertEqual(self.evaluate(findings=[dict(self.finding,**change)])[0]['status'],'under_investigation')
    def test_review_expiry_and_source_change_fail_closed(self):
        for change in ({'now':datetime(2026,11,30,tzinfo=timezone.utc)},
                       {'now':datetime(2026,10,29,tzinfo=timezone.utc)},{'source_sha':'b'*64}):
            with self.subTest(change=change),self.assertRaises(ValueError):self.evaluate(**change)
    def test_duplicate_or_unreviewed_disposition_rejected(self):
        self.policy['advisories']*=2
        with self.assertRaises(ValueError):self.evaluate()
        self.policy['advisories']=self.policy['advisories'][:1];self.policy['advisories'][0]['status']='accepted_risk'
        with self.assertRaises(ValueError):self.evaluate()
    def test_missing_probe_coverage_rejected(self):
        for change in ({'elfFiles':0},{'strictDecoderCalls':0},{'removedPackages':[]},{'architecture':'aarch64'}):
            with self.subTest(change=change),self.assertRaises(ValueError):self.evaluate(evidence=dict(self.evidence,**change))
    def test_native_caller_invalidates_absence_decision(self):
        self.policy['advisories'][0]['checks']=['no_wordexp']
        self.assertEqual(self.evaluate()[0]['status'],'not_affected')
        self.evidence['sensitiveImports']={'/app/lib.so':['wordexp']}
        self.assertEqual(self.evaluate()[0]['status'],'under_investigation')
    def test_parser_alias_weak_decoder_or_new_sink_invalidates_source_review(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);p=root/'app.py'
            good='import base64\nx=base64.b64decode(value,validate=True)\n';p.write_text(good)
            self.assertEqual(evidence.check_sources(root),1)
            for unsafe in ('import xml.etree.ElementTree\n','from base64 import b64decode\n',
                           'import base64 as b\n','x=base64.b64decode(value)\n',
                           'x=base64.b64decode(value,altchars=b"-_")\n','cookie.js_output()\n','db.enable_load_extension(True)\n'):
                p.write_text(good+unsafe)
                with self.subTest(unsafe=unsafe),self.assertRaises(ValueError):evidence.check_sources(root)
    def test_removal_keeps_package_metadata_and_licenses(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);info=root/'var/lib/dpkg/info';info.mkdir(parents=True)
            code=root/'usr/bin/tool';code.parent.mkdir(parents=True);code.write_text('code')
            license=root/'usr/share/doc/unused/copyright';license.parent.mkdir(parents=True);license.write_text('license')
            (info/'unused.list').write_text('/usr/bin/tool\n/usr/share/doc/unused/copyright\n')
            paths=hardening.payload_paths('unused',root)
            self.assertEqual(paths,{code});hardening.remove(paths)
            self.assertTrue(license.exists());self.assertTrue((info/'unused.list').exists());self.assertFalse(code.exists())
    def test_nested_shipped_python_is_checked(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);(root/'app.py').write_text('import base64\nx=base64.b64decode(value,validate=True)')
            nested=root/'vendor'/'parser.py';nested.parent.mkdir();nested.write_text('import xml.etree.ElementTree')
            with self.assertRaises(ValueError):evidence.check_sources(root)

    def test_collected_component_advisory_cannot_disappear_when_rule_omitted(self):
        record={'schema_version':'1.7.5','id':'vendor-new','upstream':['CVE-NEW'],
            'affected':[{'package':{'name':'python-3.12','ecosystem':'Wolfi','purl':'pkg:apk/wolfi/python-3.12?arch=x86_64'},
            'ranges':[{'type':'ECOSYSTEM','events':[{'introduced':'0'}]}],
            'ecosystem_specific':{'components':[{'latest_event_status':'detection'}]}}]}
        findings=advisory.runtime_findings({'records':[record]})
        new=next(f for f in findings if f['id']=='CVE-NEW')
        self.assertEqual(new,{'id':'CVE-NEW','package':'cpython','version':'3.12.16'})
        self.assertEqual(self.evaluate(findings=[new])[0]['status'],'under_investigation')

    def test_unknown_vendor_status_rejected(self):
        record={'schema_version':'1.7.5','id':'fixture','affected':[{'package':{'name':'python-3.12','ecosystem':'Wolfi','purl':'pkg:apk/wolfi/python-3.12?arch=x86_64'},
            'ranges':[{'type':'ECOSYSTEM','events':[{'introduced':'0'}]}],
            'ecosystem_specific':{'components':[{'latest_event_status':'unrecognized'}]}}]}
        with self.assertRaises(ValueError):advisory.unresolved([record],advisory.COMPONENTS)


if __name__=='__main__':unittest.main()
