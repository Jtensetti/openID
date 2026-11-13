import copy
from datetime import datetime, timedelta, timezone
import unittest

import audit_vendors
import vendor_source_advisories as source

NOW = datetime(2026, 11, 13, tzinfo=timezone.utc)


class SourceAdvisoryTests(unittest.TestCase):
    def report(self):
        return source.collect('openbao', NOW, lambda p: {'results': [{} for _ in p['queries']]})

    def test_main_module_release_and_commit_are_both_queried(self):
        report = self.report()
        self.assertEqual(len(report['results']), 2)
        self.assertEqual(report['results'][0]['query'], {'package': {
            'ecosystem': 'Go', 'name': 'github.com/openbao/openbao/v2'}, 'version': 'v2.7.2'})
        self.assertEqual(source.verify(report, 'openbao', NOW, audit_vendors.scanner.timestamp), [])

    def test_main_module_advisory_is_not_waived_by_dependency_patches(self):
        report = source.collect('openbao', NOW, lambda p: {'results': [
            {'vulns': [{'id': 'SYNTHETIC-SOURCE-001'}]}, {}]})
        findings = source.verify(report, 'openbao', NOW, audit_vendors.scanner.timestamp)
        self.assertEqual([f['id'] for f in findings], ['SYNTHETIC-SOURCE-001'])

    def test_incomplete_or_altered_source_evidence_is_rejected(self):
        for mutation in ('missing_page', 'wrong_query', 'extra_page', 'partial_response',
                         'wrong_image', 'wrong_commit', 'old', 'hidden_finding'):
            report = self.report()
            if mutation == 'missing_page': report['pages'] = []
            elif mutation == 'wrong_query': report['pages'][0]['request']['queries'][0]['version'] = 'v0.0.0'
            elif mutation == 'extra_page': report['pages'] *= 2
            elif mutation == 'partial_response': report['pages'][0]['response']['results'].pop()
            elif mutation == 'wrong_image': report['imageID'] = 'sha256:'+'0'*64
            elif mutation == 'wrong_commit': report['sourceRevision'] = '0'*40
            elif mutation == 'old': report['checkedAt'] = (NOW-timedelta(hours=2)).isoformat()
            else: report['pages'][0]['response']['results'][0] = {'vulns': [{'id': 'SYNTHETIC-HIDDEN'}]}
            with self.subTest(mutation=mutation), self.assertRaises((ValueError, StopIteration)):
                source.verify(report, 'openbao', NOW, audit_vendors.scanner.timestamp)

    def test_outage_or_partial_query_cannot_create_a_passing_report(self):
        with self.assertRaises(ValueError):
            source.collect('openbao', NOW, lambda p: {'results': [{}]})
        def outage(_): raise OSError('synthetic offline')
        with self.assertRaises(OSError): source.collect('openbao', NOW, outage)


if __name__ == '__main__': unittest.main()
