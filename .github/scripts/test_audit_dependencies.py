import unittest
from pathlib import Path
from audit_dependencies import inventory, query_all, ROOT


class AuditTests(unittest.TestCase):
    def test_inventory_covers_each_lock_and_pins_every_query(self):
        items, manifests = inventory(ROOT)
        self.assertGreater(len(items), 100)
        for path in ('verification/requirements.lock', 'verification/cluster-requirements.lock',
                     'verification/runtime-requirements.lock', 'verification/rp-requirements.lock',
                     'deployment/aws/requirements.lock', 'deployment/build/python-runtime.lock.json', 'prototype/dependencies.lock.json',
                     'prototype/package-lock.json', 'verification/package-lock.json'):
            self.assertIn(path, manifests)
        self.assertTrue(all(set(item['query']) in ({'commit'}, {'package', 'version'}) for item in items))
        self.assertTrue(any(item['query'] == {'package': {'ecosystem': 'PyPI', 'name': 'pip'},
                                            'version': '26.2.2'} for item in items))

    def test_pagination_is_per_query_and_empty_page_is_not_success(self):
        items = [{'query': {'commit': 'a'*40}, 'sources': ['a']}, {'query': {'commit': 'b'*40}, 'sources': ['b']}]
        calls = []
        def fetch(payload):
            calls.append(payload)
            return ({'results': [{'next_page_token': 'page2'}, {'vulns': [{'id': 'GHSA-test'}]}]}
                if len(calls) == 1 else {'results': [{'vulns': [{'id': 'CVE-2026-12345'}]}]})
        results, count = query_all(items, fetch)
        self.assertEqual(2, count)
        self.assertEqual([dict(items[0]['query'], page_token='page2')], calls[1]['queries'])
        self.assertEqual(['CVE-2026-12345'], results[0]['vulnerabilities'])
        self.assertEqual(['GHSA-test'], results[1]['vulnerabilities'])

    def test_partial_error_malformed_and_repeated_page_cannot_pass(self):
        items = [{'query': {'commit': 'a'*40}, 'sources': ['a']}]
        for response in ({}, {'error': 'unavailable'}, {'results': []}, {'results': [{'error': 'rate limited'}]},
                         {'results': [{'vulns': [{}]}]}, {'results': [{'next_page_token': ''}]},
                         {'results': [{'next_page_token': 'same'}]}):
            with self.subTest(response=response), self.assertRaises(ValueError):
                query_all(items, lambda _: response)
        with self.assertRaises(TimeoutError): query_all(items, lambda _: (_ for _ in ()).throw(TimeoutError()))


if __name__ == '__main__': unittest.main()
