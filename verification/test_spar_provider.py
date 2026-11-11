"""Published fictitious SPAR cases and adversarial protocol tests; no production queries."""
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
import ssl
import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ET

import spar_provider as spar

NOW = int(datetime(2026, 11, 11, tzinfo=timezone.utc).timestamp())
FIXTURES = Path(__file__).parent/'fixtures'/'spar'
NUMBER = '195704133106'


def fixture(case='3-1'):
    return (FIXTURES/('response-'+case+'.xml')).read_bytes()


def changed(edit, case='3-1'):
    root = ET.fromstring(fixture(case))
    edit(root)
    return ET.tostring(root, encoding='utf-8')


def post(root):
    return root.find('.//'+spar.tag(spar.ANSWER, 'PersonsokningSvarspost'))


class SparResponseTests(unittest.TestCase):
    def parse(self, data=None, number=NUMBER):
        return spar.parse_response(fixture() if data is None else data, number, NOW)

    def test_current_record_contains_only_minimum_observation_and_hides_repr(self):
        result = self.parse()
        self.assertEqual('ELIGIBLE_CUSTOMER_TEST', result.outcome)
        self.assertEqual(('Christina Birgitta Ulrika', 'Thomeaus', 'Efternamn3542', '1957-04-13'),
                         (result.given_names, result.middle_name, result.family_name, result.birth_date))
        self.assertNotIn(NUMBER, repr(result))
        self.assertNotIn('Christina', repr(result))
        self.assertNotIn('Gatan142', str(result.__dict__))
        self.assertFalse(hasattr(result, 'nonce'))  # This is not a RegistryResult.

    def test_deceased_current_period_does_not_fall_back_to_older_alive_period(self):
        result = self.parse(fixture('3-12'), '198604069883')
        self.assertEqual(('REVIEW_REQUIRED', 'STATUS_REQUIRES_REVIEW'), (result.outcome, result.reason))
        def reverse(root):
            p = post(root)
            values = p.findall(spar.tag(spar.DETAIL, 'Persondetaljer'))
            for value in values:
                p.remove(value)
            p.extend(reversed(values))
        self.assertEqual('REVIEW_REQUIRED', self.parse(changed(reverse, '3-12'), '198604069883').outcome)

    def test_protected_records_without_names_require_separate_handling(self):
        for case, number in (('3-16', '198203249274'), ('3-18', '198106039228')):
            result = self.parse(fixture(case), number)
            self.assertEqual(('REVIEW_REQUIRED', 'PROTECTED', ''),
                             (result.outcome, result.reason, result.given_names))
            self.assertFalse(result.matches_passport_fields(()))

    def test_coordination_cases_are_not_treated_as_eligible_from_one_positive_field(self):
        for case, number in (('3-20', '199903672385'), ('3-21', '199201782399'), ('3-24', '197605832380')):
            result = self.parse(fixture(case), number)
            self.assertEqual('REVIEW_REQUIRED', result.outcome)
        # Isolate the elapsed preliminary date from the reference in case 3.20.
        def no_reference(root):
            d = post(root).find(spar.tag(spar.DETAIL, 'Persondetaljer'))
            d.remove(d.find(spar.tag(spar.REFERENCE, 'Hanvisning')))
        result = self.parse(changed(no_reference, '3-20'), '199903672385')
        self.assertEqual('COORDINATION_STATUS_REQUIRES_REVIEW', result.reason)

    def test_exact_person_query_and_response_identity_must_agree(self):
        def wrong_echo(root):
            root.find('.//'+spar.tag(spar.SEARCH, 'PersonsokningFraga'))[0].text = '198604069883'
        def wrong_person(root):
            post(root).find(spar.tag(spar.PERSON, 'PersonId'))[0].text = '198604069883'
        for edit in (wrong_echo, wrong_person):
            with self.assertRaises(spar.SparUnavailable):
                self.parse(changed(edit))

    def test_missing_and_unknown_protection_never_match(self):
        def missing(root):
            p = post(root)
            p.remove(p.find(spar.tag(spar.PROTECTION, 'Sekretessmarkering')))
        with self.assertRaises(spar.SparUnavailable):
            self.parse(changed(missing))
        def unknown(root):
            post(root).find(spar.tag(spar.PROTECTION, 'Sekretessmarkering')).text = 'UNKNOWN'
        self.assertEqual('REVIEW_REQUIRED', self.parse(changed(unknown)).outcome)

    def test_duplicate_current_names_or_details_are_not_resolved_by_order(self):
        for namespace, name in ((spar.NAME, 'Namn'), (spar.DETAIL, 'Persondetaljer')):
            def duplicate(root):
                p = post(root)
                p.append(ET.fromstring(ET.tostring(p.find(spar.tag(namespace, name)))))
            with self.assertRaises(spar.SparUnavailable):
                self.parse(changed(duplicate))

    def test_missing_future_and_ended_current_periods_fail_closed(self):
        for value in ('2026-11-11', '2026-11-10'):
            def end(root):
                post(root).find(spar.tag(spar.NAME, 'Namn')).find(spar.tag(spar.PERIOD, 'DatumTill')).text = value
            with self.assertRaises(spar.SparUnavailable):
                self.parse(changed(end))
        def future(root):
            post(root).find(spar.tag(spar.NAME, 'Namn')).find(spar.tag(spar.PERIOD, 'DatumFrom')).text = '2026-11-12'
        with self.assertRaises(spar.SparUnavailable):
            self.parse(changed(future))

    def test_namespace_confusion_and_soap_fault_do_not_produce_observations(self):
        for data in (fixture().replace(spar.ANSWER.encode(), b'https://attacker.invalid/answer'),
                     b'<Envelope xmlns="http://schemas.xmlsoap.org/soap/envelope/"><Body><Fault/></Body></Envelope>'):
            with self.assertRaises(spar.SparUnavailable):
                self.parse(data)

    def test_forged_status_namespace_cannot_hide_death_or_protection(self):
        death = fixture('3-12').replace(spar.DEREGISTRATION.encode(), b'https://attacker.invalid/status')
        with self.assertRaises(spar.SparUnavailable):
            self.parse(death, '198604069883')
        def extra_protection(root):
            ET.SubElement(post(root), '{https://attacker.invalid/status}Sekretessmarkering').text = 'JA'
        with self.assertRaises(spar.SparUnavailable):
            self.parse(changed(extra_protection))

    def test_unknown_response_condition_or_current_detail_requires_review(self):
        def unsupported_answer(root):
            ET.SubElement(root.find(spar.tag(spar.SOAP, 'Body'))[0], '{https://unknown.invalid/}Undantag').text = 'UNKNOWN'
        def unsupported_detail(root):
            d = post(root).find(spar.tag(spar.DETAIL, 'Persondetaljer'))
            ET.SubElement(d, spar.tag(spar.DETAIL, 'NyStatus')).text = 'UNKNOWN'
        for edit in (unsupported_answer, unsupported_detail):
            with self.assertRaises(spar.SparUnavailable):
                self.parse(changed(edit))

    def test_ambiguous_or_absent_person_is_review_not_positive(self):
        def duplicate(root):
            body = root.find(spar.tag(spar.SOAP, 'Body'))[0]
            body.append(ET.fromstring(ET.tostring(post(root))))
        self.assertEqual('AMBIGUOUS', self.parse(changed(duplicate)).reason)
        def missing(root):
            root.find(spar.tag(spar.SOAP, 'Body'))[0].remove(post(root))
        self.assertEqual('NO_MATCH', self.parse(changed(missing)).reason)

    def test_entity_declarations_encoding_tricks_and_oversize_are_rejected(self):
        for data in (b'<!DOCTYPE x [<!ENTITY x "secret">]>'+fixture(),
                     fixture().decode().encode('utf-16'), b' '* (spar.MAX_RESPONSE+1),
                     fixture().replace(b"encoding='UTF-8'", b"encoding='UTF-16'")):
            with self.assertRaises(spar.SparUnavailable):
                self.parse(data)

    def test_birth_date_conflict_is_review(self):
        def wrong_date(root):
            post(root).find(spar.tag(spar.DETAIL, 'Persondetaljer')).find(spar.tag(spar.DETAIL, 'Fodelsedatum')).text = '1957-04-14'
        self.assertEqual('IDENTITY_DATE_MISMATCH', self.parse(changed(wrong_date)).reason)

    def test_exact_matching_does_not_establish_authenticated_passport(self):
        result = self.parse()
        fields = dict(givenNames='CHRISTINA BIRGITTA ULRIKA', familyName='THOMEAUS EFTERNAMN3542',
                      birthDateMrz='570413', issuingState='SWE', passportPersonalNumber=NUMBER)
        self.assertTrue(result.matches_passport_fields(tuple(fields.items())))
        for key, value in (('givenNames', 'CHRISTINA'), ('familyName', 'EFTERNAMN3542'),
                           ('birthDateMrz', '570414'), ('passportPersonalNumber', '198604069883'),
                           ('issuingState', 'UTO'), ('passportPersonalNumber', None)):
            self.assertFalse(result.matches_passport_fields(tuple((fields | {key: value}).items())))
        self.assertFalse(replace(result, outcome='REVIEW_REQUIRED').matches_passport_fields(tuple(fields.items())))
        # The published name contains digits. The real passport parser rejects it.
        from identity import VerifiedDocument
        with self.assertRaisesRegex(ValueError, '^name$'):
            VerifiedDocument.from_verifier({'passiveAuthentication': True, 'identity': fields | {
                'documentNumber': 'TEST00001', 'nationality': 'SWE', 'documentExpires': '2030-01-01'}})


class SparTransportTests(unittest.TestCase):
    def client(self):
        with patch.object(spar, '_client_context', return_value=ssl.create_default_context()):
            return spar.SparCustomerTestClient('/not-used-in-mocked-test')

    def test_unlisted_identity_is_rejected_before_network(self):
        client = self.client()
        with patch.object(spar.http.client, 'HTTPSConnection') as connection:
            with self.assertRaises(spar.SparUnavailable):
                client.observe('not-a-published-test-person')
            connection.assert_not_called()

    def test_transport_uses_verified_tls_fixed_test_destination_and_bounded_response(self):
        client = self.client()
        with patch.object(spar.http.client, 'HTTPSConnection') as factory:
            response = factory.return_value.getresponse.return_value
            response.status = 200
            response.getheader.return_value = 'text/xml; charset=UTF-8'
            response.read.return_value = fixture()
            result = client.observe(NUMBER)
            self.assertEqual('ELIGIBLE_CUSTOMER_TEST', result.outcome)
            args, kwargs = factory.call_args
            self.assertEqual((spar.TEST_HOST,), args)
            self.assertTrue(kwargs['context'].check_hostname)
            self.assertEqual(ssl.CERT_REQUIRED, kwargs['context'].verify_mode)
            self.assertEqual(10, kwargs['timeout'])
            method, path, body, headers = factory.return_value.request.call_args[0]
            self.assertEqual(('POST', '/2023.1'), (method, path))
            self.assertIn(NUMBER.encode(), body)
            response.read.assert_called_once_with(spar.MAX_RESPONSE+1)
            factory.return_value.close.assert_called_once()

    def test_redirects_server_errors_and_non_xml_are_rejected_without_following(self):
        client = self.client()
        for status, media in ((302, 'text/xml'), (500, 'text/xml'), (200, 'text/html')):
            with patch.object(spar.http.client, 'HTTPSConnection') as factory:
                response = factory.return_value.getresponse.return_value
                response.status, response.getheader.return_value = status, media
                with self.assertRaises(spar.SparUnavailable):
                    client.observe(NUMBER)
                response.read.assert_not_called()
                self.assertEqual(1, factory.call_count)
                factory.return_value.close.assert_called_once()

    def test_timeout_does_not_expose_original_exception_or_response_data(self):
        client = self.client()
        with patch.object(spar.http.client, 'HTTPSConnection') as factory:
            factory.return_value.request.side_effect = TimeoutError('sensitive upstream details')
            with self.assertRaises(spar.SparUnavailable) as result:
                client.observe(NUMBER)
            self.assertNotIn('sensitive', str(result.exception))
            self.assertTrue(result.exception.__suppress_context__)
            factory.return_value.close.assert_called_once()


if __name__ == '__main__':
    unittest.main()
