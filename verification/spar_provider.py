"""SPAR 2023.1 customer-test transport and observations, never issuance proofs.

Only the published test account and selected published test persons are queried.
Parsing recorded XML alone authenticates nothing. An observation is deliberately
not RegistryResult and cannot be passed to RegistryBindings as registry evidence.
"""
from dataclasses import dataclass
from datetime import date, datetime, timezone
import hashlib
import http.client
import os
from pathlib import Path
import re
import ssl
import stat
import xml.etree.ElementTree as ET

TEST_HOST = 'test-personsok.statenspersonadressregister.se'
TEST_PATH = '/2023.1'
TEST_NUMBERS = frozenset(('195704133106', '198604069883', '198203249274',
                          '198106039228', '199903672385', '199201782399',
                          '197605832380'))
TEST_CERT_SHA256 = '4bc92f9c718bab3d22c2d5ceec861724b22c7a8afb9f11ee9da230626f7d4c4e'
MAX_RESPONSE = 65536
SOAP = 'http://schemas.xmlsoap.org/soap/envelope/'
BASE = 'http://statenspersonadressregister.se/schema/'
QUERY = BASE+'personsok/2023.1/personsokningfraga'
ANSWER = BASE+'personsok/2023.1/personsokningsvar'
SEARCH = BASE+'komponent/sok/personsokningsokparametrar-1.2'
META = BASE+'komponent/metadata/identifieringsinformationWs-1.1'
PERSON = BASE+'komponent/person/person-1.3'
PROTECTION = BASE+'komponent/person/skyddadepersonuppgifter-1.1'
NAME = BASE+'komponent/person/namn/namn-1.0'
NAME_PART = BASE+'komponent/person/namn/deladenamnelement-1.0'
DETAIL = BASE+'komponent/person/persondetaljer-1.3'
PERIOD = BASE+'komponent/generellt/datumtid-1.1'
DEREGISTRATION = BASE+'komponent/person/avregistrering-1.0'
REFERENCE = BASE+'komponent/person/hanvisning-1.1'
COORDINATION = BASE+'komponent/person/samordningsnummer-1.1'


class SparUnavailable(ValueError):
    def __init__(self):
        super().__init__('SPAR customer-test response unavailable or invalid')


def tag(namespace, name):
    return '{'+namespace+'}'+name


def one(parent, namespace, name, *, optional=False):
    values = parent.findall(tag(namespace, name))
    if len(values) != 1:
        if not values and optional:
            return None
        raise SparUnavailable()
    return values[0]


def text(parent, namespace, name, *, optional=False):
    node = one(parent, namespace, name, optional=optional)
    if node is None:
        return None
    value = node.text
    if len(node) or not isinstance(value, str) or not value.strip():
        raise SparUnavailable()
    return value.strip()


def supported_children(parent, allowed, blocked_namespaces=()):
    for node in parent:
        if node.tag not in allowed and not any(node.tag.startswith('{'+ns+'}') for ns in blocked_namespaces):
            raise SparUnavailable()


def current(parent, namespace, name, today):
    candidates = []
    for node in parent.findall(tag(namespace, name)):
        start = date.fromisoformat(text(node, PERIOD, 'DatumFrom'))
        end = date.fromisoformat(text(node, PERIOD, 'DatumTill'))
        if start >= end:
            raise SparUnavailable()
        # A finite period ending today is not accepted as fresh evidence.
        if start <= today < end:
            candidates.append(node)
    if len(candidates) != 1:
        raise SparUnavailable()
    return candidates[0]


@dataclass(frozen=True, repr=False)
class SparObservation:
    number: str
    kind: str
    reference: str
    checked_at: int
    outcome: str
    reason: str
    given_names: str = ''
    family_name: str = ''
    middle_name: str = ''
    birth_date: str = ''

    def matches_passport_fields(self, fields):
        """Exact conservative comparison; this does not verify a passport."""
        if self.outcome != 'ELIGIBLE_CUSTOMER_TEST':
            return False
        values = dict(fields)
        number = values.get('passportPersonalNumber')
        if (values.get('issuingState') != 'SWE' or not isinstance(number, str)
                or not re.fullmatch(r'(?:[0-9]{10}|[0-9]{12})', number)
                or self.number[-len(number):] != number):
            return False
        family = ' '.join(x for x in (self.middle_name, self.family_name) if x)
        # No fuzzy names, prefix matching, inferred century or transliteration.
        return (values.get('givenNames') == self.given_names.upper()
                and values.get('familyName') == family.upper()
                and values.get('birthDateMrz') == date.fromisoformat(self.birth_date).strftime('%y%m%d'))


def parse_response(payload, expected_number, checked_at):
    """Interpret a test response. Caller must separately authenticate transport."""
    try:
        if (expected_number not in TEST_NUMBERS or type(payload) is not bytes
                or not 0 < len(payload) <= MAX_RESPONSE or type(checked_at) is not int):
            raise SparUnavailable()
        xml = payload.decode('utf-8-sig')
        if '\x00' in xml or '<!DOCTYPE' in xml.upper() or '<!ENTITY' in xml.upper():
            raise SparUnavailable()
        declaration = re.match(r'\s*<\?xml[^?]*\?>', xml)
        if declaration:
            encoding = re.search(r'encoding\s*=\s*[\"\x27]([^\"\x27]+)', declaration[0])
            if encoding and encoding[1].lower() not in ('utf-8', 'us-ascii'):
                raise SparUnavailable()
        root = ET.fromstring(xml)
        if root.tag != tag(SOAP, 'Envelope') or len(list(root.iter())) > 512:
            raise SparUnavailable()
        body = one(root, SOAP, 'Body')
        if len(body) != 1:
            raise SparUnavailable()
        answer = one(body, ANSWER, 'SPARPersonsokningSvar')
        supported_children(answer, {tag(SEARCH, 'PersonsokningFraga'),
                                   tag(ANSWER, 'PersonsokningSvarspost'), tag(ANSWER, 'UUID')})
        query = one(answer, SEARCH, 'PersonsokningFraga')
        if len(query) != 1 or text(query, PERSON, 'IdNummer') != expected_number:
            raise SparUnavailable()
        reference = text(answer, ANSWER, 'UUID')
        if not re.fullmatch('[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}', reference):
            raise SparUnavailable()
        posts = answer.findall(tag(ANSWER, 'PersonsokningSvarspost'))
        if len(posts) != 1:
            return SparObservation(expected_number, '', reference, checked_at,
                                   'REVIEW_REQUIRED', 'NO_MATCH' if not posts else 'AMBIGUOUS')
        post = posts[0]
        supported_children(post, {tag(PERSON, 'PersonId'), tag(PERSON, 'SenasteAndringSPAR'),
            tag(PROTECTION, 'Sekretessmarkering'), tag(PROTECTION, 'SekretessDatum'),
            tag(PROTECTION, 'SkyddadFolkbokforing'), tag(PROTECTION, 'SkyddadFolkbokforingDatum'),
            tag(NAME, 'Namn'), tag(DETAIL, 'Persondetaljer'),
            tag(BASE+'komponent/person/folkbokforing-1.0', 'Folkbokforing'),
            tag(BASE+'komponent/person/adress/folkbokforingsadress-1.1', 'Folkbokforingsadress'),
            tag(BASE+'komponent/person/adress/sarskildpostadress-1.1', 'SarskildPostadress'),
            tag(BASE+'komponent/person/adress/utlandsadress-1.1', 'Utlandsadress'),
            tag(BASE+'komponent/person/adress/kontaktadress-1.0', 'Kontaktadress')})
        ident = one(post, PERSON, 'PersonId')
        kind = text(ident, PERSON, 'Typ')
        if text(ident, PERSON, 'IdNummer') != expected_number or kind not in ('PERSONNUMMER', 'SAMORDNINGSNUMMER'):
            raise SparUnavailable()
        def review(reason):
            return SparObservation(expected_number, kind.lower(), reference, checked_at,
                                   'REVIEW_REQUIRED', reason)
        protected = [text(post, PROTECTION, key) for key in ('Sekretessmarkering', 'SkyddadFolkbokforing')]
        if any(x not in ('JA', 'NEJ') for x in protected):
            return review('UNKNOWN_PROTECTION')
        if 'JA' in protected:
            return review('PROTECTED')
        today = datetime.fromtimestamp(checked_at, timezone.utc).date()
        name = current(post, NAME, 'Namn', today)
        details = current(post, DETAIL, 'Persondetaljer', today)
        supported_children(name, {tag(PERIOD, 'DatumFrom'), tag(PERIOD, 'DatumTill'),
            *(tag(NAME_PART, key) for key in ('Fornamn', 'Mellannamn', 'Efternamn', 'Tilltalsnamn', 'Aviseringsnamn'))})
        supported_children(details, {tag(PERIOD, 'DatumFrom'), tag(PERIOD, 'DatumTill'),
            tag(PROTECTION, 'Sekretessmarkering'), tag(PROTECTION, 'SkyddadFolkbokforing'),
            tag(DETAIL, 'Fodelsedatum'), tag(DETAIL, 'Kon')},
            (DEREGISTRATION, REFERENCE, COORDINATION))
        detail_protection = [text(details, PROTECTION, key) for key in ('Sekretessmarkering', 'SkyddadFolkbokforing')]
        if any(x != 'NEJ' for x in detail_protection):
            return review('PROTECTED_OR_UNKNOWN')
        if any(x.tag.startswith(('{'+DEREGISTRATION+'}', '{'+REFERENCE+'}')) for x in details):
            return review('STATUS_REQUIRES_REVIEW')
        coordination = [x for x in details if x.tag.startswith('{'+COORDINATION+'}')]
        if kind == 'SAMORDNINGSNUMMER':
            known = {tag(COORDINATION, key) for key in ('SnIdentitetsniva', 'SnIdentitetsnivaDatum',
                'SnTilldelningsdatum', 'SnPreliminartVilandeforklaringsdatum')}
            if any(x.tag not in known for x in coordination):
                return review('COORDINATION_STATUS_REQUIRES_REVIEW')
            level = text(details, COORDINATION, 'SnIdentitetsniva', optional=True)
            if level != 'STYRKT':
                return review('COORDINATION_NOT_CONFIRMED')
            if any(x.tag in (tag(COORDINATION, 'SnVilandeorsak'), tag(COORDINATION, 'SnVilandeforklaringsdatum')) for x in coordination):
                return review('COORDINATION_STATUS_REQUIRES_REVIEW')
            preliminary = text(details, COORDINATION, 'SnPreliminartVilandeforklaringsdatum', optional=True)
            if preliminary is None or date.fromisoformat(preliminary) <= today:
                return review('COORDINATION_STATUS_REQUIRES_REVIEW')
        elif coordination:
            return review('UNEXPECTED_COORDINATION_STATUS')
        birth = text(details, DETAIL, 'Fodelsedatum')
        born = date.fromisoformat(birth)
        day = int(expected_number[6:8])-(60 if kind == 'SAMORDNINGSNUMMER' else 0)
        if born != date(int(expected_number[:4]), int(expected_number[4:6]), day):
            return review('IDENTITY_DATE_MISMATCH')
        given = text(name, NAME_PART, 'Fornamn')
        family = text(name, NAME_PART, 'Efternamn')
        middle = text(name, NAME_PART, 'Mellannamn', optional=True) or ''
        return SparObservation(expected_number, kind.lower(), reference, checked_at,
                               'ELIGIBLE_CUSTOMER_TEST', 'CURRENT_UNPROTECTED_RECORD',
                               given, family, middle, birth)
    except (ValueError, TypeError, OverflowError, ET.ParseError):
        raise SparUnavailable() from None


def test_query(number):
    if not isinstance(number, str) or number not in TEST_NUMBERS:
        raise SparUnavailable()
    root = ET.Element(tag(SOAP, 'Envelope'))
    question = ET.SubElement(ET.SubElement(root, tag(SOAP, 'Body')), tag(QUERY, 'SPARPersonsokningFraga'))
    metadata = ET.SubElement(question, tag(META, 'Identifieringsinformation'))
    for name, value in (('KundNrLeveransMottagare', '500243'), ('KundNrSlutkund', '500243'),
                        ('UppdragId', '637'), ('SlutAnvandarId', 'Tjipp kundtest')):
        ET.SubElement(metadata, tag(META, name)).text = value
    search = ET.SubElement(question, tag(SEARCH, 'PersonsokningFraga'))
    ET.SubElement(search, tag(PERSON, 'IdNummer')).text = number
    return ET.tostring(root, encoding='utf-8', xml_declaration=True)


def _client_context(certfile, keyfile):
    for filename in (certfile, keyfile):
        if filename is None:
            continue
        path = Path(filename)
        info = path.lstat()
        if (not path.is_absolute() or not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.geteuid() or info.st_mode & 0o077):
            raise SparUnavailable()
    pem = Path(certfile).read_text('ascii')
    match = re.search('-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----', pem, re.S)
    if match is None or hashlib.sha256(ssl.PEM_cert_to_DER_cert(match[0])).hexdigest() != TEST_CERT_SHA256:
        raise SparUnavailable()
    context = ssl.create_default_context()
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(certfile, keyfile)
    return context


class SparCustomerTestClient:
    """Fixed test host/account/certificate/persons; no production configuration."""
    def __init__(self, certfile, keyfile=None):
        try:
            self._context = _client_context(certfile, keyfile)
        except (OSError, ValueError, TypeError):
            raise SparUnavailable() from None

    def observe(self, number):
        payload = test_query(number)  # Reject other identities before opening a connection.
        connection = http.client.HTTPSConnection(TEST_HOST, timeout=10, context=self._context)
        try:
            connection.request('POST', TEST_PATH, payload, {
                'Content-Type': 'text/xml; charset=utf-8',
                'SOAPAction': 'http://skatteverket.se/spar/personsok/2023.1/PersonsokService/Personsok'})
            response = connection.getresponse()
            media = (response.getheader('Content-Type') or '').split(';', 1)[0].strip().lower()
            if response.status != 200 or media not in ('text/xml', 'application/xml'):
                raise SparUnavailable()
            raw = response.read(MAX_RESPONSE+1)
            return parse_response(raw, number, int(datetime.now(timezone.utc).timestamp()))
        except (OSError, ValueError, http.client.HTTPException):
            raise SparUnavailable() from None
        finally:
            connection.close()
