"""Fixed Sandbox recipients; labels are bound to the stored audience, never supplied by a browser."""
SANDBOX_PARTIES = {
    'https://testclient.sandbox.swedenconnect.se/testsp1': 'Sweden Connect Test-SP 1',
    'https://testclient.sandbox.swedenconnect.se/testsp2': 'Sweden Connect Test-SP 2',
    'https://testclient.sandbox.swedenconnect.se/test-signservice1': 'Sweden Connect Test – underskrift',
}
PERSON_NUMBER_PARTIES = frozenset(SANDBOX_PARTIES) - {'https://testclient.sandbox.swedenconnect.se/testsp2'}


def sandbox_purpose(signing, audience):
    attributes = 'förnamn, efternamn och personnummer från passet' if audience in PERSON_NUMBER_PARTIES else 'förnamn och efternamn'
    return ('Skriv under testtexten och dela ' if signing else 'Logga in och dela ') + attributes + ' med Sweden Connects testtjänst'


def sandbox_identity(profile, audience):
    if audience not in SANDBOX_PARTIES:
        raise ValueError('sandbox recipient')
    result = {'givenName': profile['givenNames'], 'surname': profile['familyName']}
    number = profile.get('passportPersonalNumber')
    # Preserve the authenticated field. A ten-digit value has no verified century.
    if (audience in PERSON_NUMBER_PARTIES and profile['issuingState'] == 'SWE'
            and isinstance(number, str) and len(number) == 12 and number.isascii() and number.isdecimal()):
        result['personalIdentityNumber'] = number
    return result
