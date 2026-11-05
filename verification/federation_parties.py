"""Fixed Sandbox recipients; labels are bound to the stored audience, never supplied by a browser."""
SANDBOX_PARTIES = {
    'https://testclient.sandbox.swedenconnect.se/testsp1': 'Sweden Connect Test-SP 1',
    'https://testclient.sandbox.swedenconnect.se/testsp2': 'Sweden Connect Test-SP 2',
    'https://testclient.sandbox.swedenconnect.se/test-signservice1': 'Sweden Connect Test – underskrift',
}


def sandbox_purpose(signing):
    return ('Skriv under testtexten och dela namn med Sweden Connects testtjänst' if signing
            else 'Logga in och dela namn med Sweden Connects testtjänst')
