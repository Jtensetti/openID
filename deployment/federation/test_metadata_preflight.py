"""No real identities or private production keys in metadata-preflight tests."""
import base64
import importlib.util
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

PATH = Path(__file__).with_name("metadata_preflight.py")
spec = importlib.util.spec_from_file_location("metadata_preflight", PATH)
preflight = importlib.util.module_from_spec(spec)
spec.loader.exec_module(preflight)


@unittest.skipUnless(shutil.which("openssl"), "OpenSSL required")
class MetadataPreflightTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory()
        private = Path(cls._tmp.name, "sandbox.key")
        public = Path(cls._tmp.name, "sandbox.crt")
        subprocess.run(["openssl", "req", "-new", "-x509", "-newkey", "rsa:3072", "-noenc", "-sha256", "-days", "1",
                        "-subj", "/CN=Synthetic Signing", "-keyout", str(private), "-out", str(public)],
                       capture_output=True, check=True, timeout=45)
        cls.cert = base64.b64encode(subprocess.check_output(["openssl", "x509", "-in", str(public), "-outform", "DER"])).decode()

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def xml(self, extras="", certificate=None, uses=("signing", "encryption")):
        cert = self.cert if certificate is None else certificate
        keys = "".join(f'<md:KeyDescriptor use="{use}"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>{cert}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>' for use in uses)
        return f'''<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" entityID="https://id.example.test/idp">
          <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
            <md:Extensions><mdui:UIInfo xmlns:mdui="urn:oasis:names:tc:SAML:metadata:ui"><mdui:DisplayName xml:lang="sv">Syntetisk tjänst</mdui:DisplayName><mdui:Logo height="60" width="60">https://id.example.test/logo.svg</mdui:Logo></mdui:UIInfo></md:Extensions>{keys}
            <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://id.example.test/login"/>
          </md:IDPSSODescriptor>
          <md:Organization><md:OrganizationName xml:lang="sv">Syntetisk organisation</md:OrganizationName><md:OrganizationDisplayName xml:lang="sv">Syntetisk organisation</md:OrganizationDisplayName><md:OrganizationURL xml:lang="sv">https://id.example.test</md:OrganizationURL></md:Organization>{extras}
        </md:EntityDescriptor>'''.encode()

    def audit(self, xml, role="idp", expected="https://id.example.test/idp"):
        return preflight.inspect(xml, role, expected)

    def test_well_formed_synthetic_metadata_passes_static_checks(self):
        result = self.audit(self.xml())
        self.assertFalse(any(x["level"] == "error" for x in result), result)
        self.assertIn("SHARED_KEY", {x["code"] for x in result})

    def test_missing_organization_and_logo_fail(self):
        xml = self.xml().replace(b"<md:Organization>", b"<md:NotOrganization>").replace(b"</md:Organization>", b"</md:NotOrganization>")
        xml = xml.replace(b"<mdui:Logo ", b"<mdui:NotLogo ").replace(b"</mdui:Logo>", b"</mdui:NotLogo>")
        codes = {x["code"] for x in self.audit(xml)}
        self.assertIn("ORG_ORGANIZATIONNAME", codes)
        self.assertIn("UI_LOGO", codes)

    def test_invalid_cert_and_missing_signing_role_fail(self):
        codes = {x["code"] for x in self.audit(self.xml(certificate="YWJj", uses=("encryption",)))}
        self.assertIn("CERT_X509", codes)
        self.assertIn("SIGNING_KEY", codes)

    def test_mismatched_entity_and_dtd_fail(self):
        self.assertIn("ENTITY_MISMATCH", {x["code"] for x in self.audit(self.xml(), expected="https://other.test")})
        xml = b'<!DOCTYPE foo [ <!ENTITY bar "boom"> ]>' + self.xml()
        self.assertEqual(self.audit(xml)[0]["code"], "XML_INPUT")

    def test_missing_role_fails(self):
        self.assertIn("ROLE", {x["code"] for x in self.audit(self.xml(), role="sp")})


if __name__ == "__main__":
    unittest.main()
