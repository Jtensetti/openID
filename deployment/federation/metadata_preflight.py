#!/usr/bin/env python3
"""Offline Sweden Connect SAML metadata preflight (not federation trust validation)."""
import argparse
import base64
import json
from pathlib import Path
import hashlib
import subprocess
import sys
import xml.etree.ElementTree as ET
from urllib.parse import urlsplit

NS = {
    "md": "urn:oasis:names:tc:SAML:2.0:metadata",
    "mdui": "urn:oasis:names:tc:SAML:metadata:ui",
    "ds": "http://www.w3.org/2000/09/xmldsig#",
}
XML_LANG = "{http://www.w3.org/XML/1998/namespace}lang"


def inspect(xml: bytes, role: str, expected_entity: str | None = None) -> list[dict]:
    """Find metadata-profile gaps; never decide whether a federation trusts this entity."""
    issues = []

    def issue(level: str, code: str, detail: str):
        issues.append({"level": level, "code": code, "detail": detail})

    if len(xml) > 1_000_000 or b"<!DOCTYPE" in xml.upper() or b"<!ENTITY" in xml.upper():
        return [{"level": "error", "code": "XML_INPUT", "detail": "XML exceeds 1 MB or contains a DTD/entity declaration"}]
    try:
        root = ET.fromstring(xml)
    except ET.ParseError:
        return [{"level": "error", "code": "XML_PARSE", "detail": "Invalid metadata XML"}]
    if root.tag != f"{{{NS['md']}}}EntityDescriptor":
        return [{"level": "error", "code": "ROOT", "detail": "Expected a single SAML EntityDescriptor"}]

    entity = root.get("entityID") or ""
    if not entity:
        issue("error", "ENTITY_ID", "Missing entityID")
    if expected_entity is not None and entity != expected_entity:
        issue("error", "ENTITY_MISMATCH", "entityID does not equal the pinned expected identifier")
    parsed = urlsplit(entity)
    if parsed.scheme != "https" or not parsed.hostname:
        issue("warning", "ENTITY_URL", "Use a stable HTTPS entityID for the external federation; lab identifiers are not suitable")

    descriptor_tag = "IDPSSODescriptor" if role == "idp" else "SPSSODescriptor"
    descriptor = root.find(f"md:{descriptor_tag}", NS)
    if descriptor is None:
        issue("error", "ROLE", f"Missing {descriptor_tag}")
        return issues

    org = root.find("md:Organization", NS)
    for tag in ("OrganizationName", "OrganizationDisplayName", "OrganizationURL"):
        field = org.find(f"md:{tag}", NS) if org is not None else None
        if field is None or not (field.text or "").strip() or not field.get(XML_LANG):
            issue("error", "ORG_" + tag.upper(), f"Organization/{tag} must contain a value and xml:lang")

    ui = descriptor.find("md:Extensions/mdui:UIInfo", NS)
    display = ui.findall("mdui:DisplayName", NS) if ui is not None else []
    if not any((el.text or "").strip() and el.get(XML_LANG) == "sv" for el in display):
        issue("error", "UI_DISPLAY", "Role requires Swedish mdui:DisplayName")
    logos = ui.findall("mdui:Logo", NS) if ui is not None else []
    if not any((el.text or "").strip() for el in logos):
        issue("error", "UI_LOGO", "Role requires an mdui:Logo reference")
    else:
        for logo in logos:
            if not (logo.text or "").strip().startswith("https://"):
                issue("warning", "LOGO_URL", "Use an accessible HTTPS logo URL")

    keys = descriptor.findall("md:KeyDescriptor", NS)
    if not keys:
        issue("error", "KEYS", "Missing SAML KeyDescriptor")
    role_fingerprints = {"signing": set(), "encryption": set()}
    found_uses = set()
    for index, item in enumerate(keys):
        use = item.get("use")
        if use not in (None, "signing", "encryption"):
            issue("error", "KEY_USE", f"KeyDescriptor {index} has an invalid use")
            continue
        found_uses.add(use)
        certs = item.findall("ds:KeyInfo/ds:X509Data/ds:X509Certificate", NS)
        if not certs:
            issue("error", "CERT_MISSING", f"KeyDescriptor {index} is missing its X.509 certificate")
            continue
        for cert in certs:
            try:
                der = base64.b64decode("".join((cert.text or "").split()), validate=True)
            except ValueError:
                issue("error", "CERT_BASE64", f"KeyDescriptor {index} has invalid Base64")
                continue
            try:
                p = subprocess.run(["openssl", "x509", "-inform", "DER", "-noout", "-text"],
                                   input=der, capture_output=True, timeout=10, check=False)
            except (OSError, subprocess.TimeoutExpired):
                issue("error", "OPENSSL", "OpenSSL unavailable or timed out")
                continue
            if p.returncode != 0:
                issue("error", "CERT_X509", f"KeyDescriptor {index} is not a valid X.509 certificate")
                continue
            fingerprint = hashlib.sha256(der).hexdigest()
            for effective in (("signing", "encryption") if use is None else (use,)):
                role_fingerprints[effective].add(fingerprint)
            upper = p.stdout.upper()
            if b"SIGNATURE ALGORITHM: SHA1" in upper or b"SIGNATURE ALGORITHM: MD5" in upper:
                issue("warning", "WEAK_SIGNATURE", f"KeyDescriptor {index} certificate uses a weak signature algorithm")
            try:
                valid = subprocess.run(["openssl", "x509", "-inform", "DER", "-noout", "-checkend", "0"],
                                       input=der, capture_output=True, timeout=10, check=False)
                if valid.returncode != 0:
                    issue("warning", "EXPIRED_CERT", f"KeyDescriptor {index} certificate is expired (recommended to rotate)")
            except (OSError, subprocess.TimeoutExpired):
                issue("error", "OPENSSL", "Unable to check certificate validity")
    if not role_fingerprints["signing"]:
        issue("error", "SIGNING_KEY", "No valid X.509 certificate usable for signing")
    if not role_fingerprints["encryption"]:
        issue("warning", "ENCRYPTION_KEY", "No encryption KeyDescriptor found (recommended by profile)")
    if keys and None in found_uses:
        issue("warning", "KEY_ROLE", "Mark signing and encryption KeyDescriptors explicitly for clarity")
    if role_fingerprints["signing"] & role_fingerprints["encryption"]:
        issue("warning", "SHARED_KEY", "Same certificate is used for SAML signing and encryption; consider separate credentials")

    # An offline file does not prove federation metadata signature validation, contracts or approved entity names.
    return issues


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("metadata", type=Path)
    p.add_argument("--role", choices=("idp", "sp"), required=True)
    p.add_argument("--expected-entity", required=True)
    p.add_argument("--json", action="store_true", help="Machine-readable result")
    args = p.parse_args(argv)
    try:
        findings = inspect(args.metadata.read_bytes(), args.role, args.expected_entity)
    except OSError as ex:
        p.error(f"Cannot read metadata: {ex.strerror}")
    passed = not any(i["level"] == "error" for i in findings)
    output = {"static_checks_passed": passed, "findings": findings,
              "scope": "Offline structural preflight only. Federation trust, metadata-feed signatures, approved organization, key custody and service interoperability are NOT verified."}
    if args.json:
        print(json.dumps(output, ensure_ascii=False, indent=2))
    else:
        for item in findings:
            print(f"{item['level'].upper()} {item['code']}: {item['detail']}")
        print(f"Static metadata checks: {'PASS (not federation approval)' if passed else 'FAIL'}")
        print(output["scope"])
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
