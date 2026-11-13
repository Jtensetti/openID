#!/usr/bin/env python3
"""Exercise the packaged synthetic Sandbox on loopback with verified TLS.

The public SAML feed is loaded using its pinned signing certificate. No entity
is registered and no authentication request is sent to an external service.
JWT parsing below checks publication only; it is not signature verification.
"""
import base64
import http.client
import json
from pathlib import Path
import socket
import ssl
import subprocess
import tempfile
import time

from smoke import JAVA, JAR

ISSUER = "https://tjipp-sweden-connect-sandbox.onrender.com"
HOST = ISSUER.removeprefix("https://")
PORT = 9443


def decode(part):
    return json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))


def main():
    # Refuse to test a process that was already listening on the fixed CLI port.
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", PORT))
    with tempfile.TemporaryDirectory(prefix="synthetic-sandbox-smoke-") as temp:
        root = Path(temp)
        keys = root / "keys"
        subprocess.run([JAVA, "-jar", str(JAR), "sandbox-init", str(keys)],
                       check=True, capture_output=True, timeout=60)
        settings = root / "settings.json"
        settings.write_text(json.dumps({"idp": ISSUER,
            "organization": "Synthetic Sandbox test", "contact": "operator@example.org"}))
        tls = ssl.create_default_context(cafile=str(keys / "tls.crt"))

        def request(path, *, host=HOST, headers=None, method="GET", body=None):
            connection = http.client.HTTPSConnection("localhost", PORT, context=tls, timeout=5)
            try:
                connection.request(method, path, body=body, headers={"Host": host, **(headers or {})})
                response = connection.getresponse()
                return response.status, response.read()
            finally:
                connection.close()

        with (root / "application.log").open("w") as log:
            app = subprocess.Popen([JAVA, "-jar", str(JAR), "sandbox-idp", str(keys), str(settings)],
                                   stdout=log, stderr=log)
            try:
                deadline = time.monotonic() + 90
                while time.monotonic() < deadline:
                    if app.poll() is not None:
                        raise RuntimeError("Synthetic Sandbox exited before readiness")
                    try:
                        if request("/saml2/metadata")[0] == 200:
                            break
                    except (OSError, http.client.HTTPException):
                        pass
                    time.sleep(0.2)
                else:
                    raise RuntimeError("Synthetic Sandbox did not become ready within 90 seconds")

                status, body = request("/.well-known/openid-configuration")
                assert status == 200, f"OIDC discovery returned {status}, expected 200"
                discovery = json.loads(body)
                assert discovery["issuer"] == ISSUER
                assert discovery["jwks_uri"] == ISSUER + "/oidc/jwks"
                assert discovery["token_endpoint_auth_methods_supported"] == ["private_key_jwt"]
                assert "S256" in discovery["code_challenge_methods_supported"]
                assert discovery["acr_values_supported"] == ["urn:openid:lab:simulated"]

                status, body = request("/oidc/jwks")
                assert status == 200, f"OIDC JWKS returned {status}, expected 200"
                signing_keys = json.loads(body)["keys"]
                assert signing_keys and all("d" not in key for key in signing_keys)

                status, body = request("/.well-known/openid-federation")
                assert status == 200, f"Entity Configuration returned {status}, expected 200"
                header, payload, signature = body.decode().split(".")
                assert signature and decode(header)["typ"] == "entity-statement+jwt"
                entity = decode(payload)
                assert entity["iss"] == entity["sub"] == ISSUER
                assert entity["authority_hints"] == ["https://fed.sandbox.swedenconnect.se/im-reg-sc-op"]
                assert entity["metadata"]["openid_provider"]["issuer"] == ISSUER
                assert entity["iat"] <= time.time() + 60 < entity["exp"]
                assert not entity.get("trust_marks")
                assert all("d" not in key for key in entity["jwks"]["keys"])

                assert request("/.well-known/openid-configuration", host="attacker.invalid")[0] == 403
                assert request("/.well-known/openid-configuration",
                               headers={"X-Forwarded-Host": HOST})[0] == 403
                assert request("/lab", method="POST", headers={"Origin": ISSUER},
                               body="action=approve")[0] == 403
                status, _ = request("/oidc/authorize")
                assert status == 400, f"Missing OIDC client returned {status}, expected 400"
                print("PASS: packaged sandbox-idp publishes discovery, public JWKS and Entity Configuration; "
                      "synthetic ACR, PKCE and client authentication metadata; rejected foreign Host, "
                      "forwarded Host, approval without CSRF and authorization without a client")
            finally:
                app.terminate()
                try:
                    app.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    app.kill()
                    app.wait(timeout=5)


if __name__ == "__main__":
    main()
