#!/usr/bin/env python3
"""Run the packaged CLI and an HTTPS login flow."""
from html.parser import HTMLParser
from http.cookiejar import CookieJar
import os
from pathlib import Path
import ssl
import subprocess
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
JAVA = str(Path(os.environ["JAVA_HOME"]) / "bin/java") if os.environ.get("JAVA_HOME") else "java"
JAR = ROOT / "target/isolated-eid-lab.jar"
IDP, SP = "https://127.0.0.1:8443", "https://127.0.0.1:8444"


class LocalRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        parsed = urllib.parse.urlsplit(newurl)
        if f"{parsed.scheme}://{parsed.netloc}" not in (IDP, SP):
            raise RuntimeError("Refusing redirect outside the two lab endpoints")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


class HiddenForm(HTMLParser):
    def __init__(self, text):
        super().__init__()
        self.fields = {}
        self.action = None
        self.feed(text)

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "form":
            self.action = attrs.get("action")
        if tag == "input" and attrs.get("type") == "hidden":
            self.fields[attrs["name"]] = attrs.get("value", "")


def main():
    with tempfile.TemporaryDirectory(prefix="synthetic-eid-smoke-") as temp:
        keys = Path(temp) / "keys"
        subprocess.run([JAVA, "-jar", str(JAR), "init", str(keys)], check=True, timeout=30)
        context = ssl.create_default_context(cafile=str(keys / "tls.crt"))
        client = urllib.request.build_opener(urllib.request.ProxyHandler({}),
            urllib.request.HTTPSHandler(context=context), urllib.request.HTTPCookieProcessor(CookieJar()), LocalRedirects())
        with (Path(temp) / "application.log").open("w+") as log:
            app = subprocess.Popen([JAVA, "-jar", str(JAR), "start", str(keys)], stdout=log, stderr=log)
            try:
                for _ in range(150):
                    if app.poll() is not None:
                        raise RuntimeError("Packaged application exited before startup")
                    try:
                        with client.open(SP, timeout=1) as response:
                            assert response.status == 200
                        break
                    except urllib.error.URLError:
                        time.sleep(0.1)
                else:
                    raise RuntimeError("Packaged application did not start within 15 seconds")
                with client.open(IDP, timeout=5) as response:
                    assert response.status == 200
                with client.open(SP + "/login", timeout=5) as response:
                    approval = HiddenForm(response.read().decode())
                approval.fields.update(credential="TEST-CREDENTIAL-alice", simulatedProofing="acknowledged", action="approve")
                request = urllib.request.Request(IDP + "/lab", urllib.parse.urlencode(approval.fields).encode(), {"Origin": IDP})
                with client.open(request, timeout=5) as response:
                    saml = HiddenForm(response.read().decode())
                assert saml.action == SP + "/acs" and "SAMLResponse" in saml.fields
                request = urllib.request.Request(saml.action, urllib.parse.urlencode(saml.fields).encode(), {"Origin": IDP})
                with client.open(request, timeout=5) as response:
                    assert response.status == 200 and response.url == SP + "/me"
                    assert "SYNTHETIC-alice" in response.read().decode()
                print("PASS: packaged init/start, pinned HTTPS on both listeners, complete synthetic SAML login")
            except urllib.error.HTTPError as error:
                raise RuntimeError(f"Local endpoint rejected smoke flow: HTTP {error.code}: {error.read().decode()}") from error
            finally:
                app.terminate()
                try:
                    app.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    app.kill()
                    app.wait()


if __name__ == "__main__":
    main()
