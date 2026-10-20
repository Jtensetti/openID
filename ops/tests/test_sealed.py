"""HTTP tests for the sealed deployment."""
import http.client
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
JAVA_HOME = Path(os.environ["JAVA_HOME"])


class SealedEnvironmentTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix="openid-sealed-")
        subprocess.run([str(JAVA_HOME / "bin/javac"), "--release", "21", "-d", cls.temp.name,
                        str(ROOT / "src/SealedEnvironment.java")], check=True)
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            cls.port = s.getsockname()[1]
        cls.command = [str(JAVA_HOME / "bin/java"), "-Dsun.net.httpserver.maxReqTime=10",
                       "-Dsun.net.httpserver.maxRspTime=10", "-Dsun.net.httpserver.maxReqHeaders=32",
                       "-Dsun.net.httpserver.maxReqHeaderSize=8192", "-Djdk.httpserver.maxConnections=64",
                       "-cp", cls.temp.name, "SealedEnvironment"]
        cls.env = dict(os.environ, PORT=str(cls.port), EID_ISSUANCE_ENABLED="true", SPRING_PROFILES_ACTIVE="production")
        cls.log = open(Path(cls.temp.name) / "server.log", "w+")
        cls.process = subprocess.Popen(cls.command + ["serve"], env=cls.env, stdout=cls.log, stderr=cls.log)
        for _ in range(100):
            if cls.process.poll() is not None:
                raise RuntimeError("Sealed environment failed startup")
            try:
                conn = http.client.HTTPConnection("127.0.0.1", cls.port, timeout=1)
                conn.request("GET", "/health/live")
                if conn.getresponse().status == 200:
                    conn.close()
                    break
            except OSError:
                time.sleep(.05)
        else:
            raise RuntimeError("Startup timeout")

    @classmethod
    def tearDownClass(cls):
        cls.process.terminate()
        cls.process.wait(timeout=10)
        cls.log.close()
        cls.temp.cleanup()

    def request(self, method, path, body=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=3)
        conn.request(method, path, body=body)
        response = conn.getresponse()
        result = response.status, dict(response.getheaders()), response.read()
        conn.close()
        return result

    def test_liveness_does_not_claim_eid_readiness(self):
        status, headers, body = self.request("GET", "/health/live")
        self.assertEqual(200, status)
        self.assertEqual("SEALED", json.loads(body)["status"])
        self.assertFalse(json.loads(body)["eidIssuanceEnabled"])
        self.assertEqual("no-store", headers["Cache-control"])
        self.assertEqual(503, self.request("GET", "/health/ready")[0])

    def test_no_identity_endpoints_or_test_material(self):
        for path in ("/", "/login", "/lab", "/saml2/post/authn", "/acs", "/.well-known/openid-configuration", "/tls.p12", "/registry.sqlite"):
            with self.subTest(path=path):
                status, _, body = self.request("GET", path)
                self.assertEqual(503, status)
                self.assertFalse(json.loads(body)["eidIssuanceEnabled"])
                self.assertNotIn(b"SYNTHETIC-alice", body)

    def test_requests_and_environment_cannot_open_issuance(self):
        for method in ("POST", "PUT", "DELETE", "PATCH"):
            with self.subTest(method=method):
                self.assertEqual(503, self.request(method, "/health/live", b"enable=true")[0])
        self.assertEqual(503, self.request("GET", "/health/live?enable=true")[0])
        self.assertEqual(503, self.request("HEAD", "/login")[0])

    def test_runtime_probe_and_invalid_configuration(self):
        subprocess.run(self.command + ["probe"], env=self.env, check=True, timeout=10)
        for port in ("80", "0", "65536", "not-a-port"):
            result = subprocess.run(self.command + ["serve"], env=dict(self.env, PORT=port), capture_output=True, timeout=5)
            self.assertNotEqual(0, result.returncode)

    def test_request_contents_are_not_logged(self):
        self.request("POST", "/canary-do-not-log", b"secret-canary-do-not-log")
        self.log.flush()
        text = (Path(self.temp.name) / "server.log").read_text()
        self.assertNotIn("canary-do-not-log", text)

    def test_incomplete_request_is_closed_within_the_configured_deadline(self):
        # Temurin 21's ServerImpl converts maxReqTime from seconds to milliseconds.
        with socket.create_connection(("127.0.0.1", self.port), timeout=15) as s:
            start = time.monotonic()
            s.sendall(b"GET /health/live HTTP/1.1\r\nHost: localhost\r\n")
            self.assertEqual(b"", s.recv(1))
            self.assertLess(time.monotonic() - start, 15)


if __name__ == "__main__":
    unittest.main(verbosity=2)
