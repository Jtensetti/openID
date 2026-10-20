#!/usr/bin/env python3
"""Packaged process restart/kill and stale-backup drill, using only synthetic identities."""
from contextlib import contextmanager
from http.cookiejar import CookieJar
import json
from pathlib import Path
import ssl
import subprocess
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from smoke import JAVA, JAR, IDP, SP, HiddenForm, LocalRedirects


def cli(*arguments):
    return subprocess.run([JAVA, "-jar", str(JAR), *map(str, arguments)], check=True, capture_output=True, text=True, timeout=30).stdout


def client(keys):
    context = ssl.create_default_context(cafile=str(keys / "tls.crt"))
    return urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=context),
        urllib.request.HTTPCookieProcessor(CookieJar()), LocalRedirects())


@contextmanager
def running(keys, logpath):
    with logpath.open("w") as log:
        app = subprocess.Popen([JAVA, "-jar", str(JAR), "start", str(keys)], stdout=log, stderr=log)
        try:
            c = client(keys)
            for _ in range(300):
                if app.poll() is not None:
                    raise RuntimeError("Application failed startup during recovery drill")
                try:
                    with c.open(SP, timeout=1) as response:
                        assert response.status == 200
                    break
                except urllib.error.URLError:
                    time.sleep(.1)
            else:
                raise RuntimeError("Startup timeout during recovery drill")
            yield app, c
        finally:
            if app.poll() is None:
                app.terminate()
            try:
                app.wait(timeout=10)
            except subprocess.TimeoutExpired:
                app.kill()
                app.wait(timeout=5)


def login(c):
    with c.open(SP + "/login", timeout=5) as response:
        approval = HiddenForm(response.read().decode())
    approval.fields.update(credential="TEST-CREDENTIAL-alice", simulatedProofing="acknowledged", action="approve")
    request = urllib.request.Request(IDP + "/lab", urllib.parse.urlencode(approval.fields).encode(), {"Origin": IDP})
    with c.open(request, timeout=5) as response:
        form = HiddenForm(response.read().decode())
    assert form.action == SP + "/acs" and "SAMLResponse" in form.fields
    request = urllib.request.Request(form.action, urllib.parse.urlencode(form.fields).encode(), {"Origin": IDP})
    try:
        with c.open(request, timeout=5) as response:
            return response.status == 200 and "SYNTHETIC-alice" in response.read().decode()
    except urllib.error.HTTPError as e:
        assert e.code == 400
        return False


def main():
    with tempfile.TemporaryDirectory(prefix="openid-recovery-") as temp:
        root = Path(temp)
        keys, restored = root / "state", root / "restored"
        backup = root / "old.sqlite"
        cli("init", keys)
        with running(keys, root / "first.log") as (_, c):
            assert login(c)
        cli("backup", keys, backup)
        cli("revoke", keys, "TEST-CREDENTIAL-alice")
        with running(keys, root / "restarted.log") as (_, c):
            assert not login(c), "A restart resurrected a revoked credential"
        audit = json.loads(cli("audit", keys))
        assert audit[-1]["action"] == "REVOKE"
        # The timestamp is from the actual durable success event; month is Stockholm, not a hard-coded fixture date.
        from datetime import datetime
        from zoneinfo import ZoneInfo
        report = json.loads(cli("report", keys, datetime.now(ZoneInfo("Europe/Stockholm")).strftime("%Y-%m")))
        assert report["completedSyntheticLogins"] == 1 and report["failed"] == 1
        assert report["compensableTransactions"] == 0 and report["submission"] == "INTE SKICKAT"
        cli("restore", backup, restored)
        with running(restored, root / "restore.log") as (_, c):
            assert not login(c), "An older backup resurrected a revoked credential"
        # Exercise a real ungraceful process death, not only a simulated marker file.
        crash = root / "crash"
        cli("init", crash)
        with running(crash, root / "crash.log") as (app, c):
            assert login(c)
            app.kill()
            app.wait(timeout=5)
        with running(crash, root / "crash-recovery.log") as (_, c):
            assert not login(c), "Crash recovery retained an uncertain active credential"
        assert any(e["action"] == "UNCLEAN_RECOVERY" for e in json.loads(cli("audit", crash)))
        print("PASS: packaged restart preserves revocation; stale backup and SIGKILL recovery fail closed; offline claims remain zero")


if __name__ == "__main__":
    main()
