#!/usr/bin/env python3
"""Verify the sealed deployment over HTTPS, with certificate checks and no redirects."""
import argparse
import datetime
import json
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("origin", help="HTTPS origin of the sealed environment")
    args = parser.parse_args()
    parsed = urllib.parse.urlsplit(args.origin)
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username is not None
            or parsed.password is not None or parsed.path not in ("", "/")
            or parsed.query or parsed.fragment):
        parser.error("Provide an HTTPS origin without credentials, path, query or fragment")
    origin = args.origin.rstrip("/")
    opener = urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=ssl.create_default_context()), NoRedirect())
    expected = {"environment": "production", "status": "SEALED", "eidIssuanceEnabled": False}
    cases = [("GET", "/health/live", 200)]
    cases += [("GET", path, 503) for path in (
        "/", "/health/ready", "/login", "/lab", "/saml2/post/authn", "/acs",
        "/.well-known/openid-configuration", "/tls.p12", "/registry.sqlite",
        "/health/live?enable=true")]
    cases += [("POST", "/health/live", 503), ("HEAD", "/login", 503)]
    report = {"checked_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
              "origin": origin, "certificate_verification": True, "follow_redirects": False,
              "checks": []}
    for method, path, expected_status in cases:
        check = {"method": method, "path": path, "expected_status": expected_status}
        start = time.monotonic()
        try:
            request = urllib.request.Request(origin + path, method=method,
                data=b"enable=true" if method == "POST" else None,
                headers={"Accept": "application/json", "User-Agent": "openID-sealed-verification/1"})
            try:
                response = opener.open(request, timeout=20)
            except urllib.error.HTTPError as response_error:
                response = response_error
            with response:
                check["status"] = response.status
                body = response.read(65537)
                check["headers"] = {name: response.headers.get(name, "") for name in (
                    "Content-Type", "Cache-Control", "Content-Security-Policy",
                    "X-Content-Type-Options", "Referrer-Policy")}
                problems = []
                if response.status != expected_status:
                    problems.append("unexpected HTTP status")
                if method == "HEAD":
                    if body:
                        problems.append("unexpected HEAD body")
                elif len(body) > 65536 or json.loads(body) != expected:
                    problems.append("unexpected sealed response body")
                for name, value in {
                    "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff",
                    "Referrer-Policy": "no-referrer",
                    "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'; base-uri 'none'",
                }.items():
                    if response.headers.get(name) != value:
                        problems.append("unexpected " + name)
                if response.headers.get_content_type() != "application/json":
                    problems.append("unexpected Content-Type")
                check["passed"] = not problems
                if problems:
                    check["problems"] = problems
        except (OSError, ValueError) as error:
            check["passed"] = False
            check["error"] = type(error).__name__
        check["duration_ms"] = round((time.monotonic() - start) * 1000)
        report["checks"].append(check)
    report["passed"] = all(check["passed"] for check in report["checks"])
    print(json.dumps(report, indent=2, ensure_ascii=False))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
