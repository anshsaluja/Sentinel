#!/usr/bin/env python3
"""Read-only approval API smoke probe. Never prints access tokens or response bodies."""
import argparse
import os
import sys
import urllib.error
import urllib.parse
import urllib.request


def probe(base_url: str, token: str | None, timeout: float = 5.0) -> list[str]:
    parsed = urllib.parse.urlsplit(base_url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError("Base URL must be an absolute HTTP(S) URL")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("Base URL must not contain credentials, query, or fragment")
    if parsed.scheme == "http" and parsed.hostname not in ("localhost", "127.0.0.1", "::1"):
        raise ValueError("Plain HTTP is allowed only for loopback hosts")
    if parsed.path not in ("", "/"):
        raise ValueError("Base URL must not include a path")
    if token and ("\r" in token or "\n" in token):
        raise ValueError("Access token contains invalid line breaks")
    if timeout <= 0:
        raise ValueError("Timeout must be positive")
    endpoint = urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, "/api/v1/approvals/pending", "", ""))
    results = []

    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            raise RuntimeError("Approval endpoint redirected unexpectedly")

    opener = urllib.request.build_opener(NoRedirect)

    def get(bearer: str | None) -> int:
        headers = {"Accept": "application/json"}
        if bearer:
            headers["Authorization"] = "Bearer " + bearer
        request = urllib.request.Request(endpoint, headers=headers, method="GET")
        try:
            with opener.open(request, timeout=timeout) as response:
                response.read(1024)  # Bound reads; do not expose tenant data.
                if bearer and response.status == 200:
                    media_type = response.headers.get_content_type()
                    if media_type != "application/json":
                        raise RuntimeError("Authenticated approval queue did not return JSON")
                return response.status
        except urllib.error.HTTPError as error:
            error.close()
            return error.code

    anonymous = get(None)
    if anonymous not in (401, 403):
        raise RuntimeError(f"Anonymous approval queue returned {anonymous}, expected 401/403")
    results.append(f"Anonymous approval queue denied ({anonymous})")

    if token:
        authenticated = get(token)
        if authenticated != 200:
            raise RuntimeError(
                f"Authenticated reviewer approval queue returned {authenticated}, expected 200"
            )
        results.append("Authenticated reviewer approval queue returned 200")
    else:
        results.append("Authenticated probe skipped (SENTINEL_REVIEWER_TOKEN unset)")
    return results


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", default="http://127.0.0.1:8080")
    args = parser.parse_args()
    try:
        for result in probe(args.base_url, os.environ.get("SENTINEL_REVIEWER_TOKEN")):
            print(result)
        return 0
    except (ValueError, RuntimeError, urllib.error.URLError, TimeoutError) as error:
        print(f"Smoke probe failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
