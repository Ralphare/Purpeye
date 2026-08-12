"""
PurpEye - HTTP to HTTPS Redirect Checker
Verifies that a site actually forces visitors onto HTTPS. A site can
have a perfect certificate yet still serve pages over plain HTTP if
asked - which quietly defeats the encryption. We request the http://
version and see whether the site redirects us to https://.

All passive: one ordinary request. Touches OWASP A02 (Cryptographic Failures).
"""

import requests
import json
from datetime import datetime
from urllib.parse import urlparse


def check(target_url):
    result = {
        "check_name": "HTTP to HTTPS Redirect",
        "owasp_id": "A02:2021",
        "timestamp": datetime.now().isoformat(),
        "target": target_url,
        "findings": [],
        "severity": "Info",
    }

    # Build the plain-HTTP version of the target's host to test it.
    host = urlparse(target_url).hostname
    if not host:
        result["findings"].append({
            "issue": "Could not read the site address",
            "detail": "The URL did not contain a recognizable hostname.",
            "severity": "Info",
            "fix": "Provide a full address like https://example.com.",
        })
        return result

    http_url = f"http://{host}"

    try:
        # Don't follow redirects yet - we want to SEE the redirect itself
        resp = requests.get(http_url, timeout=10, allow_redirects=False) # nosemgrep: python.lang.security.audit.insecure-transport.requests.request-with-http.request-with-http
    except requests.exceptions.RequestException as error:
        # If plain HTTP refuses to connect at all, that's actually good -
        # it means the site isn't serving anything over HTTP.
        result["findings"].append({
            "issue": "Plain HTTP is not served",
            "detail": "Good - the site did not respond over unencrypted HTTP at all.",
            "severity": "Info",
            "fix": "",
        })
        result["severity"] = "Info"
        return result

    location = resp.headers.get("Location", "")

    # --- Redirect to HTTPS? That's what we want ---
    if resp.status_code in (301, 302, 307, 308) and location.startswith("https://"):
        result["findings"].append({
            "issue": "HTTP correctly redirects to HTTPS",
            "detail": "Good - visitors who arrive over HTTP are sent to the secure version.",
            "severity": "Info",
            "fix": "",
        })
    # --- Redirects, but to another HTTP page ---
    elif resp.status_code in (301, 302, 307, 308) and location.startswith("http://"):
        result["findings"].append({
            "issue": "HTTP redirects, but not to HTTPS",
            "detail": "The site redirects HTTP visitors to another unencrypted page instead of the secure version.",
            "severity": "Medium",
            "fix": "Change the redirect so all HTTP requests are sent to the https:// version of the site.",
        })
    # --- Serves content over HTTP with no redirect (200 OK) ---
    elif resp.status_code == 200:
        result["findings"].append({
            "issue": "Site serves content over plain HTTP",
            "detail": "The site returns pages over unencrypted HTTP without forcing HTTPS, so traffic can be read or altered.",
            "severity": "High",
            "fix": "Configure the server to redirect all HTTP traffic to HTTPS, and enable HSTS.",
        })
    else:
        result["findings"].append({
            "issue": "HTTP did not clearly redirect to HTTPS",
            "detail": f"The HTTP version returned status {resp.status_code} without a secure redirect.",
            "severity": "Low",
            "fix": "Ensure HTTP requests return a redirect to the https:// version of the site.",
        })

    order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
    worst = min(result["findings"], key=lambda f: order.get(f["severity"], 4))
    result["severity"] = worst["severity"]

    return result


if __name__ == "__main__":
    import sys
    url = sys.argv[1] if len(sys.argv) > 1 else "https://example.com"
    print(f"[PurpEye] Checking {url} ...\n")
    print(json.dumps(check(url), indent=2))

