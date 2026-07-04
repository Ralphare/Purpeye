"""
PurpEye - Cookie & Session Security Checker
Examines the cookies a site sets and checks whether they carry the
flags that keep sessions safe: Secure, HttpOnly, and SameSite.
Weak cookie settings are a common, quietly serious problem - they
can let attackers steal sessions or ride along with user requests.

All passive: we only read the cookies the site hands us. Touches
OWASP A05 (Misconfiguration) and A07 (Auth/Session failures).
"""

import requests
import json
from datetime import datetime


def check(target_url):
    result = {
        "check_name": "Cookie & Session Security",
        "owasp_id": "A05/A07:2021",
        "timestamp": datetime.now().isoformat(),
        "target": target_url,
        "findings": [],
        "severity": "Info",
    }

    try:
        response = requests.get(target_url, timeout=10, allow_redirects=True)
    except requests.exceptions.RequestException as error:
        result["findings"].append({
            "issue": "Could not connect to the site",
            "detail": str(error),
            "severity": "Info",
            "fix": "Check that the website address is correct and the site is online.",
        })
        return result

    # If the site sets no cookies, there's nothing to check - note it and stop.
    cookies = list(response.cookies)
    if not cookies:
        result["findings"].append({
            "issue": "No cookies set on the homepage",
            "detail": "Nothing to review here - the homepage did not set any cookies.",
            "severity": "Info",
            "fix": "",
        })
        result["severity"] = "Info"
        return result

    # We look at the raw Set-Cookie headers too, because the SameSite
    # attribute isn't always exposed through the parsed cookie object.
    raw_set_cookie = response.headers.get("Set-Cookie", "")

    any_issue = False
    for cookie in cookies:
        name = cookie.name

        # --- Secure flag: cookie should only travel over HTTPS ---
        if not cookie.secure:
            any_issue = True
            result["findings"].append({
                "issue": f"Cookie '{name}' missing the Secure flag",
                "detail": "Without 'Secure', this cookie can be sent over unencrypted connections where it may be intercepted.",
                "severity": "Medium",
                "fix": f"Set the 'Secure' attribute on the '{name}' cookie so it is only sent over HTTPS.",
            })

        # --- HttpOnly flag: cookie should be hidden from JavaScript ---
        # (helps stop stolen sessions via cross-site scripting)
        has_httponly = cookie.has_nonstandard_attr("HttpOnly") or cookie.has_nonstandard_attr("httponly")
        if not has_httponly:
            any_issue = True
            result["findings"].append({
                "issue": f"Cookie '{name}' missing the HttpOnly flag",
                "detail": "Without 'HttpOnly', scripts on the page can read this cookie, making session theft easier if the site is ever compromised by injected code.",
                "severity": "Medium",
                "fix": f"Set the 'HttpOnly' attribute on the '{name}' cookie so browser scripts cannot read it.",
            })

        # --- SameSite attribute: limits cross-site sending (CSRF defense) ---
        samesite = cookie.get_nonstandard_attr("SameSite") or cookie.get_nonstandard_attr("samesite")
        if not samesite and "samesite" not in raw_set_cookie.lower():
            any_issue = True
            result["findings"].append({
                "issue": f"Cookie '{name}' has no SameSite attribute",
                "detail": "Without 'SameSite', this cookie may be sent on requests from other sites, which can enable cross-site request forgery.",
                "severity": "Low",
                "fix": f"Add 'SameSite=Lax' (or 'Strict') to the '{name}' cookie.",
            })

    if not any_issue:
        result["findings"].append({
            "issue": "Cookies are configured securely",
            "detail": "Good - the cookies reviewed carry appropriate security flags.",
            "severity": "Info",
            "fix": "",
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

