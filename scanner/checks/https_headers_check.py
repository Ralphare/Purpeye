"""
PurpEye - Security Headers & HTTPS Checker
Checks a website for HTTPS usage, important security headers,
and secure cookie settings. Each finding includes a plain-English
fix. Maps to OWASP A02 (Cryptographic Failures) and A05.
"""

import requests
import json
from datetime import datetime


# Each header: why it matters, and how to fix it if missing.
IMPORTANT_HEADERS = {
    "Strict-Transport-Security": {
        "why": "Forces browsers to always use HTTPS, preventing downgrade attacks.",
        "fix": "Ask whoever manages your website to add the 'Strict-Transport-Security' header (a one-line server setting).",
    },
    "Content-Security-Policy": {
        "why": "Controls what content can load, preventing many injection attacks.",
        "fix": "Add a 'Content-Security-Policy' header. Start in report-only mode so it doesn't break anything, then tighten it.",
    },
    "X-Frame-Options": {
        "why": "Stops your site being embedded in others (clickjacking protection).",
        "fix": "Add the header 'X-Frame-Options: SAMEORIGIN' on your web server.",
    },
    "X-Content-Type-Options": {
        "why": "Stops browsers guessing file types, closing a class of attacks.",
        "fix": "Add the header 'X-Content-Type-Options: nosniff' on your web server.",
    },
    "Referrer-Policy": {
        "why": "Controls how much address info leaks when users click links away.",
        "fix": "Add a 'Referrer-Policy' header, e.g. 'strict-origin-when-cross-origin'.",
    },
}


def check(target_url):
    result = {
        "check_name": "HTTPS & Security Headers",
        "owasp_id": "A02/A05:2021",
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

    # Check 1: HTTPS
    if response.url.startswith("https://"):
        result["findings"].append({
            "issue": "Site uses HTTPS",
            "detail": "Good - traffic is encrypted.",
            "severity": "Info",
            "fix": "",
        })
    else:
        result["findings"].append({
            "issue": "Site does NOT use HTTPS",
            "detail": "Traffic is unencrypted and can be read or modified by attackers.",
            "severity": "High",
            "fix": "Install an SSL certificate (many hosts offer free ones via Let's Encrypt) and redirect all traffic to HTTPS.",
        })

    # Check 2: security headers
    for header_name, info in IMPORTANT_HEADERS.items():
        if header_name in response.headers:
            result["findings"].append({
                "issue": f"Header present: {header_name}",
                "detail": "Good - this protection is enabled.",
                "severity": "Info",
                "fix": "",
            })
        else:
            # Special case: X-Frame-Options can be replaced by the modern
            # CSP 'frame-ancestors' directive. If that's present, the site
            # is still protected against clickjacking, so don't flag it.
            if header_name == "X-Frame-Options":
                csp = response.headers.get("Content-Security-Policy", "").lower()
                if "frame-ancestors" in csp:
                    result["findings"].append({
                        "issue": "Clickjacking protection via CSP frame-ancestors",
                        "detail": "Good - the site uses the modern 'frame-ancestors' directive instead of X-Frame-Options.",
                        "severity": "Info",
                        "fix": "",
                    })
                    continue
            result["findings"].append({
                "issue": f"Missing header: {header_name}",
                "detail": info["why"],
                "severity": "Medium",
                "fix": info["fix"],
            })

    # Check 3: cookies
    for cookie in response.cookies:
        if not cookie.secure:
            result["findings"].append({
                "issue": f"Cookie '{cookie.name}' missing Secure flag",
                "detail": "This cookie can be sent over unencrypted connections.",
                "severity": "Medium",
                "fix": "Set the 'Secure' flag on cookies so they are only sent over HTTPS.",
            })

    severities = [f["severity"] for f in result["findings"]]
    if "High" in severities:
        result["severity"] = "High"
    elif "Medium" in severities:
        result["severity"] = "Medium"
    else:
        result["severity"] = "Info"

    return result


if __name__ == "__main__":
    import sys
    url = sys.argv[1] if len(sys.argv) > 1 else "https://example.com"
    print(f"[PurpEye] Checking {url} ...\n")
    print(json.dumps(check(url), indent=2))

