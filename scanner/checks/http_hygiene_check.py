"""
PurpEye - HTTP Methods & Web Hygiene Checker
Looks at a few quick, passive signals of good (or poor) web hygiene:
  - Which HTTP methods the server allows (risky ones like PUT/DELETE/TRACE)
  - Whether the homepage over HTTPS pulls in insecure HTTP resources
    (mixed content), which weakens the encryption
  - Whether robots.txt accidentally advertises sensitive paths
  - Whether a security.txt file exists (a sign of security maturity)

All passive: we only make ordinary requests any visitor could make.
Touches OWASP A05 (Misconfiguration).
"""

import requests
import json
import re
from datetime import datetime
from urllib.parse import urljoin


RISKY_METHODS = {"PUT", "DELETE", "TRACE", "CONNECT", "PATCH"}

# Words in robots.txt that hint at sensitive areas being advertised.
SENSITIVE_HINTS = ["admin", "login", "backup", "config", "private", "secret", "db", "sql"]


def check(target_url):
    result = {
        "check_name": "HTTP Methods & Web Hygiene",
        "owasp_id": "A05:2021",
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

    any_issue = False

    # --- Check 1: allowed HTTP methods (via OPTIONS request) ---
    try:
        options = requests.options(target_url, timeout=8)
        allowed = options.headers.get("Allow", "")
        if allowed:
            found_risky = [m for m in RISKY_METHODS if m in allowed.upper()]
            if found_risky:
                any_issue = True
                result["findings"].append({
                    "issue": f"Risky HTTP methods enabled: {', '.join(found_risky)}",
                    "detail": "These methods can allow changes to the server if not tightly controlled and are rarely needed on a public site.",
                    "severity": "Medium",
                    "fix": "Disable HTTP methods you don't use (typically only GET, POST, and HEAD are needed).",
                })
    except requests.exceptions.RequestException:
        pass

    # --- Check 2: mixed content (HTTPS page loading HTTP resources) ---
    if target_url.startswith("https://"):
        # Look for http:// resources referenced in src= or href= attributes.
        insecure_refs = re.findall(r'(?:src|href)=["\'](http://[^"\']+)["\']', response.text)
        if insecure_refs:
            any_issue = True
            example = insecure_refs[0][:60]
            result["findings"].append({
                "issue": f"Mixed content: {len(insecure_refs)} insecure resource(s) loaded",
                "detail": f"The secure page loads content over plain HTTP (e.g. {example}...), which undermines the encryption.",
                "severity": "Medium",
                "fix": "Update all resource links on the page to use https:// instead of http://.",
            })

    # --- Check 3: robots.txt advertising sensitive paths ---
    try:
        robots = requests.get(urljoin(target_url, "/robots.txt"), timeout=8)
        if robots.status_code == 200:
            exposed = [w for w in SENSITIVE_HINTS if w in robots.text.lower()]
            if exposed:
                any_issue = True
                result["findings"].append({
                    "issue": "robots.txt hints at sensitive areas",
                    "detail": f"robots.txt mentions paths like: {', '.join(exposed)}. This file is public and can point attackers toward interesting areas.",
                    "severity": "Low",
                    "fix": "Avoid listing sensitive paths in robots.txt; protect them with real access controls instead.",
                })
    except requests.exceptions.RequestException:
        pass

    # --- Check 4: security.txt presence (a positive maturity signal) ---
    try:
        sectxt = requests.get(urljoin(target_url, "/.well-known/security.txt"), timeout=8)
        if sectxt.status_code == 200 and len(sectxt.text.strip()) > 0:
            result["findings"].append({
                "issue": "security.txt is present",
                "detail": "Good - the site publishes a security contact file, a sign of security awareness.",
                "severity": "Info",
                "fix": "",
            })
    except requests.exceptions.RequestException:
        pass

    if not any_issue:
        # Only add the all-clear if we didn't already add a positive note.
        if not result["findings"]:
            result["findings"].append({
                "issue": "No web hygiene issues found",
                "detail": "Good - no risky methods, mixed content, or leaky robots.txt detected.",
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

