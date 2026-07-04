"""
PurpEye - Software Version & Outdated Components Checker
Fingerprints the software a website runs and flags version disclosure.
Each finding includes a plain-English fix.
Maps to OWASP A06:2021 (Vulnerable and Outdated Components).
"""

import requests
import json
import re
from datetime import datetime


VERSION_LEAKING_HEADERS = ["Server", "X-Powered-By", "X-AspNet-Version", "X-Generator"]
VERSION_PATTERN = re.compile(r"\d+\.\d+(\.\d+)?")

HIDE_VERSION_FIX = (
    "Configure your web server to hide software names and versions "
    "(Apache: 'ServerTokens Prod'; nginx: 'server_tokens off;'), and keep "
    "the software itself updated to the latest version."
)


def check(target_url):
    result = {
        "check_name": "Software Version & Outdated Components",
        "owasp_id": "A06:2021",
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

    found_any = False
    for header_name in VERSION_LEAKING_HEADERS:
        if header_name in response.headers:
            value = response.headers[header_name]
            found_any = True
            if VERSION_PATTERN.search(value):
                result["findings"].append({
                    "issue": f"Software version exposed via '{header_name}' header",
                    "detail": f"The site reveals '{value}'. Attackers use this to look up known vulnerabilities (CVEs) for that exact version.",
                    "severity": "Medium",
                    "fix": HIDE_VERSION_FIX,
                })
            else:
                result["findings"].append({
                    "issue": f"Software disclosed via '{header_name}' header",
                    "detail": f"The site reveals it runs '{value}'. No version shown, but naming the software still helps attackers.",
                    "severity": "Low",
                    "fix": HIDE_VERSION_FIX,
                })

    generator_match = re.search(
        r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']',
        response.text, re.IGNORECASE)
    if generator_match:
        gen = generator_match.group(1)
        found_any = True
        sev = "Medium" if VERSION_PATTERN.search(gen) else "Low"
        result["findings"].append({
            "issue": "Software disclosed via HTML generator tag",
            "detail": f"The page's HTML reveals '{gen}', exposing the content system and often its version.",
            "severity": sev,
            "fix": "Remove or disable the 'generator' meta tag in your website's settings or theme, and keep the platform updated.",
        })

    if not found_any:
        result["findings"].append({
            "issue": "No obvious software version disclosure",
            "detail": "Good - the site does not openly advertise its software versions.",
            "severity": "Info",
            "fix": "",
        })

    severities = [f["severity"] for f in result["findings"]]
    if "High" in severities:
        result["severity"] = "High"
    elif "Medium" in severities:
        result["severity"] = "Medium"
    elif "Low" in severities:
        result["severity"] = "Low"
    else:
        result["severity"] = "Info"

    return result


if __name__ == "__main__":
    import sys
    url = sys.argv[1] if len(sys.argv) > 1 else "https://example.com"
    print(f"[PurpEye] Checking {url} ...\n")
    print(json.dumps(check(url), indent=2))
