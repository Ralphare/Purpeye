"""
PurpEye - CORS Misconfiguration Checker
Checks how the site handles Cross-Origin Resource Sharing (CORS).
A too-trusting CORS policy can let a malicious website read data
from this site on behalf of a logged-in visitor.

We ask the site (with a made-up 'Origin') and read how it answers.
This is passive - we send one ordinary request and inspect the reply.
Touches OWASP A05 (Misconfiguration) / A01 (Access Control).
"""

import requests
import json
from datetime import datetime


# A fake origin we use to see how the server responds to cross-origin requests.
TEST_ORIGIN = "https://purpeye-test-origin.example"


def check(target_url):
    result = {
        "check_name": "CORS Configuration",
        "owasp_id": "A05:2021",
        "timestamp": datetime.now().isoformat(),
        "target": target_url,
        "findings": [],
        "severity": "Info",
    }

    try:
        # Send our fake Origin header and see what the server allows.
        response = requests.get(target_url, timeout=10, allow_redirects=True,
                                headers={"Origin": TEST_ORIGIN})
    except requests.exceptions.RequestException as error:
        result["findings"].append({
            "issue": "Could not connect to the site",
            "detail": str(error),
            "severity": "Info",
            "fix": "Check that the website address is correct and the site is online.",
        })
        return result

    allow_origin = response.headers.get("Access-Control-Allow-Origin", "")
    allow_creds = response.headers.get("Access-Control-Allow-Credentials", "").lower()

    # --- Case 1: wildcard combined with credentials (worst case) ---
    if allow_origin == "*" and allow_creds == "true":
        result["findings"].append({
            "issue": "Dangerous CORS policy: wildcard with credentials",
            "detail": "The site allows any website to make credentialed requests to it, which can expose logged-in users' data.",
            "severity": "High",
            "fix": "Never combine 'Access-Control-Allow-Origin: *' with credentials. Allow only specific, trusted origins.",
        })

    # --- Case 2: the server reflects our arbitrary origin back ---
    elif allow_origin == TEST_ORIGIN:
        sev = "High" if allow_creds == "true" else "Medium"
        result["findings"].append({
            "issue": "CORS reflects arbitrary origins",
            "detail": "The site echoed back our test origin, meaning it may trust any website that asks - a common CORS mistake.",
            "severity": sev,
            "fix": "Validate the Origin against an allow-list of known sites instead of reflecting whatever is sent.",
        })

    # --- Case 3: wildcard without credentials (mild) ---
    elif allow_origin == "*":
        result["findings"].append({
            "issue": "CORS is open to all origins",
            "detail": "Any website can read this site's responses. This is only safe if none of the data is sensitive.",
            "severity": "Low",
            "fix": "If any responses contain private data, restrict CORS to specific trusted origins.",
        })

    # --- Otherwise: no problematic CORS seen ---
    else:
        result["findings"].append({
            "issue": "No risky CORS policy detected",
            "detail": "Good - the site does not appear to trust arbitrary external origins.",
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

