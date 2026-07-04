"""
PurpEye - Information Leakage Checker
Scans the page's own content for information that shouldn't be public:
verbose error messages, developer comments left in the HTML, internal
paths, and exposed email addresses. Attackers harvest these to learn
about the site and its people.

All passive: we only read the page as any visitor would.
Touches OWASP A05 (Misconfiguration) / information exposure.
"""

import requests
import json
import re
from datetime import datetime


# Signs of a verbose error or debug output being shown to visitors.
ERROR_SIGNATURES = [
    "stack trace", "traceback (most recent call last)", "fatal error",
    "warning: mysql", "sql syntax", "unhandled exception",
    "on line", "in /var/www", "in /home/", "notice: undefined",
    "microsoft ole db", "odbc drivers error",
]


def check(target_url):
    result = {
        "check_name": "Information Leakage",
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

    page = response.text
    page_lower = page.lower()
    any_issue = False

    # --- Verbose error / debug messages visible on the page ---
    for sig in ERROR_SIGNATURES:
        if sig in page_lower:
            any_issue = True
            result["findings"].append({
                "issue": "Verbose error or debug output visible",
                "detail": f"The page contains error-like text ('{sig}'), which can reveal internal details to attackers.",
                "severity": "Medium",
                "fix": "Turn off detailed error messages in production and show a generic error page instead.",
            })
            break  # one finding is enough

    # --- Developer comments left in the HTML ---
    comments = re.findall(r"<!--(.*?)-->", page, re.DOTALL)
    suspicious_comments = [
        c for c in comments
        if re.search(r"(todo|fixme|password|api[_-]?key|debug|remove|hack|temporary)", c, re.IGNORECASE)
    ]
    if suspicious_comments:
        any_issue = True
        result["findings"].append({
            "issue": f"Revealing developer comment(s) in the page source",
            "detail": "The HTML contains comments that mention things like TODO, debug, or credentials. Anyone can read page source.",
            "severity": "Low",
            "fix": "Remove developer comments from the HTML that ships to visitors.",
        })

    # --- Internal file paths disclosed ---
    if re.search(r"[A-Za-z]:\\\\(?:inetpub|xampp|wwwroot)", page) or re.search(r"/var/www/|/home/\w+/", page):
        any_issue = True
        result["findings"].append({
            "issue": "Internal server path disclosed",
            "detail": "The page reveals a file path from the server's filesystem, which helps attackers map the system.",
            "severity": "Low",
            "fix": "Prevent full file paths from appearing in page output or error messages.",
        })

    # --- Exposed email addresses (privacy / phishing target) ---
    emails = set(re.findall(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", page))
    # Ignore common false positives like example@ or image filenames.
    real_emails = {e for e in emails if not e.lower().endswith((".png", ".jpg", ".gif", ".svg"))}
    if len(real_emails) > 0:
        any_issue = True
        sample = ", ".join(list(real_emails)[:3])
        result["findings"].append({
            "issue": f"{len(real_emails)} email address(es) exposed in the page",
            "detail": f"Addresses like {sample} are visible in the page and can be harvested for phishing or spam.",
            "severity": "Low",
            "fix": "Consider a contact form instead of publishing raw email addresses, or obfuscate them.",
        })

    if not any_issue:
        result["findings"].append({
            "issue": "No obvious information leakage found",
            "detail": "Good - no verbose errors, revealing comments, internal paths, or exposed emails detected.",
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

