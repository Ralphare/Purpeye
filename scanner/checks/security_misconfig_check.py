"""
PurpEye - Security Misconfiguration Checker
Looks for exposed admin panels, directory listing, and leftover
sensitive files. Each finding includes a plain-English fix.
All checks are passive. Maps to OWASP A05:2021.
"""

import requests
import json
from datetime import datetime
from urllib.parse import urljoin


# path, friendly name, severity, why it matters, how to fix
SENSITIVE_PATHS = [
    ("/.env", "Environment file (.env)", "High",
     "May contain passwords, API keys, and database credentials.",
     "Block public access to '.env' on your server and move secrets out of the web root immediately."),
    ("/.git/config", "Git repository (.git)", "High",
     "Exposes source code and its full history to anyone.",
     "Deny web access to the '.git' folder in your server config, or remove it from the web root."),
    ("/admin", "Admin panel", "Medium",
     "Admin login exposed; a target for password guessing.",
     "Restrict the admin area by IP, add strong login protection, and consider a non-obvious URL."),
    ("/phpinfo.php", "PHP info page", "Medium",
     "Reveals server configuration details useful to attackers.",
     "Delete the phpinfo.php file from your server - it should never be public."),
    ("/backup.zip", "Backup archive", "High",
     "A downloadable backup can hand over your whole site.",
     "Remove backup files from the web root and store backups somewhere not publicly reachable."),
    ("/.htaccess", "Server config (.htaccess)", "Low",
     "Server configuration file should not be directly readable.",
     "Ensure your server blocks direct access to '.htaccess' files (most do by default - verify)."),
    ("/server-status", "Apache server-status", "Medium",
     "Exposes live server activity and visitor details.",
     "Restrict '/server-status' to localhost only in your Apache configuration."),
]


def check(target_url):
    result = {
        "check_name": "Security Misconfiguration",
        "owasp_id": "A05:2021",
        "timestamp": datetime.now().isoformat(),
        "target": target_url,
        "findings": [],
        "severity": "Info",
    }

    try:
        requests.get(target_url, timeout=10)
    except requests.exceptions.RequestException as error:
        result["findings"].append({
            "issue": "Could not connect to the site",
            "detail": str(error),
            "severity": "Info",
            "fix": "Check that the website address is correct and the site is online.",
        })
        return result

    found = False

    try:
        home = requests.get(target_url, timeout=10)
        if "Index of /" in home.text and "<title>Index of" in home.text:
            found = True
            result["findings"].append({
                "issue": "Directory listing is enabled",
                "detail": "The server shows a raw list of files instead of a web page, exposing its structure.",
                "severity": "Medium",
                "fix": "Turn off directory listing (Apache: 'Options -Indexes'; nginx: remove 'autoindex on;').",
            })
    except requests.exceptions.RequestException:
        pass

    for path, name, severity, why, fix in SENSITIVE_PATHS:
        full_url = urljoin(target_url, path)
        try:
            resp = requests.get(full_url, timeout=8, allow_redirects=False)
        except requests.exceptions.RequestException:
            continue
        if resp.status_code == 200 and len(resp.content) > 0:
            found = True
            result["findings"].append({
                "issue": f"Exposed: {name}",
                "detail": f"{why} Found at {path}.",
                "severity": severity,
                "fix": fix,
            })

    if not found:
        result["findings"].append({
            "issue": "No common misconfigurations found",
            "detail": "Good - no exposed admin panels, config files, or directory listings detected.",
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

