"""
PurpEye - Email Security Records Checker
Checks whether the domain publishes the DNS records that stop
criminals sending fake emails that appear to come from it:
SPF (who may send) and DMARC (what to do with fakes). Missing
these makes a business easy to impersonate in phishing.

We look these up over DNS. This is passive - public record lookups.
Touches OWASP A05 (Misconfiguration) / email spoofing risk.
"""

import json
import socket
from datetime import datetime
from urllib.parse import urlparse


def _dns_txt(hostname):
    """
    Fetch TXT records for a hostname using dnspython if available,
    otherwise fall back to nslookup via the system. Returns a list
    of strings (may be empty).
    """
    # Preferred: dnspython (clean and reliable).
    try:
        import dns.resolver
        answers = dns.resolver.resolve(hostname, "TXT")
        return [b"".join(r.strings).decode(errors="ignore") if hasattr(r, "strings")
                else str(r).strip('"') for r in answers]
    except ImportError:
        pass
    except Exception:
        return []

    # Fallback: shell out to nslookup (present on most systems).
    try:
        import subprocess
        out = subprocess.run(["nslookup", "-type=TXT", hostname],
                             capture_output=True, text=True, timeout=10)
        lines = [l for l in out.stdout.splitlines() if "text =" in l or "\t\"" in l]
        return lines
    except Exception:
        return []


def check(target_url):
    result = {
        "check_name": "Email Security Records",
        "owasp_id": "A05:2021",
        "timestamp": datetime.now().isoformat(),
        "target": target_url,
        "findings": [],
        "severity": "Info",
    }

    host = urlparse(target_url).hostname or target_url
    # Strip a leading 'www.' to check the root domain.
    domain = host[4:] if host.startswith("www.") else host

    # --- SPF: published as a TXT record on the domain itself ---
    root_txt = _dns_txt(domain)
    has_spf = any("v=spf1" in t.lower() for t in root_txt)

    if has_spf:
        result["findings"].append({
            "issue": "SPF record is present",
            "detail": "Good - the domain declares which servers may send its email.",
            "severity": "Info",
            "fix": "",
        })
    else:
        result["findings"].append({
            "issue": "No SPF record found",
            "detail": "Without SPF, attackers can more easily send email that appears to come from this domain.",
            "severity": "Medium",
            "fix": "Publish an SPF TXT record listing your authorized mail servers (e.g. 'v=spf1 include:_spf.yourprovider.com ~all').",
        })

    # --- DMARC: published as a TXT record at _dmarc.<domain> ---
    dmarc_txt = _dns_txt(f"_dmarc.{domain}")
    has_dmarc = any("v=dmarc1" in t.lower() for t in dmarc_txt)

    if has_dmarc:
        result["findings"].append({
            "issue": "DMARC record is present",
            "detail": "Good - the domain tells receiving servers how to handle fake email claiming to be from it.",
            "severity": "Info",
            "fix": "",
        })
    else:
        result["findings"].append({
            "issue": "No DMARC record found",
            "detail": "Without DMARC, there are no instructions for rejecting forged emails using this domain.",
            "severity": "Medium",
            "fix": "Publish a DMARC TXT record at _dmarc.yourdomain (start with 'v=DMARC1; p=none' to monitor, then tighten).",
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

