"""
PurpEye - TLS / Certificate Quality Checker
Inspects the site's HTTPS certificate: is it valid, not expired,
and issued for the right host, and is the connection using a modern
protocol version. A broken or expiring certificate quietly erodes
trust and can break the site for visitors.

All passive: we make a normal HTTPS connection and read the
certificate the server presents. Touches OWASP A02 (Cryptographic Failures).
"""

import json
import ssl
import socket
from datetime import datetime
from urllib.parse import urlparse


def check(target_url):
    result = {
        "check_name": "TLS & Certificate Quality",
        "owasp_id": "A02:2021",
        "timestamp": datetime.now().isoformat(),
        "target": target_url,
        "findings": [],
        "severity": "Info",
    }

    parsed = urlparse(target_url)
    host = parsed.hostname
    port = parsed.port or 443

    # If the site isn't https, there's no certificate to check.
    if parsed.scheme != "https":
        result["findings"].append({
            "issue": "Site is not served over HTTPS",
            "detail": "There is no TLS certificate to evaluate because the site is not using HTTPS.",
            "severity": "High",
            "fix": "Enable HTTPS with a valid certificate (free options are available via Let's Encrypt).",
        })
        result["severity"] = "High"
        return result

    # Open a secure connection and read the certificate the server presents.
    context = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                protocol = ssock.version()
    except ssl.SSLCertVerificationError as error:
        # The certificate itself failed validation - a real problem.
        result["findings"].append({
            "issue": "Certificate failed validation",
            "detail": f"The browser would warn visitors about this site. Reason: {error.verify_message if hasattr(error, 'verify_message') else str(error)}",
            "severity": "High",
            "fix": "Reinstall a valid certificate that matches the domain and is signed by a trusted authority.",
        })
        result["severity"] = "High"
        return result
    except (socket.timeout, socket.gaierror, ConnectionRefusedError, OSError) as error:
        result["findings"].append({
            "issue": "Could not establish a secure connection",
            "detail": str(error),
            "severity": "Info",
            "fix": "Check that the site is online and reachable over HTTPS.",
        })
        return result

    any_issue = False

    # --- Check certificate expiry ---
    not_after = cert.get("notAfter")
    if not_after:
        # Certificate dates look like 'Jun 10 12:00:00 2026 GMT'
        expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
        days_left = (expiry - datetime.now()).days

        if days_left < 0:
            any_issue = True
            result["findings"].append({
                "issue": "Certificate has EXPIRED",
                "detail": f"The certificate expired {abs(days_left)} day(s) ago. Visitors will see a security warning.",
                "severity": "High",
                "fix": "Renew the TLS certificate immediately.",
            })
        elif days_left < 15:
            any_issue = True
            result["findings"].append({
                "issue": "Certificate expires very soon",
                "detail": f"Only {days_left} day(s) left before the certificate expires.",
                "severity": "Medium",
                "fix": "Renew the certificate now, and set up auto-renewal to avoid outages.",
            })
        elif days_left < 30:
            any_issue = True
            result["findings"].append({
                "issue": "Certificate expiring within a month",
                "detail": f"{days_left} day(s) left before expiry.",
                "severity": "Low",
                "fix": "Plan to renew soon; consider enabling automatic renewal.",
            })
        else:
            result["findings"].append({
                "issue": "Certificate is valid and current",
                "detail": f"Good - {days_left} day(s) remaining before renewal is needed.",
                "severity": "Info",
                "fix": "",
            })

    # --- Check protocol version ---
    # TLS 1.0 and 1.1 are outdated and considered insecure.
    if protocol in ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2"):
        any_issue = True
        result["findings"].append({
            "issue": f"Outdated encryption protocol in use ({protocol})",
            "detail": "This protocol version is old and has known weaknesses.",
            "severity": "Medium",
            "fix": "Configure the server to require TLS 1.2 or TLS 1.3 and disable older versions.",
        })
    else:
        result["findings"].append({
            "issue": f"Modern encryption protocol in use ({protocol})",
            "detail": "Good - the connection uses a current, secure protocol version.",
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

