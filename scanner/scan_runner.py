"""
PurpEye - Scan Runner & Risk Scoring Engine
Runs every security check against one target, combines all their
findings into a single result, and calculates one overall
risk score from 0 (dangerous) to 100 (excellent).

This is the piece that turns separate checks into one product:
one command in, one clear score out.
"""

import json
import sys
from datetime import datetime

# Import the checks we have built so far.
# To add a new check later, import it here and add it to the CHECKS list below.
from checks import https_headers_check
from checks import software_version_check
from checks import security_misconfig_check
from checks import cookie_session_check
from checks import tls_certificate_check
from checks import http_hygiene_check
from checks import info_leakage_check
from checks import cors_check
from checks import email_security_check
from checks import https_redirect_check


# The list of all checks PurpEye will run.
# Each entry is a module that has a check(url) function returning our
# standard result format. Adding a new check = adding one line here.
CHECKS = [
    https_headers_check,
    https_redirect_check,
    software_version_check,
    security_misconfig_check,
    cookie_session_check,
    tls_certificate_check,
    http_hygiene_check,
    info_leakage_check,
    cors_check,
    email_security_check,
]


# How many points each severity level subtracts from a perfect score of 100.
# Critical hurts a lot; Info doesn't hurt at all.
SEVERITY_PENALTY = {
    "Critical": 40,
    "High": 25,
    "Medium": 10,
    "Low": 3,
    "Info": 0,
}


def calculate_score(all_findings):
    """
    Start at 100 and subtract penalties for every real problem found.
    Never go below 0. Returns an integer score.
    """
    score = 100
    for finding in all_findings:
        penalty = SEVERITY_PENALTY.get(finding["severity"], 0)
        score -= penalty

    if score < 0:
        score = 0
    return score


def score_to_rating(score):
    """Turn a number into a plain-English rating a business owner understands."""
    if score >= 85:
        return "Good"
    elif score >= 60:
        return "Needs attention"
    elif score >= 35:
        return "At risk"
    else:
        return "Critical - act now"


def run_scan(target_url):
    """
    Run every check against the target, gather all findings,
    calculate the score, and return one combined result.
    """
    print(f"[PurpEye] Starting full scan of {target_url}\n")

    combined = {
        "target": target_url,
        "scan_time": datetime.now().isoformat(),
        "checks_run": [],
        "all_findings": [],
        "risk_score": 100,
        "rating": "Good",
    }

    # Run each check one by one.
    for check_module in CHECKS:
        check_name = check_module.__name__.split(".")[-1]
        print(f"  Running {check_name} ...")

        result = check_module.check(target_url)

        # Record that this check ran and what its own severity was.
        combined["checks_run"].append({
            "check": result["check_name"],
            "owasp_id": result["owasp_id"],
            "severity": result["severity"],
        })

        # Add this check's findings to the master list, tagging each
        # with which check produced it (useful for the report later).
        for finding in result["findings"]:
            finding_with_source = dict(finding)
            finding_with_source["source_check"] = result["check_name"]
            combined["all_findings"].append(finding_with_source)

    # Now that we have every finding, calculate the overall score.
    combined["risk_score"] = calculate_score(combined["all_findings"])
    combined["rating"] = score_to_rating(combined["risk_score"])

    print(f"\n[PurpEye] Scan complete. Risk score: {combined['risk_score']}/100 ({combined['rating']})\n")
    return combined


if __name__ == "__main__":
    url = sys.argv[1] if len(sys.argv) > 1 else "https://example.com"
    outcome = run_scan(url)
    print(json.dumps(outcome, indent=2))
