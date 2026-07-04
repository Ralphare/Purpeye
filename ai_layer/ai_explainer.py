"""
PurpEye - AI Explainer
Takes the raw scan results (JSON) and turns them into a clear,
plain-English summary a non-technical business owner can understand:
what's wrong, how serious it is, and what to fix first.

Two modes:
  - REAL mode: if an Anthropic API key is set, it asks Claude to write
    an intelligent, tailored summary.
  - FREE fallback mode: if there is no API key, it builds a solid
    plain-English summary locally, for free, with no API call.

The rest of PurpEye doesn't care which mode ran - it always gets
a summary back. Add a key later and it upgrades automatically.
"""

import os
import json


def explain(scan_result):
    """
    Main entry point. Decides which mode to use based on whether
    an API key is available, and returns a plain-English summary string.
    """
    api_key = os.environ.get("ANTHROPIC_API_KEY")

    if api_key:
        try:
            return _explain_with_claude(scan_result, api_key)
        except Exception as error:
            # If the API call fails for any reason, we don't crash the
            # whole scan - we fall back to the free local summary.
            print(f"[PurpEye] AI call failed ({error}); using offline summary.")
            return _explain_offline(scan_result)
    else:
        # No key set - use the free local summary.
        return _explain_offline(scan_result)


def _explain_with_claude(scan_result, api_key):
    """
    REAL mode. Sends the scan results to Claude and returns its
    plain-English explanation. Only runs if a key is present.
    """
    # We import here so the library is only needed when actually using AI.
    import anthropic

    client = anthropic.Anthropic(api_key=api_key)

    prompt = f"""You are a friendly cybersecurity advisor helping a small business
owner who knows nothing about technical security. Below are the results of an
automated security scan of their website, in JSON.

Write a clear, calm, plain-English summary that:
1. States the overall risk in one sentence (score is {scan_result['risk_score']}/100, rated "{scan_result['rating']}").
2. Explains the most important problems in simple terms - no jargon.
3. Gives a short, prioritized list of what to fix first.
4. Ends with one encouraging sentence.

Do not invent problems that aren't in the data. Here is the scan result:

{json.dumps(scan_result, indent=2)}
"""

    message = client.messages.create(
        model="claude-sonnet-4-6",
        max_tokens=1000,
        messages=[{"role": "user", "content": prompt}],
    )

    # The response text is inside the first content block.
    return message.content[0].text


def _explain_offline(scan_result):
    """
    FREE fallback mode. Builds a plain-English summary locally using
    the scan data - no API, no cost. Not as fluent as real Claude,
    but genuinely useful and completely free.
    """
    score = scan_result["risk_score"]
    rating = scan_result["rating"]
    target = scan_result["target"]

    # Separate the real problems from the "all good" info notes.
    problems = [
        f for f in scan_result["all_findings"]
        if f["severity"] in ("Critical", "High", "Medium", "Low")
    ]
    good_notes = [
        f for f in scan_result["all_findings"]
        if f["severity"] == "Info" and f["detail"].startswith("Good")
    ]

    # Sort problems worst-first so the summary leads with what matters.
    severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    problems.sort(key=lambda f: severity_order.get(f["severity"], 4))

    lines = []
    lines.append(f"Security summary for {target}")
    lines.append("=" * 50)
    lines.append("")

    # 1. Overall statement
    lines.append(f"Overall score: {score}/100  ({rating})")
    lines.append("")

    if score >= 85:
        lines.append("Your website is in good shape. A few small improvements")
        lines.append("would make it even stronger, but nothing here is urgent.")
    elif score >= 60:
        lines.append("Your website is reasonably safe but has some gaps worth")
        lines.append("closing. None are emergencies, but they add up.")
    elif score >= 35:
        lines.append("Your website has several weaknesses that put it at real")
        lines.append("risk. These are worth fixing soon.")
    else:
        lines.append("Your website has serious security problems that need")
        lines.append("attention right away.")
    lines.append("")

    # 2. What we found
    if problems:
        lines.append(f"We found {len(problems)} issue(s) to address:")
        lines.append("")
        for i, p in enumerate(problems, start=1):
            lines.append(f"  {i}. [{p['severity']}] {p['issue']}")
            lines.append(f"      Why it matters: {p['detail']}")
            lines.append("")
    else:
        lines.append("We found no significant security issues. Well done.")
        lines.append("")

    # 3. What's already good
    if good_notes:
        lines.append("What you're already doing right:")
        for g in good_notes:
            lines.append(f"  - {g['issue']}")
        lines.append("")

    # 4. Priorities
    if problems:
        lines.append("Fix these first (most important at the top):")
        top_three = problems[:3]
        for i, p in enumerate(top_three, start=1):
            lines.append(f"  {i}. {p['issue']}")
        lines.append("")

    # 5. Encouragement
    lines.append("Every issue above is fixable, and you've taken the right")
    lines.append("first step by checking. Address them one at a time.")

    return "\n".join(lines)


if __name__ == "__main__":
    import sys

    # Load a scan result from a JSON file passed on the command line,
    # or use a small built-in example so you can test with no arguments.
    if len(sys.argv) > 1:
        with open(sys.argv[1]) as f:
            scan_result = json.load(f)
    else:
        scan_result = {
            "target": "https://example.com",
            "risk_score": 50,
            "rating": "At risk",
            "all_findings": [
                {"issue": "Site uses HTTPS", "detail": "Good - traffic is encrypted.",
                 "severity": "Info", "source_check": "HTTPS & Security Headers"},
                {"issue": "Missing header: Content-Security-Policy",
                 "detail": "Controls what content can load, preventing many injection attacks.",
                 "severity": "Medium", "source_check": "HTTPS & Security Headers"},
                {"issue": "Missing header: Strict-Transport-Security",
                 "detail": "Forces browsers to always use HTTPS, preventing downgrade attacks.",
                 "severity": "Medium", "source_check": "HTTPS & Security Headers"},
            ],
        }

    print(explain(scan_result))
