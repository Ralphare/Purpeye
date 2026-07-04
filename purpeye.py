"""
PurpEye - Main Pipeline
One command to run the whole thing against a website:

    python3 purpeye.py https://example.com

It scans the site, scores the risk, writes a plain-English summary,
and saves a professional PDF report - all in one go.
"""

import sys
import os
import subprocess
import platform


def open_file(path):
    """
    Open a file in the system's default application.
    Works on Linux, macOS, and Windows. If it fails, we skip
    quietly - the report is still saved, opening is just a bonus.
    """
    try:
        system = platform.system()
        if system == "Linux":
            subprocess.Popen(["xdg-open", path],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        elif system == "Darwin":  # macOS
            subprocess.Popen(["open", path])
        elif system == "Windows":
            os.startfile(path)  # type: ignore[attr-defined]
    except Exception:
        # Opening is optional; never let it break the scan.
        pass


# Make the sub-folders importable no matter where we run from.
BASE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(BASE, "scanner"))
sys.path.insert(0, os.path.join(BASE, "ai_layer"))
sys.path.insert(0, os.path.join(BASE, "report"))

from scanner import scan_runner
from ai_layer import ai_explainer
from report import report_generator


def run(target_url):
    # Step 1 + 2: scan and score.
    scan_result = scan_runner.run_scan(target_url)

    # Step 3: plain-English summary.
    summary = ai_explainer.explain(scan_result)

    # Show the summary in the terminal.
    print("=" * 60)
    print(summary)
    print("=" * 60)

    # Step 4: build a PDF report named after the site.
    safe_name = target_url.replace("https://", "").replace("http://", "")
    safe_name = safe_name.replace("/", "_").strip("_")
    output_file = os.path.join(BASE, f"report_{safe_name}.pdf")
    report_generator.generate(scan_result, summary, output_file)
    print(f"\n[PurpEye] PDF report saved to: {output_file}")

    # Step 5: open the report automatically for the user.
    print("[PurpEye] Opening report...")
    open_file(output_file)

    return scan_result, summary


if __name__ == "__main__":
    url = sys.argv[1] if len(sys.argv) > 1 else "https://example.com"
    run(url)

