#!/usr/bin/env python3
"""
Fetch feeds, generate a threat intelligence report via Claude,
save it to reports/, and update the REPORTS array in reports.html.
"""

import re
import sys
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).parent.parent
REPORTS_DIR = ROOT / "reports"
REPORTS_HTML = ROOT / "reports.html"

sys.path.insert(0, str(Path(__file__).parent))
from feeds import fetch_all_feeds
from analyzer import analyze_with_claude


def update_reports_list(new_filename: str) -> None:
    """Prepend new_filename to the REPORTS array in reports.html."""
    html = REPORTS_HTML.read_text(encoding="utf-8")

    # Find existing entries
    match = re.search(r"const REPORTS = \[(.*?)\];", html, re.DOTALL)
    if not match:
        print("WARNING: Could not find REPORTS array in reports.html")
        return

    existing = re.findall(r"'(threat_report_[^']+)'", match.group(1))

    # Prepend new file, keep unique
    all_reports = [new_filename] + [r for r in existing if r != new_filename]
    entries = "\n    ".join(f"'{r}'," for r in all_reports)
    new_array = f"const REPORTS = [\n    {entries}\n  ];"

    html = re.sub(r"const REPORTS = \[.*?\];", new_array, html, flags=re.DOTALL)
    REPORTS_HTML.write_text(html, encoding="utf-8")
    print(f"Updated REPORTS array with {len(all_reports)} report(s)")


def main() -> None:
    print("Fetching feeds...")
    articles = fetch_all_feeds()
    print(f"Fetched {len(articles)} articles")

    if not articles:
        print("No articles fetched. Aborting.")
        sys.exit(1)

    print("\nGenerating report...")
    report = analyze_with_claude(articles)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M")
    filename = f"threat_report_{timestamp}.txt"
    path = REPORTS_DIR / filename
    path.write_text(report, encoding="utf-8")
    print(f"\nReport saved to {path}")

    update_reports_list(filename)


if __name__ == "__main__":
    main()
