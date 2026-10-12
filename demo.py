#!/usr/bin/env python3
"""
Sourang Phishing Awareness Analyzer - Interactive Showcase Demo
Author: Sourang
Description: Runs an automated demonstration comparing legitimate and phishing samples.
"""

import os
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from sourang_analyzer import EmailAnalyzer, URLAnalyzer, PhishingScorer, ReportGenerator, Colors, colorize


def main():
    base_dir = Path(__file__).parent
    url_analyzer = URLAnalyzer()
    email_analyzer = EmailAnalyzer(custom_url_analyzer=url_analyzer)
    scorer = PhishingScorer()

    print("\n" + "=" * 78)
    print(f" {colorize('SOURANG PHISHING AWARENESS ANALYZER - DEMONSTRATION SUITE', Colors.BOLD + Colors.CYAN)}")
    print("=" * 78)
    print(" This demo showcases automated threat detection and heuristic breakdown on:")
    print(" 1) Synthetic Phishing Email (Urgent Account Suspension)")
    print(" 2) Authentic Legitimate Email (Developer Newsletter)")
    print(" 3) Typosquatted / Deceptive URL vs Benign Official URL")
    print("=" * 78 + "\n")

    # Sample 1: Phishing Email
    phish_path = base_dir / "corpus" / "phishing" / "phish_01_urgent_account_suspension.eml"
    if phish_path.exists():
        print(colorize("\n[DEMO STEP 1/3] ANALYZING SYNTHETIC PHISHING SAMPLE...", Colors.BOLD + Colors.RED))
        phish_raw = email_analyzer.analyze_file(str(phish_path))
        phish_res = scorer.score_analysis(phish_raw)
        print(ReportGenerator.render_cli(phish_res, show_educational_details=True))

    # Sample 2: Legitimate Email
    legit_path = base_dir / "corpus" / "legitimate" / "legit_01_welcome_newsletter.eml"
    if legit_path.exists():
        print(colorize("\n[DEMO STEP 2/3] ANALYZING AUTHENTIC LEGITIMATE SAMPLE...", Colors.BOLD + Colors.GREEN))
        legit_raw = email_analyzer.analyze_file(str(legit_path))
        legit_res = scorer.score_analysis(legit_raw)
        print(ReportGenerator.render_cli(legit_res, show_educational_details=True))

    # Sample 3: URL Comparison
    print(colorize("\n[DEMO STEP 3/3] COMPARING DECEPTIVE URL VS OFFICIAL URL...", Colors.BOLD + Colors.YELLOW))
    suspicious_url = "http://paypal.com.account-update.xyz/signin"
    clean_url = "https://www.paypal.com/us/signin"

    susp_raw = url_analyzer.analyze(suspicious_url)
    susp_res = scorer.score_analysis(susp_raw)

    clean_raw = url_analyzer.analyze(clean_url)
    clean_res = scorer.score_analysis(clean_raw)

    print(f"\nTarget 1: {suspicious_url}")
    print(f"  Score:    {colorize(str(susp_res['risk_score']) + '/100', Colors.RED + Colors.BOLD)} - {susp_res['severity']}")
    for ind in susp_res["indicators"]:
        print(f"  * [{ind['code']}] {ind['title']} (+{ind['weight']} pts)")

    print(f"\nTarget 2: {clean_url}")
    print(f"  Score:    {colorize(str(clean_res['risk_score']) + '/100', Colors.GREEN + Colors.BOLD)} - {clean_res['severity']}")
    if not clean_res["indicators"]:
        print("  * No deceptive indicators identified (Safe).")

    print("\n" + "=" * 78)
    print(f" {colorize('DEMONSTRATION COMPLETE', Colors.BOLD + Colors.GREEN)}")
    print(" For interactive CLI analysis, run:   python analyzer.py --interactive")
    print(" To inspect your custom email file:    python analyzer.py --email path/to/sample.eml")
    print(" To batch analyze entire corpus:      python analyzer.py --corpus corpus/")
    print("=" * 78 + "\n")


if __name__ == "__main__":
    main()
