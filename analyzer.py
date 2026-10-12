#!/usr/bin/env python3
"""
Sourang Phishing Awareness Analyzer - Command Line Interface
Author: Sourang
Description: Main CLI entrypoint for analyzing emails, URLs, or corpus directories.
"""

import argparse
import os
import sys
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from sourang_analyzer import (
    TOOL_NAME,
    VERSION,
    EmailAnalyzer,
    URLAnalyzer,
    PhishingScorer,
    ReportGenerator,
)


def analyze_email_file(filepath: str, email_analyzer: EmailAnalyzer, scorer: PhishingScorer) -> dict:
    raw = email_analyzer.analyze_file(filepath)
    return scorer.score_analysis(raw)


def analyze_url_string(url_str: str, url_analyzer: URLAnalyzer, scorer: PhishingScorer) -> dict:
    raw = url_analyzer.analyze(url_str)
    return scorer.score_analysis(raw)


def analyze_corpus_directory(dirpath: str, email_analyzer: EmailAnalyzer, url_analyzer: URLAnalyzer, scorer: PhishingScorer) -> list:
    results = []
    path_obj = Path(dirpath)
    if not path_obj.exists():
        print(f"Error: Directory '{dirpath}' does not exist.")
        return results

    # Find all .eml files
    eml_files = sorted(list(path_obj.rglob("*.eml")))
    for eml in eml_files:
        res = analyze_email_file(str(eml), email_analyzer, scorer)
        results.append(res)

    # Find any url text files (e.g. *.txt containing URLs line-by-line)
    txt_files = sorted(list(path_obj.rglob("*url*.txt")))
    for txt in txt_files:
        try:
            with open(txt, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        res = analyze_url_string(line, url_analyzer, scorer)
                        results.append(res)
        except Exception:
            pass

    return results


def run_interactive_mode(email_analyzer: EmailAnalyzer, url_analyzer: URLAnalyzer, scorer: PhishingScorer):
    print("=" * 72)
    print(f"  {TOOL_NAME} - Interactive Mode")
    print("=" * 72)
    print("Choose analysis mode:")
    print("  1. Analyze a single URL")
    print("  2. Analyze raw email content (paste headers + body)")
    print("  3. Exit")

    choice = input("\nEnter choice [1-3]: ").strip()
    if choice == "1":
        target_url = input("\nEnter URL to inspect: ").strip()
        if target_url:
            res = analyze_url_string(target_url, url_analyzer, scorer)
            print("\n" + ReportGenerator.render_cli(res))
    elif choice == "2":
        print("\nPaste raw email content below. Enter 'EOF' on a new line when done:")
        lines = []
        while True:
            try:
                line = input()
                if line.strip() == "EOF":
                    break
                lines.append(line)
            except EOFError:
                break
        raw_content = "\n".join(lines)
        if raw_content:
            raw = email_analyzer.analyze_string(raw_content, source_name="interactive_input")
            res = scorer.score_analysis(raw)
            print("\n" + ReportGenerator.render_cli(res))
    else:
        print("Exiting interactive mode.")


def main():
    parser = argparse.ArgumentParser(
        prog="analyzer.py",
        description=f"{TOOL_NAME} v{VERSION} - Threat Detection & Heuristic Phishing Analyzer",
    )
    parser.add_argument("-e", "--email", type=str, help="Path to sample email (.eml) to inspect")
    parser.add_argument("-u", "--url", type=str, help="Single URL string to inspect")
    parser.add_argument("-c", "--corpus", type=str, help="Directory path of synthetic corpus (.eml and url txt files)")
    parser.add_argument("-i", "--interactive", action="store_true", help="Launch interactive analyzer console")
    parser.add_argument("-j", "--json", action="store_true", help="Output results in JSON format")
    parser.add_argument("-o", "--output", type=str, help="Write output report to destination file (.json or .md)")
    parser.add_argument("-g", "--gui", action="store_true", help="Launch Graphical User Interface (GUI) desktop window")
    parser.add_argument("--demo", action="store_true", help="Run quick automated demo with synthetic samples")

    args = parser.parse_args()

    # GUI Mode
    if args.gui:
        import gui
        gui.main()
        return

    url_analyzer = URLAnalyzer()
    email_analyzer = EmailAnalyzer(custom_url_analyzer=url_analyzer)
    scorer = PhishingScorer()

    # Demo Mode
    if args.demo:
        demo_script = Path(__file__).parent / "demo.py"
        if demo_script.exists():
            import subprocess
            subprocess.run([sys.executable, str(demo_script)])
            return
        else:
            print("Demo script not found. Run with --corpus corpus/ instead.")
            return

    # Interactive Mode
    if args.interactive:
        run_interactive_mode(email_analyzer, url_analyzer, scorer)
        return

    # Single URL
    if args.url:
        result = analyze_url_string(args.url, url_analyzer, scorer)
        _handle_single_output(result, args)
        return

    # Single Email
    if args.email:
        if not os.path.isfile(args.email):
            print(f"Error: Email file '{args.email}' not found.", file=sys.stderr)
            sys.exit(1)
        result = analyze_email_file(args.email, email_analyzer, scorer)
        _handle_single_output(result, args)
        return

    # Batch Corpus
    if args.corpus:
        results = analyze_corpus_directory(args.corpus, email_analyzer, url_analyzer, scorer)
        if not results:
            print(f"No sample files found in '{args.corpus}'.")
            return

        if args.json:
            json_str = ReportGenerator.to_json(results)
            if args.output:
                with open(args.output, "w", encoding="utf-8") as f:
                    f.write(json_str)
                print(f"Wrote batch JSON results to {args.output}")
            else:
                print(json_str)
        else:
            batch_text = ReportGenerator.render_batch_cli(results)
            print(batch_text)
            if args.output:
                with open(args.output, "w", encoding="utf-8") as f:
                    f.write(batch_text)
                print(f"\nWrote batch report to {args.output}")
        return

    # No argument provided -> print help
    parser.print_help()


def _handle_single_output(result: dict, args):
    if args.json:
        out_str = ReportGenerator.to_json(result)
    else:
        out_str = ReportGenerator.render_cli(result)

    if args.output:
        out_path = Path(args.output)
        if out_path.suffix.lower() == ".json":
            with open(out_path, "w", encoding="utf-8") as f:
                f.write(ReportGenerator.to_json(result))
        elif out_path.suffix.lower() == ".md":
            with open(out_path, "w", encoding="utf-8") as f:
                f.write(ReportGenerator.to_markdown(result))
        else:
            with open(out_path, "w", encoding="utf-8") as f:
                f.write(out_str)
        print(f"Saved analysis output to '{args.output}'")
    else:
        print(out_str)


if __name__ == "__main__":
    main()
