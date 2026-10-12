"""
Sourang Phishing Awareness Analyzer - Graphical User Interface (GUI)
Author: Sourang
Description: Modern Tkinter desktop application for email and URL phishing analysis.
Zero external dependencies (uses standard library tkinter).
"""

import os
import sys
import json
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from sourang_analyzer import (
    TOOL_NAME,
    VERSION,
    AUTHOR,
    DISCLAIMER,
    EmailAnalyzer,
    URLAnalyzer,
    PhishingScorer,
    ReportGenerator,
)


class PhishingAnalyzerGUI:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title(f"{TOOL_NAME} v{VERSION}")
        self.root.geometry("980x720")
        self.root.minsize(800, 600)

        # Initialize engines
        self.url_analyzer = URLAnalyzer()
        self.email_analyzer = EmailAnalyzer(custom_url_analyzer=self.url_analyzer)
        self.scorer = PhishingScorer()
        self.base_dir = Path(__file__).parent

        self._setup_style()
        self._build_ui()

    def _setup_style(self):
        self.style = ttk.Style()
        try:
            self.style.theme_use("clam")
        except Exception:
            pass

        # Configure colors
        self.root.configure(bg="#f4f6f9")
        self.style.configure(".", font=("Segoe UI", 10))
        self.style.configure("Header.TLabel", font=("Segoe UI", 14, "bold"), foreground="#1a2530", background="#f4f6f9")
        self.style.configure("Subheader.TLabel", font=("Segoe UI", 10), foreground="#55606d", background="#f4f6f9")
        self.style.configure("Accent.TButton", font=("Segoe UI", 10, "bold"), background="#0066cc", foreground="#ffffff")
        self.style.configure("TNotebook", background="#f4f6f9")
        self.style.configure("TNotebook.Tab", font=("Segoe UI", 10, "bold"), padding=[12, 6])

    def _build_ui(self):
        # Top Banner
        banner_frame = tk.Frame(self.root, bg="#1a2530", height=65)
        banner_frame.pack(fill="x", side="top")

        title_lbl = tk.Label(
            banner_frame,
            text=f"  {TOOL_NAME.upper()}",
            font=("Segoe UI", 13, "bold"),
            fg="#ffffff",
            bg="#1a2530",
        )
        title_lbl.pack(side="left", padx=15, pady=12)

        sub_lbl = tk.Label(
            banner_frame,
            text=f"Threat Detection & Educational Heuristics | v{VERSION}",
            font=("Segoe UI", 9),
            fg="#8ba3c7",
            bg="#1a2530",
        )
        sub_lbl.pack(side="left", padx=5, pady=12)

        author_lbl = tk.Label(
            banner_frame,
            text=f"Author: {AUTHOR}  ",
            font=("Segoe UI", 9, "bold"),
            fg="#00d2d3",
            bg="#1a2530",
        )
        author_lbl.pack(side="right", padx=15, pady=12)

        # Notebook tabs
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill="both", expand=True, padx=12, pady=10)

        # Tab 1: URL Analyzer
        self.url_tab = ttk.Frame(self.notebook, padding=12)
        self.notebook.add(self.url_tab, text="  URL Analyzer  ")
        self._build_url_tab()

        # Tab 2: Email Analyzer
        self.email_tab = ttk.Frame(self.notebook, padding=12)
        self.notebook.add(self.email_tab, text="  Email Analyzer (.eml)  ")
        self._build_email_tab()

        # Tab 3: Batch Corpus
        self.corpus_tab = ttk.Frame(self.notebook, padding=12)
        self.notebook.add(self.corpus_tab, text="  Batch Corpus Scanner  ")
        self._build_corpus_tab()

        # Tab 4: About & Disclaimer
        self.about_tab = ttk.Frame(self.notebook, padding=15)
        self.notebook.add(self.about_tab, text="  About & Safety Notice  ")
        self._build_about_tab()

    # -------------------------------------------------------------
    # TAB 1: URL ANALYZER
    # -------------------------------------------------------------
    def _build_url_tab(self):
        input_frame = tk.LabelFrame(self.url_tab, text="Target URL Input", font=("Segoe UI", 10, "bold"), padx=10, pady=10)
        input_frame.pack(fill="x", side="top", pady=5)

        tk.Label(input_frame, text="Enter Web URL:").pack(anchor="w")

        url_entry_row = tk.Frame(input_frame)
        url_entry_row.pack(fill="x", pady=4)

        self.url_var = tk.StringVar(value="http://paypal.com.account-update.xyz/signin")
        self.url_entry = ttk.Entry(url_entry_row, textvariable=self.url_var, font=("Consolas", 10))
        self.url_entry.pack(side="left", fill="x", expand=True, padx=(0, 8))

        analyze_btn = tk.Button(
            url_entry_row,
            text="Analyze URL",
            bg="#0066cc",
            fg="white",
            font=("Segoe UI", 9, "bold"),
            padx=12,
            pady=4,
            command=self._analyze_url_action,
        )
        analyze_btn.pack(side="right")

        # Quick preset buttons
        preset_frame = tk.Frame(input_frame)
        preset_frame.pack(fill="x", pady=(5, 0))
        tk.Label(preset_frame, text="Quick Samples: ", font=("Segoe UI", 8, "italic")).pack(side="left")

        tk.Button(
            preset_frame,
            text="Phishing Sample (Subdomain)",
            font=("Segoe UI", 8),
            command=lambda: self.url_var.set("http://paypal.com.account-update.xyz/signin"),
        ).pack(side="left", padx=4)

        tk.Button(
            preset_frame,
            text="Typosquat Sample (paypa1)",
            font=("Segoe UI", 8),
            command=lambda: self.url_var.set("http://paypa1-security.com/login"),
        ).pack(side="left", padx=4)

        tk.Button(
            preset_frame,
            text="Legitimate Sample (PayPal)",
            font=("Segoe UI", 8),
            command=lambda: self.url_var.set("https://www.paypal.com/us/signin"),
        ).pack(side="left", padx=4)

        # Results Display
        self.url_results_box = self._create_result_viewer(self.url_tab)

    def _analyze_url_action(self):
        target = self.url_var.get().strip()
        if not target:
            messagebox.showwarning("Input Required", "Please enter a URL to inspect.")
            return

        raw = self.url_analyzer.analyze(target)
        result = self.scorer.score_analysis(raw)
        self._populate_results(self.url_results_box, result)

    # -------------------------------------------------------------
    # TAB 2: EMAIL ANALYZER
    # -------------------------------------------------------------
    def _build_email_tab(self):
        top_frame = tk.LabelFrame(self.email_tab, text="Email Source (.eml File or Text)", font=("Segoe UI", 10, "bold"), padx=10, pady=8)
        top_frame.pack(fill="x", side="top", pady=5)

        btn_row = tk.Frame(top_frame)
        btn_row.pack(fill="x", pady=2)

        browse_btn = tk.Button(
            btn_row,
            text="Browse .eml File...",
            font=("Segoe UI", 9, "bold"),
            bg="#2e7d32",
            fg="white",
            padx=10,
            command=self._browse_email_file,
        )
        browse_btn.pack(side="left", padx=(0, 8))

        tk.Button(
            btn_row,
            text="Load Phishing Sample 1",
            font=("Segoe UI", 8),
            command=lambda: self._load_sample_eml("corpus/phishing/phish_01_urgent_account_suspension.eml"),
        ).pack(side="left", padx=4)

        tk.Button(
            btn_row,
            text="Load Phishing Sample 2 (Microsoft)",
            font=("Segoe UI", 8),
            command=lambda: self._load_sample_eml("corpus/phishing/phish_02_fake_security_alert_microsoft.eml"),
        ).pack(side="left", padx=4)

        tk.Button(
            btn_row,
            text="Load Legitimate Newsletter",
            font=("Segoe UI", 8),
            command=lambda: self._load_sample_eml("corpus/phishing/../legitimate/legit_01_welcome_newsletter.eml"),
        ).pack(side="left", padx=4)

        analyze_eml_btn = tk.Button(
            btn_row,
            text="Analyze Content",
            font=("Segoe UI", 9, "bold"),
            bg="#0066cc",
            fg="white",
            padx=12,
            command=self._analyze_email_text_action,
        )
        analyze_eml_btn.pack(side="right")

        # Text input preview
        tk.Label(top_frame, text="Raw Email Content (Headers & Body):", font=("Segoe UI", 8)).pack(anchor="w", pady=(6, 2))
        self.email_text_box = tk.Text(top_frame, height=6, font=("Consolas", 9), wrap="word")
        self.email_text_box.pack(fill="x")

        # Pre-fill sample
        self._load_sample_eml("corpus/phishing/phish_01_urgent_account_suspension.eml")

        # Results Display
        self.email_results_box = self._create_result_viewer(self.email_tab)

    def _browse_email_file(self):
        path = filedialog.askopenfilename(
            title="Select Email File",
            filetypes=[("Email Files", "*.eml"), ("Text Files", "*.txt"), ("All Files", "*.*")],
            initialdir=str(self.base_dir / "corpus"),
        )
        if path:
            self._load_sample_eml(path)

    def _load_sample_eml(self, rel_or_abs_path: str):
        full_path = Path(rel_or_abs_path)
        if not full_path.is_absolute():
            full_path = self.base_dir / rel_or_abs_path

        if full_path.exists():
            try:
                content = full_path.read_text(encoding="utf-8", errors="replace")
                self.email_text_box.delete("1.0", tk.END)
                self.email_text_box.insert("1.0", content)
                self.current_eml_path = str(full_path)
            except Exception as e:
                messagebox.showerror("Read Error", f"Failed to read file: {e}")

    def _analyze_email_text_action(self):
        content = self.email_text_box.get("1.0", tk.END).strip()
        if not content:
            messagebox.showwarning("Input Required", "Email content is empty.")
            return

        raw = self.email_analyzer.analyze_string(content, source_name="email_sample.eml")
        result = self.scorer.score_analysis(raw)
        self._populate_results(self.email_results_box, result)

    # -------------------------------------------------------------
    # TAB 3: BATCH CORPUS SCANNER
    # -------------------------------------------------------------
    def _build_corpus_tab(self):
        ctrl_frame = tk.Frame(self.corpus_tab)
        ctrl_frame.pack(fill="x", pady=6)

        run_batch_btn = tk.Button(
            ctrl_frame,
            text="Scan Full Corpus (corpus/)",
            font=("Segoe UI", 10, "bold"),
            bg="#0066cc",
            fg="white",
            padx=12,
            pady=4,
            command=self._run_batch_scan,
        )
        run_batch_btn.pack(side="left", padx=(0, 10))

        export_json_btn = tk.Button(
            ctrl_frame,
            text="Export JSON Report...",
            font=("Segoe UI", 9),
            command=self._export_batch_json,
        )
        export_json_btn.pack(side="left", padx=5)

        self.batch_summary_lbl = tk.Label(ctrl_frame, text="Ready to scan synthetic test dataset.", font=("Segoe UI", 9, "bold"))
        self.batch_summary_lbl.pack(side="right", padx=10)

        # Batch Treeview Table
        columns = ("Target", "Score", "Severity", "Indicators", "Verdict")
        self.batch_tree = ttk.Treeview(self.corpus_tab, columns=columns, show="headings", height=18)
        self.batch_tree.heading("Target", text="Sample / Target")
        self.batch_tree.heading("Score", text="Risk Score")
        self.batch_tree.heading("Severity", text="Severity Tier")
        self.batch_tree.heading("Indicators", text="Indicators Hit")
        self.batch_tree.heading("Verdict", text="Verdict")

        self.batch_tree.column("Target", width=340)
        self.batch_tree.column("Score", width=90, anchor="center")
        self.batch_tree.column("Severity", width=140, anchor="center")
        self.batch_tree.column("Indicators", width=100, anchor="center")
        self.batch_tree.column("Verdict", width=120, anchor="center")

        tree_scroll = ttk.Scrollbar(self.corpus_tab, orient="vertical", command=self.batch_tree.yview)
        self.batch_tree.configure(yscrollcommand=tree_scroll.set)

        self.batch_tree.pack(side="left", fill="both", expand=True)
        tree_scroll.pack(side="right", fill="y")

        self.last_batch_results = []

    def _run_batch_scan(self):
        from analyzer import analyze_corpus_directory
        corpus_dir = self.base_dir / "corpus"
        results = analyze_corpus_directory(str(corpus_dir), self.email_analyzer, self.url_analyzer, self.scorer)
        self.last_batch_results = results

        # Clear existing
        for item in self.batch_tree.get_children():
            self.batch_tree.delete(item)

        phish_c = 0
        legit_c = 0
        for r in results:
            src = r.get("source", "unknown")
            short_src = src.replace("https://", "").replace("http://", "").split("/")[-1].split("\\")[-1]
            score = r.get("risk_score", 0)
            sev = r.get("severity", "Unknown")
            ind_count = len(r.get("indicators", []))

            if score >= 50:
                phish_c += 1
                verdict = "PHISHING"
            elif score >= 25:
                verdict = "SUSPICIOUS"
            else:
                legit_c += 1
                verdict = "LEGITIMATE"

            self.batch_tree.insert("", "end", values=(short_src, f"{score}/100", sev, ind_count, verdict))

        self.batch_summary_lbl.config(
            text=f"Analyzed {len(results)} samples | {legit_c} Legitimate | {phish_c} Phishing / High Risk"
        )

    def _export_batch_json(self):
        if not self.last_batch_results:
            messagebox.showinfo("Run Scan First", "Please click 'Scan Full Corpus' before exporting.")
            return

        dest = filedialog.asksaveasfilename(
            title="Save Batch JSON",
            defaultextension=".json",
            filetypes=[("JSON Files", "*.json")],
            initialfile="corpus_triage_report.json"
        )
        if dest:
            with open(dest, "w", encoding="utf-8") as f:
                f.write(ReportGenerator.to_json(self.last_batch_results))
            messagebox.showinfo("Export Successful", f"Saved batch report to {dest}")

    # -------------------------------------------------------------
    # TAB 4: ABOUT & SAFETY NOTICE
    # -------------------------------------------------------------
    def _build_about_tab(self):
        about_box = tk.Text(self.about_tab, font=("Segoe UI", 10), wrap="word", bg="#fcfcfc", padx=15, pady=15)
        about_box.pack(fill="both", expand=True)

        info_text = f"""========================================================================
  {TOOL_NAME.upper()}
  Version: {VERSION} | Author: {AUTHOR}
  License: MIT Open Source License
========================================================================

OBJECTIVE & ARCHITECTURAL SCOPE:
This tool is a threat detection and heuristic triage analyzer built for security awareness,
student education, and defensive triage. It parses emails (.eml) and URLs for suspicious
indicators without executing live network requests.

CORE DETECTION CAPABILITIES:
- Email Header Analysis: SPF, DKIM, DMARC failures, Display Name Spoofing, Reply-To Diversion,
  and missing RFC 5322 compliance.
- Body Text Heuristics: High-urgency intimidation, fake security warnings, credential requests,
  and generic greetings.
- URL Heuristics: Raw IP address detection, brand-in-subdomain spoofing, typosquatting / homoglyphs
  (Levenshtein edit distance), high-abuse TLDs (.xyz, .top), and deceptive HTML anchor tags.
- Composite Risk Score: Normalized 0 to 100 scale categorized into Low, Medium, High, and Critical.

ETHICAL & DEFENSIVE SAFETY POLICY:
- 100% Offline: Never performs active network probes, port scans, or HTTP requests.
- Safe Testing: Operates exclusively on synthetic and sanitized sample datasets.

{DISCLAIMER}
"""
        about_box.insert("1.0", info_text)
        about_box.config(state="disabled")

    # -------------------------------------------------------------
    # HELPER: RESULT VIEWER COMPONENT
    # -------------------------------------------------------------
    def _create_result_viewer(self, parent_frame: tk.Frame) -> dict:
        box_frame = tk.LabelFrame(parent_frame, text="Analysis & Educational Report", font=("Segoe UI", 10, "bold"), padx=10, pady=8)
        box_frame.pack(fill="both", expand=True, pady=5)

        # Score & Severity Header Card
        card = tk.Frame(box_frame, bg="#ffffff", relief="groove", bd=1, padx=12, pady=8)
        card.pack(fill="x", pady=(0, 8))

        score_lbl = tk.Label(card, text="Risk Score: --/100", font=("Segoe UI", 13, "bold"), bg="#ffffff")
        score_lbl.pack(side="left")

        sev_lbl = tk.Label(card, text="[Awaiting Analysis]", font=("Segoe UI", 11, "bold"), bg="#ffffff", fg="#666666")
        sev_lbl.pack(side="left", padx=15)

        progress = ttk.Progressbar(card, orient="horizontal", mode="determinate", length=220)
        progress.pack(side="right", padx=10)

        # Notebook for Detailed Results
        res_notebook = ttk.Notebook(box_frame)
        res_notebook.pack(fill="both", expand=True)

        # Tab: Threat Indicators
        ind_tab = ttk.Frame(res_notebook, padding=5)
        res_notebook.add(ind_tab, text="Flagged Threats & Evidence")

        ind_tree = ttk.Treeview(ind_tab, columns=("Category", "Indicator", "Weight", "Evidence"), show="headings", height=8)
        ind_tree.heading("Category", text="Category")
        ind_tree.heading("Indicator", text="Threat Indicator")
        ind_tree.heading("Weight", text="Weight")
        ind_tree.heading("Evidence", text="Forensic Evidence")

        ind_tree.column("Category", width=140)
        ind_tree.column("Indicator", width=260)
        ind_tree.column("Weight", width=70, anchor="center")
        ind_tree.column("Evidence", width=360)

        ind_scroll = ttk.Scrollbar(ind_tab, orient="vertical", command=ind_tree.yview)
        ind_tree.configure(yscrollcommand=ind_scroll.set)
        ind_tree.pack(side="left", fill="both", expand=True)
        ind_scroll.pack(side="right", fill="y")

        # Tab: Educational Advice
        edu_tab = ttk.Frame(res_notebook, padding=5)
        res_notebook.add(edu_tab, text="Educational Guidance")

        edu_text = tk.Text(edu_tab, font=("Segoe UI", 10), wrap="word", padx=10, pady=10)
        edu_text.pack(fill="both", expand=True)

        return {
            "score_lbl": score_lbl,
            "sev_lbl": sev_lbl,
            "progress": progress,
            "ind_tree": ind_tree,
            "edu_text": edu_text,
        }

    def _populate_results(self, viewer: dict, result: dict):
        score = result["risk_score"]
        severity = result["severity"]
        badge = result["severity_badge"]
        indicators = result["indicators"]
        recs = result.get("educational_recommendations", [])

        # Color mapping
        if score < 25:
            color = "#2e7d32"  # Green
        elif score < 50:
            color = "#f57c00"  # Orange/Yellow
        elif score < 75:
            color = "#c62828"  # Red
        else:
            color = "#6a1b9a"  # Purple/Critical

        viewer["score_lbl"].config(text=f"Risk Score: {score}/100", fg=color)
        viewer["sev_lbl"].config(text=f"{badge} - {severity.upper()}", fg=color)
        viewer["progress"]["value"] = score

        # Clear and fill Treeview
        tree = viewer["ind_tree"]
        for row in tree.get_children():
            tree.delete(row)

        if indicators:
            for ind in indicators:
                tree.insert(
                    "",
                    "end",
                    values=(
                        ind.get("category", "General"),
                        ind.get("title", ""),
                        f"+{ind.get('weight', 0)} pts",
                        ind.get("evidence", ""),
                    ),
                )
        else:
            tree.insert("", "end", values=("Safe", "No threat indicators detected", "0 pts", "Clean heuristics"))

        # Populate Educational Guidance
        edu_box = viewer["edu_text"]
        edu_box.config(state="normal")
        edu_box.delete("1.0", tk.END)

        edu_box.insert(tk.END, "DEFENSIVE SECURITY RECOMMENDATIONS:\n", "bold")
        for rec in recs:
            edu_box.insert(tk.END, f"\n[>] {rec}\n")

        edu_box.insert(tk.END, "\n" + "=" * 60 + "\nDETAILED ATTACKER MECHANICS:\n", "bold")
        for idx, ind in enumerate(indicators, 1):
            edu_box.insert(tk.END, f"\n{idx}. {ind['title']}\n")
            edu_box.insert(tk.END, f"   Why Attackers Use This: {ind['explanation']}\n")

        edu_box.config(state="disabled")


def main():
    root = tk.Tk()
    app = PhishingAnalyzerGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
