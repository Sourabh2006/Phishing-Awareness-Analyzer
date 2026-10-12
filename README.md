# Sourang Phishing Awareness Analyzer

<p align="center">
  <img src="https://img.shields.io/badge/Version-1.0.0-blue.svg" alt="Version 1.0.0">
  <img src="https://img.shields.io/badge/Python-3.8%2B-brightgreen.svg" alt="Python 3.8+">
  <img src="https://img.shields.io/badge/Security-Defensive%20Triage-red.svg" alt="Security Defensive Triage">
  <img src="https://img.shields.io/badge/Execution-100%25%20Offline%20Safe-success.svg" alt="Offline Safe">
  <img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="License MIT">
</p>

> **Sourang Phishing Awareness Analyzer** is an educational threat detection and heuristic triage engine designed to inspect suspicious emails (`.eml`) and web URLs. It analyzes structural artifacts, authentication records, deceptive social engineering keywords, and typosquatting indicators to produce a weighted risk score (0–100) paired with actionable educational breakdowns.

---

## Table of Contents

- [1. Objective & Scope](#1-objective--scope)
- [2. System Architecture](#2-system-architecture)
- [3. Core Features](#3-core-features)
- [4. Heuristic Rules & Threat Indicators](#4-heuristic-rules--threat-indicators)
- [5. Risk Scoring Engine & Thresholds](#5-risk-scoring-engine--thresholds)
- [6. Synthetic Test Corpus](#6-synthetic-test-corpus)
- [7. Installation & Quickstart](#7-installation--quickstart)
- [8. CLI Usage Guide](#8-cli-usage-guide)
- [9. Testing & Quality Assurance](#9-testing--quality-assurance)
- [10. False-Positive & Ethical Safety Disclaimer](#10-false-positive--ethical-safety-disclaimer)
- [11. Step-by-Step GitHub Upload Guide](#11-step-by-step-github-upload-guide)
- [12. License & Author](#12-license--author)

---

## 1. Objective & Scope

Phishing remains the number-one initial access vector across modern cybersecurity breaches. The primary defense against phishing is user awareness coupled with automated, transparent heuristic triage.

### Scope & Safety Standards
- **Safe & Offline:** Operates strictly on synthetic and sanitized data. It **never** executes live network probes, HTTP requests, port scans, or DNS queries that could alert adversaries or trigger malicious scripts.
- **Educational Explanations:** Every flagged indicator details the exact forensic evidence, why attackers use the technique, and concrete defensive steps the user should take.
- **Deterministic & Auditable:** Pure Python implementation with zero mandatory external dependencies, ensuring compatibility across all platforms.

---

## 2. System Architecture

```
                    +----------------------------------------+
                    |  Input: Sample Email (.eml) or URL    |
                    +-------------------+--------------------+
                                        |
                 +----------------------+----------------------+
                 |                                             |
                 v                                             v
    +---------------------------+                +---------------------------+
    |    Email Analysis Engine  |                |     URL Analysis Engine   |
    |  (sourang_analyzer/      |                |  (sourang_analyzer/       |
    |   email_analyzer.py)      |                |   url_analyzer.py)        |
    +-------------+-------------+                +-------------+-------------+
                  |                                            |
                  |-- Headers (SPF, DKIM, DMARC, Mismatches)   |-- IP Address Detection
                  |-- Display Name Spoofing                    |-- Misleading Subdomains
                  |-- Body Urgency & Coercive Keywords         |-- Typosquatting / Homoglyphs
                  |-- Credential Harvesting Cues               |-- High-Abuse TLDs (.xyz, etc.)
                  |-- HTML Anchor vs Href Discrepancies        |-- Basic Auth '@' Delimiter
                  +----------------------+---------------------+
                                         |
                                         v
                         +-------------------------------+
                         |      Scoring & Heuristic      |
                         |         Engine Matrix         |
                         |  (sourang_analyzer/scorer.py) |
                         +---------------+---------------+
                                         |
                                         v
                         +-------------------------------+
                         |    Composite Risk Score (0-100|
                         |  Categorized Severity Tier    |
                         |   Educational Explanations    |
                         |   Defensive Recommendations   |
                         +---------------+---------------+
                                         |
                 +-----------------------+-----------------------+
                 |                       |                       |
                 v                       v                       v
        [Terminal CLI UI]       [JSON Data Export]      [Markdown Report]
```

---

## 3. Core Features

### Email Header Forensics
- **Authentication Protocol Triage:** Evaluates `Authentication-Results` and `Received-SPF` headers for SPF failure (`fail`, `softfail`), DKIM signature degradation (`fail`, `none`), and DMARC alignment failures.
- **Sender Discrepancy Checks:**
  - **Display Name Spoofing:** Identifies brand names (e.g., "PayPal Security", "Microsoft Team") used as friendly names while the underlying mailbox originates from an untrusted domain.
  - **Reply-To Diversion:** Detects mismatched `Reply-To` and `From` domains used to intercept victim responses in Business Email Compromise (BEC) attacks.
  - **Free Webmail Traps:** Flags corporate or financial senders diverting replies to free webmail providers (`gmail.com`, `yahoo.com`, `outlook.com`).
- **RFC 5322 Hygiene:** Flags messages missing standard `Date`, `From`, or `Message-ID` fields.

### Body Text & Social Engineering Analysis
- **High-Urgency & Pressure:** Scans for psychological coercion patterns (`"urgent action required"`, `"account suspended within 24 hours"`, `"final warning"`).
- **Alarmist Security Notifications:** Detects fabricated breach alerts (`"unauthorized sign-in detected"`, `"unusual activity"`, `"password expired"`).
- **Credential & Financial Solicitation:** Flags calls to action demanding passwords, OTPs, PIN codes, or billing details.
- **Generic Salutations:** Spots bulk phishing markers like `"Dear Customer"` or `"Dear Valued Member"`.

### URL Inspection & Obfuscation Detection
- **IP-Based Links:** Flags raw IPv4 hosts (e.g., `http://192.168.1.105:8080/login`) used to bypass domain reputation services.
- **Misleading Subdomains:** Catches brand names embedded into multi-level subdomains where the true apex domain belongs to an attacker (e.g., `paypal.com.account-update.xyz`).
- **Typosquatting & Homoglyph Substitution:** Uses Levenshtein distance and character mapping (`0` -> `o`, `1` -> `l`, `rn` -> `m`) to detect lookalike domains for brands such as Microsoft, PayPal, Apple, Amazon, Google, Chase, and GitHub.
- **High-Risk TLDs:** Identifies top-level domains with high abuse rates (`.xyz`, `.top`, `.buzz`, `.work`, `.icu`, `.zip`).
- **HTML Anchor Discrepancy:** Detects deceptive links where visible text shows an official URL (`https://www.paypal.com`) while the underlying HTML `href` leads to an attacker domain.

---

## 4. Heuristic Rules & Threat Indicators

| Code | Indicator Description | Category | Weight |
|---|---|---|---|
| `SPF_FAIL` | SPF Authentication Hard Failure | Email Authentication | +25 pts |
| `DMARC_FAIL` | DMARC Policy Alignment Failure | Email Authentication | +25 pts |
| `DKIM_FAIL` | DKIM Cryptographic Verification Failure | Email Authentication | +20 pts |
| `SPF_SOFTFAIL` | SPF Authentication Softfail Policy | Email Authentication | +15 pts |
| `SPF_NONE_OR_NEUTRAL` | Missing or Neutral SPF Policy | Email Authentication | +8 pts |
| `SENDER_DISPLAY_NAME_SPOOF` | Display Name Impersonation | Sender Verification | +25 pts |
| `FROM_REPLY_TO_MISMATCH` | From vs. Reply-To Domain Divergence | Sender Verification | +20 pts |
| `FREE_WEBMAIL_REPLY_TO` | Corporate Sender Diverting to Free Webmail | Sender Verification | +18 pts |
| `FROM_RETURN_PATH_MISMATCH` | Return-Path Envelope Inconsistency | Sender Verification | +15 pts |
| `MISSING_ESSENTIAL_HEADERS` | Missing RFC 5322 Required Headers | Header Integrity | +10 pts |
| `CREDENTIAL_REQUEST_CUES` | Password or Billing Detail Solicitation | Credential Harvesting | +22 pts |
| `FAKE_SECURITY_WARNINGS` | Alarmist Security Breach Warning | Social Engineering | +18 pts |
| `HIGH_URGENCY_KEYWORDS` | Artificial Deadline or Panic Language | Social Engineering | +15 pts |
| `GENERIC_GREETING` | Impersonal Salutation ("Dear Customer") | Social Engineering | +8 pts |
| `IP_BASED_URL` | Raw IP Host Address in Hyperlink | URL Structure | +30 pts |
| `TYPOSQUATTED_DOMAIN` | Lookalike Domain (Levenshtein / Homoglyph) | Domain Spoofing | +30 pts |
| `MISLEADING_SUBDOMAIN` | Brand Nested in Attacker Subdomain | Domain Spoofing | +25 pts |
| `HTML_ANCHOR_TEXT_MISMATCH` | Displayed Text Contradicts Actual `href` | URL Deception | +25 pts |
| `BASIC_AUTH_IN_URL` | RFC 3986 Authority Credential Trick (`@`) | URL Deception | +25 pts |
| `LOGIN_KEYWORD_IN_NON_OFFICIAL_URL` | Login Endpoint on Unrecognized Domain | Credential Harvesting | +20 pts |
| `HEX_PUNYCODE_OBFUSCATION` | Encoded Characters or IDN Homograph (`xn--`) | Obfuscation | +18 pts |
| `SUSPICIOUS_TLD` | Known High-Abuse Top-Level Domain | Domain Reputation | +15 pts |
| `NON_STANDARD_PORT` | Unconventional Web Port (e.g., 8080, 8888) | URL Structure | +15 pts |
| `URL_SHORTENER` | Destination Obfuscation via Shortener | Obfuscation | +12 pts |
| `MULTIPLE_SUBDOMAINS` | Excessive Subdomain Chaining (> 3 Levels) | URL Structure | +10 pts |

---

## 5. Risk Scoring Engine & Thresholds

The composite score is calculated by aggregating weights of all unique detected indicators and capping the total at 100 points:

$$\text{Risk Score} = \min\left(100, \sum_{i \in \text{Detected}} \text{Weight}_i\right)$$

### Severity Tiers

```
  [0 ------------------- 24]  LOW RISK        (Likely Legitimate / Safe)
  [25 ------------------ 49]  MEDIUM RISK     (Suspicious / Exercise Caution)
  [50 ------------------ 74]  HIGH RISK       (Probable Phishing / Threat)
  [75 ----------------- 100]  CRITICAL RISK   (High-Confidence Phishing Attack)
```

- **Low Risk (0–24):** Clean authentication records, verified apex domains, standard correspondence language.
- **Medium Risk (25–49):** Isolated anomalies such as missing SPF records, promotional urgency, or third-party email routing. Requires careful contextual verification.
- **High Risk (50–74):** Multiple compounding red flags such as display name mismatches, alarming breach warnings, or suspicious TLDs. Do not click links.
- **Critical Risk (75–100):** Severe deceptive indicators (e.g., failed SPF/DMARC alongside credential harvesting links, typosquatted brand domains, or deceptive anchor text). Strong probability of active attack.

---

## 6. Synthetic Test Corpus

The repository includes a curated, 100% synthetic test corpus in `corpus/` with zero live exploits or malicious endpoints:

### Legitimate Test Corpus (`corpus/legitimate/`)
1. `legit_01_welcome_newsletter.eml`: Authentic developer newsletter with passing SPF/DKIM/DMARC and standard unsubscribe footer.
2. `legit_02_invoice_receipt.eml`: Transactional receipt from Acme Cloud with aligned headers and zero credential demands.
3. `legit_03_team_meeting_update.eml`: Internal corporate project planning email with valid organizational headers.
4. `legit_04_password_reset_authentic.eml`: Authentic GitHub password reset notification with verified cryptographic signatures.
5. `legit_05_shipping_notification.eml`: Authentic USPS delivery confirmation linking to canonical tracking endpoints.

### Phishing Test Corpus (`corpus/phishing/`)
1. `phish_01_urgent_account_suspension.eml`: PayPal account suspension threat, hard SPF fail, misleading subdomain (`paypal.com.account-update-center.xyz`).
2. `phish_02_fake_security_alert_microsoft.eml`: Display name spoofing ("Microsoft Security Team"), high-abuse TLD (`.top`), and urgent password re-entry demands.
3. `phish_03_ceo_wire_transfer_fraud.eml`: Business Email Compromise (BEC) spoofing the CEO, routing replies to a free Gmail address with wire transfer urgency.
4. `phish_04_paypal_typosquat_credential_harvest.eml`: Typosquatted domain (`paypa1`) and deceptive HTML anchor text mismatch.
5. `phish_05_package_delivery_ip_url.eml`: USPS delivery scam pointing to a raw IP address on port 8080 demanding payment within 24 hours.

### Synthetic URL Corpus (`corpus/urls/`)
- `legitimate_urls.txt`: Known benign canonical web endpoints.
- `suspicious_urls.txt`: Deceptive URLs exhibiting IP hosts, homoglyphs, shorteners, and basic auth tricks.

---

## 7. Installation & Quickstart

### Prerequisites
- Python 3.8 or higher.
- No third-party packages are required to run the core analyzer.

### Quickstart Clone & Run

```bash
# Clone the repository
git clone https://github.com/<your-username>/Sourang-Phishing-Awareness-Analyzer.git
cd Sourang-Phishing-Awareness-Analyzer

# Run the automated demonstration
python demo.py
```

*(Optional) Install development dependencies for pytest and enhanced TLD parsing:*
```bash
pip install -r requirements.txt
```

---

## 8. CLI Usage Guide

The main CLI entrypoint is `analyzer.py`.

```text
usage: analyzer.py [-h] [-e EMAIL] [-u URL] [-c CORPUS] [-i] [-j] [-o OUTPUT] [--demo]

Sourang Phishing Awareness Analyzer v1.0.0

options:
  -h, --help            Show this help message and exit
  -e, --email EMAIL     Path to sample email (.eml) to inspect
  -u, --url URL         Single URL string to inspect
  -c, --corpus CORPUS   Directory path of synthetic corpus (.eml and URL txt files)
  -i, --interactive     Launch interactive analyzer console
  -j, --json            Output results in JSON format
  -o, --output OUTPUT   Write output report to destination file (.json or .md)
  --demo                Run quick automated demo with synthetic samples
```

### Examples

#### 1. Inspect a Single URL
```bash
python analyzer.py --url "http://paypal.com.account-update.xyz/signin"
```

#### 2. Inspect a Single Email File
```bash
python analyzer.py --email corpus/phishing/phish_01_urgent_account_suspension.eml
```

#### 3. Batch Analyze Entire Synthetic Corpus
```bash
python analyzer.py --corpus corpus/
```

#### 4. Export Report to Markdown or JSON
```bash
# Save detailed markdown analysis report
python analyzer.py --email corpus/phishing/phish_02_fake_security_alert_microsoft.eml -o microsoft_phish_report.md

# Save batch corpus results as structured JSON
python analyzer.py --corpus corpus/ --json -o corpus_summary.json
```

#### 5. Interactive Console Mode
```bash
python analyzer.py --interactive
```

#### 6. Graphical User Interface (GUI) Desktop App
You can launch the full desktop graphical interface with visual risk meters, tabbed email/URL analyzers, and one-click sample loaders:
```bash
python gui.py
# or
python analyzer.py --gui
```

---

## 9. Testing & Quality Assurance

The project comes with a comprehensive test suite built on Python's standard `unittest` framework:

```bash
# Run all unit tests and corpus verification
python -m unittest discover tests -v
```

### Verified Test Cases
- `test_ip_based_url`: Confirms raw IP host detection and non-standard port recognition.
- `test_misleading_subdomain`: Verifies brand impersonation across multi-level subdomains.
- `test_typosquatting_homoglyph`: Validates Levenshtein distance and homoglyph substitutions (`paypa1`).
- `test_basic_auth_delimiter`: Checks detection of the `@` symbol trick in URL authority sections.
- `test_clean_legitimate_url`: Ensures zero false alerts on genuine brand URLs.
- `test_display_name_spoofing`: Confirms detection of brand names in display fields with mismatching sending domains.
- `test_reply_to_mismatch_and_free_webmail`: Evaluates BEC and free webmail reply diversions.
- `test_body_urgency_and_credential_cues`: Checks keyword matching for high-urgency and credential requests.
- `test_anchor_text_mismatch`: Tests deceptive HTML anchor tags where displayed text disagrees with `href`.
- `test_corpus_verification`: Validates that 100% of synthetic legitimate samples score `< 25` (Low Risk) and 100% of phishing samples score `≥ 50` (High/Critical Risk).

---

## 10. False-Positive & Ethical Safety Disclaimer

> [!WARNING]
> **False-Positive Notice:**  
> This tool relies on deterministic heuristics, keyword matching, and structural pattern recognition. Legitimate marketing communications, transactional billing notices, or third-party mailing providers (e.g., SendGrid, Mailchimp) may trigger some indicators (such as envelope domain mismatches or promotional urgency). Conversely, sophisticated zero-day targeted spear-phishing may evade standard static heuristics. This software is designed solely for user education, security awareness training, and defensive triage.

> [!IMPORTANT]
> **Ethical & Passive Defense Policy:**  
> This software is strictly defensive. It operates **100% offline** and **never** initiates outbound network connections, port probes, web crawler attacks, or credential harvesting routines.

---

## 11. Step-by-Step GitHub Upload Guide

Follow these steps to upload this project to your GitHub account:

### Option A: Using Git Command Line (Recommended)

1. **Install Git** (if not already installed on your system):
   - Download and install Git from [https://git-scm.com/download/win](https://git-scm.com/download/win).

2. **Open PowerShell / Terminal in the Project Directory:**
   ```powershell
   cd "c:\Users\Sourang_official\OneDrive\Documents\codenova\Project 2"
   ```

3. **Initialize Git and Configure your Identity:**
   ```powershell
   git init
   git config user.name "Sourang"
   git config user.email "your-email@example.com"
   ```

4. **Stage and Commit all Files:**
   ```powershell
   git add .
   git commit -m "Initial commit: Sourang Phishing Awareness Analyzer v1.0.0"
   ```

5. **Create a New Repository on GitHub:**
   - Log into [GitHub](https://github.com).
   - Click the **`+`** icon in the top right corner and choose **New repository**.
   - Repository name: `Sourang-Phishing-Awareness-Analyzer` (or `Project-2-Phishing-Analyzer`).
   - Choose **Public** or **Private**.
   - Leave "Initialize with README" **unchecked** (we already created a comprehensive README).
   - Click **Create repository**.

6. **Link Remote and Push:**
   ```powershell
   git branch -M main
   git remote add origin https://github.com/<YOUR_GITHUB_USERNAME>/Sourang-Phishing-Awareness-Analyzer.git
   git push -u origin main
   ```

---

### Option B: Using GitHub Web Upload (Zero CLI Installation Required)

1. Open [GitHub](https://github.com) in your browser and create a new repository named `Sourang-Phishing-Awareness-Analyzer`.
2. On the empty repository page, click the link: **"uploading an existing file"**.
3. Drag and drop all project folders and files from your folder:
   - `sourang_analyzer/`
   - `corpus/`
   - `tests/`
   - `analyzer.py`
   - `demo.py`
   - `README.md`
   - `LICENSE`
   - `requirements.txt`
   - `pyproject.toml`
   - `.gitignore`
4. Type commit message: `Initial upload: Sourang Phishing Awareness Analyzer` and click **Commit changes**.

---

## 12. License & Author

- **Author:** Sourang
- **Project Name:** Sourang Phishing Awareness Analyzer
- **License:** Licensed under the [MIT License](LICENSE).
