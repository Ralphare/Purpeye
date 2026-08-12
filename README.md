# PurpEye

**An AI-assisted passive web security scanner for small businesses.**

PurpEye scans a website for common, high-impact security weaknesses, scores the overall risk from 0 to 100, and produces a clear, professional PDF report that explains — in plain English — what's wrong and how to fix it. It's built for people who can't afford a dedicated security team: point it at a site, get an actionable report.

```bash
python3 purpeye.py https://example.com
```

One command runs every check, scores the result, writes a plain-English summary, and opens a PDF report.

---

## Why PurpEye

Most small businesses have a website and no one to check whether it's secure. Professional assessments are expensive, and existing tools are built for experts. PurpEye closes that gap: it runs a broad set of **passive** checks (it only reads what a site openly returns to any visitor — it never attacks or intrudes) and translates the findings into language a non-technical owner can act on.

---

## What it checks

PurpEye runs ten passive checks spanning encryption, configuration, disclosure, and email security:

| Check | What it looks for |
|-------|-------------------|
| HTTPS & Security Headers | Encryption and the key browser-protection headers (HSTS, CSP, X-Frame-Options, etc.) |
| HTTP → HTTPS Redirect | Whether the site forces visitors onto the secure version |
| Software Version Disclosure | Software names/versions leaked in headers or HTML that help attackers |
| Security Misconfiguration | Exposed admin panels, config files (`.env`, `.git`), backups, directory listing |
| Cookie & Session Security | Secure, HttpOnly, and SameSite flags on cookies |
| TLS & Certificate Quality | Certificate validity, expiry, and protocol version |
| HTTP Methods & Web Hygiene | Risky methods, mixed content, `robots.txt` leaks, `security.txt` |
| Information Leakage | Verbose errors, revealing comments, internal paths, exposed emails |
| CORS Configuration | Over-permissive cross-origin policies |
| Email Security Records | SPF and DMARC records that prevent email spoofing |

Each finding is rated **Critical / High / Medium / Low / Info**, and the report includes specific remediation steps for every issue.

---

## Example Reports

PurpEye was validated against two contrasting targets to confirm it
meaningfully distinguishes secure from insecure sites:

- **[Vulnerable site — OWASP Juice Shop](examples/juice-shop-vulnerable-site.pdf)**
  — a deliberately insecure practice application. PurpEye scored it **0/100
  (Critical)**, with findings across every category (no HTTPS, missing
  security headers, insecure cookies, and more).

- **[Secure site — GitHub](examples/github-secure-site.pdf)** — a
  well-configured production site, which scores substantially higher.

This contrast demonstrates the scanner produces meaningful, differentiated
results rather than flagging every site the same way.

---

## How it works

```
purpeye.py                 → main pipeline (one command runs everything)
├── scanner/
│   ├── scan_runner.py      → runs all checks, calculates the 0–100 risk score
│   └── checks/             → one file per security check
├── ai_layer/
│   └── ai_explainer.py     → plain-English summary (offline by default)
├── report/
│   └── report_generator.py → professional PDF report
└── tests/
    └── test_checks.py      → automated tests (run offline, no internet needed)
```

The pipeline is **scan → score → explain → report**. Every check returns the same result format, so adding a new check is a single file plus one line in the runner — the scoring, summary, and report pick it up automatically.

The **risk score** starts at 100 and subtracts a penalty per finding by severity (Critical −40, High −25, Medium −10, Low −3), then maps to a rating: Good (85+), Needs attention (60–84), At risk (35–59), or Critical (below 35).

The **AI explainer** runs in a free offline mode that builds the summary from the scan data. If an Anthropic API key is provided, it automatically upgrades to an AI-written summary — no code changes needed.

---

## Installation

Requires Python 3.9+.

```bash
git clone https://github.com/YOUR-USERNAME/purpeye.git
cd purpeye
pip install -r requirements.txt
```

## Usage

```bash
# Scan a website
python3 purpeye.py https://example.com

# The report saves as report_example.com.pdf and opens automatically
```

## Running the tests

```bash
python3 -m unittest tests.test_checks -v
```

The test suite mocks the network layer, so it runs offline in milliseconds and verifies each check returns the correct severity for controlled inputs.

---

## Responsible use

PurpEye performs **passive** testing only — it reads what a website returns to any ordinary visitor and does not attack, exploit, or intrude. Even so, only scan sites you own or have permission to assess. This tool is for defensive security and education.

---

## Roadmap

- Extend automated test coverage to all checks
- Validation runs against known-vulnerable and known-good targets
- Authorization + domain-ownership verification for any future active testing
- Optional web dashboard

---

## Author

Built by **Tunar Abaszada** as a hands-on cybersecurity project.

*PurpEye — the purple eye that watches your site so you don't have to.*

