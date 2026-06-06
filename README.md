# VulnX — AI-Augmented Web Application Penetration Testing Framework

> OWASP Top 10 · AI-Powered Analysis · Automated Recon · PDF Report Generation

![Python](https://img.shields.io/badge/Python-3.10+-blue?style=flat-square)
![Flask](https://img.shields.io/badge/Flask-REST%20API-lightgrey?style=flat-square)
![OWASP](https://img.shields.io/badge/OWASP-Top%2010-red?style=flat-square)
![AI](https://img.shields.io/badge/AI-Gemini%201.5%20Flash-purple?style=flat-square)
![License](https://img.shields.io/badge/For-Educational%20Use-green?style=flat-square)

---

## Overview

VulnX is a production-grade automated web application penetration testing framework covering 10 OWASP Top 10 vulnerability classes. It combines multithreaded reconnaissance, a depth-configurable web crawler, 10 specialized vulnerability scanners, and Google Gemini AI to auto-generate CWE mappings, CVSS scores, and remediation guidance — all delivered in a professional PDF pentest report.

Built to demonstrate end-to-end offensive security assessment workflows from recon to reporting.

---

## Key Features

### 10 Vulnerability Scanners — OWASP Top 10

| Scanner | Vulnerability | Techniques Used |
|---------|--------------|-----------------|
| SQLi | SQL Injection | Error-based, Time-blind, Boolean, Union-based |
| XSS | Cross-Site Scripting | Reflected, Stored payload detection |
| SSRF | Server-Side Request Forgery | Internal endpoint probing |
| IDOR | Insecure Direct Object Reference | Parameter manipulation |
| LFI | Local File Inclusion | Path traversal payloads |
| CMDi | Command Injection | Shell metacharacter injection |
| Open Redirect | URL Redirection | Redirect parameter fuzzing |
| CSRF | Cross-Site Request Forgery | Token validation analysis |
| JWT | JWT Misconfiguration | Algorithm confusion, none-bypass, weak secret |
| Headers | Security Header Analysis | Missing/misconfigured HTTP headers |

### AI-Powered Vulnerability Analysis
- Integrates **Google Gemini 1.5 Flash API** for per-vulnerability AI analysis
- Auto-generates: **CWE mapping** · **CVSS score estimate** · real-world attack scenario · secure code example · step-by-step remediation
- Graceful fallback when API key not set

### Multithreaded Reconnaissance Engine
- **Subdomain enumeration** — 300+ wordlist with concurrent HTTP validation
- **Port scanning** — 18 common services with banner grabbing and risk classification (Critical / High / Medium / Low)
- **Technology fingerprinting** — detects web stack, frameworks, and server info

### Advanced SQLi Detection
- Dynamic baseline averaging via **difflib similarity scoring** to eliminate false positives on noisy pages
- Union-based column-count auto-detection
- Time-based blind injection with configurable delay thresholds
- Boolean-based differential analysis

### JWT Security Analyzer
- Algorithm confusion attack detection (**RS256 → HS256** downgrade)
- **None-algorithm bypass** testing
- Weak secret brute-forcing
- Missing claims validation (exp, iat, iss)

### Web Crawler
- Depth-configurable crawling with HTML form discovery
- GET/POST parameter extraction
- Session cookie + Authorization header injection for authenticated scans

### Automated PDF Pentest Report
- Client-ready reports via **ReportLab**
- Executive summary · severity breakdown · per-vulnerability detail · payload evidence · AI remediation

---

## Architecture

```
VulnX/
├── app.py                    Flask app + scan orchestration
├── ai_engine/
│   └── gemini_analyzer.py    Gemini 1.5 Flash API — per-vuln AI analysis
├── scanner/
│   ├── sqli.py               SQL Injection (4 techniques)
│   ├── xss.py                Cross-Site Scripting
│   ├── ssrf.py               Server-Side Request Forgery
│   ├── idor.py               Insecure Direct Object Reference
│   ├── lfi.py                Local File Inclusion
│   ├── cmd_injection.py      Command Injection
│   ├── open_redirect.py      Open Redirect
│   ├── csrf.py               CSRF token analysis
│   ├── jwt_analyzer.py       JWT misconfiguration
│   └── headers.py            HTTP security headers
├── recon/
│   ├── subdomain.py          Subdomain enumeration (300+ wordlist)
│   ├── portscan.py           Port scanner (18 services + banner grab)
│   └── tech_detect.py        Technology fingerprinting
├── crawler/
│   └── spider.py             Depth-configurable web crawler
├── reports/
│   └── pdf_generator.py      ReportLab PDF report generator
└── templates/                Flask UI — scan dashboard + report viewer
```

---

## Tech Stack

| Component | Technology |
|-----------|-----------|
| Backend | Python 3.10+, Flask |
| AI Analysis | Google Gemini 1.5 Flash API |
| Scanning | Custom scanners — requests, difflib |
| Recon | socket, concurrent.futures, requests |
| Reporting | ReportLab PDF generation |
| Database | SQLite (scan history + findings) |
| Frontend | HTML/CSS/JS, Jinja2 templates |

---

## Quick Start

```bash
git clone https://github.com/Manasvi1412/VulnX.git
cd VulnX
pip install -r requirements.txt
python app.py
# Open http://localhost:5000
```

### Optional — Enable AI Analysis

```bash
export GEMINI_API_KEY=your_key    # Free at aistudio.google.com
```

> Works fully without API key — rule-based analysis activates automatically.

---

## Disclaimer

> This tool is built for **educational purposes and authorized penetration testing only**.
> Never use against systems without explicit written permission.
> The author is not responsible for any misuse.

---

## Skills Demonstrated

`Web Application Pentesting` · `OWASP Top 10` · `SQL Injection` · `XSS` · `SSRF` · `IDOR` · `LFI` · `JWT Security` · `Reconnaissance` · `AI Integration` · `Penetration Test Reporting` · `Python` · `Flask`
