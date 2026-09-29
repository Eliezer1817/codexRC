# codexRC

**Automated Web Security Auditing Tool** with local visual pipeline (n8n-style).

Built for bug bounty hunters. Supports authenticated scanning, technology fingerprinting, CVE correlation, form analysis and structured reporting.

> Only use on targets you are authorized to test.

## Features

- **3 Authentication methods** (improved)
  - Session Cookies (recommended)
  - Automatic form login with CSRF + field auto-detection
  - Bearer / JWT / Custom headers
- **Tech detection** (headers, meta, content, cookies)
- **CVE Matcher** (CIRCL API correlation)
- **Local visual dashboard** (pipeline nodes + live status)
- Modular pipeline ready for extension
- Reports reusable (structure ready)

## Quick Start

```bash
git clone https://github.com/Eliezer1817/codexRC.git
cd codexRC
pip install -r requirements.txt

# Run the local backend + dashboard
uvicorn backend.main:app --reload --host 0.0.0.0 --port 8000
```

Open in browser: **http://localhost:8000/**

You will see the visual pipeline (nodes) and can launch scans with optional authentication.

## Project Structure

```
codexRC/
├── core/
│   ├── auth.py            # 3 auth methods (improved)
│   ├── recon.py           # Headers, security headers, redirects
│   ├── tech_detect.py     # Technology fingerprinting
│   ├── cve_matcher.py     # CVE correlation via CIRCL
│   └── pipeline.py        # Node orchestrator
├── backend/
│   └── main.py            # FastAPI + API + serves dashboard
├── frontend/
│   └── index.html         # Visual pipeline UI (n8n-style)
├── config/
├── reports/
└── requirements.txt
```

## Authentication (Python)

```python
from core.auth import AuthManager

auth = AuthManager()

# 1. Cookies
auth.load_cookies_from_file("cookies.txt")
# or auth.set_cookies({"sessionid": "abc"})

# 2. Auto login (detects CSRF + fields)
auth.login_with_credentials(
    login_url="https://target.com/login",
    username="user",
    password="pass"
)

# 3. Token
auth.set_bearer_token("eyJhbGciOi...")
```

## CVE Matching

```python
from core.cve_matcher import CVEMatcher

m = CVEMatcher()
report = m.match_technologies([
    {"name": "WordPress", "version": "5.8.1"},
    {"name": "jQuery", "version": "3.5.0"},
])
print(report)
m.close()
```

## Status

- [x] Project scaffold
- [x] Auth module (3 methods + improvements)
- [x] Recon module
- [x] Tech detection
- [x] CVE matcher
- [x] Local visual dashboard (basic n8n-style)
- [ ] Form crawler / deeper analysis
- [ ] Session persistence UI
- [ ] Export .txt / JSON reports from UI
- [ ] WebSocket live updates

## Disclaimer

This tool is intended for authorized security testing and bug bounty programs only. The authors are not responsible for any misuse.
