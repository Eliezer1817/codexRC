# codexRC

**Automated Web Security Auditing Tool** with local visual pipeline (n8n-style).

Built for bug bounty hunters. Supports authenticated scanning, technology fingerprinting, CVE correlation, form detection and structured reporting.

> Only use on targets you are authorized to test.

## Features

- **3 Authentication methods**
  - Session Cookies (recommended)
  - Automatic form login (username + password)
  - Bearer / JWT / Custom headers
- Modular pipeline (easy to extend)
- Local backend + visual dashboard (coming)
- Tech detection + CVE matching
- Form discovery
- Reports in `.txt` + JSON (reusable)

## Project Structure

```
codexRC/
├── core/                  # Core engine
│   ├── recon.py
│   ├── tech_detect.py
│   ├── auth.py            # 3 auth methods
│   ├── cve_matcher.py
│   ├── crawler.py
│   └── reporter.py
├── backend/               # FastAPI local backend
│   ├── main.py
│   └── pipeline.py
├── frontend/              # Visual dashboard (n8n-style)
├── config/
├── reports/
├── requirements.txt
└── README.md
```

## Quick Start (Termux / Local)

```bash
git clone https://github.com/Eliezer1817/codexRC.git
cd codexRC
pip install -r requirements.txt
```

## Authentication Usage (preview)

```python
from core.auth import AuthManager

auth = AuthManager()

# Method 1: Cookies
auth.load_cookies_from_file("cookies.txt")

# Method 2: Auto login
auth.login_with_credentials(
    login_url="https://target.com/login",
    username="user",
    password="pass"
)

# Method 3: Token
auth.set_bearer_token("eyJhbGciOi...")
```

## Status

🚧 Under active development

- [x] Project scaffold
- [x] Auth module (3 methods)
- [ ] Recon module
- [ ] Tech detection
- [ ] CVE matcher
- [ ] Local visual dashboard
- [ ] Full pipeline

## Disclaimer

This tool is intended for authorized security testing and bug bounty programs only. The authors are not responsible for any misuse.
