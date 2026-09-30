# codexRC

**Automated Web Security Auditing Tool** with local visual pipeline.

Termux-friendly version (Flask backend, no Rust/pydantic-core compilation needed).

> Only use on targets you are authorized to test.

## Quick Start (Termux)

```bash
pkg update -y
pkg install python git -y
pip install --upgrade pip
pip install requests beautifulsoup4 httpx flask rich

cd ~
git clone https://github.com/Eliezer1817/codexRC.git
cd codexRC

python backend/app.py
```

Then open in your phone browser: **http://127.0.0.1:8000**

## Features

- 3 Authentication methods (Cookies, Auto-login, Bearer token)
- Tech detection
- CVE Matcher (CIRCL)
- Visual pipeline dashboard
- Works on Termux without compiling heavy packages

## Project Structure

```
codexRC/
├── core/
│   ├── auth.py
│   ├── recon.py
│   ├── tech_detect.py
│   ├── cve_matcher.py
│   └── pipeline.py
├── backend/
│   └── app.py          # Flask backend (Termux friendly)
├── frontend/
│   └── index.html
└── requirements.txt
```
