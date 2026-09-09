# VulnX – Recon and Vulnerability Scanner

VulnX is a lightweight but comprehensive cybersecurity reconnaissance and vulnerability scanner for subdomain enumeration, port scanning, header inspection, tech stack fingerprinting, and automated HTML/JSON report generation.

## Features

- 🔍 **Subdomain Enumeration** via Certificate Transparency (`crt.sh`)
- 🚪 **Fast Port Scanner** for common exposed TCP services
- 🛡️ **Security Header Auditor** (CSP, HSTS, X-Frame-Options, Permissions-Policy, etc.)
- 📦 **Tech Stack Fingerprinting** (Web servers, reverse proxies, frameworks, cookies)
- ☠️ **Vulnerability & Advisory Checks** for configuration weaknesses and header gaps
- 📊 **Automated Dashboard Reports** in both JSON and modern HTML formats
- 🔁 **Recursive Subdomain Scanning** with depth control
- ⏳ **Scan Resumption & Review** via `--resume`

## Installation

```bash
git clone https://github.com/your-username/vulnx.git
cd vulnx
pip install -r requirements.txt
```

## Usage

### 1. Basic Scan
Scan a single target with full recon, tech stack detection, port scanning, and subdomain enumeration:
```bash
python main.py --target example.com
```

You can also pass URLs directly:
```bash
python main.py --target https://example.com/
```

### 2. Recursive Subdomain Scan
Recursively discover and scan subdomains up to depth `N`:
```bash
python main.py --target example.com --recursive 1
```

### 3. Review & Re-render Previous Scans
Load a previous JSON scan file to view summary and generate an updated HTML report:
```bash
python main.py --resume exports/example.com/2026-09-09_12-00-00.json
```

## Output & Reports

All scan outputs are neatly saved inside the `exports/<target>/` folder:
- **JSON Data**: `exports/<target>/<timestamp>.json`
- **HTML Report Dashboard**: `exports/<target>/<timestamp>.html`
