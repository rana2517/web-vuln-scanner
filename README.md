# Web Application Vulnerability Detection and Security Assessment System

A Python-based automated scanner that crawls a target web application, detects common security vulnerabilities (SQL Injection, Reflected XSS, missing security headers), and generates a professional HTML security assessment report.

## Features
- Automated web crawling (links + forms discovery)
- Session-based authentication for scanning protected pages
- Missing security header detection (CSP, X-Frame-Options, HSTS, X-Content-Type-Options)
- Reflected XSS vulnerability testing
- SQL Injection vulnerability testing
- Automated HTML report generation with severity ratings

## Tools & Technologies
- Python 3
- Requests (HTTP + session handling)
- BeautifulSoup4 (HTML parsing)
- Jinja2 (report templating)
- DVWA (Damn Vulnerable Web Application) — test target
- Docker

## How It Works
1. Logs into the target application and maintains a session
2. Crawls the target page for links and forms
3. Checks HTTP response headers against OWASP-recommended security headers
4. Injects XSS payload into forms and checks for reflection
5. Injects SQL Injection payloads into form fields and URL parameters, checking for database error signatures
6. Compiles all findings into `report.html` with severity levels and remediation recommendations

## Setup & Usage

### 1. Install dependencies
```bash
pip install requests beautifulsoup4 jinja2 --break-system-packages
```

### 2. Run DVWA (test target) locally
```bash
docker run -d -p 8080:80 vulnerables/web-dvwa
```
Open `http://localhost:8080`, login with `admin` / `password`, click **Create / Reset Database**.

### 3. Run the scanner
```bash
python3 scanner.py
```
Enter the target URL when prompted, e.g.:http://localhost:8080/vulnerabilities/sqli/

### 4. View the report
```bash
xdg-open report.html
```

## Sample Results (DVWA)
| Vulnerability | Severity | Status |
|---|---|---|
| Missing Security Headers | Low | Detected |
| Reflected XSS | High | Detected |
| SQL Injection | Critical | Detected |

## OWASP Top 10 Mapping
- SQL Injection → A03:2021 – Injection
- XSS → A03:2021 – Injection
- Missing Security Headers → A05:2021 – Security Misconfiguration

## Disclaimer
This tool is built strictly for educational purposes and authorized security testing (e.g., DVWA, intentionally vulnerable labs). Do not use against systems you don't own or have explicit permission to test.

## Author
Rajesh Kumar — B.E. Computer Science & Cyber Security, SVCT
