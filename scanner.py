import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from jinja2 import Template
from datetime import datetime

BASE_URL = "http://localhost:8080"


def login(session):
    login_page = session.get(f"{BASE_URL}/login.php")
    soup = BeautifulSoup(login_page.text, "html.parser")
    token_input = soup.find("input", {"name": "user_token"})
    token = token_input["value"] if token_input else ""

    login_data = {
        "username": "admin",
        "password": "password",
        "Login": "Login",
        "user_token": token
    }
    res = session.post(f"{BASE_URL}/login.php", data=login_data)

    if "Login failed" in res.text:
        print("[-] Login failed! Check username/password.")
        return False
    else:
        print("[+] Login successful.")
        return True


def set_security_low(session):
    session.get(f"{BASE_URL}/security.php")
    session.post(f"{BASE_URL}/security.php", data={"security": "low", "seclev_submit": "Submit"})


def crawl(session, url):
    links = set()
    forms = []
    try:
        res = session.get(url, timeout=5)
        soup = BeautifulSoup(res.text, "html.parser")

        for a in soup.find_all("a", href=True):
            links.add(urljoin(url, a["href"]))

        for form in soup.find_all("form"):
            forms.append({
                "action": urljoin(url, form.get("action", "") or url),
                "method": form.get("method", "get").lower(),
                "inputs": [i.get("name") for i in form.find_all("input") if i.get("name")]
            })
    except Exception as e:
        print(f"Crawl error: {e}")

    return links, forms


def check_headers(session, url):
    res = session.get(url, timeout=5)
    headers = res.headers
    required = ["X-Frame-Options", "Content-Security-Policy",
                "Strict-Transport-Security", "X-Content-Type-Options"]
    missing = [h for h in required if h not in headers]
    return missing


def test_xss(session, forms):
    payload = "<script>alert(1)</script>"
    vulnerable = []
    for form in forms:
        data = {inp: payload for inp in form["inputs"]}
        try:
            if form["method"] == "post":
                r = session.post(form["action"], data=data, timeout=5)
            else:
                r = session.get(form["action"], params=data, timeout=5)
            if payload in r.text:
                vulnerable.append(form["action"])
        except Exception:
            pass
    return vulnerable


def test_sqli(session, url, forms):
    payloads = ["'", "' OR '1'='1", "1' -- -"]
    errors = ["sql syntax", "mysql_fetch", "sqlite3.operationalerror", "ora-", "warning: mysql"]
    vulnerable = []

    for payload in payloads:
        try:
            r = session.get(url, params={"id": payload, "Submit": "Submit"}, timeout=5)
            if any(err in r.text.lower() for err in errors):
                vulnerable.append(url)
                break
        except Exception:
            pass

    for form in forms:
        for payload in payloads:
            data = {inp: payload for inp in form["inputs"]}
            try:
                if form["method"] == "post":
                    r = session.post(form["action"], data=data, timeout=5)
                else:
                    r = session.get(form["action"], params=data, timeout=5)
                if any(err in r.text.lower() for err in errors):
                    vulnerable.append(form["action"])
                    break
            except Exception:
                pass

    return vulnerable


def generate_report(target, missing_headers, xss_results, sqli_results):
    template = Template("""
    <html>
    <head><title>Vulnerability Assessment Report</title>
    <style>
        body { font-family: Arial; margin: 40px; background: #f4f4f4; }
        h1 { color: #2c3e50; }
        .section { background: white; padding: 20px; margin-bottom: 15px; border-radius: 8px; }
        .high { color: #e74c3c; font-weight: bold; }
        .medium { color: #e67e22; font-weight: bold; }
        .low { color: #27ae60; }
    </style>
    </head>
    <body>
        <h1>Web Application Vulnerability Assessment Report</h1>
        <p><b>Target:</b> {{ target }}</p>
        <p><b>Scan Date:</b> {{ date }}</p>

        <div class="section">
            <h2>Missing Security Headers <span class="low">(Low Severity)</span></h2>
            <ul>
            {% for h in missing_headers %}
                <li>{{ h }}</li>
            {% else %}
                <li>None found</li>
            {% endfor %}
            </ul>
        </div>

        <div class="section">
            <h2>Cross-Site Scripting (XSS) <span class="high">(High Severity)</span></h2>
            <ul>
            {% for x in xss_results %}
                <li>{{ x }}</li>
            {% else %}
                <li>None found</li>
            {% endfor %}
            </ul>
        </div>

        <div class="section">
            <h2>SQL Injection <span class="high">(Critical Severity)</span></h2>
            <ul>
            {% for s in sqli_results %}
                <li>{{ s }}</li>
            {% else %}
                <li>None found</li>
            {% endfor %}
            </ul>
        </div>

        <div class="section">
            <h2>Recommendations</h2>
            <ul>
                <li>Implement security headers (CSP, X-Frame-Options, HSTS)</li>
                <li>Use parameterized queries / prepared statements to prevent SQLi</li>
                <li>Sanitize and encode all user input to prevent XSS</li>
            </ul>
        </div>
    </body>
    </html>
    """)

    html = template.render(
        target=target,
        date=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        missing_headers=missing_headers,
        xss_results=xss_results,
        sqli_results=sqli_results
    )

    with open("report.html", "w") as f:
        f.write(html)

    print("\n[+] Report saved as report.html")


def main():
    session = requests.Session()

    if not login(session):
        return

    set_security_low(session)

    target = input("Enter target URL to scan (e.g. http://localhost:8080/vulnerabilities/sqli/): ")
    print(f"\n[+] Scanning {target} ...\n")

    links, forms = crawl(session, target)
    print(f"[+] Found {len(links)} links, {len(forms)} forms\n")

    missing_headers = check_headers(session, target)
    print("[+] Missing Security Headers:")
    for h in missing_headers:
        print(f"    - {h}")

    xss_results = test_xss(session, forms)
    print("\n[+] XSS Vulnerable Forms:")
    for f in xss_results:
        print(f"    - {f}")

    sqli_results = test_sqli(session, target, forms)
    print("\n[+] SQL Injection Vulnerable:")
    for f in sqli_results:
        print(f"    - {f}")

    generate_report(target, missing_headers, xss_results, sqli_results)

    print("\n[+] Scan complete.")


if __name__ == "__main__":
    main()
