# Create WebShield project
mkdir -p webshield-project
cd webshield-project
python3 -m venv venv
source venv/bin/activate

cat > requirements.txt <<'EOF'
requests
beautifulsoup4
flask
jinja2
EOF

pip install -r requirements.txt

mkdir -p webshield/scanners webshield/fixers vulnerable_app/templates reports
touch webshield/__init__.py webshield/scanners/__init__.py webshield/fixers/__init__.py

cat > webshield/config.py <<'PY'
ALLOWED_HOSTS = {"localhost", "127.0.0.1"}
REQUEST_TIMEOUT = 10
USER_AGENT = "WebShield/1.0 (local authorized test)"
MAX_REQUESTS_PER_SECOND = 5
PY

cat > webshield/logging_config.py <<'PY'
import logging

def setup_logging():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )
PY

cat > webshield/models.py <<'PY'
from dataclasses import dataclass
from typing import Optional

@dataclass
class Finding:
    name: str
    severity: str
    url: str
    parameter: Optional[str] = None
    description: str = ""
    remediation: str = ""
    evidence: str = ""
    scanner: str = ""
    fixed: bool = False
PY

cat > webshield/http_client.py <<'PY'
import time
import requests
from urllib.parse import urlparse
from . import config

class HttpClient:
    def __init__(self, allowed_hosts=None):
        self.allowed_hosts = allowed_hosts or config.ALLOWED_HOSTS
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": config.USER_AGENT})
        self.last_request = 0

    def _check_host(self, url):
        host = urlparse(url).hostname
        if host not in self.allowed_hosts:
            raise ValueError(f"Host not allowed: {host}")

    def _rate_limit(self):
        elapsed = time.time() - self.last_request
        min_interval = 1.0 / config.MAX_REQUESTS_PER_SECOND
        if elapsed < min_interval:
            time.sleep(min_interval - elapsed)
        self.last_request = time.time()

    def get(self, url, **kwargs):
        self._check_host(url)
        self._rate_limit()
        return self.session.get(url, timeout=config.REQUEST_TIMEOUT, **kwargs)

    def post(self, url, **kwargs):
        self._check_host(url)
        self._rate_limit()
        return self.session.post(url, timeout=config.REQUEST_TIMEOUT, **kwargs)
PY

cat > webshield/scanners/base.py <<'PY'
from abc import ABC, abstractmethod

class BaseScanner(ABC):
    name = "base"

    @abstractmethod
    def scan(self, target, client):
        pass
PY

cat > webshield/scanners/headers.py <<'PY'
from .base import BaseScanner
from ..models import Finding

class HeadersScanner(BaseScanner):
    name = "headers"

    REQUIRED = {
        "Content-Security-Policy": ("Medium", "Add a CSP to reduce XSS risk."),
        "X-Frame-Options": ("Medium", "Set X-Frame-Options: DENY or SAMEORIGIN."),
        "X-Content-Type-Options": ("Low", "Set X-Content-Type-Options: nosniff."),
        "Strict-Transport-Security": ("Medium", "Use HSTS when HTTPS is enabled."),
        "Referrer-Policy": ("Low", "Set a strict Referrer-Policy."),
        "Permissions-Policy": ("Low", "Restrict browser features."),
    }

    def scan(self, target, client):
        findings = []
        r = client.get(target)
        for header, (severity, remediation) in self.REQUIRED.items():
            if header not in r.headers:
                findings.append(Finding(
                    name=f"Missing security header: {header}",
                    severity=severity,
                    url=target,
                    description=f"The response does not include {header}.",
                    remediation=remediation,
                    scanner=self.name,
                ))
        return findings
PY

cat > webshield/scanners/cookies.py <<'PY'
from .base import BaseScanner
from ..models import Finding

class CookiesScanner(BaseScanner):
    name = "cookies"

    def scan(self, target, client):
        findings = []
        r = client.get(target)
        for cookie in r.cookies:
            issues = []
            if not cookie.secure:
                issues.append("missing Secure")
            if not cookie.has_nonstandard_attr("HttpOnly"):
                issues.append("missing HttpOnly")
            if not cookie.has_nonstandard_attr("SameSite"):
                issues.append("missing SameSite")

            if issues:
                findings.append(Finding(
                    name=f"Insecure cookie: {cookie.name}",
                    severity="Medium",
                    url=target,
                    description="Cookie issues: " + ", ".join(issues),
                    remediation="Set Secure, HttpOnly, and SameSite=Lax/Strict.",
                    scanner=self.name,
                ))
        return findings
PY

cat > webshield/scanners/sensitive_files.py <<'PY'
from .base import BaseScanner
from ..models import Finding
from urllib.parse import urljoin

class SensitiveFilesScanner(BaseScanner):
    name = "sensitive_files"

    PATHS = [
        "/.env",
        "/.git/HEAD",
        "/backup.zip",
        "/phpinfo.php",
        "/server-status",
        "/robots.txt",
    ]

    def scan(self, target, client):
        findings = []
        for path in self.PATHS:
            url = urljoin(target, path)
            try:
                r = client.get(url, allow_redirects=False)
                if r.status_code == 200:
                    severity = "High" if path in ("/.env", "/.git/HEAD", "/backup.zip") else "Low"
                    findings.append(Finding(
                        name=f"Exposed sensitive path: {path}",
                        severity=severity,
                        url=url,
                        description=f"The path {path} returned HTTP 200.",
                        remediation="Remove or restrict access to this file/directory.",
                        scanner=self.name,
                    ))
            except Exception:
                pass
        return findings
PY

cat > webshield/scanners/xss.py <<'PY'
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlencode, urlparse, parse_qs
from .base import BaseScanner
from ..models import Finding

class XSSScanner(BaseScanner):
    name = "xss"

    PAYLOAD = '"><WSHIELD_XSS>'

    def scan(self, target, client):
        findings = []
        r = client.get(target)
        soup = BeautifulSoup(r.text, "html.parser")

        parsed = urlparse(target)
        qs = parse_qs(parsed.query)
        for param in qs:
            test_qs = qs.copy()
            test_qs[param] = [self.PAYLOAD]
            test_url = parsed._replace(query=urlencode(test_qs, doseq=True)).geturl()
            resp = client.get(test_url)
            if "<WSHIELD_XSS>" in resp.text:
                findings.append(Finding(
                    name="Reflected XSS",
                    severity="High",
                    url=test_url,
                    parameter=param,
                    description="User input is reflected without proper encoding.",
                    remediation="Encode output and use a strict Content-Security-Policy.",
                    scanner=self.name,
                ))

        for form in soup.find_all("form"):
            action = form.get("action") or target
            method = (form.get("method") or "get").lower()
            inputs = {i.get("name"): self.PAYLOAD for i in form.find_all("input") if i.get("name")}
            url = urljoin(target, action)
            if method == "post":
                resp = client.post(url, data=inputs)
            else:
                resp = client.get(url, params=inputs)
            if "<WSHIELD_XSS>" in resp.text:
                findings.append(Finding(
                    name="Reflected XSS in form",
                    severity="High",
                    url=url,
                    description="Form input is reflected without encoding.",
                    remediation="Encode output and validate input.",
                    scanner=self.name,
                ))
        return findings
PY

cat > webshield/scanners/sqli.py <<'PY'
from urllib.parse import urlparse, parse_qs, urlencode
from .base import BaseScanner
from ..models import Finding

class SQLiScanner(BaseScanner):
    name = "sqli"

    ERROR_PATTERNS = [
        "SQL syntax", "mysql_fetch", "ORA-", "PostgreSQL",
        "SQLite", "syntax error", "Unclosed quotation mark"
    ]

    def scan(self, target, client):
        findings = []
        parsed = urlparse(target)
        qs = parse_qs(parsed.query)
        for param in qs:
            for payload in ["'", '"']:
                test_qs = qs.copy()
                test_qs[param] = [qs[param][0] + payload]
                test_url = parsed._replace(query=urlencode(test_qs, doseq=True)).geturl()
                resp = client.get(test_url)
                for pattern in self.ERROR_PATTERNS:
                    if pattern.lower() in resp.text.lower():
                        findings.append(Finding(
                            name="Possible SQL Injection",
                            severity="Critical",
                            url=test_url,
                            parameter=param,
                            description="Database error was triggered by a quote character.",
                            remediation="Use parameterized queries / prepared statements.",
                            scanner=self.name,
                        ))
                        break
        return findings
PY

cat > webshield/scanners/csrf.py <<'PY'
from bs4 import BeautifulSoup
from .base import BaseScanner
from ..models import Finding

class CSRFScanner(BaseScanner):
    name = "csrf"

    def scan(self, target, client):
        findings = []
        r = client.get(target)
        soup = BeautifulSoup(r.text, "html.parser")
        for form in soup.find_all("form"):
            if (form.get("method") or "get").lower() != "post":
                continue
            token = form.find("input", attrs={"name": lambda n: n and "csrf" in n.lower()})
            if not token:
                findings.append(Finding(
                    name="Missing CSRF token",
                    severity="Medium",
                    url=target,
                    description="A POST form has no visible CSRF token.",
                    remediation="Add a CSRF token and validate it server-side.",
                    scanner=self.name,
                ))
        return findings
PY

cat > webshield/engine.py <<'PY'
from .scanners.headers import HeadersScanner
from .scanners.cookies import CookiesScanner
from .scanners.sensitive_files import SensitiveFilesScanner
from .scanners.xss import XSSScanner
from .scanners.sqli import SQLiScanner
from .scanners.csrf import CSRFScanner

class ScanEngine:
    def __init__(self, client):
        self.client = client
        self.scanners = [
            HeadersScanner(),
            CookiesScanner(),
            SensitiveFilesScanner(),
            XSSScanner(),
            SQLiScanner(),
            CSRFScanner(),
        ]

    def run(self, target):
        findings = []
        for scanner in self.scanners:
            try:
                findings.extend(scanner.scan(target, self.client))
            except Exception as e:
                print(f"[!] Scanner {scanner.name} failed: {e}")
        return findings
PY

cat > webshield/report.py <<'PY'
import json
from jinja2 import Template

def to_json(findings, path):
    data = [f.__dict__ for f in findings]
    with open(path, "w") as f:
        json.dump(data, f, indent=2)

def to_html(findings, path):
    template = Template("""
    <html><head><title>WebShield Report</title></head><body>
    <h1>WebShield Report</h1>
    <table border="1">
    <tr><th>Name</th><th>Severity</th><th>URL</th><th>Remediation</th></tr>
    {% for f in findings %}
    <tr>
        <td>{{ f.name }}</td>
        <td>{{ f.severity }}</td>
        <td>{{ f.url }}</td>
        <td>{{ f.remediation }}</td>
    </tr>
    {% endfor %}
    </table>
    </body></html>
    """)
    with open(path, "w") as f:
        f.write(template.render(findings=findings))
PY

cat > webshield/fixers/base.py <<'PY'
class BaseFixer:
    def apply(self, target, findings):
        raise NotImplementedError
PY

cat > webshield/fixers/flask_fixer.py <<'PY'
class FlaskFixer:
    def __init__(self, app_path="vulnerable_app/app.py"):
        self.app_path = app_path

    def apply(self, target, findings):
        patch = '''
@app.after_request
def add_security_headers(response):
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Content-Security-Policy"] = "default-src 'self'"
    return response
'''
        with open("reports/security_headers.patch", "w") as f:
            f.write(patch)
        print("[+] Patch written to reports/security_headers.patch")
        print("[!] Review and apply manually, or use the bundled fixed app.")
PY

cat > webshield/cli.py <<'PY'
import argparse
from .logging_config import setup_logging
from .http_client import HttpClient
from .engine import ScanEngine
from .report import to_json, to_html

def main():
    setup_logging()
    parser = argparse.ArgumentParser(description="WebShield local vulnerability scanner")
    parser.add_argument("--target", required=True, help="Target URL, e.g. http://127.0.0.1:5000")
    parser.add_argument("--report", default="reports/report.html")
    parser.add_argument("--json", default=None)
    parser.add_argument("--apply-fixes", action="store_true")
    args = parser.parse_args()

    client = HttpClient()
    engine = ScanEngine(client)
    findings = engine.run(args.target)

    print(f"[+] Found {len(findings)} findings")
    for f in findings:
        print(f"[{f.severity}] {f.name} - {f.url}")

    to_html(findings, args.report)
    if args.json:
        to_json(findings, args.json)

    if args.apply_fixes:
        from .fixers.flask_fixer import FlaskFixer
        FlaskFixer().apply(args.target, findings)
        print("[+] Fixes generated. Re-run the scan to verify.")

if __name__ == "__main__":
    main()
PY

cat > vulnerable_app/app.py <<'PY'
from flask import Flask, request, render_template_string, make_response
import sqlite3

app = Flask(__name__)
app.secret_key = "weak"

@app.route("/")
def index():
    resp = make_response("""
    <h1>Vulnerable Demo</h1>
    <a href="/search?q=test">Search</a><br>
    <a href="/login">Login</a><br>
    <a href="/user?id=1">User</a>
    """)
    resp.set_cookie("session", "abc123")
    return resp

@app.route("/search")
def search():
    q = request.args.get("q", "")
    return render_template_string(f"<h2>Results for {q}</h2>")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        resp = make_response("Logged in")
        resp.set_cookie("session", "abc123")
        return resp
    return """
    <form method="post">
    Username: <input name="username"><br>
    Password: <input name="password" type="password"><br>
    <button type="submit">Login</button>
    </form>
    """

@app.route("/user")
def user():
    uid = request.args.get("id", "1")
    conn = sqlite3.connect(":memory:")
    cur = conn.cursor()
    cur.execute("CREATE TABLE users (id INTEGER, name TEXT)")
    cur.execute("INSERT INTO users VALUES (1, 'Alice')")
    query = f"SELECT name FROM users WHERE id = {uid}"
    try:
        cur.execute(query)
        row = cur.fetchone()
        return f"User: {row[0] if row else 'not found'}"
    except Exception as e:
        return f"SQL error: {e}", 500

@app.route("/.env")
def env_file():
    return "SECRET_KEY=supersecret\nDB_PASSWORD=password123"

if __name__ == "__main__":
    app.run(debug=True, host="127.0.0.1", port=5000)
PY

echo "WebShield project created."
