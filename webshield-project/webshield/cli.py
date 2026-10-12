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
