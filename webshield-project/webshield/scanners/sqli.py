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
