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
