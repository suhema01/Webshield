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
