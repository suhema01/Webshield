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
