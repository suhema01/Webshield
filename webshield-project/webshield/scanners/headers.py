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
