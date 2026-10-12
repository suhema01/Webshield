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
