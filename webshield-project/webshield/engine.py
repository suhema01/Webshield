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
