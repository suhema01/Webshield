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
