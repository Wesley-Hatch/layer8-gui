"""Data models, enums, and category ordering for the Windows auditor."""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Dict, List, Optional


# --------------------------------------------------------------------------
# Severity + status vocabularies
# --------------------------------------------------------------------------

# Ordered from least to most serious. Used for sorting and summary counts.
SEVERITY_ORDER = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]

# A check produces findings; each finding carries a status.
#   PASS  - the control is configured securely
#   FAIL  - the control is missing/weak (this is a real finding)
#   WARN  - worth a human look, not necessarily a vulnerability
#   INFO  - informational inventory (open ports, installed hotfixes, ...)
#   ERROR - the check could not be evaluated (command failed / no data)
STATUS_VALUES = ["PASS", "FAIL", "WARN", "INFO", "ERROR"]


# --------------------------------------------------------------------------
# Categories - executed in THIS order, one category at a time.
# --------------------------------------------------------------------------

# --- Baseline categories (fast, universally applicable) ---
CATEGORY_MISCONFIG = "misconfiguration"
CATEGORY_PATCH = "patch"
CATEGORY_ACCOUNTS = "accounts"
CATEGORY_NETWORK = "network"
CATEGORY_ENDPOINT = "endpoint"
CATEGORY_LOGGING = "logging"

# --- Advanced / adversary-grade categories (deep profile) ---
CATEGORY_PRIVESC = "privesc"
CATEGORY_CREDS = "credaccess"
CATEGORY_ATTACKSURFACE = "attacksurface"
CATEGORY_HARDENING = "hardening"
CATEGORY_PERSISTENCE = "persistence"
CATEGORY_DETECTION = "detection"
CATEGORY_AD = "activedirectory"

# Baseline set - the original comprehensive audit.
BASELINE_CATEGORIES: List[str] = [
    CATEGORY_MISCONFIG,
    CATEGORY_PATCH,
    CATEGORY_ACCOUNTS,
    CATEGORY_NETWORK,
    CATEGORY_ENDPOINT,
    CATEGORY_LOGGING,
]

# The canonical run order: baseline first, then the deep attack-path categories.
CATEGORY_ORDER: List[str] = BASELINE_CATEGORIES + [
    CATEGORY_PRIVESC,
    CATEGORY_CREDS,
    CATEGORY_ATTACKSURFACE,
    CATEGORY_HARDENING,
    CATEGORY_PERSISTENCE,
    CATEGORY_DETECTION,
    CATEGORY_AD,
]

CATEGORY_LABELS: Dict[str, str] = {
    CATEGORY_MISCONFIG: "Misconfigurations",
    CATEGORY_PATCH: "Patch / Update Status",
    CATEGORY_ACCOUNTS: "Accounts & Permissions",
    CATEGORY_NETWORK: "Network & Services",
    CATEGORY_ENDPOINT: "Endpoint Protection & Encryption",
    CATEGORY_LOGGING: "Logging & Audit Policy",
    CATEGORY_PRIVESC: "Privilege Escalation Vectors",
    CATEGORY_CREDS: "Credential Access & Secrets at Rest",
    CATEGORY_ATTACKSURFACE: "Coercion / Relay / Lateral Movement",
    CATEGORY_HARDENING: "Crypto & Exploit Mitigation Hardening",
    CATEGORY_PERSISTENCE: "Persistence & Compromise Hunt",
    CATEGORY_DETECTION: "Detection & EDR Posture",
    CATEGORY_AD: "Active Directory Attack Surface",
}


def _now_iso() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


@dataclass
class Finding:
    """A single audit result row."""

    check_id: str
    category: str
    title: str
    status: str                 # one of STATUS_VALUES
    severity: str               # one of SEVERITY_ORDER
    target: str
    detail: str = ""            # human summary of what was found
    remediation: str = ""       # how to fix it
    reference: str = ""         # CIS / MS docs pointer
    attack: str = ""            # MITRE ATT&CK technique id(s), e.g. "T1078"
    evidence: str = ""          # raw supporting snippet (trimmed)
    timestamp: str = field(default_factory=_now_iso)

    def to_row(self) -> Dict[str, str]:
        d = asdict(self)
        # Keep evidence compact for CSV.
        if d.get("evidence") and len(d["evidence"]) > 1500:
            d["evidence"] = d["evidence"][:1500] + " ...[truncated]"
        return d

    @property
    def severity_rank(self) -> int:
        try:
            return SEVERITY_ORDER.index(self.severity)
        except ValueError:
            return 0


@dataclass
class AuditReport:
    """The full result set plus run metadata."""

    target: str
    transport: str                       # "local" or "winrm"
    tool_version: str
    started: str
    finished: str = ""
    categories: List[str] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

    def summary(self) -> Dict[str, Dict[str, int]]:
        by_status = {s: 0 for s in STATUS_VALUES}
        by_severity = {s: 0 for s in SEVERITY_ORDER}
        for f in self.findings:
            by_status[f.status] = by_status.get(f.status, 0) + 1
            if f.status in ("FAIL", "WARN"):
                by_severity[f.severity] = by_severity.get(f.severity, 0) + 1
        return {"by_status": by_status, "by_severity_actionable": by_severity}

    def to_dict(self) -> Dict:
        return {
            "meta": {
                "target": self.target,
                "transport": self.transport,
                "tool_version": self.tool_version,
                "started": self.started,
                "finished": self.finished,
                "categories": self.categories,
            },
            "summary": self.summary(),
            "findings": [f.to_row() for f in self.findings],
            "errors": self.errors,
        }
