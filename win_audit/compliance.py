"""
Compliance mapping for the Windows auditor.

Maps each audit finding (by its category) to the relevant controls in three
frameworks a law-enforcement / government IT shop cares about:

  - CJIS  : FBI CJIS Security Policy (policy areas 5.x)
  - CIS   : CIS Critical Security Controls v8
  - NIST  : NIST SP 800-53 Rev.5 control identifiers

It then rolls the findings up per control so a report can show, for each control,
whether the audited host PASSES, needs REVIEW, or FAILS - the basis of a
compliance report. This is an auditor's aid, not a certification; mappings are
pragmatic and should be reviewed against your authoritative control set.
"""

from __future__ import annotations

from typing import Dict, List

from .models import (
    AuditReport,
    CATEGORY_MISCONFIG, CATEGORY_PATCH, CATEGORY_ACCOUNTS, CATEGORY_NETWORK,
    CATEGORY_ENDPOINT, CATEGORY_LOGGING, CATEGORY_PRIVESC, CATEGORY_CREDS,
    CATEGORY_ATTACKSURFACE, CATEGORY_HARDENING, CATEGORY_PERSISTENCE,
    CATEGORY_DETECTION, CATEGORY_AD,
)

FRAMEWORKS = ["CJIS", "CIS", "NIST"]

# Human-readable names for every control id referenced below.
CONTROL_NAMES: Dict[str, str] = {
    # CJIS Security Policy areas
    "CJIS-5.4": "Auditing and Accountability",
    "CJIS-5.5": "Access Control",
    "CJIS-5.6": "Identification and Authentication",
    "CJIS-5.7": "Configuration Management",
    "CJIS-5.8": "Media Protection",
    "CJIS-5.10": "System and Communications Protection and Information Integrity",
    # CIS Controls v8
    "CIS-3": "Data Protection",
    "CIS-4": "Secure Configuration of Enterprise Assets and Software",
    "CIS-5": "Account Management",
    "CIS-6": "Access Control Management",
    "CIS-7": "Continuous Vulnerability Management",
    "CIS-8": "Audit Log Management",
    "CIS-10": "Malware Defenses",
    "CIS-12": "Network Infrastructure Management",
    "CIS-13": "Network Monitoring and Defense",
    # NIST SP 800-53 Rev.5
    "AC-2": "Account Management",
    "AC-3": "Access Enforcement",
    "AC-6": "Least Privilege",
    "AC-17": "Remote Access",
    "AU-2": "Event Logging",
    "AU-6": "Audit Record Review, Analysis, and Reporting",
    "AU-12": "Audit Record Generation",
    "CM-5": "Access Restrictions for Change",
    "CM-6": "Configuration Settings",
    "CM-7": "Least Functionality",
    "IA-5": "Authenticator Management",
    "RA-5": "Vulnerability Monitoring and Scanning",
    "SC-7": "Boundary Protection",
    "SC-8": "Transmission Confidentiality and Integrity",
    "SC-13": "Cryptographic Protection",
    "SC-23": "Session Authenticity",
    "SC-28": "Protection of Information at Rest",
    "SI-2": "Flaw Remediation",
    "SI-3": "Malicious Code Protection",
    "SI-4": "System Monitoring",
}

# Category -> controls in each framework.
CATEGORY_CONTROLS: Dict[str, Dict[str, List[str]]] = {
    CATEGORY_MISCONFIG: {
        "CJIS": ["CJIS-5.7", "CJIS-5.10"], "CIS": ["CIS-4"],
        "NIST": ["CM-6", "SC-7", "AC-17"],
    },
    CATEGORY_PATCH: {
        "CJIS": ["CJIS-5.10"], "CIS": ["CIS-7"], "NIST": ["SI-2", "RA-5"],
    },
    CATEGORY_ACCOUNTS: {
        "CJIS": ["CJIS-5.5", "CJIS-5.6"], "CIS": ["CIS-5", "CIS-6"],
        "NIST": ["AC-2", "AC-6", "IA-5"],
    },
    CATEGORY_NETWORK: {
        "CJIS": ["CJIS-5.7", "CJIS-5.10"], "CIS": ["CIS-4", "CIS-12"],
        "NIST": ["CM-7", "SC-7", "AC-3"],
    },
    CATEGORY_ENDPOINT: {
        "CJIS": ["CJIS-5.10", "CJIS-5.8"], "CIS": ["CIS-10", "CIS-3"],
        "NIST": ["SI-3", "SC-28"],
    },
    CATEGORY_LOGGING: {
        "CJIS": ["CJIS-5.4"], "CIS": ["CIS-8"], "NIST": ["AU-2", "AU-12"],
    },
    CATEGORY_PRIVESC: {
        "CJIS": ["CJIS-5.5"], "CIS": ["CIS-4", "CIS-6"], "NIST": ["AC-6", "CM-5"],
    },
    CATEGORY_CREDS: {
        "CJIS": ["CJIS-5.6", "CJIS-5.10"], "CIS": ["CIS-3", "CIS-5"],
        "NIST": ["IA-5", "SC-28"],
    },
    CATEGORY_ATTACKSURFACE: {
        "CJIS": ["CJIS-5.10"], "CIS": ["CIS-4", "CIS-12"],
        "NIST": ["SC-8", "SC-23", "CM-7"],
    },
    CATEGORY_HARDENING: {
        "CJIS": ["CJIS-5.10"], "CIS": ["CIS-3", "CIS-4"], "NIST": ["SC-8", "SC-13"],
    },
    CATEGORY_PERSISTENCE: {
        "CJIS": ["CJIS-5.10", "CJIS-5.4"], "CIS": ["CIS-10", "CIS-4"],
        "NIST": ["SI-3", "SI-4", "CM-7"],
    },
    CATEGORY_DETECTION: {
        "CJIS": ["CJIS-5.4", "CJIS-5.10"], "CIS": ["CIS-8", "CIS-10", "CIS-13"],
        "NIST": ["SI-4", "AU-6", "SI-3"],
    },
    CATEGORY_AD: {
        "CJIS": ["CJIS-5.5", "CJIS-5.6"], "CIS": ["CIS-5", "CIS-6"],
        "NIST": ["AC-2", "AC-6", "IA-5"],
    },
}


def _control_status(statuses: set) -> str:
    if "FAIL" in statuses:
        return "FAIL"
    if "WARN" in statuses:
        return "REVIEW"
    if "PASS" in statuses:
        return "PASS"
    if "ERROR" in statuses:
        return "NEEDS DATA"
    return "INFO"


def build_compliance(report: AuditReport) -> Dict[str, List[dict]]:
    """Return {framework: [ {control, name, status, checks, issues, failing_checks} ]}."""
    # framework -> control -> list of findings
    acc: Dict[str, Dict[str, list]] = {fw: {} for fw in FRAMEWORKS}
    for f in report.findings:
        controls = CATEGORY_CONTROLS.get(f.category)
        if not controls:
            continue
        for fw in FRAMEWORKS:
            for ctrl in controls.get(fw, []):
                acc[fw].setdefault(ctrl, []).append(f)

    result: Dict[str, List[dict]] = {}
    for fw in FRAMEWORKS:
        rows = []
        for ctrl, findings in sorted(acc[fw].items()):
            statuses = {f.status for f in findings}
            failing = sorted({f.check_id for f in findings if f.status in ("FAIL", "WARN")})
            rows.append({
                "control": ctrl,
                "name": CONTROL_NAMES.get(ctrl, ctrl),
                "status": _control_status(statuses),
                "checks": len({f.check_id for f in findings}),
                "issues": len(failing),
                "failing_checks": failing,
            })
        # FAIL first, then REVIEW, then the rest; then by control id.
        order = {"FAIL": 0, "REVIEW": 1, "NEEDS DATA": 2, "PASS": 3, "INFO": 4}
        rows.sort(key=lambda r: (order.get(r["status"], 9), r["control"]))
        result[fw] = rows
    return result


def compliance_summary_lines(compliance: Dict[str, List[dict]]) -> List[str]:
    lines = ["", "=" * 60, "Compliance mapping (CJIS / CIS v8 / NIST 800-53)", "=" * 60]
    for fw in FRAMEWORKS:
        rows = compliance.get(fw, [])
        fails = sum(1 for r in rows if r["status"] == "FAIL")
        reviews = sum(1 for r in rows if r["status"] == "REVIEW")
        passes = sum(1 for r in rows if r["status"] == "PASS")
        lines.append("")
        lines.append(f"[{fw}]  controls touched: {len(rows)}  "
                     f"FAIL={fails}  REVIEW={reviews}  PASS={passes}")
        for r in rows:
            if r["status"] in ("FAIL", "REVIEW"):
                fc = ", ".join(r["failing_checks"][:6])
                more = f" (+{len(r['failing_checks']) - 6})" if len(r["failing_checks"]) > 6 else ""
                lines.append(f"   {r['status']:<10} {r['control']:<9} {r['name']}  -> {fc}{more}")
    lines.append("")
    lines.append("Note: pragmatic control mapping to aid an audit; verify against your")
    lines.append("authoritative CJIS/CIS/NIST control set. Not a certification.")
    return lines
