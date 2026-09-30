"""
Base class + registry for audit checks.

A check is a small class that provides:
  - metadata (id, title, category, default severity, reference, remediation)
  - a PowerShell script (`ps`) that prints JSON to stdout
  - an `evaluate(data, raw, target)` method turning that JSON into Findings

Register a check by decorating the class with @register. Instances are created
once at import time and collected in a global registry.
"""

from __future__ import annotations

import json
from typing import Any, List, Optional

from ..models import Finding
from ..transport import CommandResult, Transport


_REGISTRY: List["BaseCheck"] = []


def register(cls):
    """Class decorator: instantiate and add the check to the registry."""
    _REGISTRY.append(cls())
    return cls


def all_checks() -> List["BaseCheck"]:
    return list(_REGISTRY)


def parse_json(text: str) -> Any:
    """Parse PowerShell ConvertTo-Json output; tolerate empty/whitespace."""
    text = (text or "").strip()
    if not text:
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        # PowerShell sometimes prefixes stray text; try from first brace/bracket.
        for i, ch in enumerate(text):
            if ch in "[{":
                try:
                    return json.loads(text[i:])
                except json.JSONDecodeError:
                    break
        return None


def as_list(data: Any) -> List[Any]:
    """PowerShell emits a bare object for one item, a list for many. Normalize."""
    if data is None:
        return []
    if isinstance(data, list):
        return data
    return [data]


class BaseCheck:
    id: str = ""
    title: str = ""
    category: str = ""
    severity: str = "MEDIUM"          # severity applied when a finding FAILs
    reference: str = ""
    remediation: str = ""
    attack: str = ""                  # MITRE ATT&CK technique id(s)
    ps: str = ""                      # PowerShell that prints JSON

    # ---- Finding builders -------------------------------------------------
    def finding(
        self,
        target: str,
        status: str,
        detail: str,
        *,
        severity: Optional[str] = None,
        evidence: str = "",
        remediation: Optional[str] = None,
        reference: Optional[str] = None,
        attack: Optional[str] = None,
        title: Optional[str] = None,
    ) -> Finding:
        sev = severity or (self.severity if status in ("FAIL", "WARN") else "INFO")
        return Finding(
            check_id=self.id,
            category=self.category,
            title=title or self.title,
            status=status,
            severity=sev,
            target=target,
            detail=detail,
            remediation=(remediation if remediation is not None else self.remediation),
            reference=(reference if reference is not None else self.reference),
            attack=(attack if attack is not None else self.attack),
            evidence=(evidence or "")[:2000],
        )

    def _error(self, target: str, raw: CommandResult, msg: str = "") -> Finding:
        why = msg or raw.error or (raw.stderr.strip()[:300]) or "no data returned"
        return self.finding(
            target, "ERROR",
            detail=f"Check could not be evaluated: {why}",
            severity="INFO",
            evidence=(raw.stderr or "")[:500],
            remediation="Re-run with appropriate privileges / connectivity.",
        )

    # ---- Orchestration ----------------------------------------------------
    def evaluate(self, data: Any, raw: CommandResult, target: str) -> List[Finding]:
        raise NotImplementedError

    def run(self, transport: Transport, target: str) -> List[Finding]:
        raw = transport.run_ps(self.ps)
        if not raw.ok:
            return [self._error(target, raw)]
        data = parse_json(raw.stdout)
        if data is None and not raw.stdout.strip():
            # Genuinely empty result - many checks treat this as "nothing found".
            try:
                return self.evaluate(None, raw, target)
            except NotImplementedError:
                return [self._error(target, raw, "empty output")]
        try:
            return self.evaluate(data, raw, target)
        except Exception as e:  # noqa: BLE001
            return [self._error(target, raw, f"parse error: {e}")]
