"""Audit orchestration: run categories one at a time and collect findings."""

from __future__ import annotations

from typing import Callable, List, Optional

from . import __version__
from .checks import get_checks
from .models import (
    AuditReport,
    CATEGORY_LABELS,
    CATEGORY_ORDER,
    _now_iso,
)
from .transport import Transport

try:
    from secure_logger import get_logger
    _log = get_logger("win_audit")
except Exception:  # pragma: no cover
    import logging
    _log = logging.getLogger("win_audit")


ProgressFn = Callable[[str], None]


class AuditRunner:
    def __init__(
        self,
        transport: Transport,
        target: str,
        categories: Optional[List[str]] = None,
        only: Optional[List[str]] = None,
        exclude: Optional[List[str]] = None,
        progress: Optional[ProgressFn] = None,
    ):
        self.transport = transport
        self.target = target
        self.categories = categories or list(CATEGORY_ORDER)
        self.only = set(only or [])
        self.exclude = set(exclude or [])
        self.progress = progress or (lambda _msg: None)

    def _emit(self, msg: str) -> None:
        try:
            self.progress(msg)
        except Exception:  # noqa: BLE001
            pass

    def run(self) -> AuditReport:
        report = AuditReport(
            target=self.target,
            transport=self.transport.name,
            tool_version=__version__,
            started=_now_iso(),
            categories=list(self.categories),
        )

        # Connectivity / auth probe first.
        probe = self.transport.probe()
        if not probe.ok:
            report.errors.append(f"transport probe failed: {probe.error}")
            self._emit(f"[!] Could not reach target ({probe.error})")
            report.finished = _now_iso()
            return report

        checks = get_checks(self.categories)
        if self.only:
            checks = [c for c in checks if c.id in self.only]
        if self.exclude:
            checks = [c for c in checks if c.id not in self.exclude]

        current_cat = None
        for chk in checks:
            if chk.category != current_cat:
                current_cat = chk.category
                label = CATEGORY_LABELS.get(current_cat, current_cat)
                self._emit(f"\n=== {label} ===")
                _log.info("Starting category", context={"category": current_cat, "target": self.target})

            self._emit(f"  - [{chk.id}] {chk.title}")
            try:
                findings = chk.run(self.transport, self.target)
            except Exception as e:  # noqa: BLE001
                _log.error("Check crashed", context={"check": chk.id, "error": str(e)})
                report.errors.append(f"{chk.id}: {e}")
                continue

            for f in findings:
                report.findings.append(f)
                if f.status in ("FAIL", "WARN"):
                    self._emit(f"      {f.status}/{f.severity}: {f.detail}")

        # Sort: actionable findings first, by severity desc, then category order.
        cat_index = {c: i for i, c in enumerate(CATEGORY_ORDER)}
        status_rank = {"FAIL": 0, "WARN": 1, "ERROR": 2, "INFO": 3, "PASS": 4}
        report.findings.sort(key=lambda f: (
            status_rank.get(f.status, 9),
            -f.severity_rank,
            cat_index.get(f.category, 99),
            f.check_id,
        ))
        report.finished = _now_iso()
        return report
