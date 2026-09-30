"""Write an AuditReport to CSV and/or JSON, and print a console summary."""

from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import List, Tuple

from .models import AuditReport, SEVERITY_ORDER


CSV_COLUMNS = [
    "timestamp", "target", "category", "check_id", "title",
    "status", "severity", "attack", "detail", "remediation", "reference", "evidence",
]


def write_csv(report: AuditReport, path: str) -> str:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("w", newline="", encoding="utf-8-sig") as fh:
        writer = csv.DictWriter(fh, fieldnames=CSV_COLUMNS, extrasaction="ignore")
        writer.writeheader()
        for f in report.findings:
            writer.writerow(f.to_row())
    return str(p)


def write_json(report: AuditReport, path: str) -> str:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("w", encoding="utf-8") as fh:
        json.dump(report.to_dict(), fh, indent=2, ensure_ascii=False)
    return str(p)


def write_reports(report: AuditReport, prefix: str, fmt: str) -> List[str]:
    """fmt in {'csv','json','both'}. Returns the paths written."""
    written: List[str] = []
    if fmt in ("csv", "both"):
        written.append(write_csv(report, prefix + ".csv"))
    if fmt in ("json", "both"):
        written.append(write_json(report, prefix + ".json"))
    return written


def summary_lines(report: AuditReport) -> List[str]:
    s = report.summary()
    lines = ["", "=" * 60, f"Audit summary for {report.target} ({report.transport})", "=" * 60]
    by_status = s["by_status"]
    lines.append("By status:   " + "  ".join(f"{k}={v}" for k, v in by_status.items() if v))
    sev = s["by_severity_actionable"]
    lines.append("Actionable:  " + "  ".join(
        f"{k}={sev[k]}" for k in reversed(SEVERITY_ORDER) if sev.get(k)))
    # Top findings preview.
    actionable = [f for f in report.findings if f.status in ("FAIL", "WARN")]
    if actionable:
        lines.append("")
        lines.append("Top findings:")
        for f in actionable[:12]:
            detail = f.detail if len(f.detail) <= 150 else f.detail[:147] + "..."
            tag = f" [{f.attack}]" if f.attack else ""
            lines.append(f"  [{f.severity:<8}] {f.check_id}{tag}  {detail}")
    if report.errors:
        lines.append("")
        lines.append(f"Run errors: {len(report.errors)} (see JSON 'errors')")
    return lines


def print_summary(report: AuditReport) -> None:
    print("\n".join(summary_lines(report)))
