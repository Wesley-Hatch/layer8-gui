"""
Command-line entry point for the Layer8 Windows Vulnerability Auditor.

Examples
--------
Audit the local machine, writing both CSV and JSON to ./reports/<host>-<ts>:
    python -m win_audit

Audit a remote host over WinRM (prompts for the password):
    python -m win_audit --target 10.0.0.15 --winrm --username AGENCY\\svc_audit

Only run two categories, JSON only, to a chosen prefix:
    python -m win_audit --categories misconfiguration,patch --format json --out C:\\reports\\dc01

List every check without running anything:
    python -m win_audit --list-checks
"""

from __future__ import annotations

import argparse
import getpass
import os
import re
import sys
from datetime import datetime

from . import __version__
from .checks import checks_by_category, get_checks
from .models import BASELINE_CATEGORIES, CATEGORY_LABELS, CATEGORY_ORDER
from .reporting import print_summary, write_reports
from .runner import AuditRunner
from .transport import LocalTransport, WinRMTransport

try:
    from input_validator import InputValidator  # reuse Layer8 validation
except Exception:  # pragma: no cover
    InputValidator = None


def _safe_name(text: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]", "_", text) or "host"


def _default_prefix(target: str) -> str:
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    return os.path.join("reports", f"{_safe_name(target)}-{ts}")


def _parse_categories(value: str):
    cats = [c.strip() for c in value.split(",") if c.strip()]
    bad = [c for c in cats if c not in CATEGORY_ORDER]
    if bad:
        raise argparse.ArgumentTypeError(
            f"unknown categor(y/ies): {', '.join(bad)}. Valid: {', '.join(CATEGORY_ORDER)}")
    return cats


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="win_audit",
        description="Layer8 Windows vulnerability auditor (read-only, authorized use only).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--version", action="version", version=f"win_audit {__version__}")

    tgt = p.add_argument_group("target")
    tgt.add_argument("--target", default="localhost",
                     help="Hostname/IP to audit (default: localhost = this machine).")
    tgt.add_argument("--winrm", action="store_true",
                     help="Audit the target remotely over WinRM (default is local).")
    tgt.add_argument("--username", help="WinRM username (DOMAIN\\user or user@domain).")
    tgt.add_argument("--password", help="WinRM password (prefer the prompt or WIN_AUDIT_PASSWORD env).")
    tgt.add_argument("--auth", default="ntlm", choices=["ntlm", "kerberos", "basic", "credssp"],
                     help="WinRM auth mechanism (default: ntlm).")
    tgt.add_argument("--ssl", action="store_true", help="Use HTTPS/WinRM 5986.")
    tgt.add_argument("--no-verify", action="store_true", help="Do not validate the WinRM TLS certificate.")
    tgt.add_argument("--port", type=int, help="Override the WinRM port.")
    tgt.add_argument("--timeout", type=int, default=120, help="Per-command timeout seconds (default 120).")

    sel = p.add_argument_group("selection")
    sel.add_argument("--profile", choices=["baseline", "deep"], default="deep",
                     help="baseline = the 6 fast config categories; deep = all 13 incl. "
                          "privesc/creds/coercion/persistence/AD (default: deep).")
    sel.add_argument("--categories", type=_parse_categories,
                     help=f"Comma list to run (overrides --profile). In order: {', '.join(CATEGORY_ORDER)}")
    sel.add_argument("--only", help="Comma list of check IDs to run exclusively.")
    sel.add_argument("--exclude", help="Comma list of check IDs to skip.")

    out = p.add_argument_group("output")
    out.add_argument("--format", choices=["csv", "json", "both"], default="both",
                     help="Output format (default both).")
    out.add_argument("--out", help="Output path prefix (extension added). Default: reports/<host>-<ts>.")
    out.add_argument("--quiet", action="store_true", help="Suppress per-check progress.")

    p.add_argument("--list-checks", action="store_true", help="List all checks and exit.")
    p.add_argument("--yes", action="store_true",
                   help="Skip the authorization confirmation prompt (for scripted/authorized runs).")
    return p


def _list_checks() -> int:
    grouped = checks_by_category()
    for cat in CATEGORY_ORDER:
        print(f"\n[{cat}] {CATEGORY_LABELS.get(cat, cat)}")
        for chk in grouped.get(cat, []):
            print(f"  {chk.id:<14} {chk.title}  (fail severity: {chk.severity})")
    total = sum(len(v) for v in grouped.values())
    print(f"\n{total} checks across {len(CATEGORY_ORDER)} categories.")
    return 0


def _confirm_authorization(target: str, remote: bool) -> bool:
    where = f"remote host '{target}' over WinRM" if remote else f"local machine ('{target}')"
    print("Layer8 Windows Auditor - AUTHORIZED USE ONLY")
    print(f"About to run read-only audit checks against the {where}.")
    try:
        ans = input("Confirm you are authorized to assess this system [y/N]: ").strip().lower()
    except EOFError:
        return False
    return ans in ("y", "yes")


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)

    if args.list_checks:
        return _list_checks()

    target = args.target
    remote = args.winrm

    # Validate target format when possible (reuse Layer8's validator).
    if remote and InputValidator is not None and target.lower() not in ("localhost", "127.0.0.1"):
        ok, err = InputValidator.validate_target(target)
        if not ok:
            print(f"[!] Invalid target: {err}", file=sys.stderr)
            return 2

    if not args.yes and not _confirm_authorization(target, remote):
        print("Aborted: authorization not confirmed.")
        return 1

    # Build transport.
    if remote:
        if not args.username:
            print("[!] --winrm requires --username", file=sys.stderr)
            return 2
        password = args.password or os.environ.get("WIN_AUDIT_PASSWORD")
        if not password:
            password = getpass.getpass(f"WinRM password for {args.username}@{target}: ")
        try:
            transport = WinRMTransport(
                target, args.username, password,
                use_ssl=args.ssl, port=args.port, auth=args.auth,
                verify_ssl=not args.no_verify, timeout=args.timeout,
            )
        except RuntimeError as e:
            print(f"[!] {e}", file=sys.stderr)
            return 2
    else:
        transport = LocalTransport(timeout=args.timeout)

    if args.categories:
        categories = args.categories
    elif args.profile == "baseline":
        categories = list(BASELINE_CATEGORIES)
    else:
        categories = list(CATEGORY_ORDER)
    only = [s.strip() for s in args.only.split(",")] if args.only else None
    exclude = [s.strip() for s in args.exclude.split(",")] if args.exclude else None

    progress = (lambda _m: None) if args.quiet else (lambda m: print(m))

    runner = AuditRunner(transport, target, categories=categories,
                         only=only, exclude=exclude, progress=progress)
    print(f"\nStarting Layer8 audit of '{target}' via {transport.name} ...")
    report = runner.run()

    prefix = args.out or _default_prefix(target)
    written = write_reports(report, prefix, args.format)
    print_summary(report)
    print("\nReports written:")
    for w in written:
        print(f"  {w}")

    # Exit non-zero when there are FAIL findings (useful for CI/scheduled runs).
    fails = sum(1 for f in report.findings if f.status == "FAIL")
    return 3 if fails else 0


if __name__ == "__main__":
    raise SystemExit(main())
