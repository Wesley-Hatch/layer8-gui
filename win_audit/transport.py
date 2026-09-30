"""
Execution transports.

Every check is a PowerShell script that emits JSON on stdout. A transport is
responsible only for *running* that script and returning the raw result - it
does not interpret it. Two transports are provided:

    LocalTransport  - runs powershell.exe on this machine (subprocess, shell=False)
    WinRMTransport  - runs the script on a remote host over WinRM / PS-Remoting

Both prepend a safety prelude that silences progress/errors and forces UTF-8 so
the JSON parsing downstream is reliable.
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from typing import Optional

try:
    from secure_logger import get_logger  # reuse Layer8's redacting logger
    _log = get_logger("win_audit")
except Exception:  # pragma: no cover - allow standalone use outside Layer8
    import logging
    logging.basicConfig(level=logging.INFO)
    _log = logging.getLogger("win_audit")


# Runs before every check script. Keeps stdout to just our JSON.
PS_PRELUDE = (
    "$ErrorActionPreference='SilentlyContinue';"
    "$ProgressPreference='SilentlyContinue';"
    "$WarningPreference='SilentlyContinue';"
    "try{[Console]::OutputEncoding=[System.Text.Encoding]::UTF8}catch{};"
)


@dataclass
class CommandResult:
    stdout: str = ""
    stderr: str = ""
    returncode: int = 0
    error: Optional[str] = None   # set when the transport itself failed

    @property
    def ok(self) -> bool:
        return self.error is None


class Transport:
    """Interface: run a PowerShell script and return a CommandResult."""

    name = "base"

    def run_ps(self, script: str) -> CommandResult:  # pragma: no cover
        raise NotImplementedError

    def probe(self) -> CommandResult:
        """Quick connectivity/authn check. Returns the hostname on success."""
        return self.run_ps("$env:COMPUTERNAME | ConvertTo-Json -Compress")

    def close(self) -> None:
        pass


class LocalTransport(Transport):
    name = "local"

    def __init__(self, timeout: int = 120):
        self.timeout = timeout

    def run_ps(self, script: str) -> CommandResult:
        cmd = [
            "powershell",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy", "Bypass",
            "-Command", PS_PRELUDE + script,
        ]
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=self.timeout,
                shell=False,
            )
            return CommandResult(
                stdout=proc.stdout or "",
                stderr=proc.stderr or "",
                returncode=proc.returncode,
            )
        except subprocess.TimeoutExpired:
            return CommandResult(error=f"timeout after {self.timeout}s")
        except FileNotFoundError:
            return CommandResult(error="powershell.exe not found on PATH")
        except Exception as e:  # noqa: BLE001
            return CommandResult(error=f"{type(e).__name__}: {e}")


class WinRMTransport(Transport):
    """Remote execution over WinRM. Requires the optional 'pywinrm' package."""

    name = "winrm"

    def __init__(
        self,
        host: str,
        username: str,
        password: str,
        *,
        use_ssl: bool = False,
        port: Optional[int] = None,
        auth: str = "ntlm",
        verify_ssl: bool = True,
        timeout: int = 120,
    ):
        try:
            import winrm  # noqa: F401
        except ImportError as e:  # pragma: no cover
            raise RuntimeError(
                "Remote (WinRM) auditing needs the 'pywinrm' package. "
                "Install it with:  pip install pywinrm"
            ) from e

        self._winrm = __import__("winrm")
        self.host = host
        self.username = username
        self._password = password
        self.use_ssl = use_ssl
        self.port = port or (5986 if use_ssl else 5985)
        self.auth = auth
        self.verify_ssl = verify_ssl
        self.timeout = timeout
        scheme = "https" if use_ssl else "http"
        self._endpoint = f"{scheme}://{host}:{self.port}/wsman"

    def _session(self):
        return self._winrm.Session(
            self._endpoint,
            auth=(self.username, self._password),
            transport=self.auth,
            server_cert_validation="validate" if self.verify_ssl else "ignore",
            operation_timeout_sec=self.timeout,
            read_timeout_sec=self.timeout + 15,
        )

    def run_ps(self, script: str) -> CommandResult:
        try:
            r = self._session().run_ps(PS_PRELUDE + script)
            return CommandResult(
                stdout=(r.std_out or b"").decode("utf-8", "replace"),
                stderr=(r.std_err or b"").decode("utf-8", "replace"),
                returncode=r.status_code,
            )
        except Exception as e:  # noqa: BLE001
            return CommandResult(error=f"{type(e).__name__}: {e}")
