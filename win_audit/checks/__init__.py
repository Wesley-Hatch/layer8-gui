"""
Check registry.

Importing this package imports every check module, which runs the @register
decorators and populates the global registry in base.py.
"""

from __future__ import annotations

from typing import Dict, List

from ..models import CATEGORY_ORDER
from .base import BaseCheck, all_checks  # noqa: F401

# Import order does not matter for correctness; each module self-registers.
from . import misconfig    # noqa: F401,E402
from . import patches      # noqa: F401,E402
from . import accounts     # noqa: F401,E402
from . import network      # noqa: F401,E402
from . import endpoint     # noqa: F401,E402
from . import logging_audit  # noqa: F401,E402
from . import privesc      # noqa: F401,E402
from . import credaccess   # noqa: F401,E402
from . import attacksurface  # noqa: F401,E402
from . import hardening    # noqa: F401,E402
from . import persistence  # noqa: F401,E402
from . import detection    # noqa: F401,E402
from . import activedirectory  # noqa: F401,E402


def checks_by_category() -> Dict[str, List[BaseCheck]]:
    grouped: Dict[str, List[BaseCheck]] = {c: [] for c in CATEGORY_ORDER}
    for chk in all_checks():
        grouped.setdefault(chk.category, []).append(chk)
    return grouped


def get_checks(categories: List[str]) -> List[BaseCheck]:
    """Return checks for the given categories, in canonical category order."""
    grouped = checks_by_category()
    ordered: List[BaseCheck] = []
    for cat in categories:
        ordered.extend(grouped.get(cat, []))
    return ordered
