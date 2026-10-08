"""Version comparison used to choose the minimal fixed version above the installed one."""
from __future__ import annotations

from packaging.version import InvalidVersion, Version


def _key(v: str):
    try:
        return Version(v)
    except InvalidVersion:
        return None


def is_lower(a: str, b: str) -> bool | None:
    """True if a < b. None if either version cannot be compared."""
    ka, kb = _key(a), _key(b)
    if ka is None or kb is None:
        return None
    return ka < kb


def minimal_fix_above(installed: str, fixed_versions: list[str]) -> str | None:
    """Smallest fixed version strictly greater than installed."""
    candidates = []
    for fv in fixed_versions:
        lower = is_lower(installed, fv)
        if lower:
            candidates.append(fv)
    if not candidates:
        return None
    return min(candidates, key=lambda v: _key(v) or Version("0"))
