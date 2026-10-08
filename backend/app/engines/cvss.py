"""CVSS v3.0/3.1 base score calculator (FIRST specification). Deterministic, no network."""
from __future__ import annotations

import math

_W = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62},
    "C": {"H": 0.56, "L": 0.22, "N": 0.0},
    "I": {"H": 0.56, "L": 0.22, "N": 0.0},
    "A": {"H": 0.56, "L": 0.22, "N": 0.0},
}
_PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.5}


def _roundup(x: float) -> float:
    i = round(x * 100000)
    if i % 10000 == 0:
        return i / 100000.0
    return (math.floor(i / 10000) + 1) / 10.0


def parse_vector(vector: str) -> dict[str, str] | None:
    if not isinstance(vector, str) or not vector.startswith("CVSS:3"):
        return None
    parts = dict(p.split(":", 1) for p in vector.split("/")[1:] if ":" in p)
    required = {"AV", "AC", "PR", "UI", "S", "C", "I", "A"}
    if not required.issubset(parts):
        return None
    return parts


def base_score(vector: str) -> float | None:
    """Return CVSS v3 base score for a vector string, or None if the vector is malformed."""
    m = parse_vector(vector)
    if m is None:
        return None
    try:
        changed = m["S"] == "C"
        pr = (_PR_CHANGED if changed else _PR_UNCHANGED)[m["PR"]]
        iss = 1 - (1 - _W["C"][m["C"]]) * (1 - _W["I"][m["I"]]) * (1 - _W["A"][m["A"]])
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if changed else 6.42 * iss
        exploit = 8.22 * _W["AV"][m["AV"]] * _W["AC"][m["AC"]] * pr * _W["UI"][m["UI"]]
    except KeyError:
        return None
    if impact <= 0:
        return 0.0
    if changed:
        return _roundup(min(1.08 * (impact + exploit), 10))
    return _roundup(min(impact + exploit, 10))


def severity_from_score(score: float | None) -> str:
    if score is None:
        return "UNKNOWN"
    if score == 0:
        return "NONE"
    if score < 4.0:
        return "LOW"
    if score < 7.0:
        return "MEDIUM"
    if score < 9.0:
        return "HIGH"
    return "CRITICAL"
