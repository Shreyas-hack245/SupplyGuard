"""SupplyGuard Risk Score (0-100). Every point is attributable to a named factor, so it can be explained."""
from __future__ import annotations

from app.engines.reachability import NOT_REACHABLE, REACHABLE, UNKNOWN

WEIGHTS = {"cvss": 0.35, "reachability": 0.25, "exploit": 0.15, "exposure": 0.10,
           "direct": 0.05, "fix": 0.05, "depth": 0.05}
REACH_MULTIPLIER = {REACHABLE: 1.0, UNKNOWN: 0.7, NOT_REACHABLE: 0.25}
# Hard cap: code that cannot be reached must never outrank reachable exposure, regardless of CVSS.
NOT_REACHABLE_CAP = 39


def compute_risk(cvss: float | None, reachability: str, exploit_known: bool | None,
                 internet_exposed: bool, direct: bool | None, fix_available: bool,
                 depth: int | None) -> dict:
    factors: list[dict] = []

    def add(name: str, value: float, label: str) -> None:
        w = WEIGHTS[name]
        factors.append({"factor": name, "weight": w, "value": round(value, 3),
                        "contribution": round(w * value * 100, 1), "label": label})

    add("cvss", (cvss / 10) if cvss is not None else 0.5,
        f"CVSS {cvss}" if cvss is not None else "CVSS unavailable (neutral)")
    mult = REACH_MULTIPLIER.get(reachability, 0.7)
    add("reachability", mult, f"{reachability} (multiplier {mult})")
    if exploit_known is None:
        add("exploit", 0.0, "Exploit status unavailable (CISA KEV feed not reached)")
    else:
        add("exploit", 1.0 if exploit_known else 0.0,
            "Listed as known exploited (CISA KEV)" if exploit_known else "Not in CISA KEV")
    add("exposure", 1.0 if internet_exposed else 0.0,
        "Reachable from internet-facing code (heuristic)" if internet_exposed else "No internet-facing path detected")
    add("direct", 1.0 if direct else 0.0,
        "Direct dependency" if direct else ("Transitive dependency" if direct is False else "Direct/transitive unknown"))
    add("fix", 1.0 if fix_available else 0.0,
        "Fixed version published" if fix_available else "No fixed version published")
    dv = 0.5 if depth is None else max(0.0, 1 - (depth - 1) / 4)
    add("depth", dv, f"Dependency depth {depth}" if depth is not None else "Depth unknown")

    raw = sum(f["contribution"] for f in factors)
    score = round(raw)
    capped = False
    if reachability == NOT_REACHABLE and score > NOT_REACHABLE_CAP:
        score, capped = NOT_REACHABLE_CAP, True
    return {"score": score, "raw_score": round(raw), "capped": capped, "factors": factors}


def priority(score: int, reachability: str) -> str:
    if reachability == NOT_REACHABLE:
        return "LOW"
    if score >= 80:
        return "IMMEDIATE"
    if score >= 60:
        return "HIGH"
    if score >= 35:
        return "MEDIUM"
    return "LOW"
