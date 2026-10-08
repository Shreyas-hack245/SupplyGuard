"""End-to-end analysis: components -> vulnerability intel -> reachability -> risk -> remediation -> report.

Honesty rules enforced here:
  * A lookup that failed is reported as failed, never as 'no vulnerabilities'.
  * Data source is reported per run: live / partial / unavailable / cache.
  * Reachability without source code is UNKNOWN, never NOT_REACHABLE.
"""
from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from app.engines.reachability import NOT_REACHABLE, REACHABLE, analyze_reachability
from app.engines.remediation import plan_for_component
from app.engines.risk import compute_risk, priority
from app.engines.sbom_quality import sbom_quality
from app.engines.versions import minimal_fix_above
from app.models.component import Component, ParsedSBOM
from app.engines.vulnerability_intel import LookupResult

Lookup = Callable[[Component], LookupResult]

LIMITATIONS = [
    "Reachability is package-level: it shows that application code can load a vulnerable package, not that the vulnerable function is called.",
    "Internet exposure is a heuristic based on imported server frameworks, not a deployment-level check.",
    "Python reachability does not trace transitive packages without a lockfile.",
]


def analyze(parsed: ParsedSBOM, lookup: Lookup, root: Path | None = None,
            kev: set[str] | None = None, kev_status: str = "unavailable",
            manifests: dict[str, str] | None = None) -> dict:
    comps = [c for c in parsed.components if c.ecosystem != "unknown"]

    # 1. Vulnerability intelligence
    lookups: dict[str, LookupResult] = {}
    failed: list[dict] = []
    skipped: list[dict] = []
    for c in comps:
        res = lookup(c)
        lookups[c.ref] = res
        if res.status == "missing_version":
            skipped.append({"ref": c.ref, "reason": res.message})
        elif res.status != "ok":
            failed.append({"ref": c.ref, "status": res.status, "message": res.message})
    attempted = len(comps) - len(skipped)
    if attempted == 0:
        intel_status = "not-run"
    elif len(failed) == 0:
        intel_status = "live"
    elif len(failed) == attempted:
        intel_status = "unavailable"
    else:
        intel_status = "partial"
    sources = sorted({v.source for r in lookups.values() for v in r.vulns})

    # 2. Reachability
    reach, reach_meta = analyze_reachability(comps, parsed.edges, root)

    # 3. Findings + risk
    findings: list[dict] = []
    by_ref_findings: dict[str, list[dict]] = defaultdict(list)
    for c in comps:
        for v in lookups[c.ref].vulns:
            rr = reach[c.ref]
            fixed = minimal_fix_above(c.version, v.fixed_versions) if c.version else None
            exploit = None if kev is None else (v.cve in kev if v.cve else False)
            exposed = bool(reach_meta.get("exposed")) and rr.status == REACHABLE
            risk = compute_risk(
                cvss=v.cvss_score, reachability=rr.status, exploit_known=exploit,
                internet_exposed=exposed,
                direct=c.direct, fix_available=fixed is not None, depth=c.depth,
            )
            f = {
                "id": f"{c.ref}|{v.id}", "vuln_id": v.id, "cve": v.cve, "aliases": v.aliases,
                "summary": v.summary, "component_ref": c.ref, "name": c.name, "version": c.version,
                "ecosystem": c.ecosystem, "direct": c.direct, "depth": c.depth,
                "severity": v.severity, "cvss": v.cvss_score, "cvss_vector": v.cvss_vector,
                "reachability": rr.status, "reachability_confidence": rr.confidence,
                "reachability_note": rr.note, "reachability_path": rr.path,
                "exploit_known": exploit, "internet_exposed": exposed,
                "risk_score": risk["score"], "risk_capped": risk["capped"], "risk_factors": risk["factors"],
                "priority": priority(risk["score"], rr.status),
                "fixed_version": fixed, "published": v.published, "modified": v.modified,
                "references": v.references, "data_source": v.source,
            }
            findings.append(f)
            by_ref_findings[c.ref].append(f)
    findings.sort(key=lambda x: (-x["risk_score"], x["id"]))

    # 4. Remediation (one plan per vulnerable package)
    comp_by_ref = {c.ref: c for c in comps}
    remediations = []
    for ref, fs in by_ref_findings.items():
        plan = plan_for_component(comp_by_ref[ref], [(f["id"], lookups[ref].vulns[i].fixed_versions)
                                                     for i, f in enumerate(fs)], comp_by_ref[ref].direct)
        if plan:
            remediations.append(plan)

    # 5. Graph (for the dependency view)
    graph = {
        "nodes": [{"id": c.ref, "name": c.name, "version": c.version, "direct": c.direct, "depth": c.depth,
                   "ecosystem": c.ecosystem, "vulnerabilities": len(by_ref_findings.get(c.ref, [])),
                   "reachability": reach[c.ref].status,
                   "risk_level": max((f["priority"] for f in by_ref_findings.get(c.ref, [])),
                                     key=lambda p: ["LOW", "MEDIUM", "HIGH", "IMMEDIATE"].index(p), default="NONE")}
                  for c in comps],
        "edges": [{"parent": e.parent or "__app__", "child": e.child} for e in parsed.edges],
    }

    components_out = [{
        "ref": c.ref, "name": c.name, "version": c.version, "ecosystem": c.ecosystem, "purl": c.purl,
        "direct": c.direct, "depth": c.depth, "license": c.license, "scope": c.scope,
        "reachability": reach[c.ref].status, "vulnerabilities": len(by_ref_findings.get(c.ref, [])),
    } for c in comps]

    # 6. Summary
    sev = defaultdict(int)
    for f in findings:
        sev[f["severity"]] += 1
    reach_count = defaultdict(int)
    for c in comps:
        reach_count[reach[c.ref].status] += 1
    quality = sbom_quality(parsed)
    total_risk = sum(f["risk_score"] for f in findings)
    summary = {
        "total_components": len(comps),
        "direct_dependencies": sum(1 for c in comps if c.direct is True),
        "transitive_dependencies": sum(1 for c in comps if c.direct is False),
        "vulnerable_components": len(by_ref_findings),
        "vulnerabilities": len(findings),
        "critical": sev["CRITICAL"], "high": sev["HIGH"], "medium": sev["MEDIUM"], "low": sev["LOW"],
        "reachable": sum(1 for f in findings if f["reachability"] == REACHABLE),
        "unknown_reachability": sum(1 for f in findings if f["reachability"] == "UNKNOWN"),
        "not_reachable": sum(1 for f in findings if f["reachability"] == NOT_REACHABLE),
        "known_exploited": sum(1 for f in findings if f["exploit_known"]),
        "fixable": sum(1 for f in findings if f["fixed_version"]),
        # A score is only meaningful when vulnerability data was actually obtained.
        "security_score": (max(0, round(100 - 0.1 * total_risk))
                           if intel_status in ("live", "partial") else None),
        "sbom_quality_score": quality["score"],
    }

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "application": parsed.app_name,
        "source_format": parsed.source_format,
        "reachability_mode": reach_meta.get("mode"),
        "reachability_meta": {k: v for k, v in reach_meta.items() if k != "mode"},
        "vulnerability_data": {"status": intel_status, "sources": sources, "failed_lookups": failed,
                               "skipped_lookups": skipped, "kev_status": kev_status},
        "summary": summary,
        "sbom_quality": quality,
        "components": components_out,
        "findings": findings,
        "remediations": remediations,
        "graph": graph,
        "warnings": [{"code": w.code, "message": w.message, "ref": w.ref} for w in parsed.warnings][:200],
        "limitations": LIMITATIONS,
        "manifests": sorted(manifests) if manifests else [],
    }
