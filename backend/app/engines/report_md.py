"""Render an analysis report as Markdown (for judges and for the Reports tab)."""
from __future__ import annotations


def render_markdown(r: dict) -> str:
    s = r["summary"]
    vd = r["vulnerability_data"]
    L = []
    L.append(f"# SupplyGuard Security Report: {r.get('application') or 'unnamed application'}\n")
    L.append(f"Generated: {r['generated_at']}\n")
    L.append("## 1. Executive Summary\n")
    L.append(f"- Security score: **{s['security_score']}/100**")
    L.append(f"- Vulnerabilities: **{s['vulnerabilities']}** across {s['vulnerable_components']} packages")
    L.append(f"- Reachable from application code: **{s['reachable']}**; unknown: {s['unknown_reachability']}; not reachable: {s['not_reachable']}")
    L.append(f"- Known exploited (CISA KEV): {s['known_exploited']}")
    top = next((f for f in r["findings"] if f["priority"] in ("IMMEDIATE", "HIGH")), None)
    if top:
        L.append(f"- Fix first: **{top['name']} {top['version']}** ({top['cve'] or top['vuln_id']}), risk {top['risk_score']}, reachability {top['reachability']}")
    L.append("")
    L.append("## 2. Vulnerability Data Status\n")
    L.append(f"- Status: **{vd['status']}** (sources: {', '.join(vd['sources']) or 'none'})")
    if vd["failed_lookups"]:
        L.append(f"- {len(vd['failed_lookups'])} lookups failed; those packages were NOT assessed. Reason example: {vd['failed_lookups'][0]['message']}")
    L.append(f"- CISA KEV feed: {vd['kev_status']}\n")
    L.append("## 3. Project Information\n")
    L.append(f"- Source format: {r['source_format']}")
    L.append(f"- Reachability mode: {r['reachability_mode']}\n")
    L.append("## 4. SBOM Summary\n")
    L.append(f"- Components: {s['total_components']} (direct {s['direct_dependencies']}, transitive {s['transitive_dependencies']})")
    L.append(f"- SBOM quality score: **{s['sbom_quality_score']}/100**\n")
    L.append("## 5. Vulnerabilities\n")
    L.append("| Package | Version | CVE | CVSS | Severity | Reachability | Risk | Fixed | Priority |")
    L.append("|---|---|---|---|---|---|---|---|---|")
    for f in r["findings"]:
        L.append(f"| {f['name']} | {f['version']} | {f['cve'] or f['vuln_id']} | {f['cvss'] or 'n/a'} | {f['severity']} | "
                 f"{f['reachability']} | {f['risk_score']} | {f['fixed_version'] or 'none'} | {f['priority']} |")
    L.append("")
    L.append("## 6. Reachability Analysis\n")
    for f in r["findings"]:
        path = " -> ".join(f["reachability_path"]) if f["reachability_path"] else "no path"
        L.append(f"- **{f['name']}** ({f['reachability']}, confidence {f['reachability_confidence']}): {path}. {f['reachability_note']}")
    L.append("")
    L.append("## 7. Risk Prioritization\n")
    L.append("Score = weighted factors (CVSS 35, reachability 25, exploit 15, exposure 10, direct 5, fix 5, depth 5). NOT_REACHABLE findings are capped at 39.\n")
    for f in r["findings"][:10]:
        L.append(f"- **{f['name']} {f['version']}** score {f['risk_score']}" + (" (capped)" if f["risk_capped"] else ""))
        for fac in f["risk_factors"]:
            L.append(f"  - {fac['label']}: +{fac['contribution']}")
    L.append("")
    L.append("## 8. Recommended Remediation\n")
    for p in r["remediations"]:
        L.append(f"- **{p['name']}** {p['current_version']} -> {p['target_version']} ({p['kind']}): `{p['commands'][0]}`")
    L.append("")
    L.append("## 9. Limitations\n")
    for lim in r["limitations"]:
        L.append(f"- {lim}")
    return "\n".join(L) + "\n"
