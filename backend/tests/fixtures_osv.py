"""TEST-ONLY synthetic OSV-shaped records. They exercise parsing, scoring and reachability logic.
They are NOT vulnerability data and are never used by the product at runtime."""
from app.engines.vulnerability_intel import LookupResult, Vulnerability


def vuln(vid, cvss_score, fixed, cve=None, source="live"):
    return Vulnerability(id=vid, aliases=[cve] if cve else [], cve=cve, summary=f"synthetic test record {vid}",
                         severity="CRITICAL" if cvss_score >= 9 else "HIGH" if cvss_score >= 7 else "MEDIUM",
                         cvss_score=cvss_score, cvss_vector=None, published=None, modified=None,
                         fixed_versions=fixed, references=[], source=source)


# Test scenario: lodash 4.17.15 (reachable) with a CVSS 7.5 flaw; qs 6.7.0 (reachable via express) 9.8;
# axios 0.21.1 (imported nowhere) 9.8 -> NOT_REACHABLE.
SCENARIO = {
    ("npm", "lodash", "4.17.15"): [vuln("TEST-LODASH-1", 7.5, ["4.17.19", "4.17.21"], "CVE-TEST-0001")],
    ("npm", "qs", "6.7.0"): [vuln("TEST-QS-1", 9.8, ["6.7.3"], "CVE-TEST-0002")],
    ("npm", "axios", "0.21.1"): [vuln("TEST-AXIOS-1", 9.8, ["0.21.2"], "CVE-TEST-0003")],
}


def fake_lookup(comp):
    if not comp.version:
        return LookupResult(comp.ecosystem, comp.name, comp.version, status="missing_version")
    vulns = SCENARIO.get((comp.ecosystem, comp.name, comp.version), [])
    return LookupResult(comp.ecosystem, comp.name, comp.version, vulns=list(vulns), source="live")


def failing_lookup(comp):
    return LookupResult(comp.ecosystem, comp.name, comp.version, source="unavailable", status="timeout",
                        message="OSV.dev request timed out")
