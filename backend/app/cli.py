"""Command-line scanner. Same engine as the web API.

  python -m app.cli scan examples/vulnerable-app --out reports/
  python -m app.cli scan examples/vulnerable-app/sbom.cdx.json --out reports/
"""
from __future__ import annotations

import argparse
import json
import sys
import tempfile
import zipfile
from pathlib import Path

from app.core.config import settings
from app.engines.kev import load_kev
from app.engines.pipeline import analyze
from app.engines.project import parse_project
from app.engines.report_md import render_markdown
from app.engines.vulnerability_intel import OsvClient, VulnCache
from app.parsers.detect import parse_sbom


def run(path: Path) -> dict:
    cache = VulnCache(settings.cache_path)
    client = OsvClient(cache, url=settings.osv_url)
    kev, kev_status = load_kev(cache)
    if path.is_dir():
        parsed, texts = parse_project(path)
        root = path
    else:
        parsed = parse_sbom(path.name, path.read_bytes())
        texts, root = {}, None
    report = analyze(parsed, lambda c: client.lookup(c.ecosystem, c.name, c.version),
                     root=root, kev=kev, kev_status=kev_status, manifests=texts)
    client.close()
    return report


def _print(r: dict) -> None:
    s = r["summary"]
    status = r["vulnerability_data"]["status"]
    score = f"{s['security_score']}/100" if s["security_score"] is not None else "NOT ASSESSED"
    print(f"\nSupplyGuard security score: {score}   SBOM quality: {s['sbom_quality_score']}/100")
    print(f"Vulnerability data: {status.upper()}"
          + (f"  ({len(r['vulnerability_data']['failed_lookups'])} lookups failed, those packages were not assessed)"
             if r["vulnerability_data"]["failed_lookups"] else ""))
    print(f"Components: {s['total_components']}   Vulnerabilities: {s['vulnerabilities']}   "
          f"Reachable: {s['reachable']}   Not reachable: {s['not_reachable']}   Unknown: {s['unknown_reachability']}\n")
    if status in ("unavailable", "not-run"):
        print("Vulnerability intelligence could not be retrieved, so no vulnerability conclusion is made.")
        print("Check network access to the OSV.dev API (OSV_URL) and re-run the scan.")
        return
    if not r["findings"]:
        print("No known vulnerabilities found in the assessed packages.")
        return
    print(f"{'PRIORITY':<10} {'RISK':>4}  {'PACKAGE':<22} {'VERSION':<10} {'CVE / ID':<22} {'CVSS':>5}  {'REACHABILITY':<14} FIX")
    for f in r["findings"]:
        print(f"{f['priority']:<10} {f['risk_score']:>4}  {f['name'][:22]:<22} {str(f['version'])[:10]:<10} "
              f"{(f['cve'] or f['vuln_id'])[:22]:<22} {str(f['cvss'] or 'n/a'):>5}  {f['reachability']:<14} {f['fixed_version'] or 'none'}")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="supplyguard")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sc = sub.add_parser("scan", help="scan a project directory or an SBOM file")
    sc.add_argument("path", type=Path)
    sc.add_argument("--out", type=Path, default=None, help="write report.json and report.md here")
    args = ap.parse_args(argv)
    if not args.path.exists():
        print(f"not found: {args.path}", file=sys.stderr)
        return 2
    report = run(args.path)
    _print(report)
    if args.out:
        args.out.mkdir(parents=True, exist_ok=True)
        (args.out / "report.json").write_text(json.dumps(report, indent=2))
        (args.out / "report.md").write_text(render_markdown(report))
        print(f"\nWrote {args.out / 'report.md'} and {args.out / 'report.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
