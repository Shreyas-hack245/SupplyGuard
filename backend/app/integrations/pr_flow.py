"""Remediation PR flow:
   fetch manifests from GitHub -> patch -> regenerate lockfile (no install scripts, no code execution)
   -> re-check the vulnerability against live OSV -> create branch + commit -> open PR (never merged).

Deliberate deviation from the spec: SupplyGuard does NOT run the repository's test suite on the server,
because that would execute uploaded/project code. Tests are expected to run in the project's CI on the PR.
"""
from __future__ import annotations

import json
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Callable

from app.engines.pipeline import analyze
from app.engines.remediation import apply_plan
from app.engines.vulnerability_intel import LookupResult
from app.integrations.github import BRANCH_RE, GitHubClient, GitHubError
from app.models.component import Component
from app.parsers.detect import parse_sbom

Lookup = Callable[[Component], LookupResult]
NPM_TIMEOUT = 180


class PRError(Exception):
    pass


def regenerate_npm_lock(package_json: str, package_lock: str) -> str:
    npm = shutil.which("npm")
    if not npm:
        raise PRError("npm is not installed on the server; cannot regenerate the lockfile")
    with tempfile.TemporaryDirectory(prefix="sg-lock-") as td:
        d = Path(td)
        (d / "package.json").write_text(package_json)
        (d / "package-lock.json").write_text(package_lock)
        # argument list (no shell); --ignore-scripts and --package-lock-only: nothing from the project runs
        proc = subprocess.run(
            [npm, "install", "--package-lock-only", "--ignore-scripts", "--no-audit", "--no-fund"],
            cwd=d, capture_output=True, text=True, timeout=NPM_TIMEOUT,
        )
        if proc.returncode != 0:
            raise PRError("lockfile regeneration failed: " + proc.stderr.strip()[-300:])
        return (d / "package-lock.json").read_text()


def _summary(parsed, lookup: Lookup) -> dict:
    r = analyze(parsed, lookup, root=None)
    return {"vulnerabilities": r["summary"]["vulnerabilities"], "critical": r["summary"]["critical"],
            "high": r["summary"]["high"], "data_status": r["vulnerability_data"]["status"]}


def create_remediation_pr(client: GitHubClient, owner: str, repo: str, base_branch: str | None,
                          plan: dict, finding: dict, before: dict, lookup: Lookup) -> dict:
    base = base_branch or client.repo_info(owner, repo)["default_branch"]
    base_sha = client.branch_sha(owner, repo, base)

    needed = ["package.json", "package-lock.json"] if plan["ecosystem"] == "npm" else ["requirements.txt"]
    fetched: dict[str, tuple[str, str]] = {}
    for path in needed:
        got = client.get_file(owner, repo, path, base)
        if got is None:
            raise PRError(f"{path} not found on branch {base}")
        fetched[path] = got
    old = {p: t for p, (t, _) in fetched.items()}
    new = apply_plan(old, plan)

    if plan["ecosystem"] == "npm":
        new["package-lock.json"] = regenerate_npm_lock(new["package.json"], old["package-lock.json"])
        check_parsed = parse_sbom("package-lock.json", new["package-lock.json"].encode())
    else:
        check_parsed = parse_sbom("requirements.txt", new["requirements.txt"].encode())

    # Verification: the targeted component must now be at the fixed version and the finding must be gone.
    target = next((c for c in check_parsed.components if c.name == plan["name"] and c.version == plan["target_version"]), None)
    if target is None:
        raise PRError("verification failed: target version not present after patching")
    res = lookup(target)
    if res.status != "ok":
        raise PRError(f"verification could not complete: OSV lookup {res.status}. No PR was created.")
    still_present = [v.id for v in res.vulns if v.id == finding["vuln_id"] or (finding.get("cve") and finding["cve"] in [v.cve for v in res.vulns])]
    if still_present:
        raise PRError(f"verification failed: {still_present[0]} still reported at {plan['target_version']}. No PR was created.")
    after = _summary(check_parsed, lookup)

    slug = re.sub(r"[^A-Za-z0-9._-]", "-", finding.get("cve") or finding["vuln_id"])[:60].strip("-")
    branch = f"security/fix-{slug}"
    if not BRANCH_RE.match(branch):
        raise PRError("invalid branch name")
    client.create_branch(owner, repo, branch, base_sha)
    msg = f"fix(security): upgrade vulnerable {plan['name']} dependency"
    for path in needed:
        if new[path] != old[path]:
            client.put_file(owner, repo, path, new[path], msg, branch, fetched[path][1])

    title = f"fix(security): upgrade vulnerable {plan['name']} dependency"
    body = _pr_body(plan, finding, before, after)
    pr = client.open_pr(owner, repo, branch, base, title, body)
    return {"pr": pr, "branch": branch, "base": base,
            "verification": {"finding_resolved": True, "target_version": plan["target_version"]},
            "before": before, "after": after}


def _pr_body(plan: dict, f: dict, before: dict, after: dict) -> str:
    path = " -> ".join(f["reachability_path"]) if f["reachability_path"] else "no import path found"
    return f"""## Security vulnerability

**Identifier:** {f.get('cve') or f['vuln_id']} ({f['vuln_id']})
**Package:** `{plan['name']}` ({plan['ecosystem']})
**Current version:** {plan['current_version']}
**Fixed version:** {plan['target_version']}
**CVSS:** {f.get('cvss') or 'n/a'} ({f['severity']})
**Risk score:** {f['risk_score']}
**Reachability:** {f['reachability']} (confidence: {f['reachability_confidence']})

**Reason:** {f['reachability_note']}.
**Path:** `{path}`

## Verification
- Lockfile regenerated with `npm install --package-lock-only --ignore-scripts` (no project code executed).
- Vulnerability re-checked against OSV.dev for `{plan['name']}@{plan['target_version']}`: **resolved**.
- Rescan of the full lockfile: vulnerabilities {before['vulnerabilities']} -> {after['vulnerabilities']}, critical {before['critical']} -> {after['critical']}, high {before['high']} -> {after['high']}.
- Project tests: **not run by SupplyGuard**. Please confirm they pass in CI before merging.

## Review
This PR was created by SupplyGuard and requires human review and approval. It has not been merged.
"""
