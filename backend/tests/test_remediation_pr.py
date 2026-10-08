import json
from pathlib import Path

import httpx
import pytest

from app.engines.pipeline import analyze
from app.engines.project import parse_project
from app.engines.remediation import apply_plan
from app.integrations.github import BRANCH_RE, GitHubClient, GitHubError
from app.integrations.pr_flow import PRError, create_remediation_pr
from app.models.component import Component
from tests.fixtures_osv import fake_lookup, SCENARIO
from app.engines.vulnerability_intel import LookupResult

ROOT = Path(__file__).resolve().parents[2] / "examples" / "vulnerable-app"


def _report():
    p, texts = parse_project(ROOT)
    return analyze(p, fake_lookup, root=ROOT, kev=set(), kev_status="live", manifests=texts), texts


def test_direct_npm_plan_and_patch():
    report, texts = _report()
    plan = next(p for p in report["remediations"] if p["name"] == "lodash")
    assert plan["kind"] == "direct" and plan["target_version"] == "4.17.19"
    assert plan["commands"] == ["npm install lodash@4.17.19"]
    new = apply_plan({"package.json": texts["package.json"]}, plan)
    assert json.loads(new["package.json"])["dependencies"]["lodash"] == "4.17.19"


def test_transitive_npm_plan_uses_overrides():
    report, texts = _report()
    plan = next(p for p in report["remediations"] if p["name"] == "qs")
    assert plan["kind"] == "transitive"
    new = apply_plan({"package.json": texts["package.json"]}, plan)
    assert json.loads(new["package.json"])["overrides"]["qs"] == "6.7.3"


def test_plan_targets_highest_required_fix_when_several_vulns():
    # a needs 1.0.5, b's lowest fix above 1.0.0 is 1.2.0; one upgrade to 1.2.0 clears both.
    from app.engines.remediation import plan_for_component
    c = Component(ref="npm:x@1.0.0", name="x", version="1.0.0", ecosystem="npm", direct=True)
    plan = plan_for_component(c, [("a", ["1.0.5"]), ("b", ["1.2.0", "1.3.1"])], True)
    assert plan["target_version"] == "1.2.0"
    assert set(plan["clears_findings"]) == {"a", "b"}


def test_no_fix_means_no_plan():
    from app.engines.remediation import plan_for_component
    c = Component(ref="npm:x@1.0.0", name="x", version="1.0.0", ecosystem="npm", direct=True)
    assert plan_for_component(c, [("a", [])], True) is None


def test_pyproject_style_pin_patch():
    plan = {"name": "requests", "ecosystem": "PyPI", "target_version": "2.32.0", "kind": "direct"}
    out = apply_plan({"requirements.txt": "Requests==2.19.1\nflask==1.0.0\n"}, plan)
    assert out["requirements.txt"].splitlines()[0] == "requests==2.32.0"


def test_branch_name_rule():
    assert BRANCH_RE.match("security/fix-CVE-2099-0001")
    assert not BRANCH_RE.match("main")
    assert not BRANCH_RE.match("security/fix-../../etc")


def test_github_client_requires_token():
    with pytest.raises(GitHubError):
        GitHubClient(None, "https://api.github.test")


class FakeGitHub:
    """Records every call so the PR logic can be checked without touching GitHub."""
    def __init__(self, package_json, package_lock):
        self.calls = []
        self.files = {"package.json": package_json, "package-lock.json": package_lock}

    def handler(self, req: httpx.Request):
        self.calls.append((req.method, req.url.path))
        path = req.url.path
        if req.method == "GET" and path.endswith("/repos/o/r"):
            return httpx.Response(200, json={"default_branch": "main"})
        if req.method == "GET" and "/git/ref/heads/main" in path:
            return httpx.Response(200, json={"object": {"sha": "abc123"}})
        if req.method == "POST" and path.endswith("/git/refs"):
            return httpx.Response(201, json={})
        if req.method == "GET" and "/contents/" in path:
            name = path.rsplit("/contents/", 1)[1]
            import base64
            return httpx.Response(200, json={"content": base64.b64encode(self.files[name].encode()).decode(), "sha": "sha-" + name})
        if req.method == "PUT" and "/contents/" in path:
            return httpx.Response(200, json={})
        if req.method == "POST" and path.endswith("/pulls"):
            body = json.loads(req.content)
            assert "Human" in body["body"] or "human" in body["body"]
            return httpx.Response(201, json={"html_url": "https://github.test/o/r/pull/7", "number": 7})
        return httpx.Response(404, json={"message": "not found"})


def _patched_lock_via_fake_npm(monkeypatch, report_texts):
    """Replace the npm step with a deterministic lock edit so the test does not depend on network."""
    import app.integrations.pr_flow as pf
    def fake_regen(package_json, package_lock):
        lock = json.loads(package_lock)
        pj = json.loads(package_json)
        for name, ver in pj.get("dependencies", {}).items():
            key = f"node_modules/{name}"
            if key in lock["packages"]:
                lock["packages"][key]["version"] = ver.lstrip("^~")
        return json.dumps(lock, indent=2)
    monkeypatch.setattr(pf, "regenerate_npm_lock", fake_regen)


def test_pr_flow_direct_fix_end_to_end(monkeypatch):
    report, texts = _report()
    _patched_lock_via_fake_npm(monkeypatch, texts)
    finding = next(f for f in report["findings"] if f["name"] == "lodash")
    plan = next(p for p in report["remediations"] if p["name"] == "lodash")
    # Point the test OSV at the patched version: 4.17.21 has no finding in SCENARIO.
    fake = FakeGitHub(texts["package.json"], texts["package-lock.json"])
    client = GitHubClient("test-token", "https://api.github.test", transport=httpx.MockTransport(fake.handler))
    before = {"vulnerabilities": report["summary"]["vulnerabilities"], "critical": 0, "high": 1}
    out = create_remediation_pr(client, "o", "r", None, plan, finding, before, fake_lookup)
    assert out["pr"]["url"].endswith("/pull/7")
    assert out["branch"] == f"security/fix-{finding['cve']}"
    assert out["after"]["vulnerabilities"] == report["summary"]["vulnerabilities"] - 1
    assert any(m == "POST" and p.endswith("/pulls") for m, p in fake.calls)


def test_pr_refused_when_vulnerability_persists(monkeypatch):
    report, texts = _report()
    _patched_lock_via_fake_npm(monkeypatch, texts)
    finding = next(f for f in report["findings"] if f["name"] == "lodash")
    plan = next(p for p in report["remediations"] if p["name"] == "lodash")

    def still_vulnerable(comp):
        if comp.name == "lodash":
            return LookupResult("npm", "lodash", comp.version, vulns=[SCENARIO[("npm", "lodash", "4.17.15")][0]])
        return fake_lookup(comp)

    fake = FakeGitHub(texts["package.json"], texts["package-lock.json"])
    client = GitHubClient("test-token", "https://api.github.test", transport=httpx.MockTransport(fake.handler))
    with pytest.raises(PRError, match="verification failed"):
        create_remediation_pr(client, "o", "r", None, plan, finding, {}, still_vulnerable)
    assert not any(m == "POST" and p.endswith("/pulls") for m, p in fake.calls), "no PR may be opened"


def test_pr_refused_when_verification_cannot_complete(monkeypatch):
    report, texts = _report()
    _patched_lock_via_fake_npm(monkeypatch, texts)
    finding = next(f for f in report["findings"] if f["name"] == "lodash")
    plan = next(p for p in report["remediations"] if p["name"] == "lodash")
    from tests.fixtures_osv import failing_lookup
    fake = FakeGitHub(texts["package.json"], texts["package-lock.json"])
    client = GitHubClient("test-token", "https://api.github.test", transport=httpx.MockTransport(fake.handler))
    with pytest.raises(PRError, match="could not complete"):
        create_remediation_pr(client, "o", "r", None, plan, finding, {}, failing_lookup)
    assert not any(m == "POST" and p.endswith("/pulls") for m, p in fake.calls)
