import io
import json
import zipfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import app.api as api
from tests.fixtures_osv import fake_lookup, failing_lookup

ROOT = Path(__file__).resolve().parents[2] / "examples" / "vulnerable-app"


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(api, "_lookup", fake_lookup)
    monkeypatch.setattr(api, "SessionLocal", api.SessionLocal)
    monkeypatch.setattr(api.limiter, "limit", 1000)
    return TestClient(api.app)


def _zip_of(folder: Path) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for p in folder.rglob("*"):
            if p.is_file() and "node_modules" not in p.parts:
                z.write(p, p.relative_to(folder).as_posix())
    return buf.getvalue()


def test_health_does_not_leak_token(client, monkeypatch):
    monkeypatch.setattr(api.settings, "github_token", "ghp_secret_value")
    r = client.get("/api/health")
    assert r.status_code == 200 and "ghp_secret" not in r.text
    assert r.json()["github_configured"] is True


def test_dashboard_served(client):
    r = client.get("/")
    assert r.status_code == 200 and "SupplyGuard" in r.text


def test_sbom_scan_and_read_back(client):
    data = (ROOT / "sbom.cdx.json").read_bytes()
    r = client.post("/api/scan/sbom", files={"file": ("sbom.cdx.json", data, "application/json")})
    assert r.status_code == 200, r.text
    sid = r.json()["scan_id"]
    assert client.get(f"/api/scans/{sid}/components").json()
    assert client.get(f"/api/scans/{sid}/dependency-graph").json()["nodes"]
    assert client.get(f"/api/scans/{sid}/report.md").text.startswith("# SupplyGuard")


def test_repository_scan_finds_reachability(client):
    data = _zip_of(ROOT)
    r = client.post("/api/scan/repository", files={"file": ("app.zip", data, "application/zip")})
    assert r.status_code == 200, r.text
    rep = r.json()["report"]
    assert rep["reachability_mode"] == "static-source"
    names = {f["name"]: f["reachability"] for f in rep["findings"]}
    assert names["axios"] == "NOT_REACHABLE" and names["qs"] == "REACHABLE"


def test_rejects_path_traversal_zip(client):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("../../evil.txt", "x")
    r = client.post("/api/scan/repository", files={"file": ("bad.zip", buf.getvalue(), "application/zip")})
    assert r.status_code == 400 and "rejected" in r.json()["detail"]


def test_rejects_oversized_sbom(client, monkeypatch):
    monkeypatch.setattr(api.settings, "max_sbom_bytes", 100)
    r = client.post("/api/scan/sbom", files={"file": ("x.json", b"{" + b" " * 500 + b"}", "application/json")})
    assert r.status_code == 413


def test_rejects_unknown_format(client):
    r = client.post("/api/scan/sbom", files={"file": ("notes.json", b'{"a":1}', "application/json")})
    assert r.status_code == 400


def test_invalid_scan_id_rejected(client):
    assert client.get("/api/scans/not-a-uuid").status_code == 400
    assert client.get("/api/scans/00000000-0000-0000-0000-000000000000").status_code == 404


def test_pr_endpoint_requires_token_and_valid_names(client, monkeypatch):
    monkeypatch.setattr(api.settings, "github_token", None)
    data = (ROOT / "sbom.cdx.json").read_bytes()
    sid = client.post("/api/scan/sbom", files={"file": ("s.json", data, "application/json")}).json()["scan_id"]
    bad = client.post("/api/github/create-pr", json={"scan_id": sid, "finding_id": "x", "owner": "a/../b", "repo": "r"})
    assert bad.status_code == 422
    fid = "nope"
    r = client.post("/api/github/create-pr", json={"scan_id": sid, "finding_id": fid, "owner": "o", "repo": "r"})
    assert r.status_code == 404


def test_unavailable_intel_returned_honestly(monkeypatch):
    monkeypatch.setattr(api, "_lookup", failing_lookup)
    monkeypatch.setattr(api.limiter, "limit", 1000)
    c = TestClient(api.app)
    data = (ROOT / "sbom.cdx.json").read_bytes()
    rep = c.post("/api/scan/sbom", files={"file": ("s.json", data, "application/json")}).json()["report"]
    assert rep["vulnerability_data"]["status"] == "unavailable"
    assert rep["summary"]["security_score"] is None
