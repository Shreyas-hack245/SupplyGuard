from pathlib import Path

from app.engines.reachability import NOT_REACHABLE, REACHABLE, UNKNOWN, analyze_reachability
from app.engines.risk import NOT_REACHABLE_CAP, compute_risk, priority
from app.parsers.detect import parse_sbom
from tests.fixtures_osv import fake_lookup, failing_lookup
from app.engines.pipeline import analyze

ROOT = Path(__file__).resolve().parents[2] / "examples" / "vulnerable-app"


def _parsed():
    return parse_sbom("package-lock.json", (ROOT / "package-lock.json").read_bytes())


def test_direct_import_on_reachable_path_is_reachable():
    p = _parsed()
    res, meta = analyze_reachability(p.components, p.edges, ROOT)
    lodash = next(c for c in p.components if c.name == "lodash")
    r = res[lodash.ref]
    assert r.status == REACHABLE and r.confidence == "high"
    assert r.path[0] == "src/server.js" and r.path[-1] == "lodash"
    assert "src/routes/users.js" in r.path and "src/services/parser.js" in r.path


def test_transitive_package_reached_through_import_is_reachable_medium():
    p = _parsed()
    res, _ = analyze_reachability(p.components, p.edges, ROOT)
    qs = next(c for c in p.components if c.name == "qs")
    r = res[qs.ref]
    assert r.status == REACHABLE and r.confidence == "medium"
    assert "express" in r.path and r.path[-1] == "qs"


def test_declared_but_never_imported_is_not_reachable():
    p = _parsed()
    res, _ = analyze_reachability(p.components, p.edges, ROOT)
    axios = next(c for c in p.components if c.name == "axios")
    assert res[axios.ref].status == NOT_REACHABLE


def test_no_source_is_unknown_never_not_reachable():
    p = _parsed()
    res, meta = analyze_reachability(p.components, p.edges, None)
    assert all(r.status == UNKNOWN for r in res.values())
    assert meta["mode"] == "not-analyzed"


def test_exposure_detected_from_server_framework(tmp_path):
    (tmp_path / "package.json").write_text('{"main":"app.js"}')
    (tmp_path / "app.js").write_text("const express = require('express');\nconst x = require('lodash');\n")
    lock = {"lockfileVersion": 3, "packages": {"": {"name": "t", "dependencies": {"express": "4.17.1", "lodash": "4.17.15"}},
            "node_modules/express": {"version": "4.17.1"}, "node_modules/lodash": {"version": "4.17.15"}}}
    import json
    (tmp_path / "package-lock.json").write_text(json.dumps(lock))
    p = parse_sbom("package-lock.json", (tmp_path / "package-lock.json").read_bytes())
    res, meta = analyze_reachability(p.components, p.edges, tmp_path)
    assert meta["exposed"] is True
    assert res[next(c.ref for c in p.components if c.name == "lodash")].status == REACHABLE


def test_dynamic_require_downgrades_absence_to_unknown(tmp_path):
    (tmp_path / "package.json").write_text('{"main":"app.js"}')
    (tmp_path / "app.js").write_text("const name = process.env.X;\nrequire(name);\n")
    lock = {"lockfileVersion": 3, "packages": {"": {"name": "t", "dependencies": {"left-pad": "1.3.0"}},
            "node_modules/left-pad": {"version": "1.3.0"}}}
    import json
    (tmp_path / "package-lock.json").write_text(json.dumps(lock))
    p = parse_sbom("package-lock.json", (tmp_path / "package-lock.json").read_bytes())
    res, _ = analyze_reachability(p.components, p.edges, tmp_path)
    assert res[p.components[0].ref].status == UNKNOWN


def test_unreachable_file_import_does_not_count(tmp_path):
    (tmp_path / "package.json").write_text('{"main":"app.js"}')
    (tmp_path / "app.js").write_text("console.log('hi');\n")
    (tmp_path / "orphan.js").write_text("const _ = require('lodash');\n")
    import json
    lock = {"lockfileVersion": 3, "packages": {"": {"name": "t", "dependencies": {"lodash": "4.17.15"}},
            "node_modules/lodash": {"version": "4.17.15"}}}
    (tmp_path / "package-lock.json").write_text(json.dumps(lock))
    p = parse_sbom("package-lock.json", (tmp_path / "package-lock.json").read_bytes())
    res, _ = analyze_reachability(p.components, p.edges, tmp_path)
    r = res[p.components[0].ref]
    assert r.status == NOT_REACHABLE and "not reachable" in r.note


def test_python_import_detected(tmp_path):
    (tmp_path / "app.py").write_text("import requests\nfrom flask import Flask\n")
    (tmp_path / "requirements.txt").write_text("requests==2.19.1\nflask==1.0.0\nPyYAML==5.1\n")
    from app.engines.project import parse_project
    p, _ = parse_project(tmp_path)
    res, meta = analyze_reachability(p.components, p.edges, tmp_path)
    by = {c.name: res[c.ref].status for c in p.components}
    assert by["requests"] == REACHABLE and by["flask"] == REACHABLE
    assert by["pyyaml"] == NOT_REACHABLE
    assert meta["exposed"] is True


# ---- risk scoring ----

def test_not_reachable_is_capped_even_at_critical_cvss():
    r = compute_risk(cvss=9.8, reachability=NOT_REACHABLE, exploit_known=False, internet_exposed=False,
                     direct=True, fix_available=True, depth=1)
    assert r["score"] <= NOT_REACHABLE_CAP and r["capped"] is True
    assert priority(r["score"], NOT_REACHABLE) == "LOW"


def test_reachable_exposed_exploited_outranks_critical_unreachable():
    a = compute_risk(9.8, NOT_REACHABLE, False, False, True, True, 1)
    b = compute_risk(7.5, REACHABLE, True, True, True, True, 1)
    assert b["score"] > a["score"]
    assert priority(b["score"], REACHABLE) == "IMMEDIATE"


def test_every_factor_is_explained():
    r = compute_risk(7.5, REACHABLE, None, False, True, True, 2)
    assert {f["factor"] for f in r["factors"]} == {"cvss", "reachability", "exploit", "exposure", "direct", "fix", "depth"}
    assert all(f["label"] for f in r["factors"])
    assert round(sum(f["contribution"] for f in r["factors"])) == r["raw_score"]


def test_unknown_exploit_status_is_not_zero_risk_claim():
    r = compute_risk(7.5, REACHABLE, None, False, True, True, 1)
    exploit = next(f for f in r["factors"] if f["factor"] == "exploit")
    assert "unavailable" in exploit["label"]


# ---- end to end on the sample project with test intel ----

def test_pipeline_prioritizes_reachable_over_unreachable_critical():
    p, texts = __import__("app.engines.project", fromlist=["x"]).parse_project(ROOT)
    report = analyze(p, fake_lookup, root=ROOT, kev=set(), kev_status="live", manifests=texts)
    by_name = {f["name"]: f for f in report["findings"]}
    assert by_name["axios"]["reachability"] == NOT_REACHABLE and by_name["axios"]["priority"] == "LOW"
    assert by_name["qs"]["reachability"] == REACHABLE
    assert report["findings"][0]["name"] != "axios"
    assert report["summary"]["security_score"] is not None
    assert report["remediations"] and all(r["target_version"] for r in report["remediations"])


def test_failed_intel_never_produces_a_score_or_clean_result():
    p, texts = __import__("app.engines.project", fromlist=["x"]).parse_project(ROOT)
    report = analyze(p, failing_lookup, root=ROOT, kev=None, kev_status="unavailable", manifests=texts)
    assert report["vulnerability_data"]["status"] == "unavailable"
    assert report["summary"]["security_score"] is None
    assert report["findings"] == []
    assert len(report["vulnerability_data"]["failed_lookups"]) == len(p.components)
