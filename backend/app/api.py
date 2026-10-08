"""FastAPI application: REST API for scans, remediation, and GitHub PRs, plus the dashboard."""
from __future__ import annotations

import difflib
import json
import re
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, PlainTextResponse
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import DateTime, String, Text, create_engine, select
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker

from app.core.config import settings
from app.core.security import RateLimiter, UnsafeArchiveError, safe_basename, safe_extract_zip
from app.engines.kev import load_kev
from app.engines.pipeline import analyze
from app.engines.project import parse_project
from app.engines.remediation import apply_plan, diff_text
from app.engines.report_md import render_markdown
from app.engines.vulnerability_intel import LookupResult, OsvClient, VulnCache
from app.integrations.github import OWNER_REPO_RE, GitHubClient, GitHubError
from app.integrations.pr_flow import PRError, create_remediation_pr
from app.models.component import Component
from app.parsers.detect import parse_sbom

FRONTEND = Path(__file__).resolve().parents[2] / "frontend" / "index.html"
SCAN_ID_RE = re.compile(r"^[0-9a-f-]{36}$")


class Base(DeclarativeBase):
    pass


class ScanRecord(Base):
    __tablename__ = "scans"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    created_at: Mapped[datetime] = mapped_column(DateTime)
    kind: Mapped[str] = mapped_column(String(20))
    filename: Mapped[str] = mapped_column(String(200))
    report_json: Mapped[str] = mapped_column(Text)
    manifests_json: Mapped[str] = mapped_column(Text, default="{}")


engine = create_engine(f"sqlite:///{settings.db_path}", connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine)
Base.metadata.create_all(engine)

app = FastAPI(title="SupplyGuard", version="1.0.0")
limiter = RateLimiter(settings.rate_limit_per_min)
_osv: OsvClient | None = None


def _osv_client() -> OsvClient:
    global _osv
    if _osv is None:
        _osv = OsvClient(VulnCache(settings.cache_path), url=settings.osv_url)
    return _osv


def _lookup(c: Component) -> LookupResult:
    return _osv_client().lookup(c.ecosystem, c.name, c.version)


def _check_rate(request: Request) -> None:
    key = request.client.host if request.client else "unknown"
    if not limiter.allow(key):
        raise HTTPException(429, "rate limit exceeded; try again in a minute")


def _run(parsed, root: Path | None, manifests: dict[str, str]) -> dict:
    cache = VulnCache(settings.cache_path)
    kev, kev_status = load_kev(cache)
    return analyze(parsed, _lookup, root=root, kev=kev, kev_status=kev_status, manifests=manifests)


def _store(kind: str, filename: str, report: dict, manifests: dict[str, str]) -> str:
    scan_id = str(uuid.uuid4())
    with SessionLocal() as s:
        s.add(ScanRecord(id=scan_id, created_at=datetime.now(timezone.utc).replace(tzinfo=None), kind=kind,
                         filename=filename, report_json=json.dumps(report),
                         manifests_json=json.dumps(manifests)))
        s.commit()
    return scan_id


def _load(scan_id: str) -> tuple[dict, dict[str, str]]:
    if not SCAN_ID_RE.match(scan_id):
        raise HTTPException(400, "invalid scan id")
    with SessionLocal() as s:
        rec = s.get(ScanRecord, scan_id)
    if rec is None:
        raise HTTPException(404, "scan not found")
    return json.loads(rec.report_json), json.loads(rec.manifests_json or "{}")


async def _read_limited(file: UploadFile, limit: int) -> bytes:
    data = await file.read(limit + 1)
    if len(data) > limit:
        raise HTTPException(413, f"file exceeds {limit} byte limit")
    return data


@app.get("/", include_in_schema=False)
def dashboard():
    return FileResponse(FRONTEND)


@app.get("/api/health")
def health():
    return {"status": "ok", "vulnerability_source": settings.osv_url,
            "github_configured": bool(settings.github_token)}


@app.post("/api/scan/sbom")
async def scan_sbom(request: Request, file: UploadFile):
    _check_rate(request)
    data = await _read_limited(file, settings.max_sbom_bytes)
    name = safe_basename(file.filename)
    try:
        parsed = parse_sbom(name, data)
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    report = _run(parsed, None, {})
    return {"scan_id": _store("sbom", name, report, {}), "report": report}


@app.post("/api/scan/repository")
async def scan_repository(request: Request, file: UploadFile):
    _check_rate(request)
    data = await _read_limited(file, settings.max_zip_bytes)
    name = safe_basename(file.filename)
    with tempfile.TemporaryDirectory(prefix="sg-scan-") as td:
        root = Path(td) / "repo"
        root.mkdir()
        try:
            safe_extract_zip(data, root, settings)
        except UnsafeArchiveError as exc:
            raise HTTPException(400, f"archive rejected: {exc}")
        # If the zip wraps everything in one top-level folder, scan that folder.
        children = [p for p in root.iterdir()]
        scan_root = children[0] if len(children) == 1 and children[0].is_dir() else root
        parsed, manifests = parse_project(scan_root)
        report = _run(parsed, scan_root, manifests)
    return {"scan_id": _store("repository", name, report, manifests), "report": report}


@app.get("/api/scans/{scan_id}")
def get_scan(scan_id: str):
    report, _ = _load(scan_id)
    return report


@app.get("/api/scans/{scan_id}/components")
def get_components(scan_id: str):
    report, _ = _load(scan_id)
    return report["components"]


@app.get("/api/scans/{scan_id}/vulnerabilities")
def get_vulnerabilities(scan_id: str):
    report, _ = _load(scan_id)
    return report["findings"]


@app.get("/api/scans/{scan_id}/dependency-graph")
def get_graph(scan_id: str):
    report, _ = _load(scan_id)
    return report["graph"]


@app.get("/api/scans/{scan_id}/risk")
def get_risk(scan_id: str):
    report, _ = _load(scan_id)
    return {"security_score": report["summary"]["security_score"],
            "findings": [{k: f[k] for k in ("id", "name", "version", "cve", "risk_score", "risk_capped",
                                             "priority", "risk_factors")} for f in report["findings"]]}


@app.get("/api/scans/{scan_id}/report.md", response_class=PlainTextResponse)
def get_report_md(scan_id: str):
    report, _ = _load(scan_id)
    return render_markdown(report)


@app.get("/api/vulnerabilities/{finding_id:path}")
def get_finding(finding_id: str):
    with SessionLocal() as s:
        recs = s.scalars(select(ScanRecord).order_by(ScanRecord.created_at.desc()).limit(50)).all()
    for rec in recs:
        for f in json.loads(rec.report_json)["findings"]:
            if f["id"] == finding_id:
                return {"scan_id": rec.id, "finding": f}
    raise HTTPException(404, "finding not found in recent scans")


class RemediationRequest(BaseModel):
    scan_id: str = Field(pattern=r"^[0-9a-f-]{36}$")


@app.post("/api/remediation")
def remediation(body: RemediationRequest):
    report, manifests = _load(body.scan_id)
    plans = []
    for p in report["remediations"]:
        diffs = []
        if p["ecosystem"] == "npm" and "package.json" in manifests:
            new = apply_plan(manifests, p)
            diffs.append({"path": "package.json", "diff": diff_text(manifests["package.json"], new["package.json"], "package.json")})
        elif p["ecosystem"] == "PyPI":
            for path in [k for k in manifests if k.endswith("requirements.txt")]:
                new = apply_plan({path: manifests[path]}, p)
                if new[path] != manifests[path]:
                    diffs.append({"path": path, "diff": diff_text(manifests[path], new[path], path)})
        plans.append({**p, "diffs": diffs,
                      "lockfile_note": "package-lock.json is regenerated when the PR is created"
                      if p["ecosystem"] == "npm" else None})
    return {"scan_id": body.scan_id, "plans": plans}


class PRRequest(BaseModel):
    scan_id: str = Field(pattern=r"^[0-9a-f-]{36}$")
    finding_id: str = Field(min_length=1, max_length=300)
    owner: str
    repo: str
    base_branch: str | None = Field(default=None, max_length=100)

    @field_validator("owner", "repo")
    @classmethod
    def _valid_name(cls, v: str) -> str:
        if not OWNER_REPO_RE.match(v) or v in (".", ".."):
            raise ValueError("invalid GitHub owner or repository name")
        return v

    @field_validator("base_branch")
    @classmethod
    def _valid_branch(cls, v: str | None) -> str | None:
        if v is not None and not re.match(r"^[A-Za-z0-9._/-]{1,100}$", v):
            raise ValueError("invalid branch name")
        return v


@app.post("/api/github/create-pr")
def create_pr(request: Request, body: PRRequest):
    _check_rate(request)
    report, _ = _load(body.scan_id)
    finding = next((f for f in report["findings"] if f["id"] == body.finding_id), None)
    if finding is None:
        raise HTTPException(404, "finding not found in this scan")
    plan = next((p for p in report["remediations"] if p["component_ref"] == finding["component_ref"]), None)
    if plan is None or finding["id"] not in plan["clears_findings"]:
        raise HTTPException(409, "no safe automated fix exists for this finding")
    try:
        client = GitHubClient(settings.github_token, settings.github_api_url)
        before = {"vulnerabilities": report["summary"]["vulnerabilities"],
                  "critical": report["summary"]["critical"], "high": report["summary"]["high"]}
        return create_remediation_pr(client, body.owner, body.repo, body.base_branch, plan, finding, before, _lookup)
    except GitHubError as exc:
        raise HTTPException(502, str(exc))
    except PRError as exc:
        raise HTTPException(409, str(exc))
