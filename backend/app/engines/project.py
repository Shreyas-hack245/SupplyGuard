"""Find dependency manifests inside a project directory and parse them into one merged SBOM."""
from __future__ import annotations

import os
from pathlib import Path

from app.models.component import ParsedSBOM, ParseWarning
from app.parsers.detect import parse_sbom

MANIFEST_NAMES = {"package-lock.json", "requirements.txt", "pyproject.toml"}
SKIP_DIRS = {"node_modules", ".git", "venv", ".venv", "__pycache__", "dist", "build"}


def find_manifests(root: Path, max_files: int = 200) -> list[Path]:
    found: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not Path(dirpath, d).is_symlink()]
        for fn in filenames:
            if fn in MANIFEST_NAMES or (fn.endswith("requirements.txt")):
                found.append(Path(dirpath, fn))
                if len(found) >= max_files:
                    return sorted(found)
    return sorted(found)


def merge_parsed(parts: list[ParsedSBOM]) -> ParsedSBOM:
    merged = ParsedSBOM(source_format="+".join(sorted({p.source_format for p in parts})) or "none")
    seen_refs: set[str] = set()
    for p in parts:
        merged.app_name = merged.app_name or p.app_name
        for c in p.components:
            if c.ref in seen_refs:
                continue
            seen_refs.add(c.ref)
            merged.components.append(c)
        merged.edges.extend(p.edges)
        merged.warnings.extend(p.warnings)
    return merged


def parse_project(root: Path) -> tuple[ParsedSBOM, dict[str, str]]:
    """Parse every manifest under root. Returns merged SBOM and the manifest texts (for remediation diffs)."""
    parts: list[ParsedSBOM] = []
    texts: dict[str, str] = {}
    for path in find_manifests(root):
        rel = path.relative_to(root).as_posix()
        data = path.read_bytes()
        try:
            parsed = parse_sbom(path.name, data)
        except ValueError as exc:
            parts.append(ParsedSBOM(source_format="error", warnings=[ParseWarning(code="PARSE_ERROR", message=f"{rel}: {exc}")]))
            continue
        parts.append(parsed)
        if path.name in ("package.json", "package-lock.json", "requirements.txt", "pyproject.toml") or path.name.endswith("requirements.txt"):
            texts[rel] = data.decode("utf-8", errors="replace")
    # package.json is not parsed as an SBOM (lockfile is the source of truth) but is kept for remediation diffs.
    for pj in root.rglob("package.json"):
        rel = pj.relative_to(root).as_posix()
        if "node_modules" in pj.parts or rel.count("/") > 3 or pj.is_symlink():
            continue
        texts.setdefault(rel, pj.read_text(encoding="utf-8", errors="replace"))
    if not parts:
        return ParsedSBOM(source_format="none", warnings=[ParseWarning(code="NO_MANIFESTS", message="no supported manifests found")]), texts
    return merge_parsed(parts), texts
