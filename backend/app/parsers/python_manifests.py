"""requirements.txt and pyproject.toml parsers. Only exact pins (==) are treated as versioned."""
from __future__ import annotations

import re
import tomllib

from app.models.component import Component, DependencyEdge, ParsedSBOM, ParseWarning
from app.parsers.common import build_purl, component_ref, finalize, normalize_name

REQ_RE = re.compile(r"^\s*(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)\s*(?P<extras>\[[^\]]*\])?\s*(?P<spec>[<>=!~][^;#]*)?")
EXACT_RE = re.compile(r"^==\s*([^\s,;]+)$")


def _spec_to_version(spec: str | None) -> str | None:
    if not spec:
        return None
    m = EXACT_RE.match(spec.strip())
    return m.group(1) if m else None


def _make_component(raw_name: str, spec: str | None, scope: str, fmt: str, warnings: list, source: str) -> Component:
    name = normalize_name(raw_name, "PyPI")
    version = _spec_to_version(spec)
    if version is None:
        warnings.append(ParseWarning(code="UNPINNED_VERSION", message=f"{raw_name} is not pinned with == ({spec or 'no version'}); version unknown", ref=source))
    ref = component_ref("PyPI", name, version)
    return Component(
        ref=ref, name=name, version=version, ecosystem="PyPI", purl=build_purl("PyPI", name, version),
        scope=scope, source_format=fmt,
    )


def parse_requirements_txt(text: str) -> ParsedSBOM:
    if not isinstance(text, str):
        raise ValueError("requirements.txt must be text")
    parsed = ParsedSBOM(source_format="requirements.txt")
    warnings: list[ParseWarning] = []
    seen: set[str] = set()
    for lineno, raw in enumerate(text.splitlines(), start=1):
        line = raw.split(" #", 1)[0].strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith(("-r", "-c", "--", "-e", "git+", "http://", "https://")):
            warnings.append(ParseWarning(code="UNSUPPORTED_LINE", message=f"line {lineno} not supported: {line[:80]}"))
            continue
        m = REQ_RE.match(line)
        if not m:
            warnings.append(ParseWarning(code="MALFORMED_LINE", message=f"line {lineno} could not be parsed"))
            continue
        comp = _make_component(m.group("name"), m.group("spec"), "runtime", "requirements.txt", warnings, f"line:{lineno}")
        if comp.ref in seen:
            warnings.append(ParseWarning(code="DUPLICATE_COMPONENT", message=f"duplicate {comp.ref}", ref=comp.ref))
            continue
        seen.add(comp.ref)
        comp.direct = True
        parsed.components.append(comp)
    parsed.edges = [DependencyEdge(parent="", child=c.ref) for c in parsed.components]
    for c in parsed.components:
        c.depth = 1
    parsed.warnings = warnings
    return parsed


def parse_pyproject_toml(text: str) -> ParsedSBOM:
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        raise ValueError(f"invalid pyproject.toml: {exc}") from exc
    project = data.get("project")
    if not isinstance(project, dict):
        raise ValueError("pyproject.toml has no [project] table")
    parsed = ParsedSBOM(source_format="pyproject.toml", app_name=project.get("name"))
    warnings: list[ParseWarning] = []
    seen: set[str] = set()

    def add(req: str, scope: str):
        m = REQ_RE.match(req)
        if not m:
            warnings.append(ParseWarning(code="MALFORMED_LINE", message=f"cannot parse dependency {req!r}"))
            return
        comp = _make_component(m.group("name"), m.group("spec"), scope, "pyproject.toml", warnings, req)
        if comp.ref in seen:
            return
        seen.add(comp.ref)
        comp.direct = True
        comp.depth = 1
        parsed.components.append(comp)

    for req in project.get("dependencies", []) or []:
        add(req, "runtime")
    for group, reqs in (project.get("optional-dependencies") or {}).items():
        for req in reqs:
            add(req, f"optional:{group}")
    parsed.edges = [DependencyEdge(parent="", child=c.ref) for c in parsed.components]
    parsed.warnings = warnings
    return parsed
