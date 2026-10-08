"""Shared helpers: PURL parsing, name normalization, graph depth computation."""
from __future__ import annotations

import re
from collections import deque
from urllib.parse import unquote

from app.models.component import Component, DependencyEdge

PURL_RE = re.compile(r"^pkg:(?P<type>[a-z0-9.+-]+)/(?P<rest>.+)$", re.IGNORECASE)
PURL_TYPE_TO_ECOSYSTEM = {"npm": "npm", "pypi": "PyPI"}


class PurlError(ValueError):
    pass


def parse_purl(purl: str) -> dict:
    """Parse a package URL into type/namespace/name/version. Raises PurlError if malformed."""
    if not isinstance(purl, str):
        raise PurlError("purl is not a string")
    base = purl.split("?", 1)[0].split("#", 1)[0]
    m = PURL_RE.match(base)
    if not m:
        raise PurlError(f"malformed purl: {purl!r}")
    ptype = m.group("type").lower()
    rest = m.group("rest")
    version = None
    if "@" in rest:
        rest, version = rest.rsplit("@", 1)
        version = unquote(version)
    parts = [unquote(p) for p in rest.split("/") if p]
    if not parts:
        raise PurlError(f"purl has no name: {purl!r}")
    name = parts[-1]
    namespace = "/".join(parts[:-1]) or None
    return {"type": ptype, "namespace": namespace, "name": name, "version": version}


def normalize_name(name: str, ecosystem: str) -> str:
    if ecosystem == "PyPI":
        # PEP 503 canonical form
        return re.sub(r"[-_.]+", "-", name).lower()
    return name.strip()


def component_ref(ecosystem: str, name: str, version: str | None) -> str:
    return f"{ecosystem.lower()}:{name}@{version or '?'}"


def build_purl(ecosystem: str, name: str, version: str | None) -> str | None:
    if ecosystem == "npm":
        if name.startswith("@"):
            scope, pkg = name.split("/", 1)
            base = f"pkg:npm/%40{scope[1:]}/{pkg}"
        else:
            base = f"pkg:npm/{name}"
    elif ecosystem == "PyPI":
        base = f"pkg:pypi/{name}"
    else:
        return None
    return f"{base}@{version}" if version else base


def compute_depths(components: list[Component], edges: list[DependencyEdge]) -> dict[str, int]:
    """BFS from the application root (parent == ""). Returns ref -> shortest depth."""
    children: dict[str, list[str]] = {}
    for e in edges:
        children.setdefault(e.parent, []).append(e.child)
    depths: dict[str, int] = {}
    queue: deque[tuple[str, int]] = deque([("", 0)])
    seen = {""}
    while queue:
        node, d = queue.popleft()
        for child in children.get(node, []):
            if child not in seen:
                seen.add(child)
                depths[child] = d + 1
                queue.append((child, d + 1))
    return depths


def finalize(parsed, edges: list[DependencyEdge]):
    """Attach direct flag and depth to every component, based on the edge list."""
    root_children = {e.child for e in edges if e.parent == ""}
    depths = compute_depths(parsed.components, edges)
    for c in parsed.components:
        # direct is only known when the graph actually has root -> child edges
        c.direct = (c.ref in root_children) if root_children else None
        c.depth = depths.get(c.ref)
    parsed.edges = edges
    return parsed
