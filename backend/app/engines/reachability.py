"""Static reachability analysis.

Granularity: PACKAGE level. We determine whether application code can load a package (directly, or
through a package it imports, using the lockfile graph). We do NOT claim function-level reachability.

Result semantics (conservative):
  REACHABLE      an import path from an application entry point reaches the package
  NOT_REACHABLE  no import path exists AND the analysis could see all reachable code
  UNKNOWN        dynamic imports, unresolved relative imports, or missing graph prevent a proof either way
"""
from __future__ import annotations

import ast
import json
import os
import posixpath
import re
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path

from app.models.component import Component, DependencyEdge

REACHABLE = "REACHABLE"
NOT_REACHABLE = "NOT_REACHABLE"
UNKNOWN = "UNKNOWN"

SKIP_DIRS = {"node_modules", ".git", "dist", "build", "coverage", "__pycache__", ".venv", "venv",
             "test", "tests", "__tests__", "spec"}
JS_EXTS = (".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx")
MAX_FILE_BYTES = 512 * 1024
MAX_FILES = 5000
NODE_BUILTINS = {"fs", "path", "http", "https", "url", "util", "os", "stream", "crypto", "events",
                 "child_process", "net", "tls", "zlib", "buffer", "querystring", "assert", "module",
                 "process", "timers", "readline", "worker_threads", "cluster", "dns", "string_decoder",
                 "vm", "async_hooks", "perf_hooks", "v8", "tty", "dgram", "punycode"}
# Heuristic: packages that start network servers. Used only for the internet-exposure hint.
JS_SERVER_FRAMEWORKS = {"express", "fastify", "koa", "@hapi/hapi", "hapi", "restify"}
PY_SERVER_FRAMEWORKS = {"flask", "fastapi", "django", "aiohttp", "sanic", "tornado", "starlette", "bottle", "pyramid"}
PY_ALIASES = {"pyyaml": "yaml", "pillow": "pil", "beautifulsoup4": "bs4", "scikit-learn": "sklearn",
              "python-dateutil": "dateutil", "pyjwt": "jwt", "opencv-python": "cv2", "protobuf": "google",
              "pycryptodome": "crypto", "python-dotenv": "dotenv"}

IMPORT_RES = [
    re.compile(r"""\brequire\(\s*['"]([^'"]+)['"]\s*\)"""),
    re.compile(r"""\bimport\s+(?:[\w*{}\s,$]+?\s+from\s+)?['"]([^'"]+)['"]"""),
    re.compile(r"""\bexport\s+[\w*{}\s,]+?\s+from\s+['"]([^'"]+)['"]"""),
    re.compile(r"""\bimport\(\s*['"]([^'"]+)['"]\s*\)"""),
]
JS_DYNAMIC_RE = re.compile(r"""\b(?:require|import)\(\s*[^'"\s)]""")
PY_DYNAMIC_RE = re.compile(r"\b(?:importlib\.import_module|__import__|exec|eval)\s*\(")


@dataclass
class ReachResult:
    status: str
    confidence: str  # high | medium | low
    path: list[str] = field(default_factory=list)
    note: str = ""


def load_sources(root: Path) -> dict[str, str]:
    files: dict[str, str] = {}
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not Path(dirpath, d).is_symlink()]
        for fn in filenames:
            p = Path(dirpath, fn)
            if p.suffix not in JS_EXTS + (".py",) or p.is_symlink():
                continue
            if p.stat().st_size > MAX_FILE_BYTES:
                continue
            rel = p.relative_to(root).as_posix()
            files[rel] = p.read_text(encoding="utf-8", errors="replace")
            if len(files) >= MAX_FILES:
                return files
    return files


def _resolve_local(base_dir: str, spec: str, files: dict[str, str]) -> str | None:
    if not (spec.startswith("./") or spec.startswith("../") or spec.startswith("/")):
        return None
    target = posixpath.normpath(posixpath.join(base_dir, spec.lstrip("/") if spec.startswith("/") else spec))
    candidates = [target] + [target + ext for ext in JS_EXTS] + [posixpath.join(target, "index" + ext) for ext in JS_EXTS]
    for c in candidates:
        if c in files:
            return c
    return None


def _package_name(spec: str) -> str | None:
    if spec.startswith("node:") or spec.startswith(".") or spec.startswith("/"):
        return None
    if spec.startswith("@"):
        parts = spec.split("/")
        return "/".join(parts[:2]) if len(parts) >= 2 else None
    head = spec.split("/")[0]
    return None if head in NODE_BUILTINS else head


def js_entry_points(root: Path, files: dict[str, str]) -> list[str]:
    entries: list[str] = []
    pj = root / "package.json"
    if pj.is_file():
        try:
            data = json.loads(pj.read_text(encoding="utf-8", errors="replace"))
        except json.JSONDecodeError:
            data = {}
        if isinstance(data.get("main"), str):
            entries.append(data["main"])
        scripts = data.get("scripts") if isinstance(data.get("scripts"), dict) else {}
        for key in ("start", "dev", "serve"):
            cmd = scripts.get(key)
            if isinstance(cmd, str):
                m = re.search(r"node\s+(?:--?\S+\s+)*([\w./-]+\.(?:js|mjs|cjs|ts))", cmd)
                if m:
                    entries.append(m.group(1))
        bins = data.get("bin")
        if isinstance(bins, str):
            entries.append(bins)
        elif isinstance(bins, dict):
            entries += [v for v in bins.values() if isinstance(v, str)]
    resolved = []
    for e in entries:
        r = _resolve_local("", "./" + e.lstrip("./"), files)
        if r:
            resolved.append(r)
    return sorted(set(resolved))


def _build_js_graph(files: dict[str, str]):
    local: dict[str, list[str]] = {}
    pkgs: dict[str, set[str]] = {}
    dynamic: set[str] = set()
    unresolved: set[str] = set()
    for f, text in files.items():
        if not f.endswith(JS_EXTS):
            continue
        base = posixpath.dirname(f)
        if JS_DYNAMIC_RE.search(text):
            dynamic.add(f)
        for rx in IMPORT_RES:
            for spec in rx.findall(text):
                if spec.startswith("."):
                    target = _resolve_local(base, spec, files)
                    if target:
                        local.setdefault(f, []).append(target)
                    else:
                        unresolved.add(f)
                else:
                    name = _package_name(spec)
                    if name:
                        pkgs.setdefault(f, set()).add(name)
    return local, pkgs, dynamic, unresolved


def _bfs_files(entries: list[str], local: dict[str, list[str]]) -> dict[str, str | None]:
    parent: dict[str, str | None] = {e: None for e in entries}
    queue = deque(entries)
    while queue:
        cur = queue.popleft()
        for nxt in local.get(cur, []):
            if nxt not in parent:
                parent[nxt] = cur
                queue.append(nxt)
    return parent


def _file_chain(f: str, parent: dict[str, str | None]) -> list[str]:
    chain: list[str] = []
    cur: str | None = f
    while cur is not None:
        chain.append(cur)
        cur = parent[cur]
    return list(reversed(chain))


def _closure(start_refs: list[str], children: dict[str, list[str]]) -> dict[str, list[str]]:
    paths: dict[str, list[str]] = {}
    queue: deque[str] = deque()
    for r in start_refs:
        paths[r] = [r]
        queue.append(r)
    while queue:
        cur = queue.popleft()
        for ch in children.get(cur, []):
            if ch not in paths:
                paths[ch] = paths[cur] + [ch]
                queue.append(ch)
    return paths


def analyze_js(comps: list[Component], edges: list[DependencyEdge], files: dict[str, str], root: Path):
    local, pkgs, dynamic, unresolved = _build_js_graph(files)
    entries = js_entry_points(root, files)
    if entries:
        parent = _bfs_files(entries, local)
        mode, conf = "entrypoints", "high"
    else:
        parent = {f: None for f in files if f.endswith(JS_EXTS)}
        mode, conf = "no-entrypoint", "medium"
    reach_files = set(parent)

    importer: dict[str, str] = {}
    for f in sorted(reach_files):
        for name in sorted(pkgs.get(f, ())):
            importer.setdefault(name, f)
    all_imported = {n for f in files for n in pkgs.get(f, ())}

    children: dict[str, list[str]] = {}
    for e in edges:
        children.setdefault(e.parent, []).append(e.child)
    name_refs: dict[str, list[str]] = {}
    ref_name: dict[str, str] = {}
    for c in comps:
        if c.ecosystem == "npm":
            name_refs.setdefault(c.name, []).append(c.ref)
            ref_name[c.ref] = c.name
    via: dict[str, list[str]] = {}
    for name in importer:
        for ref, path in _closure(name_refs.get(name, []), children).items():
            via.setdefault(ref, [name] + [ref_name.get(r, r) for r in path[1:]])

    dyn_reach = bool(dynamic & reach_files)
    unres_reach = bool(unresolved & reach_files)
    exposed = any(p in JS_SERVER_FRAMEWORKS for f in reach_files for p in pkgs.get(f, ()))

    results: dict[str, ReachResult] = {}
    for c in comps:
        if c.ecosystem != "npm":
            continue
        if c.name in importer:
            f = importer[c.name]
            results[c.ref] = ReachResult(REACHABLE, conf, _file_chain(f, parent) + [c.name],
                                         "application code imports this package directly")
        elif c.ref in via:
            f = importer[via[c.ref][0]]
            results[c.ref] = ReachResult(REACHABLE, "medium", _file_chain(f, parent) + via[c.ref],
                                         "loaded transitively through an imported package (package-level)")
        elif dyn_reach or unres_reach:
            results[c.ref] = ReachResult(UNKNOWN, "low", [],
                                         "reachable code uses dynamic or unresolved imports; absence cannot be proven")
        else:
            note = "no import of this package from code reachable from the entry points"
            if c.name in all_imported:
                note = "imported only by code that is not reachable from the entry points"
            results[c.ref] = ReachResult(NOT_REACHABLE, conf, [], note)
    return results, {"mode": mode, "exposed": exposed, "entry_points": entries}


PY_CANDIDATE_KEYS = lambda name: {name, PY_ALIASES.get(name, name)}  # noqa: E731


def analyze_py(comps: list[Component], files: dict[str, str]):
    imported: dict[str, str] = {}
    dynamic: set[str] = set()
    unparsed: set[str] = set()
    for f, text in files.items():
        if not f.endswith(".py"):
            continue
        if PY_DYNAMIC_RE.search(text):
            dynamic.add(f)
        try:
            tree = ast.parse(text)
        except SyntaxError:
            unparsed.add(f)
            continue
        for node in ast.walk(tree):
            mods: list[str] = []
            if isinstance(node, ast.Import):
                mods = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                mods = [node.module]
            for m in mods:
                top = _norm_py(m.split(".")[0])
                imported.setdefault(top, f)
    py_exposed = any(k in PY_SERVER_FRAMEWORKS for k in imported)
    dyn = bool(dynamic) or bool(unparsed)

    results: dict[str, ReachResult] = {}
    for c in comps:
        if c.ecosystem != "PyPI":
            continue
        hit = next((imported[k] for k in PY_CANDIDATE_KEYS(_norm_py(c.name)) if k in imported), None)
        if hit:
            results[c.ref] = ReachResult(REACHABLE, "medium", [hit, c.name],
                                         "imported by application code (Python entry points not analysed)")
        elif c.direct is False:
            results[c.ref] = ReachResult(UNKNOWN, "low", [],
                                         "transitive Python dependency; no lockfile graph to trace it")
        elif dyn:
            results[c.ref] = ReachResult(UNKNOWN, "low", [], "dynamic imports or unparsable files present")
        else:
            results[c.ref] = ReachResult(NOT_REACHABLE, "medium", [], "not imported by any application module")
    return results, {"exposed": py_exposed}


def _norm_py(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def analyze_reachability(comps: list[Component], edges: list[DependencyEdge], root: Path | None):
    """Entry point. root=None means no source was provided, so nothing can be concluded."""
    if root is None:
        results = {c.ref: ReachResult(UNKNOWN, "low", [], "no source code provided; reachability not analysed")
                   for c in comps}
        return results, {"mode": "not-analyzed", "exposed": False, "entry_points": []}
    files = load_sources(root)
    results: dict[str, ReachResult] = {}
    meta: dict = {"mode": "static-source", "exposed": False, "entry_points": [],
                  "files_analyzed": len(files)}
    if any(f.endswith(JS_EXTS) for f in files):
        r, m = analyze_js(comps, edges, files, root)
        results.update(r)
        meta["exposed"] = meta["exposed"] or m["exposed"]
        meta["entry_points"] = m["entry_points"]
        meta["js_mode"] = m["mode"]
    if any(f.endswith(".py") for f in files):
        r, m = analyze_py(comps, files)
        results.update(r)
        meta["exposed"] = meta["exposed"] or m["exposed"]
    for c in comps:
        if c.ref not in results:
            results[c.ref] = ReachResult(UNKNOWN, "low", [], "no source files for this ecosystem")
    return results, meta
