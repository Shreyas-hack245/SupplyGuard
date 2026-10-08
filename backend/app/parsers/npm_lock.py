"""package-lock.json parser (lockfileVersion 2 and 3). Resolves nested node_modules and dependency edges."""
from __future__ import annotations

from app.models.component import Component, DependencyEdge, ParsedSBOM, ParseWarning
from app.parsers.common import component_ref, build_purl, finalize


def _name_from_path(path: str) -> str:
    # "node_modules/a/node_modules/@scope/b" -> "@scope/b"
    return path.rsplit("node_modules/", 1)[-1]


def _resolve(path_prefix: str, name: str, packages: dict) -> str | None:
    """Node resolution: look in the nearest node_modules first, then walk up to the root."""
    prefix = path_prefix
    while True:
        candidate = f"{prefix}node_modules/{name}" if prefix else f"node_modules/{name}"
        if candidate in packages:
            return candidate
        if not prefix:
            return None
        idx = prefix.rstrip("/").rfind("node_modules/")
        prefix = "" if idx <= 0 else prefix[:idx]


def parse_npm_lock(doc: dict) -> ParsedSBOM:
    if not isinstance(doc, dict) or "packages" not in doc:
        raise ValueError("not a v2/v3 package-lock.json (missing 'packages'). Lockfile v1 is not supported.")
    packages: dict = doc["packages"]
    root = packages.get("", {})
    warnings: list[ParseWarning] = []
    parsed = ParsedSBOM(source_format="npm-package-lock", app_name=root.get("name") or doc.get("name"))

    path_to_ref: dict[str, str] = {}
    seen: set[str] = set()
    for path, entry in packages.items():
        if path == "":
            continue
        name = entry.get("name") or _name_from_path(path)
        version = entry.get("version")
        if not version:
            warnings.append(ParseWarning(code="MISSING_VERSION", message=f"{name} has no version in lockfile", ref=path))
        ref = component_ref("npm", name, version)
        path_to_ref[path] = ref
        if ref in seen:
            warnings.append(ParseWarning(code="DUPLICATE_COMPONENT", message=f"{ref} installed at multiple paths", ref=ref))
            continue
        seen.add(ref)
        integrity = entry.get("integrity")
        hashes = {}
        if integrity and "-" in integrity:
            alg, _, val = integrity.partition("-")
            hashes[alg.upper()] = val
        else:
            warnings.append(ParseWarning(code="MISSING_HASH", message=f"{name}@{version} has no integrity hash", ref=ref))
        parsed.components.append(Component(
            ref=ref, name=name, version=version, ecosystem="npm",
            purl=build_purl("npm", name, version), license=entry.get("license") if isinstance(entry.get("license"), str) else None,
            hashes=hashes, scope="dev" if entry.get("dev") else "runtime", source_format="npm-package-lock",
        ))

    edges: list[DependencyEdge] = []
    root_deps = {**root.get("dependencies", {}), **root.get("devDependencies", {}), **root.get("optionalDependencies", {})}
    for dep_name in root_deps:
        target = _resolve("", dep_name, packages)
        if target and target in path_to_ref:
            edges.append(DependencyEdge(parent="", child=path_to_ref[target]))
        else:
            warnings.append(ParseWarning(code="UNRESOLVED_DEPENDENCY", message=f"root dependency {dep_name} not found in lockfile"))

    for path, entry in packages.items():
        if path == "" or path not in path_to_ref:
            continue
        child_deps = {**entry.get("dependencies", {}), **entry.get("optionalDependencies", {})}
        for dep_name in child_deps:
            target = _resolve(path + "/", dep_name, packages)
            if target and target in path_to_ref:
                edges.append(DependencyEdge(parent=path_to_ref[path], child=path_to_ref[target]))
            elif dep_name not in entry.get("optionalDependencies", {}):
                warnings.append(ParseWarning(code="UNRESOLVED_DEPENDENCY", message=f"{dep_name} required by {path_to_ref[path]} not found", ref=path_to_ref[path]))

    unique = list({(e.parent, e.child): e for e in edges}.values())
    parsed.warnings = warnings
    return finalize(parsed, unique)
