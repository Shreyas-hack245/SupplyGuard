"""CycloneDX JSON parser (1.4+). Extracts components, PURLs, hashes, licenses, and dependency edges."""
from __future__ import annotations

from app.models.component import Component, DependencyEdge, ParsedSBOM, ParseWarning
from app.parsers.common import PURL_TYPE_TO_ECOSYSTEM, PurlError, component_ref, finalize, normalize_name, parse_purl


def _license(entry: dict) -> str | None:
    licenses = entry.get("licenses") or []
    names = []
    for item in licenses:
        if "expression" in item:
            names.append(item["expression"])
        elif "license" in item:
            lic = item["license"]
            names.append(lic.get("id") or lic.get("name"))
    names = [n for n in names if n]
    return " AND ".join(names) if names else None


def _hashes(entry: dict) -> dict[str, str]:
    return {h["alg"]: h["content"] for h in entry.get("hashes", []) if "alg" in h and "content" in h}


def parse_cyclonedx(doc: dict) -> ParsedSBOM:
    if not isinstance(doc, dict) or doc.get("bomFormat") != "CycloneDX":
        raise ValueError("not a CycloneDX document (missing bomFormat=CycloneDX)")
    warnings: list[ParseWarning] = []
    parsed = ParsedSBOM(source_format="cyclonedx-json")

    bom_ref_to_ref: dict[str, str] = {}
    seen_refs: set[str] = set()
    for entry in doc.get("components", []) or []:
        name = entry.get("name")
        version = entry.get("version")
        purl = entry.get("purl")
        ecosystem = None
        if purl:
            try:
                info = parse_purl(purl)
                ecosystem = PURL_TYPE_TO_ECOSYSTEM.get(info["type"])
                if info["version"] and not version:
                    version = info["version"]
                if not name:
                    name = info["name"]
            except PurlError as exc:
                warnings.append(ParseWarning(code="INVALID_PURL", message=str(exc), ref=entry.get("bom-ref")))
        if not name:
            warnings.append(ParseWarning(code="MISSING_NAME", message="component without name skipped", ref=entry.get("bom-ref")))
            continue
        if ecosystem is None:
            warnings.append(ParseWarning(code="UNSUPPORTED_ECOSYSTEM", message=f"no supported ecosystem for {name} (purl={purl})", ref=entry.get("bom-ref")))
            ecosystem = "unknown"
        if not version:
            warnings.append(ParseWarning(code="MISSING_VERSION", message=f"{name} has no version", ref=entry.get("bom-ref")))
        name = normalize_name(name, ecosystem)
        ref = component_ref(ecosystem, name, version)
        if ref in seen_refs:
            warnings.append(ParseWarning(code="DUPLICATE_COMPONENT", message=f"duplicate {ref}", ref=ref))
            bom_ref = entry.get("bom-ref")
            if bom_ref:
                bom_ref_to_ref[bom_ref] = ref
            continue
        seen_refs.add(ref)
        if entry.get("bom-ref"):
            bom_ref_to_ref[entry["bom-ref"]] = ref
        parsed.components.append(Component(
            ref=ref, name=name, version=version, ecosystem=ecosystem, purl=purl,
            license=_license(entry), hashes=_hashes(entry),
            scope="runtime" if entry.get("scope", "required") == "required" else entry.get("scope"),
            source_format="cyclonedx-json",
        ))

    root = doc.get("metadata", {}).get("component", {})
    parsed.app_name = root.get("name")
    root_bom_ref = root.get("bom-ref")
    if root_bom_ref:
        bom_ref_to_ref[root_bom_ref] = ""  # application root sentinel

    edges: list[DependencyEdge] = []
    deps = doc.get("dependencies")
    if deps is None:
        warnings.append(ParseWarning(code="MISSING_RELATIONSHIPS", message="SBOM has no dependencies section; direct/transitive cannot be determined"))
    else:
        for dep in deps:
            parent_ref = bom_ref_to_ref.get(dep.get("ref"))
            if parent_ref is None:
                continue
            for child_bom in dep.get("dependsOn", []) or []:
                child_ref = bom_ref_to_ref.get(child_bom)
                if child_ref is None or child_ref == "":
                    continue
                edges.append(DependencyEdge(parent=parent_ref, child=child_ref))

    # Components with no incoming edge are attached to the application root so depth is defined.
    if deps is not None:
        has_parent = {e.child for e in edges}
        for c in parsed.components:
            if c.ref not in has_parent:
                edges.append(DependencyEdge(parent="", child=c.ref))

    parsed.warnings = warnings
    return finalize(parsed, edges)
