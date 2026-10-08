"""SPDX 2.x JSON parser. Uses packages, purl external refs, checksums, and DEPENDS_ON relationships."""
from __future__ import annotations

from app.models.component import Component, DependencyEdge, ParsedSBOM, ParseWarning
from app.parsers.common import PURL_TYPE_TO_ECOSYSTEM, PurlError, component_ref, finalize, normalize_name, parse_purl

NOASSERTION = {"NOASSERTION", "NONE", ""}


def _purl_from_refs(pkg: dict) -> str | None:
    for ref in pkg.get("externalRefs", []) or []:
        if ref.get("referenceType") == "purl":
            return ref.get("referenceLocator")
    return None


def parse_spdx(doc: dict) -> ParsedSBOM:
    if not isinstance(doc, dict) or "spdxVersion" not in doc:
        raise ValueError("not an SPDX JSON document (missing spdxVersion)")
    warnings: list[ParseWarning] = []
    parsed = ParsedSBOM(source_format="spdx-json", app_name=doc.get("name"))

    # The package(s) the document describes are the application root, not dependencies.
    root_ids: set[str] = set(doc.get("documentDescribes", []) or [])
    for rel in doc.get("relationships", []) or []:
        if rel.get("spdxElementId") == "SPDXRef-DOCUMENT" and rel.get("relationshipType") == "DESCRIBES":
            root_ids.add(rel.get("relatedSpdxElement"))

    spdx_to_ref: dict[str, str] = {rid: "" for rid in root_ids}
    seen: set[str] = set()
    for pkg in doc.get("packages", []) or []:
        sid = pkg.get("SPDXID")
        if sid in root_ids:
            continue
        name = pkg.get("name")
        version = pkg.get("versionInfo")
        version = None if version in NOASSERTION else version
        purl = _purl_from_refs(pkg)
        ecosystem = None
        if purl:
            try:
                info = parse_purl(purl)
                ecosystem = PURL_TYPE_TO_ECOSYSTEM.get(info["type"])
                if not version and info["version"]:
                    version = info["version"]
                if not name:
                    name = info["name"]
            except PurlError as exc:
                warnings.append(ParseWarning(code="INVALID_PURL", message=str(exc), ref=sid))
        if not name:
            warnings.append(ParseWarning(code="MISSING_NAME", message=f"package {sid} has no name", ref=sid))
            continue
        if ecosystem is None:
            warnings.append(ParseWarning(code="UNSUPPORTED_ECOSYSTEM", message=f"no supported ecosystem for {name}", ref=sid))
            ecosystem = "unknown"
        if not version:
            warnings.append(ParseWarning(code="MISSING_VERSION", message=f"{name} has no version", ref=sid))
        name = normalize_name(name, ecosystem)
        ref = component_ref(ecosystem, name, version)
        if sid:
            spdx_to_ref[sid] = ref
        if ref in seen:
            warnings.append(ParseWarning(code="DUPLICATE_COMPONENT", message=f"duplicate {ref}", ref=ref))
            continue
        seen.add(ref)
        hashes = {c["algorithm"]: c["checksumValue"] for c in pkg.get("checksums", []) or [] if "algorithm" in c}
        lic = pkg.get("licenseConcluded")
        parsed.components.append(Component(
            ref=ref, name=name, version=version, ecosystem=ecosystem, purl=purl,
            license=None if lic in NOASSERTION else lic, hashes=hashes, source_format="spdx-json",
        ))

    edges: list[DependencyEdge] = []
    for rel in doc.get("relationships", []) or []:
        if rel.get("relationshipType") != "DEPENDS_ON":
            continue
        a, b = rel.get("spdxElementId"), rel.get("relatedSpdxElement")
        if a not in spdx_to_ref or b not in spdx_to_ref or spdx_to_ref[b] == "":
            continue
        edges.append(DependencyEdge(parent=spdx_to_ref[a], child=spdx_to_ref[b]))

    if not any(r.get("relationshipType") == "DEPENDS_ON" for r in doc.get("relationships", []) or []):
        warnings.append(ParseWarning(code="MISSING_RELATIONSHIPS", message="SPDX document has no DEPENDS_ON relationships"))

    # Deduplicate edges
    unique = list({(e.parent, e.child): e for e in edges}.values())
    parsed.warnings = warnings
    return finalize(parsed, unique)
