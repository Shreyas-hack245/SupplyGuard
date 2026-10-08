"""SBOM quality score: penalises missing versions, duplicates, invalid PURLs, missing relationships,
missing hashes, unsupported ecosystems, and unpinned or unresolved entries."""
from __future__ import annotations

from collections import Counter

from app.models.component import ParsedSBOM

QUALITY_CODES = {"MISSING_VERSION", "DUPLICATE_COMPONENT", "INVALID_PURL", "MISSING_RELATIONSHIPS",
                 "MISSING_HASH", "UNSUPPORTED_ECOSYSTEM", "UNPINNED_VERSION", "UNRESOLVED_DEPENDENCY", "MISSING_NAME"}


def sbom_quality(parsed: ParsedSBOM) -> dict:
    counts = Counter(w.code for w in parsed.warnings if w.code in QUALITY_CODES)
    missing_hashes = sum(1 for c in parsed.components if not c.hashes)
    if missing_hashes:
        counts["MISSING_HASH"] += 0  # per-component hash gaps are reported separately, not double counted
    n = max(len(parsed.components), 1)
    issues = sum(counts.values())
    score = max(0, round(100 - 100 * issues / n))
    return {"score": score, "issues": dict(counts), "components": len(parsed.components),
            "components_without_hash": missing_hashes}
