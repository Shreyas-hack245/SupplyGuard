"""Format detection and the single public entry point for SBOM ingestion."""
from __future__ import annotations

import json

from app.models.component import ParsedSBOM
from app.parsers.cyclonedx import parse_cyclonedx
from app.parsers.npm_lock import parse_npm_lock
from app.parsers.python_manifests import parse_pyproject_toml, parse_requirements_txt
from app.parsers.spdx import parse_spdx

MAX_BYTES = 10 * 1024 * 1024  # 10 MB upload limit for SBOM parsing


class UnsupportedFormatError(ValueError):
    pass


def parse_sbom(filename: str, content: bytes) -> ParsedSBOM:
    """Detect the format from filename and content, then parse. Raises ValueError on bad input."""
    if len(content) > MAX_BYTES:
        raise ValueError(f"file exceeds {MAX_BYTES} bytes")
    name = (filename or "").lower()
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("file is not valid UTF-8 text") from exc

    if name.endswith("requirements.txt") or name.endswith(".requirements.txt"):
        return parse_requirements_txt(text)
    if name.endswith("pyproject.toml"):
        return parse_pyproject_toml(text)
    if name.endswith(".json"):
        try:
            doc = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ValueError(f"invalid JSON: {exc}") from exc
        if isinstance(doc, dict):
            if doc.get("bomFormat") == "CycloneDX":
                return parse_cyclonedx(doc)
            if "spdxVersion" in doc:
                return parse_spdx(doc)
            if "lockfileVersion" in doc and "packages" in doc:
                return parse_npm_lock(doc)
    raise UnsupportedFormatError(
        "unsupported file. Supported: CycloneDX JSON, SPDX JSON, package-lock.json (v2/v3), requirements.txt, pyproject.toml"
    )
