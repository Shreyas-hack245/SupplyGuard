import json

import pytest

from app.parsers.cyclonedx import parse_cyclonedx
from app.parsers.common import PurlError, parse_purl
from app.parsers.detect import UnsupportedFormatError, parse_sbom
from app.parsers.npm_lock import parse_npm_lock
from app.parsers.python_manifests import parse_pyproject_toml, parse_requirements_txt
from app.parsers.spdx import parse_spdx


def test_purl_parse_scoped_npm():
    info = parse_purl("pkg:npm/%40babel/core@7.20.0")
    assert info == {"type": "npm", "namespace": "@babel", "name": "core", "version": "7.20.0"}


def test_purl_malformed_raises():
    with pytest.raises(PurlError):
        parse_purl("not-a-purl")


def test_cyclonedx_parses_components_and_edges(demo_cdx_bytes):
    p = parse_sbom("demo-sbom.json", demo_cdx_bytes)
    assert p.source_format == "cyclonedx-json"
    names = {c.name for c in p.components}
    assert {"lodash", "express", "axios", "uuid", "qs"} <= names
    lodash = next(c for c in p.components if c.name == "lodash")
    assert lodash.version == "4.17.15" and lodash.ecosystem == "npm"
    assert lodash.purl == "pkg:npm/lodash@4.17.15"
    assert lodash.direct is True and lodash.depth == 1


def test_cyclonedx_invalid_purl_is_warned_not_fatal():
    doc = {"bomFormat": "CycloneDX", "specVersion": "1.5",
           "components": [{"bom-ref": "a", "name": "x", "version": "1", "purl": "garbage"}]}
    p = parse_cyclonedx(doc)
    codes = [w.code for w in p.warnings]
    assert "INVALID_PURL" in codes
    assert len(p.components) == 1


def test_cyclonedx_missing_version_warned():
    doc = {"bomFormat": "CycloneDX", "components": [{"bom-ref": "a", "name": "left-pad", "purl": "pkg:npm/left-pad"}]}
    p = parse_cyclonedx(doc)
    assert "MISSING_VERSION" in [w.code for w in p.warnings]
    assert p.components[0].version is None


def test_cyclonedx_rejects_wrong_format():
    with pytest.raises(ValueError):
        parse_cyclonedx({"spdxVersion": "SPDX-2.3"})


def test_spdx_parses_purls_and_depends_on():
    doc = {
        "spdxVersion": "SPDX-2.3", "name": "app",
        "documentDescribes": ["SPDXRef-App"],
        "packages": [
            {"SPDXID": "SPDXRef-App", "name": "app", "versionInfo": "1.0.0"},
            {"SPDXID": "SPDXRef-lodash", "name": "lodash", "versionInfo": "4.17.15",
             "externalRefs": [{"referenceType": "purl", "referenceLocator": "pkg:npm/lodash@4.17.15"}],
             "checksums": [{"algorithm": "SHA512", "checksumValue": "abc"}], "licenseConcluded": "MIT"},
            {"SPDXID": "SPDXRef-qs", "name": "qs", "versionInfo": "6.7.0",
             "externalRefs": [{"referenceType": "purl", "referenceLocator": "pkg:npm/qs@6.7.0"}]},
        ],
        "relationships": [
            {"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES", "relatedSpdxElement": "SPDXRef-App"},
            {"spdxElementId": "SPDXRef-App", "relationshipType": "DEPENDS_ON", "relatedSpdxElement": "SPDXRef-lodash"},
            {"spdxElementId": "SPDXRef-lodash", "relationshipType": "DEPENDS_ON", "relatedSpdxElement": "SPDXRef-qs"},
        ],
    }
    p = parse_spdx(doc)
    lodash = next(c for c in p.components if c.name == "lodash")
    qs = next(c for c in p.components if c.name == "qs")
    assert lodash.direct is True and lodash.license == "MIT" and lodash.hashes == {"SHA512": "abc"}
    assert qs.direct is False and qs.depth == 2


def test_npm_lock_direct_and_transitive(demo_lock_bytes):
    p = parse_sbom("package-lock.json", demo_lock_bytes)
    by = {c.name: c for c in p.components}
    assert by["express"].direct is True
    assert by["qs"].direct is False
    assert by["qs"].depth == 2
    assert all(c.hashes for c in p.components), "every demo lock entry has integrity"


def test_npm_lock_rejects_v1():
    with pytest.raises(ValueError):
        parse_npm_lock({"lockfileVersion": 1, "dependencies": {}})


def test_requirements_pinned_and_unpinned():
    text = "requests==2.19.1\n# comment\nflask>=2.0\nDjango==3.2.0  # pinned\n-r other.txt\n"
    p = parse_requirements_txt(text)
    by = {c.name: c for c in p.components}
    assert by["requests"].version == "2.19.1" and by["requests"].ecosystem == "PyPI"
    assert by["flask"].version is None
    assert by["django"].version == "3.2.0"
    codes = [w.code for w in p.warnings]
    assert "UNPINNED_VERSION" in codes and "UNSUPPORTED_LINE" in codes


def test_pyproject_dependencies():
    text = '[project]\nname = "demo"\ndependencies = ["httpx==0.27.0", "pydantic>=2"]\n'
    p = parse_pyproject_toml(text)
    by = {c.name: c for c in p.components}
    assert by["httpx"].version == "0.27.0"
    assert by["pydantic"].version is None
    assert p.app_name == "demo"


def test_detect_rejects_unknown_format():
    with pytest.raises(UnsupportedFormatError):
        parse_sbom("notes.json", b'{"hello": 1}')


def test_detect_rejects_oversize():
    with pytest.raises(ValueError):
        parse_sbom("big.json", b"x" * (10 * 1024 * 1024 + 1))


def test_detect_rejects_binary():
    with pytest.raises(ValueError):
        parse_sbom("requirements.txt", b"\xff\xfe\x00")
