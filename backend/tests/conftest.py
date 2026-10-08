import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
DEMO = ROOT / "examples" / "vulnerable-app"


@pytest.fixture
def demo_lock_bytes():
    return (DEMO / "package-lock.json").read_bytes()


@pytest.fixture
def demo_cdx_bytes():
    return (DEMO / "sbom.cdx.json").read_bytes()
