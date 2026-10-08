"""CISA Known Exploited Vulnerabilities catalogue. Returns None (not an empty set) when unavailable,
so 'unknown exploit status' is never confused with 'not exploited'."""
from __future__ import annotations

import httpx

from app.core.config import settings
from app.engines.vulnerability_intel import VulnCache

KEV_TIMEOUT = 10.0


def load_kev(cache: VulnCache, transport: httpx.BaseTransport | None = None) -> tuple[set[str] | None, str]:
    cached = cache.get("kev-catalog")
    if cached is not None:
        return {r["cve"] for r in cached}, "cache"
    try:
        with httpx.Client(timeout=KEV_TIMEOUT, transport=transport) as c:
            resp = c.get(settings.kev_url)
        body = resp.json() if resp.status_code == 200 else None
    except (httpx.HTTPError, ValueError):
        return None, "unavailable"
    if not isinstance(body, dict) or not isinstance(body.get("vulnerabilities"), list):
        return None, "unavailable"
    records = [{"cve": v["cveID"]} for v in body["vulnerabilities"] if isinstance(v, dict) and v.get("cveID")]
    cache.put("kev-catalog", records)
    return {r["cve"] for r in records}, "live"
