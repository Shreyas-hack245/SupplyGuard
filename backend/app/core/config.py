"""All runtime configuration comes from environment variables. No secrets are hardcoded."""
import os
from dataclasses import dataclass, field


@dataclass
class Settings:
    db_path: str = field(default_factory=lambda: os.getenv("SUPPLYGUARD_DB", "supplyguard.db"))
    cache_path: str = field(default_factory=lambda: os.getenv("SUPPLYGUARD_CACHE", "supplyguard_cache.sqlite"))
    osv_url: str = field(default_factory=lambda: os.getenv("OSV_URL", "https://api.osv.dev/v1/query"))
    kev_url: str = field(default_factory=lambda: os.getenv(
        "KEV_URL", "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"))
    github_token: str | None = field(default_factory=lambda: os.getenv("GITHUB_TOKEN") or None)
    github_api_url: str = field(default_factory=lambda: os.getenv("GITHUB_API_URL", "https://api.github.com"))
    max_sbom_bytes: int = 10 * 1024 * 1024
    max_zip_bytes: int = 25 * 1024 * 1024
    max_unzipped_bytes: int = 100 * 1024 * 1024
    max_zip_entries: int = 10_000
    rate_limit_per_min: int = int(os.getenv("SUPPLYGUARD_RATE_LIMIT", "60"))


settings = Settings()
