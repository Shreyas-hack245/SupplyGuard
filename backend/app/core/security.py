"""Security controls: safe archive extraction (zip-slip, symlink, zip-bomb guards) and rate limiting."""
from __future__ import annotations

import io
import os
import re
import shutil
import stat
import time
import zipfile
from collections import defaultdict, deque
from pathlib import Path

from app.core.config import Settings


class UnsafeArchiveError(ValueError):
    pass


def safe_extract_zip(data: bytes, dest: Path, cfg: Settings) -> Path:
    """Extract an uploaded zip without ever executing or following anything in it.
    Rejects absolute paths, traversal, symlinks, zip bombs, and oversized archives."""
    if len(data) > cfg.max_zip_bytes:
        raise UnsafeArchiveError("archive exceeds upload size limit")
    dest = dest.resolve()
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile as exc:
        raise UnsafeArchiveError("not a valid zip archive") from exc
    with zf:
        infos = zf.infolist()
        if len(infos) > cfg.max_zip_entries:
            raise UnsafeArchiveError("archive has too many entries")
        total = 0
        for info in infos:
            name = info.filename
            if "\x00" in name or name.startswith(("/", "\\")) or re.match(r"^[A-Za-z]:", name):
                raise UnsafeArchiveError(f"absolute path rejected: {name[:80]!r}")
            if ".." in Path(name).parts:
                raise UnsafeArchiveError(f"path traversal rejected: {name[:80]!r}")
            mode = (info.external_attr >> 16) & 0xFFFF
            if stat.S_ISLNK(mode):
                raise UnsafeArchiveError(f"symlink rejected: {name[:80]!r}")
            total += info.file_size
            if total > cfg.max_unzipped_bytes:
                raise UnsafeArchiveError("decompressed size exceeds limit")
            if info.compress_size and info.file_size / info.compress_size > 100:
                raise UnsafeArchiveError("suspicious compression ratio (zip bomb)")
            target = (dest / name).resolve()
            if target != dest and dest not in target.parents:
                raise UnsafeArchiveError("path escapes extraction directory")
            if info.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(info) as src, open(target, "wb") as out:
                shutil.copyfileobj(src, out)
    return dest


class RateLimiter:
    """Sliding-window limiter keyed by client address."""

    def __init__(self, per_minute: int):
        self.limit = per_minute
        self.hits: dict[str, deque[float]] = defaultdict(deque)

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        q = self.hits[key]
        while q and now - q[0] > 60:
            q.popleft()
        if len(q) >= self.limit:
            return False
        q.append(now)
        return True


SAFE_NAME_RE = re.compile(r"^[A-Za-z0-9._-]{1,120}$")


def safe_basename(filename: str | None) -> str:
    base = os.path.basename(filename or "")
    return base if SAFE_NAME_RE.match(base) else "upload"
