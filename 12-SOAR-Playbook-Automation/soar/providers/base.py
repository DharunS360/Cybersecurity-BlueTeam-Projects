"""Provider contract. A provider answers ONE question: what does this source know about X?"""
from __future__ import annotations

import json
import time
from abc import ABC, abstractmethod
from pathlib import Path

from ..config import Settings
from ..http import HttpClient, ProviderError, RateLimiter
from ..models import IOC, Finding, IOCType, Status


class Provider(ABC):
    name: str = ""
    supports: frozenset[IOCType] = frozenset()
    key_attr: str | None = None      # Settings attribute holding the API key (None = keyless)
    rate_per_min: float = 0          # 0 = unlimited
    cacheable: bool = True           # False for local feed lookups
    probe: tuple[IOCType, str] | None = None   # known indicator for `doctor`

    def __init__(self, settings: Settings, http: HttpClient) -> None:
        self.settings = settings
        self.http = http
        self.limiter = RateLimiter(self.rate_per_min)

    @property
    def key(self) -> str:
        return getattr(self.settings, self.key_attr) if self.key_attr else ""

    @property
    def enabled(self) -> bool:
        return self.key_attr is None or bool(self.key)

    def applies_to(self, ioc: IOC) -> bool:
        return ioc.type in self.supports

    @abstractmethod
    def lookup(self, ioc: IOC) -> Finding:
        """Query the source. Raise ProviderError on transport/auth/parse problems."""

    # helpers -------------------------------------------------------------
    def found(self, points: int, reason: str, evidence: dict | None = None, link: str = "") -> Finding:
        return Finding(self.name, Status.OK, points, reason, evidence or {}, link)

    def not_found(self, reason: str, link: str = "") -> Finding:
        return Finding(self.name, Status.NOT_FOUND, 0, reason, {}, link)


class FeedProvider(Provider):
    """Provider backed by a downloadable feed, cached on disk. Lookups are local & instant."""
    cacheable = False
    feed_url: str = ""
    feed_file: str = ""
    max_age_hours: float = 1.0

    def load_feed(self) -> tuple[object, float, bool]:
        """Return (parsed_json, age_hours, stale). Falls back to a stale copy if download fails."""
        path: Path = self.settings.feeds_dir / self.feed_file
        path.parent.mkdir(parents=True, exist_ok=True)
        age = (time.time() - path.stat().st_mtime) / 3600 if path.exists() else None
        if age is None or age > self.max_age_hours:
            try:
                resp = self.http.request("GET", self.feed_url)
                if resp.status_code != 200:
                    raise ProviderError("http", f"feed HTTP {resp.status_code}")
                data = self.http.json(resp)
                path.write_text(json.dumps(data), encoding="utf-8")
                return data, 0.0, False
            except ProviderError:
                if age is None:
                    raise
        data = json.loads(path.read_text(encoding="utf-8"))
        age = (time.time() - path.stat().st_mtime) / 3600
        return data, age, age > self.max_age_hours