"""Test doubles. These exist ONLY in the test-suite; the product itself never uses mock data."""
from __future__ import annotations

import json
import tempfile
from pathlib import Path

from soar.config import Settings
from soar.http import HttpClient, ProviderError


class FakeResp:
    def __init__(self, status: int = 200, body=None):
        self.status_code = status
        self._body = body

    def json(self):
        if self._body is None:
            raise ValueError("no json")
        return self._body


class FakeHttp(HttpClient):
    """Routes (substring of URL -> response or exception). Records every call."""

    def __init__(self, routes: dict | None = None):
        self.routes = routes or {}
        self.calls: list[tuple[str, str, dict]] = []

    def request(self, method, url, *, limiter=None, **kwargs):
        self.calls.append((method, url, kwargs))
        for needle, result in self.routes.items():
            if needle in url:
                if isinstance(result, Exception):
                    raise result
                return result
        raise ProviderError("network", f"no fake route for {url}")


def settings(**kw) -> Settings:
    tmp = Path(tempfile.mkdtemp(prefix="soar-test-"))
    base = dict(vt_key="k", abuseipdb_key="k", otx_key="k", abusech_key="k", data_dir=tmp)
    base.update(kw)
    return Settings(**base)


def jresp(body, status=200) -> FakeResp:
    return FakeResp(status, json.loads(json.dumps(body)))