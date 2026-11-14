"""HTTP client: one shared session, retries on 5xx, per-provider rate limiting.

Every failure is raised as ProviderError with a *kind*, so the engine can report
exactly why a source did not answer instead of guessing "clean".
"""
from __future__ import annotations

import threading
import time
from urllib.parse import urlsplit

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

USER_AGENT = "SOAR-Playbook-Automation/0.1 (+defensive security research)"


class ProviderError(Exception):
    def __init__(self, kind: str, message: str) -> None:
        super().__init__(message)
        self.kind = kind          # auth | rate_limit | timeout | network | http | parse
        self.message = message


class RateLimiter:
    """Reservation-style limiter: callers are spaced min_interval apart, thread-safe."""

    def __init__(self, per_minute: float) -> None:
        self.interval = 60.0 / per_minute if per_minute > 0 else 0.0
        self._next = 0.0
        self._lock = threading.Lock()

    def wait(self) -> None:
        if not self.interval:
            return
        with self._lock:
            now = time.monotonic()
            slot = max(now, self._next)
            self._next = slot + self.interval
        delay = slot - now
        if delay > 0:
            time.sleep(delay)


class HttpClient:
    def __init__(self, timeout: float = 20.0) -> None:
        self.timeout = timeout
        self.session = requests.Session()
        retry = Retry(
            total=2, backoff_factor=1.0, status_forcelist=(502, 503, 504),
            allowed_methods=frozenset({"GET", "POST"}), raise_on_status=False,
        )
        adapter = HTTPAdapter(max_retries=retry, pool_maxsize=16)
        self.session.mount("https://", adapter)
        self.session.mount("http://", adapter)
        self.session.headers["User-Agent"] = USER_AGENT

    def request(self, method: str, url: str, *, limiter: RateLimiter | None = None,
                **kwargs) -> requests.Response:
        if limiter:
            limiter.wait()
        kwargs.setdefault("timeout", self.timeout)
        try:
            resp = self.session.request(method, url, **kwargs)
        except requests.Timeout:
            raise ProviderError("timeout", f"timed out after {self.timeout:.0f}s") from None
        except requests.exceptions.SSLError:
            raise ProviderError("network", f"TLS error contacting {urlsplit(url).hostname} (check clock/proxy)") from None
        except requests.ConnectionError:
            raise ProviderError("network", f"cannot connect to {urlsplit(url).hostname} (DNS/network/firewall)") from None
        except requests.RequestException as exc:
            raise ProviderError("network", f"{type(exc).__name__}: {exc}"[:160]) from None
        if resp.status_code in (401, 403):
            raise ProviderError("auth", f"HTTP {resp.status_code} - API key rejected or not authorised")
        if resp.status_code == 429:
            raise ProviderError("rate_limit", "HTTP 429 - rate limit / quota exceeded")
        if resp.status_code >= 500:
            raise ProviderError("http", f"HTTP {resp.status_code} from provider")
        return resp

    @staticmethod
    def json(resp: requests.Response):
        try:
            return resp.json()
        except ValueError:
            raise ProviderError("parse", "provider returned non-JSON response") from None