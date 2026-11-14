from __future__ import annotations

from ..http import ProviderError
from ..models import IOC, Finding, IOCType
from .base import Provider

_TYPE = {IOCType.DOMAIN: "domain", IOCType.URL: "url", IOCType.HASH: "file"}


def otx_points(pulses: int) -> int:
    """Community pulses are noisy (context, not proof), so weight is deliberately modest."""
    if pulses >= 10:
        return 30
    if pulses >= 3:
        return 20
    if pulses >= 1:
        return 10
    return 0


class OTX(Provider):
    name = "AlienVault OTX"
    supports = frozenset({IOCType.IP, IOCType.DOMAIN, IOCType.URL, IOCType.HASH})
    key_attr = "otx_key"
    rate_per_min = 60
    probe = (IOCType.IP, "8.8.8.8")

    def lookup(self, ioc: IOC) -> Finding:
        if ioc.type is IOCType.IP:
            t = "IPv6" if ":" in ioc.value else "IPv4"
        else:
            t = _TYPE[ioc.type]
        url = f"https://otx.alienvault.com/api/v1/indicators/{t}/{ioc.value}/general"
        link = f"https://otx.alienvault.com/indicator/{'ip' if ioc.type is IOCType.IP else t}/{ioc.value}"
        resp = self.http.request("GET", url, headers={"X-OTX-API-KEY": self.key}, limiter=self.limiter)
        if resp.status_code == 404:
            return self.not_found("indicator unknown to OTX", link)
        if resp.status_code != 200:
            raise ProviderError("http", f"HTTP {resp.status_code}")
        data = self.http.json(resp)
        pi = data.get("pulse_info")
        if not isinstance(pi, dict):
            raise ProviderError("parse", "unexpected OTX response shape")
        count = int(pi.get("count", 0))
        names = [p.get("name", "") for p in (pi.get("pulses") or [])[:3]]
        benign = [v.get("message") or v.get("source") for v in (data.get("validation") or [])]
        evidence = {"pulse_count": count, "sample_pulses": names}
        if benign:
            evidence["validation"] = benign
        pts = otx_points(count)
        reason = f"referenced in {count} community pulse(s)"
        if benign:
            pts, reason = 0, reason + f" - OTX validation marks it benign ({benign[0]})"
            evidence["benign"] = True
        return self.found(pts, reason, evidence, link) if count or benign else self.not_found("no OTX pulses reference it", link)