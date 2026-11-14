from __future__ import annotations

from ..http import ProviderError
from ..models import IOC, Finding, IOCType
from .base import Provider

MAX_AGE_DAYS = 90


def abuse_points(score: int) -> int:
    if score >= 75:
        return 50
    if score >= 50:
        return 40
    if score >= 25:
        return 25
    if score >= 1:
        return 10
    return 0


class AbuseIPDB(Provider):
    name = "AbuseIPDB"
    supports = frozenset({IOCType.IP})
    key_attr = "abuseipdb_key"
    rate_per_min = 30
    probe = (IOCType.IP, "8.8.8.8")

    def lookup(self, ioc: IOC) -> Finding:
        link = f"https://www.abuseipdb.com/check/{ioc.value}"
        resp = self.http.request(
            "GET", "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": self.key, "Accept": "application/json"},
            params={"ipAddress": ioc.value, "maxAgeInDays": MAX_AGE_DAYS},
            limiter=self.limiter,
        )
        if resp.status_code != 200:
            raise ProviderError("http", f"HTTP {resp.status_code}")
        d = self.http.json(resp).get("data")
        if not isinstance(d, dict):
            raise ProviderError("parse", "unexpected AbuseIPDB response shape")
        score = int(d.get("abuseConfidenceScore", 0))
        reports = int(d.get("totalReports", 0))
        users = int(d.get("numDistinctUsers", 0))
        evidence = {
            "abuse_confidence": score, "total_reports": reports, "distinct_reporters": users,
            "country": d.get("countryCode"), "isp": d.get("isp"), "usage_type": d.get("usageType"),
            "last_reported": d.get("lastReportedAt"), "whitelisted": d.get("isWhitelisted"),
        }
        pts = abuse_points(score)
        reason = f"abuse confidence {score}% ({reports} reports from {users} users, last {MAX_AGE_DAYS}d)"
        if d.get("isWhitelisted"):
            pts, reason = 0, reason + " - listed as WHITELISTED by AbuseIPDB"
            evidence["benign"] = True
        return self.found(pts, reason, evidence, link)