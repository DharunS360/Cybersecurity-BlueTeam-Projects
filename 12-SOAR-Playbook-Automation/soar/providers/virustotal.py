from __future__ import annotations

import base64
import hashlib
from datetime import datetime, timezone

from ..http import ProviderError
from ..models import IOC, Finding, IOCType
from .base import Provider

BASE = "https://www.virustotal.com/api/v3"


def vt_points(malicious: int, suspicious: int, total: int = 0) -> int:
    """Engine-count thresholds. A single-engine hit is weak evidence (often a false positive).

    Overwhelming consensus (20+ engines, or 40%+ of engines) is strong enough to be Malicious alone.
    """
    if malicious >= 20 or (total and malicious >= 5 and malicious / total >= 0.4):
        return 75
    if malicious >= 10:
        return 60
    if malicious >= 5:
        return 45
    if malicious >= 2:
        return 30
    if malicious == 1:
        return 15
    if suspicious >= 3:
        return 10
    return 0


class VirusTotal(Provider):
    name = "VirusTotal"
    supports = frozenset({IOCType.IP, IOCType.DOMAIN, IOCType.URL, IOCType.HASH})
    key_attr = "vt_key"
    rate_per_min = 4                 # public API quota
    probe = (IOCType.IP, "8.8.8.8")

    def _endpoint(self, ioc: IOC) -> tuple[str, str]:
        v = ioc.value
        if ioc.type is IOCType.IP:
            return f"ip_addresses/{v}", f"https://www.virustotal.com/gui/ip-address/{v}"
        if ioc.type is IOCType.DOMAIN:
            return f"domains/{v}", f"https://www.virustotal.com/gui/domain/{v}"
        if ioc.type is IOCType.HASH:
            return f"files/{v}", f"https://www.virustotal.com/gui/file/{v}"
        url_id = base64.urlsafe_b64encode(v.encode()).decode().rstrip("=")
        return f"urls/{url_id}", f"https://www.virustotal.com/gui/url/{hashlib.sha256(v.encode()).hexdigest()}"

    def lookup(self, ioc: IOC) -> Finding:
        path, link = self._endpoint(ioc)
        resp = self.http.request("GET", f"{BASE}/{path}", headers={"x-apikey": self.key}, limiter=self.limiter)
        if resp.status_code == 404:
            return self.not_found("not in VirusTotal corpus (no submission was made - passive lookup only)", link)
        if resp.status_code != 200:
            raise ProviderError("http", f"HTTP {resp.status_code}")
        attrs = (self.http.json(resp).get("data") or {}).get("attributes")
        if attrs is None:
            raise ProviderError("parse", "unexpected VirusTotal response shape")
        stats = attrs.get("last_analysis_stats") or {}
        mal, sus = int(stats.get("malicious", 0)), int(stats.get("suspicious", 0))
        total = sum(int(stats.get(k, 0)) for k in ("malicious", "suspicious", "harmless", "undetected"))
        evidence = {"malicious": mal, "suspicious": sus, "engines": total, "reputation": attrs.get("reputation")}
        ts = attrs.get("last_analysis_date")
        if ts:
            evidence["last_analysis"] = datetime.fromtimestamp(int(ts), timezone.utc).strftime("%Y-%m-%d")
        for k in ("country", "as_owner", "meaningful_name", "type_description"):
            if attrs.get(k):
                evidence[k] = attrs[k]
        label = (attrs.get("popular_threat_classification") or {}).get("suggested_threat_label")
        if label:
            evidence["threat_label"] = label
        pts = vt_points(mal, sus, total)
        reason = f"{mal}/{total} engines flag malicious, {sus} suspicious"
        if label:
            reason += f" (label: {label})"
            if "eicar" in label.lower():
                reason += " - EICAR antivirus TEST file, harmless by design"
                evidence["test_file"] = True
        return self.found(pts, reason, evidence, link)