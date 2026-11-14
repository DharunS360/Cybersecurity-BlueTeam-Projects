"""Keyless, authoritative feeds: Feodo Tracker (botnet C2), CISA KEV, FIRST EPSS."""
from __future__ import annotations

from ..http import ProviderError
from ..models import IOC, Finding, IOCType
from .base import FeedProvider, Provider


class FeodoTracker(FeedProvider):
    name = "Feodo Tracker"
    supports = frozenset({IOCType.IP})
    feed_url = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"
    feed_file = "feodo_ipblocklist.json"
    max_age_hours = 1.0
    probe = (IOCType.IP, "8.8.8.8")

    def lookup(self, ioc: IOC) -> Finding:
        data, age, stale = self.load_feed()
        if not isinstance(data, list):
            raise ProviderError("parse", "unexpected Feodo feed shape")
        note = f"feed age {age:.1f}h" + (" (STALE - refresh failed)" if stale else "")
        hits = [r for r in data if r.get("ip_address") == ioc.value]
        if not hits:
            return self.not_found(f"not on current Feodo C2 blocklist ({len(data)} entries, {note})")
        r = hits[0]
        ev = {k: r.get(k) for k in ("malware", "port", "status", "country", "as_name", "first_seen", "last_online")}
        reason = f"listed botnet C2: {r.get('malware')} port {r.get('port')} ({r.get('status')}) - {note}"
        pts = 80 if str(r.get("status")).lower() == "online" else 60     # offline IPs may be reassigned
        return self.found(pts, reason, ev, f"https://feodotracker.abuse.ch/browse/host/{ioc.value}/")


class CisaKEV(FeedProvider):
    name = "CISA KEV"
    supports = frozenset({IOCType.CVE})
    feed_url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    feed_file = "cisa_kev.json"
    max_age_hours = 12.0
    probe = (IOCType.CVE, "CVE-2021-44228")

    def lookup(self, ioc: IOC) -> Finding:
        data, age, stale = self.load_feed()
        vulns = data.get("vulnerabilities") if isinstance(data, dict) else None
        if vulns is None:
            raise ProviderError("parse", "unexpected CISA KEV feed shape")
        note = f"catalog v{data.get('catalogVersion')}, feed age {age:.1f}h" + (" (STALE)" if stale else "")
        for v in vulns:
            if v.get("cveID", "").upper() == ioc.value:
                ev = {k: v.get(k) for k in ("vendorProject", "product", "vulnerabilityName", "dateAdded",
                                            "dueDate", "knownRansomwareCampaignUse", "requiredAction")}
                reason = (f"actively exploited in the wild: {v.get('vendorProject')} {v.get('product')}"
                          f" (added {v.get('dateAdded')}, ransomware use: {v.get('knownRansomwareCampaignUse')})")
                return self.found(80, reason, ev, "https://www.cisa.gov/known-exploited-vulnerabilities-catalog")
        return self.not_found(f"not in CISA KEV ({note})")


class EPSS(Provider):
    name = "FIRST EPSS"
    supports = frozenset({IOCType.CVE})
    rate_per_min = 60
    probe = (IOCType.CVE, "CVE-2021-44228")

    def lookup(self, ioc: IOC) -> Finding:
        resp = self.http.request("GET", "https://api.first.org/data/v1/epss", params={"cve": ioc.value},
                                 limiter=self.limiter)
        if resp.status_code != 200:
            raise ProviderError("http", f"HTTP {resp.status_code}")
        rows = self.http.json(resp).get("data") or []
        if not rows:
            return self.not_found("no EPSS score published for this CVE")
        epss, pct = float(rows[0]["epss"]), float(rows[0]["percentile"])
        pts = 30 if epss >= 0.7 else 20 if epss >= 0.3 else 10 if epss >= 0.1 else 0
        ev = {"epss": epss, "percentile": pct, "score_date": rows[0].get("date")}
        reason = f"{epss * 100:.1f}% estimated exploitation probability in next 30 days (top {100 - pct * 100:.1f}%)"
        return self.found(pts, reason, ev, f"https://api.first.org/data/v1/epss?cve={ioc.value}")