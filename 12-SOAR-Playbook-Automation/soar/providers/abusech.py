"""abuse.ch family (URLhaus, MalwareBazaar, ThreatFox). One Auth-Key covers all three."""
from __future__ import annotations

from ..http import ProviderError
from ..models import IOC, Finding, IOCType
from .base import Provider


class _AbuseCh(Provider):
    key_attr = "abusech_key"
    rate_per_min = 60

    @property
    def _headers(self) -> dict[str, str]:
        return {"Auth-Key": self.key}


class URLhaus(_AbuseCh):
    name = "URLhaus"
    supports = frozenset({IOCType.URL, IOCType.DOMAIN, IOCType.IP})
    probe = (IOCType.DOMAIN, "example.com")

    def lookup(self, ioc: IOC) -> Finding:
        if ioc.type is IOCType.URL:
            endpoint, payload = "https://urlhaus-api.abuse.ch/v1/url/", {"url": ioc.value}
        else:
            endpoint, payload = "https://urlhaus-api.abuse.ch/v1/host/", {"host": ioc.value}
        resp = self.http.request("POST", endpoint, data=payload, headers=self._headers, limiter=self.limiter)
        if resp.status_code != 200:
            raise ProviderError("http", f"HTTP {resp.status_code}")
        d = self.http.json(resp)
        status = d.get("query_status")
        if status == "no_results":
            return self.not_found("not listed on URLhaus")
        if status != "ok":
            raise ProviderError("parse", f"URLhaus query_status={status}")
        link = d.get("urlhaus_reference") or ""
        if ioc.type is IOCType.URL:
            online = d.get("url_status") == "online"
            ev = {"url_status": d.get("url_status"), "threat": d.get("threat"),
                  "tags": d.get("tags"), "date_added": d.get("date_added")}
            reason = f"listed as malware distribution URL ({d.get('url_status')}, threat: {d.get('threat')})"
            return self.found(70 if online else 50, reason, ev, link)
        count, online_n = int(d.get("url_count") or 0), int(d.get("urls_online") or 0)
        ev = {"url_count": count, "urls_online": online_n, "blacklists": d.get("blacklists")}
        reason = f"host serves {count} known malware URL(s), {online_n} currently online"
        return self.found(65 if online_n else 45, reason, ev, link)


class MalwareBazaar(_AbuseCh):
    name = "MalwareBazaar"
    supports = frozenset({IOCType.HASH})
    probe = (IOCType.HASH, "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f")

    def lookup(self, ioc: IOC) -> Finding:
        resp = self.http.request("POST", "https://mb-api.abuse.ch/api/v1/",
                                 data={"query": "get_info", "hash": ioc.value},
                                 headers=self._headers, limiter=self.limiter)
        if resp.status_code != 200:
            raise ProviderError("http", f"HTTP {resp.status_code}")
        d = self.http.json(resp)
        status = d.get("query_status")
        if status in ("hash_not_found", "no_results"):
            return self.not_found("hash not in MalwareBazaar")
        if status != "ok" or not d.get("data"):
            raise ProviderError("parse", f"MalwareBazaar query_status={status}")
        s = d["data"][0]
        ev = {"signature": s.get("signature"), "file_type": s.get("file_type"),
              "file_name": s.get("file_name"), "first_seen": s.get("first_seen"),
              "tags": s.get("tags"), "delivery_method": s.get("delivery_method")}
        reason = f"known malware sample: {s.get('signature') or 'unclassified'} ({s.get('file_type')})"
        return self.found(80, reason, ev, f"https://bazaar.abuse.ch/sample/{ioc.value}/")


class ThreatFox(_AbuseCh):
    name = "ThreatFox"
    supports = frozenset({IOCType.IP, IOCType.DOMAIN, IOCType.URL})
    probe = (IOCType.DOMAIN, "example.com")

    def lookup(self, ioc: IOC) -> Finding:
        # ThreatFox stores IPs as "ip:port", so IPs need a partial search + local exact filter.
        exact = ioc.type is not IOCType.IP
        resp = self.http.request(
            "POST", "https://threatfox-api.abuse.ch/api/v1/",
            json={"query": "search_ioc", "search_term": ioc.value, "exact_match": exact},
            headers=self._headers, limiter=self.limiter)
        if resp.status_code != 200:
            raise ProviderError("http", f"HTTP {resp.status_code}")
        d = self.http.json(resp)
        status = d.get("query_status")
        if status == "no_result":
            return self.not_found("not listed on ThreatFox")
        if status != "ok":
            raise ProviderError("parse", f"ThreatFox query_status={status}")
        rows = d.get("data") or []
        if ioc.type is IOCType.IP:
            rows = [r for r in rows if str(r.get("ioc", "")).rsplit(":", 1)[0].strip("[]") == ioc.value]
        if not rows:
            return self.not_found("not listed on ThreatFox")
        best = max(rows, key=lambda r: int(r.get("confidence_level") or 0))
        conf = int(best.get("confidence_level") or 0)
        ev = {"records": len(rows), "malware": best.get("malware_printable"),
              "threat_type": best.get("threat_type"), "confidence": conf,
              "first_seen": best.get("first_seen"), "tags": best.get("tags")}
        reason = (f"{len(rows)} ThreatFox record(s): {best.get('malware_printable')} "
                  f"({best.get('threat_type')}), confidence {conf}%")
        return self.found(60 if conf >= 75 else 40, reason, ev, "https://threatfox.abuse.ch/browse/")