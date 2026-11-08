"""Live threat-intelligence lookups (all real network data)."""
import base64
import ipaddress
import time
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests

from . import dnsutil
from .config import CACHE_DIR

UA = {"User-Agent": "PhishScope/1.0 (blue-team email analyzer)"}
DNSBL_ZONES = (("zen.spamhaus.org", "Spamhaus ZEN"), ("bl.spamcop.net", "SpamCop"))


def geoip(ip, timeout=8.0):
    try:
        r = requests.get(
            f"http://ip-api.com/json/{ip}", headers=UA, timeout=timeout,
            params={"fields": "status,message,country,countryCode,regionName,city,isp,org,as,asname,"
                              "reverse,hosting,proxy,mobile,query"})
        j = r.json()
        if j.get("status") != "success":
            return {"error": j.get("message", "lookup failed")}
        return j
    except Exception as e:
        return {"error": str(e)[:120]}


def dnsbl_ip(ip, timeout=4.0):
    res = []
    try:
        if ipaddress.ip_address(ip).version != 4:
            return res
    except ValueError:
        return res
    rev = ".".join(reversed(ip.split(".")))
    for zone, name in DNSBL_ZONES:
        a, _ = dnsutil.query(f"{rev}.{zone}", "A", timeout)
        if not a:
            res.append({"list": name, "listed": False})
        elif a[0].startswith("127.255.255."):
            res.append({"list": name, "listed": False, "note": "query refused by resolver"})
        else:
            res.append({"list": name, "listed": True, "code": a[0]})
    return res


def dbl(domain, timeout=4.0):
    a, _ = dnsutil.query(f"{domain}.dbl.spamhaus.org", "A", timeout)
    if not a:
        return {"listed": False}
    if a[0].startswith("127.255.255."):
        return {"listed": False, "unavailable": True}
    return {"listed": True, "code": a[0]}


def rdap_age(domain, timeout=8.0):
    try:
        r = requests.get(f"https://rdap.org/domain/{domain}", timeout=timeout, allow_redirects=True,
                         headers={**UA, "Accept": "application/rdap+json"})
        if r.status_code != 200:
            return {"error": f"RDAP HTTP {r.status_code}"}
        j = r.json()
        created = None
        for ev in j.get("events", []):
            if str(ev.get("eventAction", "")).lower() == "registration":
                created = ev.get("eventDate")
        registrar = ""
        for ent in j.get("entities", []):
            if "registrar" in ent.get("roles", []):
                for item in (ent.get("vcardArray") or [None, []])[1]:
                    if item and item[0] == "fn":
                        registrar = item[3]
        age = None
        if created:
            try:
                dt = datetime.fromisoformat(created.replace("Z", "+00:00"))
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                age = (datetime.now(timezone.utc) - dt).days
            except ValueError:
                pass
        return {"created": created, "age_days": age, "registrar": registrar}
    except Exception as e:
        return {"error": str(e)[:120]}


# ---------------------------------------------------------------- VirusTotal v3
def _vt_get(path, key, timeout):
    try:
        r = requests.get("https://www.virustotal.com/api/v3/" + path,
                         headers={"x-apikey": key, **UA}, timeout=timeout)
    except Exception as e:
        return {"status": "error", "error": str(e)[:100]}
    if r.status_code == 404:
        return {"status": "not_found"}
    if r.status_code == 429:
        return {"status": "rate_limited"}
    if r.status_code != 200:
        return {"status": f"http_{r.status_code}"}
    a = r.json().get("data", {}).get("attributes", {})
    st = a.get("last_analysis_stats", {})
    return {"status": "ok", "malicious": st.get("malicious", 0), "suspicious": st.get("suspicious", 0),
            "harmless": st.get("harmless", 0), "undetected": st.get("undetected", 0),
            "label": (a.get("popular_threat_classification") or {}).get("suggested_threat_label", ""),
            "name": a.get("meaningful_name", "")}


def vt_batch(items, key, timeout=8.0):
    """items: list of (kind, value) where kind is 'file' (sha256) or 'url'. Sequential, stops on 429."""
    out, limited = {}, False
    for kind, value in items:
        k = f"{kind}:{value}"
        if limited:
            out[k] = {"status": "skipped_rate_limit"}
            continue
        if kind == "file":
            r = _vt_get(f"files/{value}", key, timeout)
            r["link"] = f"https://www.virustotal.com/gui/file/{value}"
        else:
            uid = base64.urlsafe_b64encode(value.encode()).decode().strip("=")
            r = _vt_get(f"urls/{uid}", key, timeout)
            r["link"] = f"https://www.virustotal.com/gui/url/{uid}"
        if r["status"] == "rate_limited":
            limited = True
        out[k] = r
    return out


# ---------------------------------------------------------------------- OpenPhish
def openphish_feed(timeout=10.0):
    f = CACHE_DIR / "openphish.txt"
    try:
        if not f.exists() or time.time() - f.stat().st_mtime > 6 * 3600:
            r = requests.get("https://openphish.com/feed.txt", timeout=timeout, headers=UA)
            if r.ok and r.text.strip():
                f.write_text(r.text, encoding="utf-8")
    except Exception:
        pass
    urls = set()
    if f.exists():
        urls = {ln.strip() for ln in f.read_text(encoding="utf-8", errors="ignore").splitlines() if ln.strip()}
    hosts = {(urlparse(u).hostname or "").lower() for u in urls}
    return urls, hosts
