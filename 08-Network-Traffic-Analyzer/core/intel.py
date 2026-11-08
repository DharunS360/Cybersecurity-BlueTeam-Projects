"""Live threat-intelligence feeds (IP, domain, JA3). No API keys required."""
import ipaddress
import json
import os
import re
import threading
import time

import requests

# (name, type, url)
FEEDS = [
    ("Feodo Tracker C2 IPs (abuse.ch)", "ip", "https://feodotracker.abuse.ch/downloads/ipblocklist.txt"),
    ("Emerging Threats compromised IPs", "ip", "https://rules.emergingthreats.net/blockrules/compromised-ips.txt"),
    ("SSLBL malicious JA3 (abuse.ch)", "ja3", "https://sslbl.abuse.ch/blacklist/ja3_fingerprints.csv"),
    ("URLhaus malware hosts (abuse.ch)", "domain", "https://urlhaus.abuse.ch/downloads/hostfile/"),
]
BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CACHE = os.path.join(BASE, "data", "intel_cache.json")
MD5 = re.compile(r"^[0-9a-f]{32}$")


def _is_ip(s):
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


class ThreatIntel:
    def __init__(self):
        self.ips, self.ja3, self.domains = {}, {}, {}
        self.feed_status = {name: "not loaded" for name, _, _ in FEEDS}
        self.status = "not loaded"
        self.lock = threading.Lock()
        self._load_cache()

    # ------------------------------------------------------------- persistence
    def _load_cache(self):
        try:
            with open(CACHE, encoding="utf-8") as f:
                d = json.load(f)
            self.ips, self.ja3, self.domains = d.get("ip", {}), d.get("ja3", {}), d.get("domain", {})
            for k in self.feed_status:
                self.feed_status[k] = "cache"
            self.status = "cache: %d IOCs" % self.total()
        except Exception:
            pass

    def _save_cache(self):
        try:
            os.makedirs(os.path.dirname(CACHE), exist_ok=True)
            with open(CACHE, "w", encoding="utf-8") as f:
                json.dump({"ip": self.ips, "ja3": self.ja3, "domain": self.domains}, f)
        except OSError:
            pass

    # ------------------------------------------------------------------ update
    def update(self):
        self.status = "updating feeds..."
        new = {"ip": {}, "ja3": {}, "domain": {}}
        ok_types = set()
        for name, kind, url in FEEDS:
            try:
                r = requests.get(url, timeout=30, headers={"User-Agent": "BlueTeam-NTA/2.0"})
                r.raise_for_status()
                n0 = len(new[kind])
                for line in r.text.splitlines():
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    if kind == "ip":
                        if _is_ip(line):
                            new["ip"][line] = name
                    elif kind == "ja3":
                        h = line.split(",")[0].strip().strip('"').lower()
                        if MD5.match(h):
                            new["ja3"][h] = name
                    else:
                        tok = line.split()[-1].lower()
                        if "." in tok and tok not in ("localhost", "127.0.0.1", "0.0.0.0") and not _is_ip(tok):
                            new["domain"][tok] = name
                self.feed_status[name] = "OK - %d entries" % (len(new[kind]) - n0)
                ok_types.add(kind)
            except Exception as e:
                self.feed_status[name] = "failed (%s)" % type(e).__name__
        with self.lock:
            if "ip" in ok_types:
                self.ips = new["ip"]
            if "ja3" in ok_types:
                self.ja3 = new["ja3"]
            if "domain" in ok_types:
                self.domains = new["domain"]
        if ok_types:
            self._save_cache()
            self.status = "%d IOCs live (%s)" % (self.total(), time.strftime("%H:%M:%S"))
        else:
            self.status = "feed update failed" + (" - using cache (%d)" % self.total() if self.total() else "")
        return self.status

    def total(self):
        return len(self.ips) + len(self.ja3) + len(self.domains)

    # ------------------------------------------------------------------ checks
    def check_ip(self, ip):
        return self.ips.get(ip)

    def check_ja3(self, h):
        return self.ja3.get(h)

    def check_domain(self, d):
        d = (d or "").lower().rstrip(".")
        parts = d.split(".")
        for i in range(len(parts) - 1):
            hit = self.domains.get(".".join(parts[i:]))
            if hit:
                return hit
        return None

    def lookup(self, text):
        t = text.strip().lower()
        if not t:
            return ""
        if _is_ip(t):
            h = self.check_ip(t)
            kind = "IP"
        elif MD5.match(t):
            h = self.check_ja3(t)
            kind = "JA3"
        else:
            h = self.check_domain(t)
            kind = "Domain"
        return "%s %s: %s" % (kind, t, ("MALICIOUS - listed in " + h) if h else "not found in loaded feeds")