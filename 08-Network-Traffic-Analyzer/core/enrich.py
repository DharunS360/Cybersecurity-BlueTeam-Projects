"""Background enrichment: GeoIP/ASN (ipwho.is) + reverse DNS, and process attribution (psutil)."""
import json
import os
import queue
import socket
import threading
import time

import requests

try:
    import psutil
except ImportError:  # pragma: no cover
    psutil = None

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GEO_CACHE = os.path.join(BASE, "data", "geo_cache.json")


class Enricher:
    """Looks up country / ASN / org and reverse-DNS for external IPs in a background thread."""

    def __init__(self):
        self.enabled = True
        self.cache = {}
        self.q = queue.Queue()
        self.pending = set()
        try:
            with open(GEO_CACHE, encoding="utf-8") as f:
                self.cache = json.load(f)
        except Exception:
            pass
        threading.Thread(target=self._run, daemon=True).start()

    def get(self, ip):
        return self.cache.get(ip)

    def request(self, ip):
        if ip in self.cache or ip in self.pending or not self.enabled:
            return
        self.pending.add(ip)
        self.q.put(ip)

    def _run(self):
        saved = time.time()
        while True:
            ip = self.q.get()
            info = {"cc": "??", "country": "", "org": "", "asn": "", "rdns": ""}
            try:
                r = requests.get("https://ipwho.is/" + ip, timeout=8, headers={"User-Agent": "BlueTeam-NTA/2.0"})
                j = r.json()
                if j.get("success"):
                    c = j.get("connection") or {}
                    info.update(cc=j.get("country_code") or "??", country=j.get("country") or "",
                                org=c.get("org") or c.get("isp") or "",
                                asn=("AS%s" % c["asn"]) if c.get("asn") else "")
            except Exception:
                pass
            try:
                socket.setdefaulttimeout(2)
                info["rdns"] = socket.gethostbyaddr(ip)[0].lower()
            except Exception:
                pass
            self.cache[ip] = info
            self.pending.discard(ip)
            if time.time() - saved > 30:
                saved = time.time()
                self.save()
            time.sleep(0.25)

    def save(self):
        try:
            os.makedirs(os.path.dirname(GEO_CACHE), exist_ok=True)
            with open(GEO_CACHE, "w", encoding="utf-8") as f:
                json.dump(self.cache, f)
        except Exception:
            pass


class ProcessMapper:
    """Maps live sockets to owning process name/PID (needs Administrator for all processes)."""

    def __init__(self):
        self.by4, self.byp, self.names = {}, {}, {}
        self.error = "" if psutil else "psutil not installed"
        if psutil:
            threading.Thread(target=self._run, daemon=True).start()

    def _name(self, pid):
        if pid in self.names:
            return self.names[pid]
        try:
            n = psutil.Process(pid).name()
        except Exception:
            n = "pid-%d" % pid
        if pid in (0, 4):
            n = "System"
        self.names[pid] = n
        return n

    def _run(self):
        while True:
            try:
                by4, byp = {}, {}
                for c in psutil.net_connections(kind="inet"):
                    if not c.laddr or c.pid is None:
                        continue
                    proto = "TCP" if c.type == socket.SOCK_STREAM else "UDP"
                    val = (self._name(c.pid), c.pid)
                    byp[(proto, c.laddr.port)] = val
                    if c.raddr:
                        by4[(proto, c.laddr.port, c.raddr.ip, c.raddr.port)] = val
                self.by4, self.byp = by4, byp
                self.error = ""
            except Exception as e:
                self.error = type(e).__name__
            time.sleep(1.0)

    def lookup(self, proto, lport, rip, rport):
        return self.by4.get((proto, lport, rip, rport)) or self.byp.get((proto, lport))


def local_addresses():
    out = set()
    if psutil:
        try:
            for addrs in psutil.net_if_addrs().values():
                for a in addrs:
                    if a.family in (socket.AF_INET, socket.AF_INET6):
                        out.add(a.address.split("%")[0])
        except Exception:
            pass
    return out