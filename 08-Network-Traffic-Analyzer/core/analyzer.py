"""Flow tracking + detection engine."""
import ipaddress
import json
import math
import os
import statistics
import threading
import time
from collections import Counter, OrderedDict, defaultdict, deque
from dataclasses import dataclass
from functools import lru_cache

from .tls import parse_client_hello

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

QTYPES = {1: "A", 2: "NS", 5: "CNAME", 10: "NULL", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV", 65: "HTTPS", 255: "ANY"}
APP_PORTS = {80: "HTTP", 443: "HTTPS", 8080: "HTTP", 8443: "HTTPS", 53: "DNS", 22: "SSH", 21: "FTP", 25: "SMTP", 587: "SMTP",
             110: "POP3", 143: "IMAP", 3389: "RDP", 445: "SMB", 139: "NetBIOS", 123: "NTP", 5353: "mDNS", 5355: "LLMNR",
             1900: "SSDP", 67: "DHCP", 68: "DHCP", 137: "NetBIOS", 138: "NetBIOS", 23: "Telnet", 993: "IMAPS", 465: "SMTPS"}
DNS_SAFE = (".in-addr.arpa", ".ip6.arpa", ".local", ".akamaiedge.net", ".cloudfront.net", ".amazonaws.com",
            ".googleusercontent.com", ".azureedge.net", ".akadns.net", ".edgekey.net", ".fastly.net", ".msedge.net")
BEACON_SKIP_PORTS = {53, 67, 68, 123, 137, 138, 1900, 5353, 5355}
RISKY_PORTS = {23: ("Telnet", "Medium"), 445: ("SMB over internet", "Medium"), 3389: ("RDP over internet", "Medium"),
               5900: ("VNC", "Medium"), 1433: ("MSSQL", "Medium"), 3306: ("MySQL", "Medium"), 5985: ("WinRM", "Medium"),
               4444: ("Metasploit default port", "High"), 6667: ("IRC (common botnet C2)", "Medium"),
               9001: ("Tor relay port", "Medium"), 31337: ("Backdoor port", "High")}
SEV_POINTS = {"Critical": 100, "High": 70, "Medium": 40, "Low": 15}
COOLDOWN = 300
EXFIL_BYTES = 50 * 1024 * 1024

ADVICE = {
    "Known Malicious IP": "Remote IP is on a public C2/compromise blocklist. Isolate the host, identify the process (see Process column), block the IP at the firewall and check the host for malware.",
    "Malicious Domain": "Domain is listed in URLhaus (malware distribution). Identify the process/user that requested it, block the domain at DNS/proxy and scan the endpoint.",
    "Malicious JA3": "The TLS client fingerprint matches a known malware family (SSLBL). Investigate the process making the connection and the destination server.",
    "Port Scan": "One host probed many ports quickly (reconnaissance). If internal, treat the source as compromised or an unauthorised scanner; if external, block it.",
    "Network Sweep": "One host contacted many internal machines on the same port - typical of worm/lateral-movement discovery. Investigate the source host immediately.",
    "SYN Flood": "A very high rate of SYN packets hit one destination (DoS attempt). Enable SYN cookies / rate limiting and identify the sources.",
    "Beaconing": "Connections happen at suspiciously regular intervals - a classic malware check-in pattern. Many legitimate apps also do this (updates/telemetry), so verify the process and destination reputation before escalating.",
    "DNS Tunneling": "DNS names look like encoded data (long/high-entropy subdomains or TXT abuse) - data exfiltration or C2 over DNS. Inspect the queried domain and block it.",
    "DNS Tunneling (volume)": "Hundreds of unique subdomains under one parent in a minute - encoded data is likely being tunnelled over DNS.",
    "Possible DGA": "Domain looks algorithmically generated (random letters/digits). Malware often uses DGAs to find C2 servers; check what process asked for it.",
    "NXDOMAIN Storm": "A client is getting many 'domain does not exist' answers - typical of DGA malware hunting for a live C2 domain.",
    "ARP Spoofing": "An IP address suddenly maps to a different MAC address - possible man-in-the-middle (T1557). Verify the gateway MAC and check for rogue devices.",
    "Rogue DHCP": "More than one DHCP server is answering on the network - possible MITM/rogue device. Locate and remove the extra DHCP server.",
    "ICMP Tunneling": "Unusually large ICMP echo payloads - data may be hidden inside ping traffic.",
    "Cleartext Credentials": "Credentials crossed the network unencrypted. Rotate the account password, and move the service to an encrypted protocol (HTTPS/SFTP/IMAPS).",
    "Large Upload (Exfiltration?)": "A single connection uploaded a very large amount of data compared to what it downloaded. Confirm it is a legitimate backup/upload; otherwise treat as data exfiltration.",
    "Risky Outbound Port": "Outbound connection to a service that is rarely legitimate across the internet. Confirm the business need; block at the firewall if unexpected.",
}


@lru_cache(maxsize=65536)
def is_internal(ip):
    try:
        a = ipaddress.ip_address(ip)
        return (a.is_private or a.is_multicast or a.is_loopback or a.is_link_local
                or a.is_unspecified or a.is_reserved)
    except ValueError:
        return True


def entropy(s):
    if not s:
        return 0.0
    c = Counter(s)
    n = len(s)
    return -sum(v / n * math.log2(v / n) for v in c.values())


def tcp_flags(f):
    names = [("F", 0x01), ("S", 0x02), ("R", 0x04), ("P", 0x08), ("A", 0x10), ("U", 0x20)]
    return "".join(n for n, b in names if f & b)


@dataclass
class Alert:
    ts: float
    severity: str
    kind: str
    src: str
    dst: str
    detail: str
    mitre: str
    proc: str = ""


class Flow:
    __slots__ = ("id", "proto", "lip", "lport", "rip", "rport", "start", "last", "pkts_out", "pkts_in", "bytes_out",
                 "bytes_in", "state", "proc", "pid", "sni", "ja3", "tls", "exfil", "proc_try", "app")

    def __init__(self, fid, proto, lip, lport, rip, rport, ts, app):
        self.id, self.proto, self.lip, self.lport, self.rip, self.rport = fid, proto, lip, lport, rip, rport
        self.start = self.last = ts
        self.pkts_out = self.pkts_in = self.bytes_out = self.bytes_in = 0
        self.state, self.proc, self.pid, self.sni, self.ja3, self.tls = "-", "", 0, "", "", ""
        self.exfil, self.proc_try, self.app = False, 0.0, app


class LogWriter:
    """SIEM-friendly JSON-lines logs (Zeek style): conn, dns, tls, alerts."""

    def __init__(self, base):
        self.dir = os.path.join(base, "logs")
        os.makedirs(self.dir, exist_ok=True)
        self.files = {}
        self.lock = threading.Lock()

    def write(self, name, obj):
        try:
            with self.lock:
                f = self.files.get(name)
                if f is None:
                    f = open(os.path.join(self.dir, name + ".jsonl"), "a", encoding="utf-8")
                    self.files[name] = f
                f.write(json.dumps(obj, default=str) + "\n")
                f.flush()
        except Exception:
            pass


class Analyzer:
    def __init__(self, intel, enricher=None, procmap=None, logger=None):
        self.intel, self.enricher, self.procmap, self.logger = intel, enricher, procmap, logger
        self.lock = threading.RLock()
        self.local_ips = set()
        self.live = False
        self.allow = set()
        self.allow_file = os.path.join(BASE, "data", "allowlist.txt")
        try:
            with open(self.allow_file, encoding="utf-8") as f:
                self.allow = {l.strip() for l in f if l.strip()}
        except OSError:
            pass
        self.reset()

    # ----------------------------------------------------------------- state
    def reset(self):
        with self.lock:
            self.total = self.bytes = 0
            self.last_ts = 0.0
            self.proto = Counter()
            self.flows = {}
            self.flow_seq = 0
            self.history = deque(maxlen=1000)
            self.hosts_seen = set()
            self.ip_domain = {}
            self.ip_risk = {}
            self.rproc = {}
            self.dns_rows = deque(maxlen=1500)
            self.dns_wait = OrderedDict()
            self.tls_rows = deque(maxlen=1000)
            self.pending = deque(maxlen=3000)
            self.ring = deque(maxlen=20000)
            self.alerts = []
            self.mitre = Counter()
            self.bw = deque(maxlen=400)
            self.scan = defaultdict(lambda: deque(maxlen=500))
            self.synflood = defaultdict(lambda: deque(maxlen=800))
            self.beacon = defaultdict(lambda: deque(maxlen=40))
            self.dns_sub = defaultdict(lambda: deque(maxlen=400))
            self.nx = defaultdict(lambda: deque(maxlen=200))
            self.icmpbig = defaultdict(lambda: deque(maxlen=20))
            self.arp_map = {}
            self.dhcp = set()
            self.cool = {}

    def set_local_ips(self, ips):
        with self.lock:
            self.local_ips = set(ips)

    def allow_add(self, value):
        with self.lock:
            self.allow.add(value)
            try:
                os.makedirs(os.path.dirname(self.allow_file), exist_ok=True)
                with open(self.allow_file, "w", encoding="utf-8") as f:
                    f.write("\n".join(sorted(self.allow)))
            except OSError:
                pass

    def is_local(self, ip):
        if self.local_ips:
            return ip in self.local_ips
        try:
            return ipaddress.ip_address(ip).is_private
        except ValueError:
            return False

    def domain_for(self, ip, f=None):
        if f is not None and f.sni:
            return f.sni
        d = self.ip_domain.get(ip)
        if d:
            return d
        if self.enricher:
            g = self.enricher.get(ip)
            if g and g.get("rdns"):
                return g["rdns"]
        return ""

    # ---------------------------------------------------------------- ingest
    def process(self, pkt):
        """Scapy callback: parse + ingest."""
        from .parser import parse
        r = parse(pkt)
        if r is not None:
            self.ingest(r)

    def ingest(self, r):
        try:
            with self.lock:
                self._ingest(r)
        except Exception:
            pass

    def _app(self, r):
        if r.dns is not None:
            return "DNS"
        if r.l4 == "UDP" and 443 in (r.sport, r.dport):
            return "QUIC"
        if r.l4 in ("TCP", "UDP"):
            return APP_PORTS.get(r.dport) or APP_PORTS.get(r.sport) or r.l4
        return r.l4

    def _ingest(self, r):
        ts = r.ts
        self.last_ts = ts
        self.total += 1
        self.bytes += r.length
        if r.raw:
            self.ring.append((ts, r.raw))
        if r.l4 == "ARP":
            self.proto["ARP"] += 1
            self.pending.append((ts, r.src, r.dst, "ARP", "ARP", 0, 0, r.length, "who-has" if r.arp["op"] == 1 else "is-at"))
            self._arp(r)
            return
        app = self._app(r)
        self.proto[app] += 1
        f, out = self._flow(r, app)
        sec = int(ts)
        if self.bw and self.bw[-1][0] == sec:
            self.bw[-1][1 if out else 2] += r.length
        else:
            self.bw.append([sec, r.length if out else 0, 0 if out else r.length])

        info = tcp_flags(r.flags) if r.l4 == "TCP" else ("type %d" % r.icmp_type if r.l4 == "ICMP" else "")
        syn_only = r.l4 == "TCP" and (r.flags & 0x17) == 0x02
        if r.dns:
            d = r.dns
            info = ("Query %s %s" % (QTYPES.get(d["qtype"], d["qtype"]), d["qname"])) if d["qr"] == 0 else \
                   ("Response %s -> %s" % (d["qname"], ", ".join(d["answers"][:3]) or ("NXDOMAIN" if d["rcode"] == 3 else "no answer")))
        if r.l4 == "TCP" and r.payload and out:
            ch = parse_client_hello(r.payload) if r.payload[0] == 0x16 else None
            if ch:
                info = "ClientHello SNI=%s" % (ch["sni"] or "-")
                self._tls(r, f, ch)
            elif r.dport in (21, 80, 110, 143, 8080, 8000):
                self._cleartext(r, f)
        self.pending.append((ts, r.src, r.dst, r.l4, app, r.sport, r.dport, r.length, info))

        if syn_only:
            self._scan(r)
            if out and not is_internal(r.dst):
                if r.dport in RISKY_PORTS:
                    name, sev = RISKY_PORTS[r.dport]
                    self._raise(ts, ("risky", r.src, r.dst, r.dport), sev, "Risky Outbound Port", r.src, r.dst,
                                "%s -> %s:%d (%s)" % (r.src, r.dst, r.dport, name), "T1571 Non-Standard Port", f.proc or self.rproc.get((r.dst, r.dport), ""))
                if r.dport not in BEACON_SKIP_PORTS:
                    self._beacon(ts, (r.src, r.dst, r.dport), r.src, r.dst, "%s:%d" % (r.dst, r.dport), 0.20,
                                 f.proc or self.rproc.get((r.dst, r.dport), ""))
        elif r.l4 == "UDP" and out and not is_internal(r.dst) and r.dport not in BEACON_SKIP_PORTS and not r.dns:
            self._beacon(ts, (r.src, r.dst, r.dport, "u"), r.src, r.dst, "%s:%d/udp" % (r.dst, r.dport), 0.20,
                           f.proc or self.rproc.get((r.dst, r.dport), ""))
        if r.dns:
            self._dns(r, f)
        if r.l4 == "UDP" and r.sport == 67 and r.dport == 68 and r.payload[:1] == b"\x02":
            self.dhcp.add(r.src)
            if len(self.dhcp) > 1:
                self._raise(ts, ("dhcp",), "High", "Rogue DHCP", r.src, "", "DHCP offers from multiple servers: %s"
                            % ", ".join(sorted(self.dhcp)), "T1557 Adversary-in-the-Middle")
        if r.l4 == "ICMP" and r.icmp_type in (0, 8) and r.icmp_len >= 128:
            dq = self.icmpbig[(r.src, r.dst)]
            dq.append(ts)
            if len([t for t in dq if ts - t < 60]) >= 5:
                self._raise(ts, ("icmp", r.src, r.dst), "Medium", "ICMP Tunneling", r.src, r.dst,
                            "repeated ICMP echo with %d-byte payloads" % r.icmp_len, "T1095 Non-Application Layer Protocol")

    # ------------------------------------------------------------------ flows
    def _flow(self, r, app):
        a, b = (r.src, r.sport), (r.dst, r.dport)
        key = (r.l4,) + (a + b if a <= b else b + a)
        f = self.flows.get(key)
        if f is None:
            sl, dl = self.is_local(r.src), self.is_local(r.dst)
            if dl and not sl:
                lip, lp, rip, rp = r.dst, r.dport, r.src, r.sport
            else:
                lip, lp, rip, rp = r.src, r.sport, r.dst, r.dport
            self.flow_seq += 1
            f = Flow(self.flow_seq, r.l4, lip, lp, rip, rp, r.ts, app)
            self.flows[key] = f
            self._new_flow(f, r.ts)
        out = r.src == f.lip and (r.l4 == "ICMP" or r.sport == f.lport)
        f.last = r.ts
        if out:
            f.pkts_out += 1
            f.bytes_out += r.length
        else:
            f.pkts_in += 1
            f.bytes_in += r.length
        if r.l4 == "TCP":
            fl = r.flags
            if fl & 0x04:
                f.state = "RESET"
            elif fl & 0x01:
                f.state = "CLOSING"
            elif (fl & 0x12) == 0x12:
                f.state = "ESTABLISHED"
            elif (fl & 0x17) == 0x02:
                f.state = "SYN"
            elif f.state == "-":
                f.state = "ESTABLISHED"
        elif f.state == "-":
            f.state = "ACTIVE"
        if not f.proc and self.live and self.procmap and time.time() - f.proc_try > 1.0 and ts_recent(f):
            f.proc_try = time.time()
            res = self.procmap.lookup(f.proto, f.lport, f.rip, f.rport)
            if res:
                f.proc, f.pid = res
                self.rproc[(f.rip, f.rport)] = f.proc
        if (not f.exfil and f.bytes_out >= EXFIL_BYTES and f.bytes_out >= 10 * max(f.bytes_in, 1)
                and not is_internal(f.rip)):
            f.exfil = True
            self._raise(r.ts, ("exfil", f.id), "Medium", "Large Upload (Exfiltration?)", f.lip, f.rip,
                        "%.0f MB sent vs %.1f MB received to %s (%s)" % (f.bytes_out / 1048576.0, f.bytes_in / 1048576.0,
                                                                         f.rip, self.domain_for(f.rip, f) or "no domain"),
                        "T1048 Exfiltration Over Alternative Protocol", f.proc)
        return f, out

    def _new_flow(self, f, ts):
        self.hosts_seen.add(f.rip)
        for ip in (f.rip, f.lip):
            if not is_internal(ip):
                feed = self.intel.check_ip(ip)
                if feed:
                    self._raise(ts, ("ti", ip), "Critical", "Known Malicious IP", f.lip, f.rip,
                                "%s is listed in %s" % (ip, feed), "T1071 Application Layer Protocol (C2)", f.proc)
        if self.enricher and not is_internal(f.rip):
            self.enricher.request(f.rip)

    def sweep(self):
        """Expire idle flows into the closed-flow history + conn log."""
        with self.lock:
            now = self.last_ts
            dead = []
            for k, f in self.flows.items():
                idle = now - f.last
                limit = 10 if f.state in ("CLOSING", "RESET") else (120 if f.proto == "TCP" else 45)
                if idle > limit:
                    dead.append(k)
            for k in dead:
                f = self.flows.pop(k)
                row = self._flow_row(f)
                self.history.append(row)
                if self.logger:
                    self.logger.write("conn", {k2: v for k2, v in row.items()})

    def _flow_row(self, f):
        dom = self.domain_for(f.rip, f)
        g = (self.enricher.get(f.rip) if self.enricher else None) or {}
        cc = "LAN" if is_internal(f.rip) else (g.get("cc") or "...")
        risk = max(self.ip_risk.get(f.rip, 0), self.ip_risk.get(dom, 0) if dom else 0)
        return dict(id=f.id, proc=f.proc or "-", pid=f.pid, proto=f.proto, app=f.app, local="%s:%d" % (f.lip, f.lport),
                    remote="%s:%d" % (f.rip, f.rport), rip=f.rip, domain=dom, cc=cc,
                    org=(g.get("org") or "") if cc != "LAN" else "Local network", asn=g.get("asn", ""),
                    out=f.bytes_out, inn=f.bytes_in, pkts=f.pkts_out + f.pkts_in, dur=f.last - f.start,
                    state=f.state, risk=risk, ja3=f.ja3, tls=f.tls, start=f.start, last=f.last)

    # ------------------------------------------------------------- detections
    def _raise(self, ts, key, sev, kind, src, dst, detail, mitre, proc=""):
        if src in self.allow or dst in self.allow:
            return
        last = self.cool.get(key)
        if last is not None and ts - last < COOLDOWN:
            return
        self.cool[key] = ts
        a = Alert(ts, sev, kind, src, dst, detail, mitre, proc)
        self.alerts.append(a)
        self.mitre[mitre] += 1
        pts = SEV_POINTS.get(sev, 0)
        for ip in (src, dst):
            if ip and not self.is_local(ip):
                self.ip_risk[ip] = max(self.ip_risk.get(ip, 0), pts)
        if self.logger:
            self.logger.write("alerts", {"ts": ts, "severity": sev, "detection": kind, "src": src, "dst": dst,
                                         "process": proc, "detail": detail, "mitre": mitre})

    def _arp(self, r):
        ip, mac = r.arp["psrc"], r.arp["hwsrc"].lower()
        if ip in ("0.0.0.0", "") or mac in ("00:00:00:00:00:00",):
            return
        old = self.arp_map.get(ip)
        if old is None:
            self.arp_map[ip] = mac
        elif old != mac:
            self._raise(r.ts, ("arp", ip, mac), "High", "ARP Spoofing", ip, mac,
                        "%s changed MAC %s -> %s" % (ip, old, mac), "T1557.002 ARP Cache Poisoning")
            self.arp_map[ip] = mac

    def _scan(self, r):
        ts, src = r.ts, r.src
        dq = self.scan[src]
        dq.append((ts, r.dst, r.dport))
        while dq and ts - dq[0][0] > 10:
            dq.popleft()
        fl = self.synflood[r.dst]
        fl.append(ts)
        if len(fl) >= 300 and ts - fl[-300] <= 5:
            self._raise(ts, ("synflood", r.dst), "High", "SYN Flood", "multiple", r.dst,
                        "300+ SYN packets to %s in 5s" % r.dst, "T1498 Network Denial of Service")
        if len(dq) < 20:
            return
        dsts = {d for _, d, _ in dq}
        ports = {p for _, _, p in dq}
        pairs = {(d, p) for _, d, p in dq}
        if len(pairs) >= 20 and len(dsts) <= 3 and len(ports) >= 15:
            self._raise(ts, ("scan", src, tuple(sorted(dsts))), "High", "Port Scan", src, ", ".join(sorted(dsts)),
                        "%d distinct ports probed in 10s (SYN)" % len(ports), "T1046 Network Service Discovery")
        internal = {d for d in dsts if is_internal(d)}
        if len(internal) >= 20 and len(ports) <= 3:
            self._raise(ts, ("sweep", src), "High", "Network Sweep", src, "%d internal hosts" % len(internal),
                        "SYNs to %d hosts on port(s) %s in 10s" % (len(internal), sorted(ports)),
                        "T1046 Network Service Discovery")

    def _beacon(self, ts, key, src, dst, label, cv_max, proc=""):
        dq = self.beacon[key]
        if dq and ts - dq[-1] < 1.0:
            return
        dq.append(ts)
        if len(dq) < 8:
            return
        pts = list(dq)
        iv = [b - a for a, b in zip(pts, pts[1:])]
        mean = statistics.mean(iv)
        if not (5 <= mean <= 3600):
            return
        cv = statistics.pstdev(iv) / mean
        if cv <= cv_max:
            dom = self.domain_for(dst)
            self._raise(ts, ("beacon", key), "Medium", "Beaconing", src, dst,
                        "%d connections to %s%s every %.1fs (jitter %.0f%%) - verify if legitimate"
                        % (len(pts), label, (" [%s]" % dom) if dom else "", mean, cv * 100),
                        "T1071 Application Layer Protocol (C2)", proc)

    def _tls(self, r, f, ch):
        f.sni, f.ja3, f.tls = ch["sni"], ch["ja3"], ch["version"]
        if ch["sni"]:
            self.ip_domain[f.rip] = ch["sni"]
        row = [r.ts, f.lip, f.rip, ch["sni"], ch["ja3"], ch["version"], f]
        self.tls_rows.append(row)
        if self.logger:
            self.logger.write("tls", {"ts": r.ts, "src": f.lip, "dst": f.rip, "sni": ch["sni"], "ja3": ch["ja3"],
                                      "version": ch["version"], "process": f.proc})
        h = self.intel.check_ja3(ch["ja3"])
        if h:
            self._raise(r.ts, ("ja3", ch["ja3"], f.rip), "High", "Malicious JA3", f.lip, f.rip,
                        "JA3 %s matches %s (SNI %s)" % (ch["ja3"], h, ch["sni"] or "-"),
                        "T1071.001 Web Protocols", f.proc)
        d = self.intel.check_domain(ch["sni"])
        if d:
            self._raise(r.ts, ("dom", ch["sni"]), "Critical", "Malicious Domain", f.lip, ch["sni"],
                        "TLS connection to %s listed in %s" % (ch["sni"], d), "T1071.001 Web Protocols", f.proc)

    def _cleartext(self, r, f):
        p, port = r.payload, r.dport
        low = p[:800].lower()
        what = None
        if b"authorization: basic" in low:
            what = "HTTP Basic auth header"
        elif port in (80, 8080, 8000) and low.startswith(b"post ") and any(
                k in low for k in (b"password=", b"passwd=", b"pwd=", b"pass=")):
            what = "password field in HTTP POST"
        elif port == 21 and p.startswith(b"PASS "):
            what = "FTP PASS command"
        elif port == 110 and p.startswith(b"PASS "):
            what = "POP3 PASS command"
        elif port == 143 and b" login " in low:
            what = "IMAP LOGIN command"
        if what:
            dom = self.domain_for(f.rip, f)
            self._raise(r.ts, ("cred", f.rip, port, what), "High", "Cleartext Credentials", f.lip, f.rip,
                        "%s sent unencrypted to %s:%d%s (value masked)" % (what, f.rip, port, (" [%s]" % dom) if dom else ""),
                        "T1552 Unsecured Credentials", f.proc)

    def _dns(self, r, f):
        d, ts = r.dns, r.ts
        qname, qt = d["qname"], QTYPES.get(d["qtype"], str(d["qtype"]))
        if d["qr"] == 1:
            client = r.dst
            row = self.dns_wait.pop((client, qname, qt), None)
            ans = ", ".join(d["answers"][:4]) or ("NXDOMAIN" if d["rcode"] == 3 else "NOERROR/no-data" if d["rcode"] == 0 else "rcode %d" % d["rcode"])
            if row is not None:
                row[4], row[5] = ans, (ts - row[0]) * 1000.0
            for ip in d["answers"]:
                self.ip_domain.setdefault(ip, qname)
            if self.logger:
                self.logger.write("dns", {"ts": ts, "client": client, "query": qname, "type": qt, "answers": d["answers"],
                                          "rcode": d["rcode"]})
            if d["rcode"] == 3:
                dq = self.nx[client]
                dq.append(ts)
                recent = [t for t in dq if ts - t <= 60]
                if len(recent) >= 15:
                    self._raise(ts, ("nx", client), "High", "NXDOMAIN Storm", client, "DNS resolver",
                                "%d NXDOMAIN answers in 60s (last: %s)" % (len(recent), qname),
                                "T1568.002 Domain Generation Algorithms")
            return
        row = [ts, r.src, qname, qt, "", None]
        self.dns_rows.append(row)
        self.dns_wait[(r.src, qname, qt)] = row
        if len(self.dns_wait) > 3000:
            self.dns_wait.popitem(last=False)
        if "." not in qname or qname.endswith(DNS_SAFE):
            return
        bad = self.intel.check_domain(qname)
        if bad:
            self._raise(ts, ("dom", qname), "Critical", "Malicious Domain", r.src, qname,
                        "DNS lookup of %s (listed in %s)" % (qname, bad), "T1071.004 DNS")
        labels = qname.split(".")
        base = ".".join(labels[-2:])
        sub = ".".join(labels[:-2])
        sld = labels[-2]
        ent = entropy(sub.replace(".", ""))
        reasons = []
        if len(qname) >= 70:
            reasons.append("very long name (%d chars)" % len(qname))
        if len(sub) >= 25 and ent >= 3.7:
            reasons.append("high-entropy subdomain (H=%.2f)" % ent)
        if d["qtype"] in (10, 16) and len(sub) >= 20:
            reasons.append("%s query with long subdomain" % qt)
        if reasons:
            self._raise(ts, ("dnst", r.src, base), "High" if len(reasons) > 1 else "Medium", "DNS Tunneling", r.src, base,
                        "; ".join(reasons) + " e.g. " + qname[:60], "T1071.004 DNS")
        digits = sum(c.isdigit() for c in sld) / max(len(sld), 1)
        vowels = sum(c in "aeiou" for c in sld) / max(len(sld), 1)
        if len(sld) >= 12 and entropy(sld) >= 3.3 and (digits >= 0.25 or vowels <= 0.2) and "-" not in sld:
            self._raise(ts, ("dga", r.src, base), "Medium", "Possible DGA", r.src, base,
                        "algorithmically-looking domain %s (H=%.2f, digits %.0f%%)" % (base, entropy(sld), digits * 100),
                        "T1568.002 Domain Generation Algorithms")
        dq = self.dns_sub[(r.src, base)]
        dq.append((ts, sub))
        while dq and ts - dq[0][0] > 60:
            dq.popleft()
        if len({s for _, s in dq}) >= 40:
            self._raise(ts, ("dnsvol", r.src, base), "High", "DNS Tunneling (volume)", r.src, base,
                        "%d unique subdomains of %s in 60s" % (len({s for _, s in dq}), base), "T1071.004 DNS")
        self._beacon(ts, (r.src, "dns", qname), r.src, base, "DNS %s" % qname, 0.10)

    # --------------------------------------------------------------- GUI access
    def drain_packets(self):
        with self.lock:
            out = list(self.pending)
            self.pending.clear()
            return out

    def get_alerts(self, start=0):
        with self.lock:
            return list(self.alerts[start:])

    def ring_snapshot(self):
        with self.lock:
            return list(self.ring)

    def snapshot(self):
        with self.lock:
            rows = [self._flow_row(f) for f in self.flows.values()]
            closed = list(self.history)[-400:]
            procs, dests, cc = {}, {}, {}
            for r in rows + closed:
                p = procs.setdefault(r["proc"], dict(pids=set(), flows=0, remotes=set(), out=0, inn=0, risk=0))
                p["pids"].add(r["pid"])
                p["flows"] += 1
                p["remotes"].add(r["rip"])
                p["out"] += r["out"]
                p["inn"] += r["inn"]
                p["risk"] = max(p["risk"], r["risk"])
                dkey = r["domain"] or r["rip"]
                d = dests.setdefault(r["rip"], dict(host=dkey, ip=r["rip"], cc=r["cc"], org=r["org"], flows=0, out=0, inn=0, risk=0))
                if r["domain"]:
                    d["host"] = r["domain"]
                d["flows"] += 1
                d["out"] += r["out"]
                d["inn"] += r["inn"]
                d["risk"] = max(d["risk"], r["risk"])
                c = cc.setdefault(r["cc"], dict(flows=0, bytes=0))
                c["flows"] += 1
                c["bytes"] += r["out"] + r["inn"]
            series_up, series_down = [], []
            if self.bw:
                end = self.bw[-1][0]
                m = {s: (u, d) for s, u, d in self.bw}
                for s in range(end - 119, end + 1):
                    u, d = m.get(s, (0, 0))
                    series_up.append(u / 1024.0)
                    series_down.append(d / 1024.0)
            ext_hosts = {r["rip"] for r in rows + closed if r["cc"] != "LAN"}
            risky = len([ip for ip, v in self.ip_risk.items() if v >= 70])
            sev = Counter(a.severity for a in self.alerts)
            return dict(
                total=self.total, bytes=self.bytes, proto=dict(self.proto), flows=rows, closed=list(reversed(closed)),
                procs=procs, dests=list(dests.values()), countries=cc, up=series_up, down=series_down,
                active=len(rows), hosts=len(ext_hosts), risky=risky, sev=dict(sev), alerts=len(self.alerts),
                mitre=dict(self.mitre),
                dns=[list(x) for x in list(self.dns_rows)[-300:]][::-1],
                tls=[[a, b, c, d, e, f2, g.proc or "-"] for a, b, c, d, e, f2, g in list(self.tls_rows)[-300:]][::-1])


def ts_recent(f):
    """Only keep trying process lookup for the first ~60s of a flow's life."""
    return f.last - f.start < 60