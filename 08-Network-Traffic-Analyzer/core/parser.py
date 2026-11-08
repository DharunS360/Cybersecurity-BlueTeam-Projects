"""Scapy packet -> Rec converter."""
from scapy.all import ARP, DNS, DNSQR, ICMP, IP, TCP, UDP, IPv6

from .records import Rec


def parse(pkt):
    try:
        return _parse(pkt)
    except Exception:
        return None


def _dns(pkt):
    d, q = pkt[DNS], pkt[DNSQR]
    raw = q.qname.decode(errors="ignore") if isinstance(q.qname, bytes) else str(q.qname)
    answers = []
    if d.qr == 1:
        for i in range(int(d.ancount or 0)):
            try:
                rr = d.an[i]
                if rr.type in (1, 28):
                    answers.append(str(rr.rdata))
            except Exception:
                break
    return {"qr": int(d.qr), "qname": raw.rstrip(".").lower(), "qtype": int(q.qtype),
            "rcode": int(d.rcode or 0), "answers": answers}


def _parse(pkt):
    ts = float(pkt.time)
    n = len(pkt)
    try:
        raw = bytes(pkt)
    except Exception:
        raw = b""
    if pkt.haslayer(ARP):
        a = pkt[ARP]
        return Rec(ts, n, str(a.psrc), str(a.pdst), "ARP",
                   arp={"op": int(a.op), "hwsrc": str(a.hwsrc), "psrc": str(a.psrc)}, raw=raw)
    if pkt.haslayer(IP):
        src, dst = pkt[IP].src, pkt[IP].dst
    elif pkt.haslayer(IPv6):
        src, dst = pkt[IPv6].src, pkt[IPv6].dst
    else:
        return None
    r = Rec(ts, n, src, dst, "OTHER", raw=raw)
    if pkt.haslayer(TCP):
        t = pkt[TCP]
        r.l4, r.sport, r.dport, r.flags = "TCP", int(t.sport), int(t.dport), int(t.flags)
        r.payload = bytes(t.payload)[:2000]
    elif pkt.haslayer(UDP):
        u = pkt[UDP]
        r.l4, r.sport, r.dport = "UDP", int(u.sport), int(u.dport)
        r.payload = bytes(u.payload)[:400]
    elif pkt.haslayer(ICMP):
        i = pkt[ICMP]
        r.l4, r.icmp_type, r.icmp_len = "ICMP", int(i.type), len(i.payload)
    if pkt.haslayer(DNS) and pkt.haslayer(DNSQR) and r.l4 in ("UDP", "TCP"):
        r.dns = _dns(pkt)
    return r