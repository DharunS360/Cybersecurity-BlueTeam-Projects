"""Plain data record produced by the packet parser (no scapy dependency, so it is unit-testable)."""
from dataclasses import dataclass


@dataclass
class Rec:
    ts: float
    length: int
    src: str
    dst: str
    l4: str                      # TCP / UDP / ICMP / ARP / OTHER
    sport: int = 0
    dport: int = 0
    flags: int = 0
    payload: bytes = b""
    icmp_type: int = -1
    icmp_len: int = 0
    dns: dict = None             # {qr, qname, qtype, rcode, answers}
    arp: dict = None             # {op, hwsrc, psrc}
    raw: bytes = b""