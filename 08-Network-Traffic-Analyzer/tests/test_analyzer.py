"""Unit tests for the detection engine. Uses synthetic Rec records, so no scapy / Npcap / network needed."""
import pytest

from core import analyzer as az
from core.analyzer import Analyzer
from core.records import Rec

LOCAL = "192.168.1.35"


class StubIntel:
    def __init__(self, ips=(), ja3=(), domains=()):
        self.ips, self.j, self.d = set(ips), set(ja3), tuple(domains)

    def check_ip(self, ip):
        return "stub-feed" if ip in self.ips else None

    def check_ja3(self, h):
        return "stub-ja3-feed" if h in self.j else None

    def check_domain(self, name):
        return "stub-domain-feed" if any(name.endswith(x) for x in self.d) else None


@pytest.fixture
def an(tmp_path, monkeypatch):
    monkeypatch.setattr(az, "BASE", str(tmp_path))
    a = Analyzer(StubIntel(ips={"45.33.32.156"}, domains=("evil-test.example",)))
    a.allow_file = str(tmp_path / "allow.txt")
    a.set_local_ips({LOCAL})
    return a


def kinds(a):
    return [x.kind for x in a.alerts]


def dns(qr, name, qtype=1, rcode=0, answers=()):
    return {"qr": qr, "qname": name, "qtype": qtype, "rcode": rcode, "answers": list(answers)}


def test_port_scan_detected(an):
    for i in range(25):
        an.ingest(Rec(100 + i * 0.2, 60, "10.9.9.9", LOCAL, "TCP", 4000 + i, 1000 + i, 0x02))
    assert "Port Scan" in kinds(an)
    alert = next(x for x in an.alerts if x.kind == "Port Scan")
    assert alert.severity == "High" and alert.mitre.startswith("T1046")


def test_normal_browsing_does_not_alert(an):
    for i in range(5):
        an.ingest(Rec(100 + i, 66, LOCAL, "20.1.1.1", "TCP", 50000 + i, 443, 0x02))
        an.ingest(Rec(100.1 + i, 66, "20.1.1.1", LOCAL, "TCP", 443, 50000 + i, 0x12))
    assert an.alerts == []


def test_beaconing_regular_interval(an):
    for i in range(10):
        an.ingest(Rec(1000 + i * 60 + (i % 2), 66, LOCAL, "8.8.4.4", "TCP", 51000 + i, 8443, 0x02))
    assert "Beaconing" in kinds(an)


def test_irregular_traffic_is_not_beaconing(an):
    t = 1000
    for gap in (3, 90, 7, 240, 15, 500, 11, 60, 400, 5):
        t += gap
        an.ingest(Rec(t, 66, LOCAL, "8.8.4.4", "TCP", 51000 + t, 8443, 0x02))
    assert "Beaconing" not in kinds(an)


def test_dns_tunneling_long_encoded_label(an):
    name = "dGhpcyBpcyBhIHRlc3Qgb2YgZXhmaWx0cmF0aW9uIGRhdGE.evil-c2.com"
    an.ingest(Rec(5, 90, LOCAL, "8.8.8.8", "UDP", 5000, 53, dns=dns(0, name, 16)))
    assert "DNS Tunneling" in kinds(an)


def test_dns_tunneling_volume(an):
    for i in range(45):
        an.ingest(Rec(10 + i, 70, LOCAL, "8.8.8.8", "UDP", 5000 + i, 53, dns=dns(0, "x%dab.t.example.org" % i)))
    assert "DNS Tunneling (volume)" in kinds(an)


def test_dga_detected_but_normal_domain_ignored(an):
    an.ingest(Rec(1, 70, LOCAL, "8.8.8.8", "UDP", 5000, 53, dns=dns(0, "github.com")))
    an.ingest(Rec(2, 70, LOCAL, "8.8.8.8", "UDP", 5001, 53, dns=dns(0, "login.microsoftonline.com")))
    assert "Possible DGA" not in kinds(an)
    an.ingest(Rec(3, 70, LOCAL, "8.8.8.8", "UDP", 5002, 53, dns=dns(0, "xk3j9q2m7v5b8n1z.net")))
    assert "Possible DGA" in kinds(an)


def test_nxdomain_storm(an):
    for i in range(16):
        an.ingest(Rec(10 + i, 70, "8.8.8.8", LOCAL, "UDP", 53, 5003, dns=dns(1, "q%dwzxkpl.biz" % i, 1, 3)))
    assert "NXDOMAIN Storm" in kinds(an)


def test_arp_spoofing(an):
    arp = lambda mac: {"op": 2, "hwsrc": mac, "psrc": "192.168.1.1"}
    an.ingest(Rec(1, 42, "192.168.1.1", LOCAL, "ARP", arp=arp("aa:aa:aa:aa:aa:aa")))
    assert an.alerts == []
    an.ingest(Rec(2, 42, "192.168.1.1", LOCAL, "ARP", arp=arp("bb:bb:bb:bb:bb:bb")))
    assert "ARP Spoofing" in kinds(an)


def test_known_malicious_ip(an):
    an.ingest(Rec(1, 66, LOCAL, "45.33.32.156", "TCP", 50001, 443, 0x02))
    a = next(x for x in an.alerts if x.kind == "Known Malicious IP")
    assert a.severity == "Critical"
    assert an.snapshot()["risky"] >= 1


def test_cleartext_http_basic_auth(an):
    payload = b"GET / HTTP/1.1\r\nHost: x\r\nAuthorization: Basic dXNlcjpwYXNz\r\n\r\n"
    an.ingest(Rec(1, 200, LOCAL, "20.1.1.2", "TCP", 50002, 80, 0x18, payload=payload))
    a = next(x for x in an.alerts if x.kind == "Cleartext Credentials")
    assert "dXNlcjpwYXNz" not in a.detail  # credential value must never be stored


def test_large_upload_exfil(an):
    an.ingest(Rec(1, 60 * 1024 * 1024, LOCAL, "20.1.1.9", "TCP", 52000, 443, 0x10))
    assert "Large Upload (Exfiltration?)" in kinds(an)


def test_risky_outbound_port(an):
    an.ingest(Rec(1, 66, LOCAL, "20.1.1.9", "TCP", 52001, 4444, 0x02))
    assert "Risky Outbound Port" in kinds(an)


def test_alert_cooldown_suppresses_duplicates(an):
    for i in range(3):
        an.ingest(Rec(1 + i, 66, LOCAL, "45.33.32.156", "TCP", 50001 + i, 443, 0x02))
    assert kinds(an).count("Known Malicious IP") == 1


def test_allowlist_suppresses_alert(an):
    an.allow_add("45.33.32.156")
    an.ingest(Rec(1, 66, LOCAL, "45.33.32.156", "TCP", 50001, 443, 0x02))
    assert an.alerts == []


def test_flow_accounting_and_sweep(an):
    an.ingest(Rec(1, 100, LOCAL, "20.1.1.1", "TCP", 50000, 443, 0x02))
    an.ingest(Rec(1.1, 500, "20.1.1.1", LOCAL, "TCP", 443, 50000, 0x12))
    snap = an.snapshot()
    assert snap["active"] == 1
    row = snap["flows"][0]
    assert row["out"] == 100 and row["inn"] == 500 and row["state"] == "ESTABLISHED"
    an.last_ts = 100000
    an.sweep()
    assert len(an.history) == 1 and an.snapshot()["active"] == 0


def test_dns_response_correlation(an):
    an.ingest(Rec(10, 70, LOCAL, "8.8.8.8", "UDP", 5000, 53, dns=dns(0, "example.com")))
    an.ingest(Rec(10.05, 90, "8.8.8.8", LOCAL, "UDP", 53, 5000, dns=dns(1, "example.com", 1, 0, ["93.184.216.34"])))
    row = an.snapshot()["dns"][0]
    assert row[2] == "example.com" and row[4] == "93.184.216.34" and 40 < row[5] < 60
    assert an.ip_domain["93.184.216.34"] == "example.com"