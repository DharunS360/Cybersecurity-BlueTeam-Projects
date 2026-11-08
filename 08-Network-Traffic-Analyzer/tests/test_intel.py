import pytest

from core import intel as intel_mod

FEED_TEXT = {
    "ip": "# comment\n1.2.3.4\nnot-an-ip\n5.6.7.8\n",
    "ja3": "# ja3\nada2bb9b7c9f5ab1c5b9f3c3f7e6a001,ts,Malware\nbad-line\n",
    "domain": "# hosts\n127.0.0.1 localhost\n0.0.0.0 evil.example\n0.0.0.0 payload.bad.test\n",
}


class FakeResp:
    def __init__(self, text):
        self.text = text

    def raise_for_status(self):
        pass


@pytest.fixture
def ti(tmp_path, monkeypatch):
    monkeypatch.setattr(intel_mod, "CACHE", str(tmp_path / "cache.json"))
    monkeypatch.setattr(intel_mod, "FEEDS", [("ip-feed", "ip", "u1"), ("ja3-feed", "ja3", "u2"), ("dom-feed", "domain", "u3")])
    mapping = {"u1": FEED_TEXT["ip"], "u2": FEED_TEXT["ja3"], "u3": FEED_TEXT["domain"]}
    monkeypatch.setattr(intel_mod.requests, "get", lambda url, **k: FakeResp(mapping[url]))
    t = intel_mod.ThreatIntel()
    t.update()
    return t


def test_parses_all_feed_types(ti):
    assert set(ti.ips) == {"1.2.3.4", "5.6.7.8"}
    assert "ada2bb9b7c9f5ab1c5b9f3c3f7e6a001" in ti.ja3
    assert set(ti.domains) == {"evil.example", "payload.bad.test"}
    assert all(v.startswith("OK") for v in ti.feed_status.values())


def test_domain_matching_includes_subdomains(ti):
    assert ti.check_domain("cdn.evil.example") == "dom-feed"
    assert ti.check_domain("EVIL.example.") == "dom-feed"
    assert ti.check_domain("example.com") is None


def test_lookup_helper(ti):
    assert "MALICIOUS" in ti.lookup("1.2.3.4")
    assert "not found" in ti.lookup("9.9.9.9")
    assert "JA3" in ti.lookup("ada2bb9b7c9f5ab1c5b9f3c3f7e6a001")


def test_cache_roundtrip(ti, monkeypatch):
    fresh = intel_mod.ThreatIntel()
    assert set(fresh.ips) == set(ti.ips) and fresh.status.startswith("cache")


def test_feed_failure_keeps_previous_data(ti, monkeypatch):
    def boom(url, **k):
        raise ConnectionError("offline")
    monkeypatch.setattr(intel_mod.requests, "get", boom)
    ti.update()
    assert "1.2.3.4" in ti.ips  # old data retained
    assert all(v.startswith("failed") for v in ti.feed_status.values())