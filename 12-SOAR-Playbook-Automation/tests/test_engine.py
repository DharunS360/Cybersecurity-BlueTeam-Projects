import unittest

from soar.engine import Engine
from soar.http import ProviderError
from soar.ingest import from_indicators
from soar.models import IOC, Finding, IOCType, Status
from soar.providers.base import Provider
from soar.store import Store

from .helpers import settings


class Fake(Provider):
    supports = frozenset({IOCType.IP, IOCType.DOMAIN})
    key_attr = None

    def __init__(self, name, outcome, cacheable=True, supports=None):
        self.name, self.outcome, self.cacheable, self.calls = name, outcome, cacheable, 0
        if supports:
            self.supports = supports
        self.settings = None

    @property
    def enabled(self):
        return True

    def lookup(self, ioc):
        self.calls += 1
        if isinstance(self.outcome, Exception):
            raise self.outcome
        return self.outcome


class NoKey(Fake):
    key_attr = "vt_key"

    @property
    def enabled(self):
        return False


def engine(providers, **kw):
    return Engine(settings(**kw), Store(":memory:"), providers)


class TestEngine(unittest.TestCase):
    def eng(self, providers, **kw):
        e = engine(providers, **kw)
        self.addCleanup(e.store.close)
        return e

    def test_end_to_end_malicious_with_audit_trail(self):
        p1 = Fake("A", Finding("A", Status.OK, 60, "bad"))
        p2 = Fake("B", Finding("B", Status.OK, 30, "worse"))
        e = self.eng([p1, p2])
        r = e.analyze(from_indicators(["45.33.32.9"]))
        self.assertEqual((r.label, r.score), ("Malicious", 90))
        actions = [x["action"] for x in e.store.audit_entries(r.case_id)]
        self.assertEqual(actions, ["case.created", "enrich.query", "enrich.query", "case.verdict"])
        self.assertTrue(e.store.verify_audit()[0])
        self.assertEqual(e.store.get_case(r.case_id)["overall_verdict"], "Malicious")

    def test_cache_hit_avoids_second_lookup_and_is_flagged(self):
        p = Fake("A", Finding("A", Status.OK, 45, "x"))
        e = self.eng([p])
        e.analyze(from_indicators(["45.33.32.9"]))
        r = e.analyze(from_indicators(["45.33.32.9"]))
        self.assertEqual(p.calls, 1)
        self.assertTrue(r.verdicts[0].findings[0].cached)
        e.analyze(from_indicators(["45.33.32.9"]), use_cache=False)
        self.assertEqual(p.calls, 2)

    def test_errors_not_cached_and_never_reported_clean(self):
        p = Fake("A", ProviderError("timeout", "slow"))
        e = self.eng([p])
        r = e.analyze(from_indicators(["45.33.32.9"]))
        self.assertEqual(r.verdicts[0].label, "Unknown")
        self.assertEqual(r.verdicts[0].findings[0].status, Status.ERROR)
        e.analyze(from_indicators(["45.33.32.9"]))
        self.assertEqual(p.calls, 2)

    def test_rate_limit_status(self):
        e = self.eng([Fake("A", ProviderError("rate_limit", "429"))])
        f = e.analyze(from_indicators(["45.33.32.9"])).verdicts[0].findings[0]
        self.assertEqual(f.status, Status.RATE_LIMITED)

    def test_buggy_provider_is_contained(self):
        good = Fake("G", Finding("G", Status.NOT_FOUND, 0, "clean"))
        bad = Fake("X", RuntimeError("boom"))
        r = self.eng([good, bad]).analyze(from_indicators(["45.33.32.9"]))
        statuses = {f.provider: f.status for f in r.verdicts[0].findings}
        self.assertEqual(statuses, {"G": Status.NOT_FOUND, "X": Status.ERROR})

    def test_missing_key_is_visible_skip(self):
        e = self.eng([NoKey("VT", None), Fake("A", Finding("A", Status.NOT_FOUND))])
        v = e.analyze(from_indicators(["45.33.32.9"])).verdicts[0]
        self.assertIn(Status.SKIPPED, {f.status for f in v.findings})
        self.assertIn("not queried", " ".join(v.notes))

    def test_provider_only_gets_supported_types(self):
        ip_only = Fake("IPONLY", Finding("IPONLY", Status.OK, 10), supports=frozenset({IOCType.IP}))
        e = self.eng([ip_only])
        e.analyze(from_indicators(["45.33.32.9", "evil-site.xyz"]))
        self.assertEqual(ip_only.calls, 1)

    def test_max_iocs_cap_is_reported_not_silent(self):
        e = self.eng([Fake("A", Finding("A", Status.NOT_FOUND))], max_iocs=2)
        r = e.analyze(from_indicators(["45.33.32.1", "45.33.32.2", "45.33.32.3"]))
        self.assertEqual(len(r.verdicts), 2)
        self.assertTrue(any("SOAR_MAX_IOCS" in s["reason"] for s in r.alert.skipped))

    def test_json_report_is_serialisable(self):
        import json
        r = self.eng([Fake("A", Finding("A", Status.OK, 50, "x", {"k": 1}, "http://l"))]).analyze(from_indicators(["45.33.32.9"]))
        out = json.loads(json.dumps(r.to_dict()))
        self.assertEqual(out["indicators"][0]["findings"][0]["status"], "ok")


if __name__ == "__main__":
    unittest.main()