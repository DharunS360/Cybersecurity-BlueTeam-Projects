import unittest

from soar.models import Finding, Status
from soar.store import Store


class TestStore(unittest.TestCase):
    def setUp(self):
        self.s = Store(":memory:")
        self.addCleanup(self.s.close)

    def test_audit_chain_valid(self):
        for i in range(5):
            self.s.audit("tester", "x", "CASE-1", {"i": i})
        self.assertEqual(self.s.verify_audit(), (True, 5, None))

    def test_empty_log_is_valid(self):
        self.assertEqual(self.s.verify_audit(), (True, 0, None))

    def test_tampered_detail_detected(self):
        for i in range(4):
            self.s.audit("t", "x", "C", {"i": i})
        self.s.raw_execute("UPDATE audit_log SET detail_json='{\"i\":99}' WHERE seq=2")
        ok, _, broken = self.s.verify_audit()
        self.assertFalse(ok)
        self.assertEqual(broken, 2)

    def test_deleted_entry_detected(self):
        for i in range(4):
            self.s.audit("t", "x", "C", {"i": i})
        self.s.raw_execute("DELETE FROM audit_log WHERE seq=2")
        self.assertFalse(self.s.verify_audit()[0])

    def test_cache_roundtrip_and_ttl(self):
        f = Finding("VT", Status.OK, 30, "r", {"a": 1})
        self.s.cache_put("VT", "ip", "1.2.3.4", f)
        hit = self.s.cache_get("VT", "ip", "1.2.3.4", ttl_hours=1)
        self.assertTrue(hit.cached)
        self.assertEqual((hit.points, hit.evidence), (30, {"a": 1}))
        self.assertIsNone(self.s.cache_get("VT", "ip", "1.2.3.4", ttl_hours=0))
        self.assertIsNone(self.s.cache_get("VT", "ip", "9.9.9.9", ttl_hours=1))


if __name__ == "__main__":
    unittest.main()