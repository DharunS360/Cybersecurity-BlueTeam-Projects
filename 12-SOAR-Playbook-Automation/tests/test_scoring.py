import unittest

from soar.models import IOC, Finding, IOCType, Status
from soar.scoring import aggregate, label_for, overall

IP = IOC(IOCType.IP, "45.33.32.9")


def f(name, status, pts=0, reason=""):
    return Finding(name, status, pts, reason)


class TestScoring(unittest.TestCase):
    def test_bands(self):
        self.assertEqual([label_for(s) for s in (0, 9, 10, 39, 40, 69, 70, 100)],
                         ["Not Flagged", "Not Flagged", "Low Risk", "Low Risk", "Suspicious", "Suspicious", "Malicious", "Malicious"])

    def test_points_sum_and_cap(self):
        v = aggregate(IP, [f("A", Status.OK, 60), f("B", Status.OK, 50)])
        self.assertEqual((v.score, v.label), (100, "Malicious"))
        self.assertTrue(any("corroborated" in n for n in v.notes))

    def test_errors_are_never_clean(self):
        v = aggregate(IP, [f("A", Status.ERROR, reason="timeout"), f("B", Status.RATE_LIMITED)])
        self.assertEqual(v.label, "Unknown")
        self.assertIn("NOT a clean result", " ".join(v.notes))

    def test_error_plus_clean_reports_coverage(self):
        v = aggregate(IP, [f("A", Status.NOT_FOUND), f("B", Status.NOT_FOUND), f("C", Status.ERROR)])
        self.assertEqual((v.label, v.answered, v.applicable), ("Not Flagged", 2, 3))
        self.assertIn("did not answer", " ".join(v.notes))

    def test_single_source_clean_is_low_confidence(self):
        v = aggregate(IP, [f("A", Status.NOT_FOUND), f("B", Status.SKIPPED)])
        self.assertEqual((v.answered, v.applicable), (1, 1))
        self.assertIn("low confidence", " ".join(v.notes))

    def test_skipped_excluded_from_applicable(self):
        v = aggregate(IP, [f("A", Status.OK, 45), f("B", Status.SKIPPED)])
        self.assertEqual((v.score, v.label, v.applicable), (45, "Suspicious", 1))

    def test_no_providers(self):
        v = aggregate(IOC(IOCType.EMAIL, "a@b.com"), [])
        self.assertEqual(v.label, "Not Enriched")

    def test_overall_is_worst_indicator(self):
        a = aggregate(IP, [f("A", Status.OK, 80)])
        b = aggregate(IOC(IOCType.DOMAIN, "x.com"), [f("A", Status.NOT_FOUND)])
        self.assertEqual(overall([a, b]), (80, "Malicious"))
        self.assertEqual(overall([]), (0, "Unknown"))

    def test_known_benign_overrides_weak_noise(self):
        # real-world case: 8.8.8.8 -> 1 VT engine (+15) but AbuseIPDB whitelist + OTX false-positive validation
        v = aggregate(IP, [f("VT", Status.OK, 15), Finding("AbuseIPDB", Status.OK, 0, "wl", {"benign": True}),
                           f("Feodo", Status.NOT_FOUND)])
        self.assertEqual((v.label, v.score), ("Known Benign", 0))
        self.assertIn("weak residual signals ignored (VT +15)", " ".join(v.notes))

    def test_benign_does_not_hide_strong_detection(self):
        v = aggregate(IP, [f("Feodo", Status.OK, 80), Finding("OTX", Status.OK, 0, "x", {"benign": True})])
        self.assertEqual((v.label, v.score), ("Malicious", 80))
        self.assertIn("CONFLICT", " ".join(v.notes))


if __name__ == "__main__":
    unittest.main()