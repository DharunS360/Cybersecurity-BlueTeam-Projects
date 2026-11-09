"""Regression checks for SysmonHunter; no demo log files or synthetic datasets are shipped."""
import os
import sys
import unittest
from datetime import datetime

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from sysmonhunter.engine import analyze
from sysmonhunter.rules import catalog, TACTICS


def event(eid, channel, data, when="2026-01-01T12:00:00"):
    return {
        "time": datetime.fromisoformat(when),
        "eid": eid,
        "channel": channel,
        "provider": "Microsoft-Windows-Sysmon",
        "host": "UNIT-TEST-HOST",
        "record_id": "1",
        "data": data,
    }


class RuleCatalogueTests(unittest.TestCase):
    def test_rule_ids_are_unique(self):
        ids = [row["id"] for row in catalog()]
        self.assertEqual(len(ids), len(set(ids)))

    def test_all_rule_severities_are_supported(self):
        allowed = {"Low", "Medium", "High", "Critical"}
        self.assertTrue(all(row["severity"] in allowed for row in catalog()))

    def test_rule_tactics_are_represented(self):
        self.assertTrue(all(row["tactic"] in TACTICS for row in catalog()))


class EngineTests(unittest.TestCase):
    def test_empty_input_has_no_findings(self):
        self.assertEqual(analyze([]), [])

    def test_encoded_powershell_rule_matches_realistic_event_shape(self):
        # In-memory unit-test input only; not a demo dataset or shipped log.
        ev = event(1, "Microsoft-Windows-Sysmon/Operational", {
            "Image": r"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "CommandLine": "powershell.exe -EncodedCommand VwByAGkAdABlAC0ATwB1AHQAcAB1AHQA",
            "ParentImage": r"C:\\Windows\\explorer.exe",
            "User": "UNITTEST\\analyst",
        })
        diagnostics = []
        results = analyze([ev], diagnostics=diagnostics)
        self.assertTrue(any(row["rule_id"] == "HUNT-001" for row in results))
        self.assertEqual(diagnostics, [])

    def test_benign_process_does_not_match_encoded_powershell_rule(self):
        ev = event(1, "Microsoft-Windows-Sysmon/Operational", {
            "Image": r"C:\\Windows\\System32\\notepad.exe",
            "CommandLine": "notepad.exe",
            "ParentImage": r"C:\\Windows\\explorer.exe",
            "User": "UNITTEST\\analyst",
        })
        self.assertFalse(any(row["rule_id"] == "HUNT-001" for row in analyze([ev])))


if __name__ == "__main__":
    unittest.main(verbosity=2)
