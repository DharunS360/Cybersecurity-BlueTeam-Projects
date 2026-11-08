"""Unit tests for the detection engine.

The collectors read the live host, so these tests feed hand-built artifact rows
into analysis.analyze() to prove each rule fires (and that benign defaults do not).
Run:  python -m unittest discover -s tests -v
"""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import analysis as A  # noqa: E402

TMP = tempfile.mkdtemp()
A.ALLOW_PATH = os.path.join(TMP, "allow.json")
A.BASELINE_PATH = os.path.join(TMP, "baseline.json")


def proc(pid, name, path, cmd="", parent="explorer.exe", sig="Valid"):
    return {"Severity": "", "PID": pid, "PPID": 1, "Name": name, "Parent": parent, "ParentPath": "", "User": "u",
            "Path": path, "CmdLine": cmd, "Started": "2026-11-08 10:00:00", "SHA256": "a" * 64,
            "Signature": sig, "Signer": "", "Flags": ""}


def event(eid, detail, t="2026-11-08 09:00:00", log="Security"):
    return {"Time": t, "Log": log, "EventID": eid, "Provider": "", "Detail": detail, "Message": "", "Severity": "", "Flags": ""}


def run(**sections):
    data = {"meta": {"Hostname": "TESTHOST", "Analyst": "t", "CollectionStartLocal": "t0", "Tool": "t", "Warnings": []},
            "processes": [], "network": [], "persistence": [], "events": [], "files": [], "artifacts": []}
    data.update(sections)
    return A.analyze(data)


def titles(d):
    return [f["Title"] for f in d["findings"]]


class DetectionTests(unittest.TestCase):
    def test_masquerading_system_process(self):
        d = run(processes=[proc(1, "svchost.exe", r"C:\Users\x\AppData\Local\Temp\svchost.exe", sig="NotSigned")])
        self.assertTrue(any("masquerading" in t for t in titles(d)))
        self.assertEqual(d["summary"]["counts"]["Critical"] >= 1, True)

    def test_office_spawns_encoded_powershell(self):
        cmd = "powershell.exe -nop -w hidden -enc " + "A" * 60
        d = run(processes=[proc(2, "powershell.exe", r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", cmd, "winword.exe")])
        t = titles(d)
        self.assertTrue(any("Office application spawned" in x for x in t))
        self.assertTrue(any("Encoded PowerShell" in x for x in t))

    def test_lookalike_process_name(self):
        d = run(processes=[proc(3, "scvhost.exe", r"C:\Windows\System32\scvhost.exe", sig="NotSigned")])
        self.assertTrue(any("Look-alike" in x for x in titles(d)))

    def test_benign_system_process_is_clean(self):
        d = run(processes=[proc(4, "svchost.exe", r"C:\Windows\System32\svchost.exe", "svchost.exe -k netsvcs", "services.exe")])
        self.assertEqual(d["findings"], [])

    def test_brute_force_then_success(self):
        ev = [event(4625, "User=admin LogonType=3 Src=198.51.100.7 Status=0", "2026-11-08 09:%02d:00" % i) for i in range(8)]
        ev.append(event(4624, "User=admin LogonType=10 Src=198.51.100.7 Proc=-", "2026-11-08 09:30:00"))
        d = run(events=ev)
        self.assertTrue(any("after 8 failed attempts" in x for x in titles(d)))

    def test_log_cleared(self):
        d = run(events=[event(1102, "")])
        self.assertIn("Windows event log was cleared", titles(d))

    def test_default_wmi_consumer_ignored_but_custom_flagged(self):
        base = {"Severity": "", "Type": "WMI Subscription", "Location": "root\\subscription (NTEventLogEventConsumer)",
                "Value": "", "Target": "", "Signature": "", "Signer": "", "Context": "", "Modified": "", "Flags": ""}
        d = run(persistence=[dict(base, Name="SCM Event Log Consumer")])
        self.assertEqual(d["findings"], [])
        d = run(persistence=[dict(base, Name="evil", Value="powershell -enc AAAA")])
        self.assertTrue(any("WMI event consumer" in x for x in titles(d)))

    def test_run_key_user_directory_unsigned(self):
        row = {"Severity": "", "Type": "Registry Run Key", "Name": "upd", "Location": r"HKCU\...\Run",
               "Value": r'"C:\Users\x\AppData\Roaming\u.exe"', "Target": r"C:\Users\x\AppData\Roaming\u.exe",
               "Signature": "NotSigned", "Signer": "", "Context": "", "Modified": "", "Flags": ""}
        d = run(persistence=[row])
        self.assertTrue(any("user-writable" in x for x in titles(d)))

    def test_double_extension_file(self):
        f = {"Severity": "", "Kind": "Dropped File", "Name": "invoice.pdf.exe", "Path": r"C:\Users\x\Downloads\invoice.pdf.exe",
             "Size": 1, "Created": "2026-11-08 08:00:00", "Modified": "2026-11-08 08:00:00", "SHA256": "b" * 64,
             "Signature": "", "Signer": "", "Flags": ""}
        d = run(files=[f])
        self.assertTrue(any("Double-extension" in x for x in titles(d)))

    def test_allowlist_suppresses(self):
        p = proc(5, "scvhost.exe", r"C:\Windows\System32\scvhost.exe", sig="NotSigned")
        self.assertTrue(run(processes=[dict(p)])["findings"])
        A.add_allow("names", "scvhost.exe")
        self.assertEqual(run(processes=[dict(p)])["findings"], [])
        os.remove(A.ALLOW_PATH)

    def test_baseline_marks_new_persistence(self):
        row = {"Severity": "", "Type": "Registry Run Key", "Name": "known", "Location": "L", "Value": "C:\\Windows\\a.exe",
               "Target": "", "Signature": "", "Signer": "", "Context": "", "Modified": "", "Flags": ""}
        A.save_baseline(run(persistence=[dict(row)]))
        d = run(persistence=[dict(row), dict(row, Name="brand-new", Value="C:\\Windows\\b.exe")])
        self.assertTrue(any("New persistence item" in x for x in titles(d)))
        self.assertEqual([r["New"] for r in d["persistence"]], ["", "NEW"])
        os.remove(A.BASELINE_PATH)

    def test_risk_score_is_capped_and_noise_resistant(self):
        many_low = [proc(i, "tool%d.exe" % i, r"C:\Users\x\AppData\Local\app%d\t.exe" % i) for i in range(50)]
        d = run(processes=many_low)
        self.assertLess(d["summary"]["score"], 50)


if __name__ == "__main__":
    unittest.main()
