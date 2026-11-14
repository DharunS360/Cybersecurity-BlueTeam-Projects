import hashlib
import json
import tempfile
import unittest
from email.message import EmailMessage
from pathlib import Path

from soar.ingest import from_indicators, load_alert


def write(name: str, data) -> Path:
    p = Path(tempfile.mkdtemp()) / name
    p.write_bytes(data if isinstance(data, bytes) else data.encode())
    return p


def keys(alert):
    return {(i.type.value, i.value) for i in alert.iocs}


class TestIngest(unittest.TestCase):
    def test_wazuh_style_json_tracks_field_paths(self):
        alert = {"rule": {"id": "5712", "level": 10, "description": "sshd: brute force attempt"},
                 "agent": {"name": "srv-01"}, "data": {"srcip": "45.33.32.9", "dstip": "10.0.0.5"}}
        a = load_alert(write("alert.json", json.dumps(alert)))
        self.assertIn(("ip", "45.33.32.9"), keys(a))
        self.assertEqual(a.title, "sshd: brute force attempt")
        self.assertEqual(a.severity, "10")
        self.assertEqual(a.meta["agent"], "srv-01")
        self.assertIn("data.srcip", next(i for i in a.iocs if i.value == "45.33.32.9").sources)
        self.assertEqual([s["value"] for s in a.skipped], ["10.0.0.5"])

    def test_sysmon_hashes_field(self):
        sha = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
        ev = [{"EventID": 1, "Image": "C:\\a\\x.exe", "Hashes": f"MD5=d41d8cd98f00b204e9800998ecf8427e,SHA256={sha}"}]
        a = load_alert(write("sysmon.json", json.dumps(ev)))
        self.assertIn(("hash", sha), keys(a))
        self.assertIn(("hash", "d41d8cd98f00b204e9800998ecf8427e"), keys(a))

    def test_jsonl(self):
        a = load_alert(write("e.jsonl", '{"ip":"45.33.32.1"}\n{"ip":"45.33.32.2"}\n'))
        self.assertEqual(a.meta["format"], "jsonl")
        self.assertEqual(len(a.iocs), 2)

    def test_invalid_json_gives_clear_error(self):
        with self.assertRaises(ValueError):
            load_alert(write("bad.json", "{not json"))

    def test_csv_records_row_and_column(self):
        a = load_alert(write("log.csv", "time,src,msg\n1,45.33.32.7,login ok\n"))
        self.assertEqual(next(iter(a.iocs)).sources, ["row 1, src"])

    def test_plain_log_with_line_numbers(self):
        a = load_alert(write("auth.log", "ok\nFailed password from 45.33.32.50 port 22\n"))
        self.assertEqual(a.iocs[0].sources, ["line 2"])

    def test_eml_headers_body_and_attachment_hash(self):
        m = EmailMessage()
        m["From"] = "Support <help@secure-login.xyz>"
        m["To"] = "victim@corp.example"
        m["Subject"] = "Urgent: verify account"
        m["Authentication-Results"] = "mx; spf=fail smtp.mailfrom=secure-login.xyz; dkim=none; dmarc=fail"
        m["Received"] = "from mail.evil.test (unknown [45.33.32.77]) by mx.corp.test"
        m.set_content("Click hxxps://secure-login[.]xyz/verify now")
        payload = b"MZ\x90fake-binary-bytes"
        m.add_attachment(payload, maintype="application", subtype="octet-stream", filename="invoice.exe")
        a = load_alert(write("phish.eml", m.as_bytes()))
        k = keys(a)
        self.assertIn(("url", "https://secure-login.xyz/verify"), k)
        self.assertIn(("ip", "45.33.32.77"), k)
        self.assertIn(("hash", hashlib.sha256(payload).hexdigest()), k)
        self.assertEqual(a.meta["auth_results"], {"spf": "fail", "dkim": "none", "dmarc": "fail"})
        self.assertEqual(a.meta["attachments"][0]["filename"], "invoice.exe")
        self.assertTrue(a.title.startswith("Email: Urgent"))

    def test_missing_file(self):
        with self.assertRaises(FileNotFoundError):
            load_alert("nope.json")

    def test_manual_indicators(self):
        a = from_indicators(["45.33.32.9", "evil-site.xyz"])
        self.assertEqual(keys(a), {("ip", "45.33.32.9"), ("domain", "evil-site.xyz")})


if __name__ == "__main__":
    unittest.main()