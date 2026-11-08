"""Offline unit tests for PhishScope core logic. Network calls are mocked."""
import io
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core import attach, authcheck, config, domains, emailparse, engine, urls  # noqa: E402


def fake_dns(records):
    def q(name, rtype="TXT", timeout=4.0):
        key = (name.lower().rstrip("."), rtype)
        return (list(records[key]), "ok") if key in records else ([], "nxdomain")
    return q


class DomainTests(unittest.TestCase):
    def test_org_domain(self):
        self.assertEqual(domains.org_domain("mail.google.com"), "google.com")
        self.assertEqual(domains.org_domain("a.b.co.uk"), "b.co.uk")
        self.assertEqual(domains.org_domain("portal.gov.in"), "portal.gov.in")

    def test_alignment(self):
        self.assertTrue(domains.aligned("mail.example.com", "example.com"))
        self.assertFalse(domains.aligned("mail.example.com", "example.com", strict=True))
        self.assertFalse(domains.aligned("example.com", "evil.com"))

    def test_defang(self):
        self.assertEqual(domains.defang("http://a.com"), "hxxp://a[.]com")


class SpfTests(unittest.TestCase):
    def run_spf(self, ip, domain, records):
        with mock.patch("core.dnsutil.query", fake_dns(records)):
            return authcheck.spf_check(ip, domain)

    def test_ip4_pass_and_fail(self):
        rec = {("example.com", "TXT"): ["v=spf1 ip4:203.0.113.0/24 -all"]}
        self.assertEqual(self.run_spf("203.0.113.7", "example.com", rec)["result"], "pass")
        self.assertEqual(self.run_spf("198.51.100.1", "example.com", rec)["result"], "fail")

    def test_include_and_softfail(self):
        rec = {("example.com", "TXT"): ["v=spf1 include:_spf.mail.test ~all"],
               ("_spf.mail.test", "TXT"): ["v=spf1 ip4:192.0.2.10 -all"]}
        self.assertEqual(self.run_spf("192.0.2.10", "example.com", rec)["result"], "pass")
        self.assertEqual(self.run_spf("192.0.2.99", "example.com", rec)["result"], "softfail")

    def test_a_mechanism_and_redirect(self):
        rec = {("example.com", "TXT"): ["v=spf1 redirect=_spf.example.net"],
               ("_spf.example.net", "TXT"): ["v=spf1 a:relay.example.net -all"],
               ("relay.example.net", "A"): ["192.0.2.55"]}
        self.assertEqual(self.run_spf("192.0.2.55", "example.com", rec)["result"], "pass")

    def test_none_and_lookup_limit(self):
        self.assertEqual(self.run_spf("192.0.2.1", "nospf.test", {})["result"], "none")
        many = "v=spf1 " + " ".join(f"a:h{i}.test" for i in range(11)) + " -all"
        res = self.run_spf("192.0.2.1", "big.test", {("big.test", "TXT"): [many]})
        self.assertEqual(res["result"], "permerror")

    def test_plus_all_flagged(self):
        res = self.run_spf("192.0.2.1", "open.test", {("open.test", "TXT"): ["v=spf1 +all"]})
        self.assertEqual(res["result"], "pass")
        self.assertTrue(any("+all" in i for i in res["issues"]))


class DmarcTests(unittest.TestCase):
    def test_policy_parsing(self):
        rec = {("_dmarc.example.com", "TXT"): ["v=DMARC1; p=reject; adkim=s; rua=mailto:r@example.com"]}
        with mock.patch("core.dnsutil.query", fake_dns(rec)):
            d = authcheck.dmarc_lookup("example.com")
        self.assertTrue(d["found"])
        self.assertEqual((d["policy"], d["adkim"], d["aspf"]), ("reject", "s", "r"))

    def test_org_domain_fallback(self):
        rec = {("_dmarc.example.com", "TXT"): ["v=DMARC1; p=quarantine"]}
        with mock.patch("core.dnsutil.query", fake_dns(rec)):
            d = authcheck.dmarc_lookup("mail.example.com")
        self.assertTrue(d["found"])
        self.assertEqual(d["domain"], "example.com")

    def test_missing(self):
        with mock.patch("core.dnsutil.query", fake_dns({})):
            self.assertFalse(authcheck.dmarc_lookup("example.com")["found"])


class UrlTests(unittest.TestCase):
    def codes(self, url, text=""):
        return {f["code"] for f in urls.analyze_url(url, text)["flags"]}

    def test_text_mismatch_tld_http(self):
        c = self.codes("http://login.example.top/signin", "www.paypal.com")
        self.assertTrue({"TEXT_MISMATCH", "SUSP_TLD", "HTTP_ONLY"} <= c)

    def test_punycode_ip_shortener(self):
        self.assertIn("PUNYCODE", self.codes("https://xn--pple-43d.com/"))
        self.assertIn("IP_HOST", self.codes("http://192.168.1.5/login"))
        self.assertIn("SHORTENER", self.codes("https://bit.ly/abc"))

    def test_brand_and_lookalike(self):
        self.assertIn("BRAND_IN_HOST", self.codes("https://paypal.com.evil.top/verify"))
        self.assertIn("LOOKALIKE", self.codes("https://paypa1.com/"))

    def test_legit_brand_clean(self):
        c = self.codes("https://www.paypal.com/signin")
        self.assertFalse({"BRAND_IN_HOST", "LOOKALIKE", "TEXT_MISMATCH"} & c)

    def test_extract_html(self):
        html = '<a href="http://evil.top/x">paypal.com</a><img src="http://t.top/p.gif" width="1" height="1">'
        found, extras = urls.extract_urls([], [html])
        self.assertEqual(found[0]["url"], "http://evil.top/x")
        self.assertEqual(found[0]["text"], "paypal.com")
        self.assertEqual(len(extras["pixels"]), 1)


def make_zip(files):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for name, data in files.items():
            z.writestr(name, data)
    return buf.getvalue()


class AttachmentTests(unittest.TestCase):
    def codes(self, name, data):
        return {f["code"] for f in attach.analyze_bytes(name, "application/octet-stream", data)["flags"]}

    def test_double_extension_exe(self):
        c = self.codes("invoice.pdf.exe", b"MZ" + b"\x00" * 100)
        self.assertTrue({"DOUBLE_EXT", "DANGEROUS_EXT"} <= c)

    def test_pe_disguised_as_pdf(self):
        self.assertIn("TYPE_MISMATCH", self.codes("report.pdf", b"MZ" + b"\x00" * 100))

    def test_vba_macro_docm(self):
        data = make_zip({"[Content_Types].xml": "x", "word/vbaProject.bin": "y"})
        self.assertTrue({"VBA_MACRO", "MACRO_EXT"} <= self.codes("q3.docm", data))

    def test_remote_template(self):
        rel = ('<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/'
               'relationships/attachedTemplate" Target="http://evil.top/t.dotm" TargetMode="External"/>')
        data = make_zip({"[Content_Types].xml": "x", "word/_rels/settings.xml.rels": rel})
        self.assertIn("REMOTE_TEMPLATE", self.codes("memo.docx", data))

    def test_pdf_javascript(self):
        self.assertIn("PDF_JAVASCRIPT", self.codes("a.pdf", b"%PDF-1.4 /OpenAction /JavaScript (x)"))

    def test_html_smuggling(self):
        data = b"<html><script>var b=new Blob([atob('AAAA')]);URL.createObjectURL(b)</script></html>"
        self.assertIn("HTML_SMUGGLING", self.codes("invoice.html", data))

    def test_clean_png(self):
        self.assertEqual(self.codes("photo.png", b"\x89PNG\r\n\x1a\n" + b"0" * 64), set())


RAW_HOPS = (
    "Received: from mx.relay.test (mx.relay.test [8.8.8.8]) by in.example.com with ESMTP; Mon, 03 Nov 2026 10:00:20 +0000\r\n"
    "Received: from [10.0.0.2] (host [1.1.1.1]) by mx.relay.test with SMTP; Mon, 03 Nov 2026 10:00:10 +0000\r\n"
    "From: a@example.com\r\nSubject: x\r\n\r\nbody\r\n")


class ParserTests(unittest.TestCase):
    def test_hops_and_ips(self):
        from email import policy
        from email.parser import BytesParser
        msg = BytesParser(policy=policy.default).parsebytes(RAW_HOPS.encode())
        hops = emailparse.build_hops(msg)
        self.assertEqual([h["ip"] for h in hops], ["1.1.1.1", "8.8.8.8"])
        self.assertEqual(hops[1]["delay"], 10.0)
        ips = emailparse.pick_ips(hops, msg)
        self.assertEqual((ips["origin"], ips["delivering"]), ("1.1.1.1", "8.8.8.8"))

    def test_private_ip_not_global(self):
        self.assertFalse(emailparse.is_global("10.0.0.2"))
        self.assertTrue(emailparse.is_global("8.8.8.8"))


PHISH = (
    "Received: from mail.evil-secure.top (mail.evil-secure.top [8.8.4.4]) by mx.example.com with ESMTP; Sun, 08 Nov 2026 05:00:10 +0000\r\n"
    'From: "PayPal Support security@paypal.com" <support@evil-secure.top>\r\n'
    "Reply-To: help@gmail.com\r\nReturn-Path: <bounce@evil-secure.top>\r\nTo: victim@example.com\r\n"
    "Subject: Urgent: verify your account\r\nDate: Sun, 08 Nov 2026 04:59:50 +0000\r\n"
    "Message-ID: <abc@evil-secure.top>\r\nMIME-Version: 1.0\r\n"
    'Content-Type: multipart/mixed; boundary="B"\r\n\r\n--B\r\nContent-Type: text/html; charset=utf-8\r\n\r\n'
    '<html>Your account has been suspended. <a href="http://paypa1-login.evil-secure.top/signin">www.paypal.com</a>'
    '<form action="http://x.evil.top/post"><input type="password"></form></html>\r\n--B\r\n'
    'Content-Type: application/octet-stream; name="invoice.pdf.exe"\r\n'
    'Content-Disposition: attachment; filename="invoice.pdf.exe"\r\nContent-Transfer-Encoding: base64\r\n\r\n'
    "TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\r\n--B--\r\n")

LEGIT = (
    "Received: from mail-sor-f41.google.com (mail-sor-f41.google.com [209.85.220.41]) by mx.example.com with SMTPS; Sun, 08 Nov 2026 05:00:10 +0000\r\n"
    "Authentication-Results: mx.example.com; dkim=pass header.d=example.org; spf=pass smtp.mailfrom=news@example.org; dmarc=pass header.from=example.org\r\n"
    "From: News <news@example.org>\r\nReturn-Path: <news@example.org>\r\nTo: me@example.com\r\n"
    "Subject: Weekly update\r\nDate: Sun, 08 Nov 2026 04:59:50 +0000\r\nMessage-ID: <1@example.org>\r\n"
    "Content-Type: text/plain\r\n\r\nHello, here is your weekly update.\r\n")


class EngineTests(unittest.TestCase):
    def run_engine(self, raw):
        records = {("example.org", "TXT"): ["v=spf1 ip4:209.85.220.41 -all"],
                   ("_dmarc.example.org", "TXT"): ["v=DMARC1; p=reject"]}
        rdap = lambda d, *a, **k: {"age_days": 5 if "evil" in d else 4000, "created": "2010-01-01T00:00:00Z", "registrar": "R"}
        cfg = dict(config.DEFAULTS)
        with tempfile.TemporaryDirectory() as tmp, \
                mock.patch("core.dnsutil.query", fake_dns(records)), \
                mock.patch("core.intel.geoip", return_value={"country": "US", "isp": "ISP"}), \
                mock.patch("core.intel.dnsbl_ip", return_value=[]), \
                mock.patch("core.intel.dbl", return_value={"listed": False}), \
                mock.patch("core.intel.rdap_age", side_effect=rdap), \
                mock.patch("core.intel.openphish_feed", return_value=(set(), set())):
            p = Path(tmp) / "m.eml"
            p.write_bytes(raw.encode())
            return engine.analyze(str(p), cfg)

    def test_phishing_scores_high(self):
        R = self.run_engine(PHISH)
        titles = " | ".join(f["title"] for f in R["findings"])
        self.assertGreaterEqual(R["score"], 65)
        self.assertEqual(R["verdict"]["level"], "critical")
        self.assertIn("Display name impersonates 'paypal'", titles)
        self.assertIn("Reply-To redirects", titles)
        self.assertIn("registered 5 day", titles)
        self.assertTrue(any(t["id"] == "T1566.001" for t in R["mitre"]))
        self.assertTrue(any(i["type"] == "sha256" for i in R["iocs"]))

    def test_legit_scores_low(self):
        R = self.run_engine(LEGIT)
        self.assertLess(R["score"], 20)
        self.assertEqual(R["auth"]["spf"]["effective"], "pass")
        self.assertEqual(R["auth"]["dmarc"]["effective"], "pass")


if __name__ == "__main__":
    unittest.main()
