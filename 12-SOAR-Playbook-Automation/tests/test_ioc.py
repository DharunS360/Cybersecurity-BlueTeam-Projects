import unittest

from soar.ioc import extract, load_allowlist, refang
from soar.models import IOCType


def found(text):
    return {(i.type.value, i.value) for i in extract(text).iocs}


class TestIOC(unittest.TestCase):
    def test_refang(self):
        self.assertEqual(refang("hxxps://evil[.]com/a"), "https://evil.com/a")
        self.assertEqual(refang("1[.]2(.)3{.}4"), "1.2.3.4")
        self.assertEqual(refang("a[at]b[dot]com"), "a@b.com")

    def test_defanged_url_yields_url_and_domain(self):
        f = found("download from hxxp://bad-site[.]xyz/payload.bin now")
        self.assertIn(("url", "http://bad-site.xyz/payload.bin"), f)
        self.assertIn(("domain", "bad-site.xyz"), f)

    def test_public_ip_extracted_private_skipped_with_reason(self):
        c = extract("conn 8.8.8.8:443 from 192.168.1.5 and 10.1.1.1 and 127.0.0.1")
        self.assertEqual([i.value for i in c.iocs if i.type is IOCType.IP], ["8.8.8.8"])
        self.assertEqual(len(c.skipped), 3)
        self.assertTrue(all(s["reason"] for s in c.skipped))

    def test_version_numbers_and_octet_overflow_not_ips(self):
        self.assertEqual(found("build 10.0.19045.1 and 999.1.1.1"), set())

    def test_trailing_sentence_period(self):
        self.assertIn(("ip", "8.8.4.4"), found("Contact came from 8.8.4.4."))

    def test_hash_types_and_junk(self):
        md5, sha1, sha256 = "d41d8cd98f00b204e9800998ecf8427e", "da39a3ee5e6b4b0d3255bfef95601890afd80709", "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
        f = found(f"{md5} {sha1} {sha256} {'0' * 32} {'f' * 40}")
        self.assertEqual({v for t, v in f if t == "hash"}, {md5, sha1, sha256})

    def test_hash_inside_longer_hex_ignored(self):
        self.assertEqual(found("a" * 33 + "b"), set())

    def test_file_extensions_are_not_domains(self):
        self.assertEqual({v for t, v in found("run setup.exe then payload.dll and app.py config.yaml") if t == "domain"}, set())

    def test_ambiguous_tld_bare_ignored_but_kept_in_url(self):
        self.assertEqual({v for t, v in found("see script.sh") if t == "domain"}, set())
        self.assertIn(("domain", "evil.sh"), found("http://evil.sh/x"))

    def test_email_and_domain(self):
        f = found("From: Alice <Alice@Phish-Corp.xyz>")
        self.assertIn(("email", "alice@phish-corp.xyz"), f)
        self.assertIn(("domain", "phish-corp.xyz"), f)

    def test_cve_normalised(self):
        self.assertIn(("cve", "CVE-2021-44228"), found("exploits cve-2021-44228 here"))

    def test_ipv6_and_false_positives(self):
        f = found("addr 2606:4700:4700::1111 time 12:34:56 mac aa:bb:cc:dd:ee:ff")
        self.assertEqual({v for t, v in f if t == "ip"}, {"2606:4700:4700::1111"})

    def test_allowlist_default_and_custom(self):
        c = extract("xmlns schemas.microsoft.com and corp.internal-vendor.com", load_allowlist(None))
        self.assertNotIn("schemas.microsoft.com", {i.value for i in c.iocs})
        self.assertIn(("domain", "schemas.microsoft.com", "allowlisted"),
                      {(s["type"], s["value"], s["reason"]) for s in c.skipped})

    def test_url_trailing_punctuation_and_parens(self):
        f = found("(see http://bad.com/x).")
        self.assertIn(("url", "http://bad.com/x"), f)

    def test_dedup_tracks_sources(self):
        c = extract("8.8.8.8")
        c.scan("8.8.8.8", "field.a")
        self.assertEqual(len([i for i in c.iocs if i.value == "8.8.8.8"]), 1)


if __name__ == "__main__":
    unittest.main()