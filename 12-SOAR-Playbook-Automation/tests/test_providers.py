import json
import time
import unittest
from unittest import mock

import requests

from soar.http import HttpClient, ProviderError
from soar.models import IOC, IOCType, Status
from soar.providers.abuseipdb import AbuseIPDB, abuse_points
from soar.providers.abusech import MalwareBazaar, ThreatFox, URLhaus
from soar.providers.feeds import EPSS, CisaKEV, FeodoTracker
from soar.providers.otx import OTX
from soar.providers.virustotal import VirusTotal, vt_points

from .helpers import FakeHttp, FakeResp, jresp, settings

IP = IOC(IOCType.IP, "45.33.32.9")


class TestHttpClientErrors(unittest.TestCase):
    def _client(self, **kw):
        c = HttpClient(5)
        c.session = mock.Mock()
        c.session.request.side_effect = kw.get("exc")
        if "status" in kw:
            c.session.request.return_value = FakeResp(kw["status"], {})
        return c

    def test_status_mapping(self):
        for status, kind in ((401, "auth"), (403, "auth"), (429, "rate_limit"), (503, "http")):
            with self.assertRaises(ProviderError) as cm:
                self._client(status=status).request("GET", "https://x")
            self.assertEqual(cm.exception.kind, kind)

    def test_timeout_and_network(self):
        with self.assertRaises(ProviderError) as cm:
            self._client(exc=requests.Timeout()).request("GET", "https://x")
        self.assertEqual(cm.exception.kind, "timeout")
        with self.assertRaises(ProviderError) as cm:
            self._client(exc=requests.ConnectionError("dns")).request("GET", "https://x/path")
        self.assertEqual(cm.exception.kind, "network")
        self.assertIn("cannot connect to x", cm.exception.message)

    def test_non_json_is_parse_error(self):
        with self.assertRaises(ProviderError) as cm:
            HttpClient.json(FakeResp(200, None))
        self.assertEqual(cm.exception.kind, "parse")


class TestVirusTotal(unittest.TestCase):
    def test_points_ladder(self):
        self.assertEqual([vt_points(m, 0) for m in (0, 1, 2, 5, 10, 40)], [0, 15, 30, 45, 60, 75])
        self.assertEqual(vt_points(0, 3), 10)

    def test_overwhelming_consensus_is_malicious_alone(self):
        self.assertEqual(vt_points(66, 0, 68), 75)       # EICAR-style consensus
        self.assertEqual(vt_points(14, 0, 92), 60)       # 15% of engines stays below the threshold
        self.assertEqual(vt_points(4, 0, 8), 30)         # small sample: ratio rule needs >=5 engines

    def test_eicar_is_labelled_as_test_file(self):
        body = {"data": {"attributes": {"last_analysis_stats": {"malicious": 66, "harmless": 0, "undetected": 2},
                                        "popular_threat_classification": {"suggested_threat_label": "virus.eicar/test"}}}}
        f = VirusTotal(settings(), FakeHttp({"files/": jresp(body)})).lookup(IOC(IOCType.HASH, "a" * 64))
        self.assertIn("TEST file", f.reason)
        self.assertEqual(f.points, 75)

    def test_malicious_ip(self):
        body = {"data": {"attributes": {"last_analysis_stats": {"malicious": 12, "suspicious": 1, "harmless": 50, "undetected": 20},
                                        "country": "RU", "as_owner": "EvilNet", "last_analysis_date": 1700000000, "reputation": -40}}}
        p = VirusTotal(settings(), FakeHttp({"ip_addresses/45.33.32.9": jresp(body)}))
        f = p.lookup(IP)
        self.assertEqual((f.status, f.points), (Status.OK, 60))
        self.assertIn("12/83", f.reason)
        self.assertEqual(f.evidence["country"], "RU")
        self.assertIn("virustotal.com/gui/ip-address", f.link)

    def test_404_is_not_found(self):
        p = VirusTotal(settings(), FakeHttp({"/urls/": FakeResp(404, {})}))
        f = p.lookup(IOC(IOCType.URL, "http://x.test/a"))
        self.assertEqual(f.status, Status.NOT_FOUND)

    def test_url_id_is_base64url_without_padding(self):
        http = FakeHttp({"/urls/": FakeResp(404, {})})
        VirusTotal(settings(), http).lookup(IOC(IOCType.URL, "http://x.test/a"))
        self.assertTrue(http.calls[0][1].endswith("/urls/aHR0cDovL3gudGVzdC9h"))

    def test_bad_shape_is_parse_error(self):
        p = VirusTotal(settings(), FakeHttp({"files/": jresp({"unexpected": 1})}))
        with self.assertRaises(ProviderError):
            p.lookup(IOC(IOCType.HASH, "a" * 64))


class TestAbuseIPDB(unittest.TestCase):
    def test_points(self):
        self.assertEqual([abuse_points(s) for s in (0, 1, 25, 50, 75, 100)], [0, 10, 25, 40, 50, 50])

    def test_high_confidence(self):
        d = {"data": {"abuseConfidenceScore": 92, "totalReports": 310, "numDistinctUsers": 80, "countryCode": "CN", "isWhitelisted": False}}
        f = AbuseIPDB(settings(), FakeHttp({"abuseipdb": jresp(d)})).lookup(IP)
        self.assertEqual(f.points, 50)
        self.assertIn("92%", f.reason)

    def test_whitelisted_gets_zero(self):
        d = {"data": {"abuseConfidenceScore": 30, "totalReports": 5, "numDistinctUsers": 2, "isWhitelisted": True}}
        f = AbuseIPDB(settings(), FakeHttp({"abuseipdb": jresp(d)})).lookup(IP)
        self.assertEqual(f.points, 0)
        self.assertTrue(f.evidence["benign"])
        self.assertIn("WHITELISTED", f.reason)


class TestOTX(unittest.TestCase):
    def test_pulses(self):
        d = {"pulse_info": {"count": 12, "pulses": [{"name": "Campaign A"}]}}
        f = OTX(settings(), FakeHttp({"IPv4/45.33.32.9": jresp(d)})).lookup(IP)
        self.assertEqual(f.points, 30)

    def test_benign_validation_zeroes_score(self):
        d = {"pulse_info": {"count": 4, "pulses": []}, "validation": [{"source": "whitelist", "message": "Whitelisted domain"}]}
        f = OTX(settings(), FakeHttp({"/domain/": jresp(d)})).lookup(IOC(IOCType.DOMAIN, "good.com"))
        self.assertEqual(f.points, 0)
        self.assertTrue(f.evidence["benign"])

    def test_zero_pulses_not_found(self):
        f = OTX(settings(), FakeHttp({"IPv4": jresp({"pulse_info": {"count": 0, "pulses": []}})})).lookup(IP)
        self.assertEqual(f.status, Status.NOT_FOUND)


class TestAbuseCh(unittest.TestCase):
    def test_urlhaus_online_url(self):
        d = {"query_status": "ok", "url_status": "online", "threat": "malware_download", "tags": ["exe"], "urlhaus_reference": "https://urlhaus.abuse.ch/url/1/"}
        f = URLhaus(settings(), FakeHttp({"/v1/url/": jresp(d)})).lookup(IOC(IOCType.URL, "http://x.test/a"))
        self.assertEqual(f.points, 70)

    def test_urlhaus_host_and_no_results(self):
        p = URLhaus(settings(), FakeHttp({"/v1/host/": jresp({"query_status": "ok", "url_count": "7", "urls_online": "0"})}))
        self.assertEqual(p.lookup(IOC(IOCType.DOMAIN, "x.test")).points, 45)
        p = URLhaus(settings(), FakeHttp({"/v1/host/": jresp({"query_status": "no_results"})}))
        self.assertEqual(p.lookup(IOC(IOCType.DOMAIN, "x.test")).status, Status.NOT_FOUND)

    def test_malwarebazaar(self):
        h = IOC(IOCType.HASH, "a" * 64)
        d = {"query_status": "ok", "data": [{"signature": "AgentTesla", "file_type": "exe", "file_name": "inv.exe"}]}
        f = MalwareBazaar(settings(), FakeHttp({"mb-api": jresp(d)})).lookup(h)
        self.assertEqual((f.points, f.evidence["signature"]), (80, "AgentTesla"))
        nf = MalwareBazaar(settings(), FakeHttp({"mb-api": jresp({"query_status": "hash_not_found"})})).lookup(h)
        self.assertEqual(nf.status, Status.NOT_FOUND)

    def test_threatfox_ip_requires_exact_ip_match_not_prefix(self):
        d = {"query_status": "ok", "data": [
            {"ioc": "45.33.32.99:443", "malware_printable": "Other", "threat_type": "botnet_cc", "confidence_level": 100},
            {"ioc": "45.33.32.9:8080", "malware_printable": "Cobalt Strike", "threat_type": "botnet_cc", "confidence_level": 80}]}
        http = FakeHttp({"threatfox": jresp(d)})
        f = ThreatFox(settings(), http).lookup(IP)
        self.assertEqual((f.points, f.evidence["malware"], f.evidence["records"]), (60, "Cobalt Strike", 1))
        self.assertFalse(http.calls[0][2]["json"]["exact_match"])

    def test_threatfox_only_prefix_matches_is_not_found(self):
        d = {"query_status": "ok", "data": [{"ioc": "45.33.32.99:443", "confidence_level": 100}]}
        self.assertEqual(ThreatFox(settings(), FakeHttp({"threatfox": jresp(d)})).lookup(IP).status, Status.NOT_FOUND)

    def test_auth_key_header_sent(self):
        http = FakeHttp({"mb-api": jresp({"query_status": "hash_not_found"})})
        MalwareBazaar(settings(abusech_key="SECRET"), http).lookup(IOC(IOCType.HASH, "a" * 64))
        self.assertEqual(http.calls[0][2]["headers"], {"Auth-Key": "SECRET"})


class TestFeeds(unittest.TestCase):
    FEODO = [{"ip_address": "45.33.32.9", "port": 443, "status": "online", "malware": "QakBot", "country": "US"}]

    def test_feodo_hit_and_miss(self):
        p = FeodoTracker(settings(), FakeHttp({"feodotracker": jresp(self.FEODO)}))
        self.assertEqual(p.lookup(IP).points, 80)
        self.assertEqual(p.lookup(IOC(IOCType.IP, "45.33.33.7")).status, Status.NOT_FOUND)

    def test_feodo_offline_c2_scores_lower(self):
        off = [dict(self.FEODO[0], status="offline")]
        p = FeodoTracker(settings(), FakeHttp({"feodotracker": jresp(off)}))
        self.assertEqual(p.lookup(IP).points, 60)

    def test_feed_cached_on_disk_then_stale_fallback(self):
        st = settings()
        http = FakeHttp({"feodotracker": jresp(self.FEODO)})
        FeodoTracker(st, http).lookup(IP)
        FeodoTracker(st, http).lookup(IP)
        self.assertEqual(len(http.calls), 1)                      # second call served from disk
        path = st.feeds_dir / "feodo_ipblocklist.json"
        old = time.time() - 5 * 3600
        import os
        os.utime(path, (old, old))
        down = FakeHttp({"feodotracker": ProviderError("network", "offline")})
        f = FeodoTracker(st, down).lookup(IP)
        self.assertIn("STALE", f.reason)                          # stale data is labelled, never hidden

    def test_feed_unavailable_and_no_copy_raises(self):
        p = FeodoTracker(settings(), FakeHttp({"feodotracker": ProviderError("network", "offline")}))
        with self.assertRaises(ProviderError):
            p.lookup(IP)

    def test_kev(self):
        feed = {"catalogVersion": "2026.01.01", "vulnerabilities": [
            {"cveID": "CVE-2021-44228", "vendorProject": "Apache", "product": "Log4j2", "dateAdded": "2021-12-10", "knownRansomwareCampaignUse": "Known"}]}
        p = CisaKEV(settings(), FakeHttp({"cisa.gov": jresp(feed)}))
        self.assertEqual(p.lookup(IOC(IOCType.CVE, "CVE-2021-44228")).points, 80)
        self.assertEqual(p.lookup(IOC(IOCType.CVE, "CVE-2000-0001")).status, Status.NOT_FOUND)

    def test_epss(self):
        d = {"data": [{"cve": "CVE-2021-44228", "epss": "0.94358", "percentile": "0.99989", "date": "2026-01-01"}]}
        f = EPSS(settings(), FakeHttp({"first.org": jresp(d)})).lookup(IOC(IOCType.CVE, "CVE-2021-44228"))
        self.assertEqual(f.points, 30)
        self.assertEqual(EPSS(settings(), FakeHttp({"first.org": jresp({"data": []})})).lookup(IOC(IOCType.CVE, "CVE-1999-1")).status, Status.NOT_FOUND)


if __name__ == "__main__":
    unittest.main()