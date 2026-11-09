"""Web route regression tests for CSRF and Origin handling."""
import re
import unittest
import importlib.util

if importlib.util.find_spec("flask") is None:
    raise unittest.SkipTest("Flask is not installed in this test environment")

from app import app


EVENT_XML = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
<System>
  <Provider Name="Microsoft-Windows-Sysmon" />
  <EventID>1</EventID>
  <TimeCreated SystemTime="2026-01-01T12:00:00.000Z" />
  <EventRecordID>1</EventRecordID>
  <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
  <Computer>UNIT-TEST-HOST</Computer>
</System>
<EventData>
  <Data Name="Image">C:\\Windows\\System32\\notepad.exe</Data>
  <Data Name="CommandLine">notepad.exe</Data>
</EventData>
</Event>"""


class WebSecurityTests(unittest.TestCase):
    def setUp(self):
        app.config.update(TESTING=True, SECRET_KEY="test-only-secret")
        self.client = app.test_client()
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        match = re.search(rb'name="csrf_token" value="([^"]+)"', response.data)
        self.assertIsNotNone(match)
        self.csrf = match.group(1).decode("ascii")

    def post_xml(self, headers=None, token=None):
        data = {"mode": "paste", "csrf_token": token or self.csrf, "xml": EVENT_XML}
        return self.client.post("/analyze", data=data, headers=headers or {})

    def test_valid_csrf_allows_null_origin_with_same_origin_fetch_metadata(self):
        response = self.post_xml({"Origin": "null", "Sec-Fetch-Site": "same-origin"})
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"SysmonHunter", response.data)

    def test_cross_site_is_rejected_even_with_valid_csrf(self):
        response = self.post_xml({"Origin": "null", "Sec-Fetch-Site": "cross-site"})
        self.assertEqual(response.status_code, 403)

    def test_invalid_csrf_is_rejected(self):
        response = self.post_xml({"Origin": "null", "Sec-Fetch-Site": "same-origin"}, token="wrong")
        self.assertEqual(response.status_code, 403)

    def test_untrusted_non_null_origin_is_rejected(self):
        response = self.post_xml({"Origin": "https://attacker.example", "Sec-Fetch-Site": "cross-site"})
        self.assertEqual(response.status_code, 403)


if __name__ == "__main__":
    unittest.main(verbosity=2)
