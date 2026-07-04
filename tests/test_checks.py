"""
PurpEye - Test Suite
Automated tests that prove each security check produces the correct
severity for a given input - WITHOUT touching the real internet.

We do this by "mocking": we replace the real network call (requests.get)
with a fake response we control, so we can hand each check exactly the
scenario we want to test (e.g. a site missing HTTPS) and assert the
check reacts correctly.

Run with:   python3 -m unittest tests/test_checks.py -v
(from the project root)
"""

import unittest
from unittest.mock import patch, MagicMock
import sys
import os

# Make the checks importable from the project root.
BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(BASE, "scanner"))

from checks import https_headers_check
from checks import software_version_check
from checks import cors_check
from checks import cookie_session_check


def make_fake_response(url="https://example.com", headers=None, text="", cookies=None):
    """
    Build a fake 'response' object that looks enough like a real
    requests response for our checks to use it. We only fill in the
    parts the checks actually read: url, headers, text, cookies.
    """
    fake = MagicMock()
    fake.url = url
    fake.headers = headers if headers is not None else {}
    fake.text = text
    fake.content = text.encode() if text else b"x"
    fake.status_code = 200
    fake.cookies = cookies if cookies is not None else []
    return fake


class TestHttpsHeadersCheck(unittest.TestCase):
    """Tests for the HTTPS & Security Headers check."""

    @patch("checks.https_headers_check.requests.get")
    def test_missing_all_headers_is_medium(self, mock_get):
        # A site on HTTPS but with NO security headers should be Medium.
        mock_get.return_value = make_fake_response(
            url="https://example.com", headers={})
        result = https_headers_check.check("https://example.com")
        self.assertEqual(result["severity"], "Medium")

    @patch("checks.https_headers_check.requests.get")
    def test_no_https_is_high(self, mock_get):
        # A site served over plain HTTP should raise a High finding.
        mock_get.return_value = make_fake_response(
            url="http://example.com", headers={})
        result = https_headers_check.check("http://example.com")
        self.assertEqual(result["severity"], "High")

    @patch("checks.https_headers_check.requests.get")
    def test_all_headers_present_is_info(self, mock_get):
        # A site with every security header should come back clean (Info).
        good_headers = {
            "Strict-Transport-Security": "max-age=63072000",
            "Content-Security-Policy": "default-src 'self'",
            "X-Frame-Options": "SAMEORIGIN",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "strict-origin-when-cross-origin",
        }
        mock_get.return_value = make_fake_response(
            url="https://example.com", headers=good_headers)
        result = https_headers_check.check("https://example.com")
        self.assertEqual(result["severity"], "Info")


class TestSoftwareVersionCheck(unittest.TestCase):
    """Tests for the Software Version disclosure check."""

    @patch("checks.software_version_check.requests.get")
    def test_version_in_server_header_is_medium(self, mock_get):
        # A Server header exposing a version number should be Medium.
        mock_get.return_value = make_fake_response(
            headers={"Server": "Apache/2.4.29"}, text="<html></html>")
        result = software_version_check.check("https://example.com")
        self.assertEqual(result["severity"], "Medium")

    @patch("checks.software_version_check.requests.get")
    def test_no_disclosure_is_info(self, mock_get):
        # No version-leaking headers and clean HTML => Info.
        mock_get.return_value = make_fake_response(
            headers={}, text="<html><body>hello</body></html>")
        result = software_version_check.check("https://example.com")
        self.assertEqual(result["severity"], "Info")


class TestCorsCheck(unittest.TestCase):
    """Tests for the CORS configuration check."""

    @patch("checks.cors_check.requests.get")
    def test_wildcard_with_credentials_is_high(self, mock_get):
        # The worst CORS case: wildcard origin + credentials allowed.
        mock_get.return_value = make_fake_response(headers={
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Credentials": "true",
        })
        result = cors_check.check("https://example.com")
        self.assertEqual(result["severity"], "High")

    @patch("checks.cors_check.requests.get")
    def test_no_cors_headers_is_info(self, mock_get):
        # No CORS headers at all => nothing risky => Info.
        mock_get.return_value = make_fake_response(headers={})
        result = cors_check.check("https://example.com")
        self.assertEqual(result["severity"], "Info")


class TestCookieSessionCheck(unittest.TestCase):
    """Tests for the Cookie & Session Security check."""

    @patch("checks.cookie_session_check.requests.get")
    def test_insecure_cookie_flagged(self, mock_get):
        # A cookie without Secure/HttpOnly should produce a Medium finding.
        fake_cookie = MagicMock()
        fake_cookie.name = "session"
        fake_cookie.secure = False
        fake_cookie.has_nonstandard_attr = lambda attr: False
        fake_cookie.get_nonstandard_attr = lambda attr: None

        mock_get.return_value = make_fake_response(
            headers={}, cookies=[fake_cookie])
        result = cookie_session_check.check("https://example.com")
        self.assertEqual(result["severity"], "Medium")

    @patch("checks.cookie_session_check.requests.get")
    def test_no_cookies_is_info(self, mock_get):
        # No cookies set => nothing to flag => Info.
        mock_get.return_value = make_fake_response(headers={}, cookies=[])
        result = cookie_session_check.check("https://example.com")
        self.assertEqual(result["severity"], "Info")


if __name__ == "__main__":
    unittest.main(verbosity=2)

