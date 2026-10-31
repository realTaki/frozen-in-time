"""Offline regression for CVE-2023-32681; no dataset/model/network access.

This bounded fix does not address later Requests or PyTorch advisories.
"""

import unittest
from pathlib import Path

import requests
import yaml


ROOT = Path(__file__).resolve().parents[1]


class RequestsSecurityTests(unittest.TestCase):
    def test_export_pins_proxy_header_fix_and_required_decoder(self):
        dependencies = yaml.safe_load((ROOT / "environment.yml").read_text())["dependencies"]
        packages = {
            item.split("=", 1)[0]: item.split("=", 2)[1]
            for item in dependencies if isinstance(item, str) and "=" in item
        }
        self.assertEqual(packages["requests"], "2.31.0")
        self.assertEqual(packages["charset-normalizer"], "2.0.12")
        self.assertEqual(packages["python"], "3.7.10")
        self.assertEqual(packages["pytorch"], "1.8.1")

    def test_https_redirect_does_not_forward_proxy_authorization(self):
        # Synthetic credentials only. Exercise real Requests redirect handling,
        # without sending a request or contacting a proxy.
        session = requests.Session()
        session.trust_env = False
        request = requests.Request(
            "GET", "https://origin.example/image.jpg",
            headers={"Proxy-Authorization": "Basic stale-synthetic-value"},
        ).prepare()
        proxies = {"https": "http://synthetic-user:synthetic-pass@proxy.example:3128"}
        self.assertEqual(session.rebuild_proxies(request, proxies), proxies)
        self.assertNotIn("Proxy-Authorization", request.headers)

    def test_http_proxy_authentication_is_preserved(self):
        session = requests.Session()
        session.trust_env = False
        request = requests.Request("GET", "http://origin.example/image.jpg").prepare()
        proxies = {"http": "http://synthetic-user:synthetic-pass@proxy.example:3128"}
        self.assertEqual(session.rebuild_proxies(request, proxies), proxies)
        self.assertIn("Proxy-Authorization", request.headers)


if __name__ == "__main__":
    unittest.main()
