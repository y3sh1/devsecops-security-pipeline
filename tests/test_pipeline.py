import http.client
import json
from pathlib import Path
import sys
import threading
import unittest
from http.server import ThreadingHTTPServer

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from security.check import normalize
from service.server import HealthHandler


class PolicyTests(unittest.TestCase):
    def report(self, result):
        return normalize({"results": [], "errors": []}, {"SchemaVersion": 2, "Results": [result]})

    def test_empty_scan_passes(self):
        self.assertEqual(self.report({"Target": "service"})["decision"], "PASS")

    def test_low_configuration_reported_and_passes(self):
        report = self.report({"Target": "Dockerfile", "Misconfigurations": [
            {"Status": "FAIL", "Severity": "LOW", "ID": "example"}]})
        self.assertEqual(report["decision"], "PASS")
        self.assertFalse(report["findings"][0]["blocking"])

    def test_high_dependency_blocks_even_without_available_fix(self):
        self.assertEqual(self.report({"Target": "requirements.txt", "Vulnerabilities": [
            {"Severity": "HIGH", "VulnerabilityID": "example", "PkgName": "package",
             "InstalledVersion": "1"}]})["decision"], "BLOCK")

    def test_secret_blocks_without_retaining_matched_value(self):
        report = self.report({"Target": "settings.ini", "Secrets": [
            {"Severity": "LOW", "RuleID": "demo", "StartLine": 9, "Match": "private match",
             "Code": {"Lines": ["private source"]}}]})
        self.assertEqual(report["decision"], "BLOCK")
        self.assertNotIn("private", json.dumps(report))

    def test_incomplete_scans_raise(self):
        with self.assertRaises(ValueError):
            normalize({"results": [], "errors": ["timeout"]}, {"SchemaVersion": 2})
        with self.assertRaises(ValueError):
            normalize({"results": [], "errors": []}, {})


class HealthTests(unittest.TestCase):
    def test_health_and_unknown_routes(self):
        with ThreadingHTTPServer(("127.0.0.1", 0), HealthHandler) as server:
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                for path, status in (("/health", 200), ("/missing", 404)):
                    conn = http.client.HTTPConnection(*server.server_address, timeout=2)
                    try:
                        conn.request("GET", path)
                        response = conn.getresponse()
                        self.assertEqual(response.status, status)
                        self.assertIsInstance(json.loads(response.read()), dict)
                    finally:
                        conn.close()
            finally:
                server.shutdown()
                thread.join()
