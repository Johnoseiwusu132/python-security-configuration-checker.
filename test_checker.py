import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from checker import check_config


class CheckConfigTests(unittest.TestCase):
    def test_insecure_config_reports_expected_findings(self):
        config = {
            "debug_mode": True,
            "cors_allowed_origins": ["*"],
            "cookies": {"secure": False, "http_only": False, "same_site": "None"},
            "minimum_password_length": 8,
            "rate_limiting_enabled": False,
        }
        findings = check_config(config)
        settings = {finding.setting for finding in findings}
        self.assertIn("debug_mode", settings)
        self.assertIn("cors_allowed_origins", settings)
        self.assertIn("cookies.secure", settings)
        self.assertIn("cookies.http_only", settings)
        self.assertIn("cookies.same_site", settings)
        self.assertIn("minimum_password_length", settings)
        self.assertIn("rate_limiting_enabled", settings)

    def test_reasonable_config_has_no_findings(self):
        config = {
            "debug_mode": False,
            "cors_allowed_origins": ["https://example.com"],
            "cookies": {"secure": True, "http_only": True, "same_site": "Lax"},
            "minimum_password_length": 14,
            "rate_limiting_enabled": True,
        }
        self.assertEqual(check_config(config), [])

    def test_missing_settings_are_flagged(self):
        settings = {finding.setting for finding in check_config({})}
        self.assertIn("minimum_password_length", settings)
        self.assertIn("rate_limiting_enabled", settings)


if __name__ == "__main__":
    unittest.main()
