#!/usr/bin/env python3
"""Tests for the PHANTOM config loader (config file is actually respected)."""

import os
import sys
import json
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import phantom_config as config


class TestConfig(unittest.TestCase):
    def tearDown(self):
        os.environ.pop("PHANTOM_CONFIG", None)
        config.load(force=True)

    def test_defaults_present(self):
        cfg = config.load(force=True)
        for key in ("database", "ai", "logging", "reports"):
            self.assertIn(key, cfg)

    def test_paths_are_expanded(self):
        self.assertNotIn("~", config.db_path())
        self.assertNotIn("~", config.logs_dir())
        self.assertNotIn("~", config.reports_dir())

    def test_ai_settings_typed(self):
        ai = config.ai_settings()
        self.assertIsInstance(ai["port"], int)
        self.assertIsInstance(ai["enabled"], bool)

    def test_env_override_is_respected(self):
        tmp = tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False, encoding="utf-8"
        )
        json.dump({"database": {"path": "/tmp/custom_phantom.db"}}, tmp)
        tmp.close()
        try:
            os.environ["PHANTOM_CONFIG"] = tmp.name
            config.load(force=True)
            self.assertEqual(config.db_path(), "/tmp/custom_phantom.db")
            # partial override still merges defaults for other sections
            self.assertEqual(config.ai_settings()["port"], 11434)
        finally:
            os.unlink(tmp.name)

    def test_malformed_config_falls_back(self):
        tmp = tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False, encoding="utf-8"
        )
        tmp.write("{ this is not valid json ")
        tmp.close()
        try:
            os.environ["PHANTOM_CONFIG"] = tmp.name
            cfg = config.load(force=True)
            self.assertIn("database", cfg)  # did not crash
        finally:
            os.unlink(tmp.name)


if __name__ == "__main__":
    unittest.main(verbosity=2)
