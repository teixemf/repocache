"""Stdlib-only guardrails for the #94 long-observation sandbox."""
import sys
import subprocess
from unittest import mock
from pathlib import Path
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import spike_nginx_eviction_extended_v06 as lab


class ExtendedEvictionConfigTests(unittest.TestCase):
    def test_retired_zone_dropped_entirely(self):
        with tempfile.TemporaryDirectory() as tmp:
            c = lab.candidate_config(Path(tmp), 31001, 31002, "isolated-drop", "retired")
            self.assertNotIn("keys_zone=removed:", c)
            self.assertNotIn("location /removed/", c)
            self.assertIn("keys_zone=hot:1m", c)
            self.assertIn("127.0.0.1:31002", c)

    def test_parked_zone_managed_but_not_exposed(self):
        with tempfile.TemporaryDirectory() as tmp:
            c = lab.candidate_config(Path(tmp), 31001, 31002, "isolated-keep", "retired")
            self.assertIn("keys_zone=removed:1m", c)
            self.assertIn("max_size=128k", c)
            self.assertNotIn("location /removed/", c)

    def test_shared_zone_uses_one_manager(self):
        with tempfile.TemporaryDirectory() as tmp:
            c = lab.candidate_config(Path(tmp), 31001, 31002, "shared", "retired")
            self.assertIn("keys_zone=shared:1m", c)
            self.assertNotIn("keys_zone=removed:", c)
            self.assertNotIn("location /removed/", c)

    def test_reattach_restores_removed_zone_path_and_route(self):
        with tempfile.TemporaryDirectory() as tmp:
            c = lab.candidate_config(Path(tmp), 31001, 31002, "isolated-drop", "recover")
            self.assertIn("keys_zone=removed:1m", c)
            self.assertIn("location /removed/", c)
            self.assertIn("max_size=32m", c)

    def test_snapshot_never_creates_cache_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            snapshot = lab.cache_snapshot(root, "isolated-drop", 10)
            self.assertEqual(snapshot["zones"]["removed"], {"files": 0, "bytes": 0})
            self.assertFalse((root / "cache").exists())

    def test_failed_private_start_reaps_child(self):
        """Regression S-04: an NGINX listener timeout must not leak a child."""
        child = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(30)"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            with (mock.patch.object(lab.subprocess, "Popen", return_value=child),
                  mock.patch.object(lab.base, "wait_for_listener",
                                    side_effect=TimeoutError("synthetic bind failure"))):
                with self.assertRaisesRegex(TimeoutError, "synthetic bind failure"):
                    lab.start_private_master("unused", Path("/tmp/private-test"),
                                             Path("/tmp/private-test/nginx.conf"),
                                             object(), 12345)
            self.assertIsNotNone(child.poll(), "listener failure left child running")
        finally:
            if child.poll() is None:
                child.kill()
                child.wait(timeout=5)

    def test_unknown_mode_and_stage_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(ValueError):
                lab.candidate_config(Path(tmp), 3, 4, "unknown", "warm")
            with self.assertRaises(ValueError):
                lab.candidate_config(Path(tmp), 3, 4, "shared", "unknown")


if __name__ == "__main__":
    unittest.main()
