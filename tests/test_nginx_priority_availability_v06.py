"""Guard the scope of the disposable NGINX #94 priority/availability lab."""
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import spike_nginx_priority_availability_v06 as lab


class PriorityAvailabilityTests(unittest.TestCase):
    def test_payload_deterministic_per_key(self):
        self.assertEqual(len(lab.body_for("/hot/package-0")), lab.BODY_SIZE)
        self.assertEqual(lab.body_for("/hot/package-0"),
                         lab.body_for("/hot/package-0"))
        self.assertNotEqual(lab.body_for("/hot/package-0"),
                            lab.body_for("/cold/package-0"))

    def test_loopback_and_private_config_only(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            conf = lab.config(root, 1234, 5678, "128k")
            self.assertIn("listen 127.0.0.1:5678", conf)
            self.assertIn("proxy_pass http://127.0.0.1:1234", conf)
            self.assertIn(f"pid {root}/nginx.pid", conf)
            self.assertIn(f"proxy_cache_path {root}/cache", conf)
            self.assertIn("max_size=128k", conf)
            self.assertIn("proxy_cache_lock on", conf)
            self.assertNotIn("proxy_cache_purge", conf)

    def test_invalid_limit_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(ValueError):
                lab.config(Path(directory), 1234, 5678, "unlimited")

    def test_usage_is_read_only(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.assertEqual(lab.usage(root), {"files": 0, "bytes": 0})
            self.assertFalse((root / "cache").exists())


if __name__ == "__main__":
    unittest.main()
