"""Pure unit guards for the disposable #94 experiment (no NGINX needed)."""
from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "spike_nginx_eviction_v06.py"
SPEC = spec_from_file_location("nginx_eviction_spike", SCRIPT)
module = module_from_spec(SPEC)
SPEC.loader.exec_module(module)


class CacheSpikeTests(unittest.TestCase):
    def test_reproducible_fixture_is_distinct_by_path(self):
        path = "/hot/package-0.rpm"
        self.assertEqual(module.payload(path), module.payload(path))
        self.assertEqual(len(module.payload(path)), module.OBJECT_BYTES)
        self.assertNotEqual(module.payload(path), module.payload("/cold/package-0.rpm"))

    def test_shared_cache_keeps_manager_zone_after_retiring_route(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = module.config(Path(tmp), 12345, 12346, "shared", removed=True)
            self.assertIn("keys_zone=shared:1m", config)
            self.assertNotIn("location /removed/", config)
            self.assertIn("location /hot/", config)
            self.assertIn("127.0.0.1:12346", config)

    def test_isolated_cache_retains_path_without_active_zone(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = module.config(Path(tmp), 12345, 12346, "isolated", removed=True)
            self.assertNotIn("keys_zone=removed:1m", config)
            self.assertNotIn("location /removed/", config)
            self.assertIn("keys_zone=cold:1m", config)
            self.assertIn("keys_zone=hot:1m", config)

    def test_stats_only_read_selected_sandbox(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.assertEqual(module.cache_stats(root / "missing"), {"bytes": 0, "files": 0})
            file = root / "sample"
            file.write_bytes(b"payload")
            self.assertEqual(module.cache_stats(root), {"bytes": 7, "files": 1})


if __name__ == "__main__":
    unittest.main()
