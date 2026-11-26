"""Offline report regression fixtures. All responses are synthetic."""
import base64
import json
import unittest
from pathlib import Path

from core.findings import FindingsStore
from core.lua_engine import LuaEngine


class ReportTests(unittest.TestCase):
    def setUp(self):
        self.store = FindingsStore("https://example.test")
        self.engine = LuaEngine(modules_dir=str(Path(__file__).resolve().parents[1] / "modules"),
                                store=self.store)
        self.g = self.engine.lua.globals()
        self.g["http_get_full"] = lambda *args: "__ERRO__"
        self.g["throttle"] = lambda *args: True

    def run_module(self, name, html=""):
        return self.engine.executar_modulo(name, {"target": self.store.target,
                                                  "html": html, "show_data": False})

    def test_public_markers_are_not_secrets(self):
        def enc(obj):
            return base64.urlsafe_b64encode(json.dumps(obj).encode()).decode().rstrip("=")
        token = enc({"alg": "HS256"}) + "." + enc({"role": "anon"}) + ".fixture"
        output = self.run_module("js_secrets.lua", token + " supabase.co VITE_EXAMPLE")
        self.assertIn("[INFO]", output)
        self.assertNotIn(token, output)
        self.assertEqual(len(self.store), 0)

    def test_secret_pattern_never_prints_value(self):
        marker = "ghp_" + "X" * 36
        output = self.run_module("js_secrets.lua", marker)
        self.assertIn("[REVIEW]", output)
        self.assertNotIn(marker, output)
        self.assertNotIn(marker, self.store.to_json())
        self.assertEqual(len(self.store), 1)

    def test_columns_redaction_and_deduplication(self):
        def enc(obj):
            return base64.urlsafe_b64encode(json.dumps(obj).encode()).decode().rstrip("=")
        token = enc({"alg": "HS256"}) + "." + enc({"role": "anon"}) + ".fixture"
        html = "https://fixture.supabase.co " + token
        marker = "private-fixture@example.test"
        sample = json.dumps([{"id": "private-id", "email": marker}])
        def get(url):
            return sample if "/profiles?" in url else "[]"
        def count(base, key, table):
            return self.engine.lua.table_from({"status": 200 if table == "profiles" else 403, "total": 1})
        self.g["rest_count"] = count
        self.g["http_get"] = get
        self.g["http_status"] = lambda url: 200 if "/profiles?" in url else 403
        for module in ("supabase_columns.lua", "supabase_enum.lua"):
            out = self.run_module(module, html)
            self.assertIn("[REVIEW]", out)
            self.assertNotIn(marker, out)
            self.assertNotIn("private-id", out)
        self.assertEqual(len(self.store), 1)
        report = self.store.to_json()
        self.assertNotIn(marker, report)
        self.assertIn("supabase_columns.lua", report)
        self.assertIn("supabase_enum.lua", report)

    def test_distinct_resources_not_merged(self):
        for base in ("https://one.example.test", "https://two.example.test"):
            self.store.add_dict(title="Read review", module="fixture", category="supabase-public-read",
                                evidence={"base": base, "tabela": "profiles"})
        self.assertEqual(len(self.store), 2)


if __name__ == "__main__":
    unittest.main()
