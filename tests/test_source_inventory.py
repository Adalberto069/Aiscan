import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from core.source_inventory import inventory


class InventoryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def write(self, name, content):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")

    def test_known_dependencies_and_imports(self):
        self.write("package.json", json.dumps({"dependencies": {"react": "1", "@supabase/supabase-js": "2"}}))
        self.write("app.py", "from flask import Flask\nimport sqlite3")
        report = inventory(self.root)
        self.assertEqual([x["id"] for x in report["components"]], ["flask", "react", "sqlite", "supabase"])
        self.assertEqual(report["relationships"], [])
        self.assertEqual(report["metrics"]["files_read"], 2)

    def test_source_not_executed_or_copied(self):
        self.write("app.py", "import flask\nraise RuntimeError('SECRET_FIXTURE_VALUE')")
        self.write(".env", "SECRET_FIXTURE_VALUE=abc")
        report = inventory(self.root)
        self.assertNotIn("SECRET_FIXTURE_VALUE", json.dumps(report))
        self.assertEqual(report["metrics"]["files_read"], 1)

    def test_ignored_directories(self):
        self.write("node_modules/pkg/package.json", '{"dependencies":{"firebase":"1"}}')
        self.write(".venv/a.py", "import django")
        self.assertEqual(inventory(self.root)["components"], [])

    def test_invalid_files(self):
        self.write("package.json", "not json")
        self.write("broken.py", "import !")
        self.assertEqual(inventory(self.root)["metrics"]["parse_errors"], 2)

    def test_no_inferred_controls(self):
        self.write("app.py", "import supabase")
        report = inventory(self.root)
        self.assertEqual(report["components"][0]["classification"], "unknown")
        self.assertNotIn("review_items", report)

    def test_large_file_skipped(self):
        self.write("large.py", "#" * (256 * 1024 + 1))
        self.assertEqual(inventory(self.root)["metrics"]["files_skipped"], 1)

    def test_duplicate_observations(self):
        self.write("app.py", "import flask\nfrom flask import Flask")
        self.assertEqual(len(inventory(self.root)["components"][0]["observations"]), 1)

    def test_cli(self):
        self.write("app.py", "import fastapi")
        root = Path(__file__).resolve().parents[1]
        p = subprocess.run([sys.executable, "-m", "core.security_graph", "--source", str(self.root)],
                           cwd=root, capture_output=True, text=True, check=True)
        self.assertEqual(json.loads(p.stdout)["components"][0]["id"], "fastapi")


if __name__ == "__main__":
    unittest.main()
