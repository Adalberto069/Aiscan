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


    def test_unknown_import_and_declared_package_are_visible(self):
        self.write("app.py", "import requests\nfrom rich.console import Console\nimport os")
        self.write("requirements.txt", "requests==2.31.0\nrich==13.7.0\n")
        result = inventory(self.root)
        entries = {c["name"]: c for c in result["components"]}
        self.assertEqual(set(entries), {"requests", "rich"})
        self.assertEqual(len(entries["requests"]["observations"]), 2)
        self.assertEqual(entries["rich"]["zone"], "unknown")

    def test_local_imports_are_not_runtime_relationships(self):
        self.write("core/__init__.py", "")
        self.write("core/helper.py", "")
        self.write("app.py", "from core.helper import function")
        result = inventory(self.root)
        self.assertEqual(result["components"], [])
        self.assertEqual(result["relationships"], [])
        self.assertEqual(result["source_links"],
                         [{"file": "app.py", "module": "core", "basis": "local_python_import"}])

    def test_pyproject_and_unknown_npm_package(self):
        self.write("pyproject.toml", '[project]\ndependencies = ["httpx>=0.27"]')
        self.write("package.json", '{"devDependencies":{"@scope/example":"2.0"}}')
        result = inventory(self.root)
        self.assertEqual({x["name"] for x in result["components"]}, {"httpx", "@scope/example"})

    def test_no_versions_or_direct_urls_in_output(self):
        self.write("requirements.txt", "requests==123.456\nsecret @ https://example.test/PRIVATE_TOKEN\n")
        self.write("package.json", '{"dependencies":{"react":"PRIVATE_TOKEN"}}')
        output = json.dumps(inventory(self.root))
        self.assertNotIn("PRIVATE_TOKEN", output)
        self.assertNotIn("123.456", output)

    def test_main_cli_local_mode_and_json(self):
        self.write("app.py", "import requests")
        root = Path(__file__).resolve().parents[1]
        output = self.root / "report.json"
        command = [sys.executable, "aiscan.py", "--source", str(self.root), "--json", str(output)]
        proc = subprocess.run(command, cwd=root, capture_output=True, text=True, check=True)
        self.assertIn("requests", proc.stdout)
        self.assertEqual(json.loads(output.read_text(encoding="utf-8"))["components"][0]["name"], "requests")
        again = subprocess.run(command, cwd=root, capture_output=True)
        self.assertNotEqual(again.returncode, 0)

    def test_main_cli_rejects_combined_network_mode(self):
        root = Path(__file__).resolve().parents[1]
        p = subprocess.run([sys.executable, "aiscan.py", "--source", str(self.root), "-u", "https://example.test"],
                           cwd=root, capture_output=True)
        self.assertEqual(p.returncode, 2)


if __name__ == "__main__":
    unittest.main()
