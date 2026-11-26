import copy
import json
import subprocess
import sys
import unittest
from pathlib import Path

from core.security_graph import SecurityGraph

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "lab" / "architecture.json"


class SecurityGraphTests(unittest.TestCase):
    def setUp(self):
        self.spec = json.loads(FIXTURE.read_text(encoding="utf-8"))

    def report(self):
        return SecurityGraph.from_dict(self.spec).analyze()

    def test_fixture_metrics(self):
        m = self.report()["metrics"]
        self.assertEqual(m["components"], 7)
        self.assertEqual(m["relationships"], 6)
        self.assertEqual(m["trust_boundaries"], 6)
        self.assertEqual(m["review_items"], 2)
        self.assertEqual(m["declared_controls"], {"server": 3, "client": 0, "none": 0, "unknown": 1})

    def test_public_resource_not_flagged(self):
        self.assertFalse(any(r["target"] == "catalog" for r in self.report()["review_items"]))

    def test_server_control_not_proof(self):
        result = self.report()
        self.assertIn("Declared server controls do not prove effective authorization.", result["limitations"])
        self.assertFalse(any(r["target"] == "profiles" for r in result["review_items"]))

    def test_client_only_policy_requires_review(self):
        self.spec["relationships"][3]["control"] = "client"
        item = next(r for r in self.report()["review_items"] if r["target"] == "profiles")
        self.assertEqual(item["code"], "POLICY_REVIEW_REQUIRED")
        self.assertEqual(item["status"], "REVIEW_REQUIRED")

    def test_unknown_control_distinct_from_unknown_classification(self):
        items = {r["target"]: r["code"] for r in self.report()["review_items"]}
        self.assertEqual(items, {"files": "ENFORCEMENT_UNKNOWN", "events": "DATA_CLASSIFICATION_UNKNOWN"})

    def test_deterministic_order(self):
        before = self.report()
        self.spec["components"].reverse()
        self.spec["relationships"].reverse()
        self.assertEqual(before, self.report())

    def test_duplicate_component(self):
        self.spec["components"].append(copy.deepcopy(self.spec["components"][0]))
        with self.assertRaisesRegex(ValueError, "duplicate component"):
            self.report()

    def test_unknown_endpoint(self):
        self.spec["relationships"][0]["target"] = "missing"
        with self.assertRaisesRegex(ValueError, "unknown component"):
            self.report()

    def test_duplicate_edge(self):
        self.spec["relationships"].append(copy.deepcopy(self.spec["relationships"][0]))
        with self.assertRaisesRegex(ValueError, "duplicate relationship"):
            self.report()

    def test_invalid_schema(self):
        self.spec["schema"] = True
        with self.assertRaises(ValueError):
            self.report()

    def test_invalid_control(self):
        self.spec["relationships"][0]["control"] = "maybe"
        with self.assertRaises(ValueError):
            self.report()

    def test_cli(self):
        proc = subprocess.run([sys.executable, "-m", "core.security_graph", str(FIXTURE)],
                              cwd=ROOT, capture_output=True, text=True, check=True)
        self.assertEqual(json.loads(proc.stdout), self.report())


if __name__ == "__main__":
    unittest.main()
