import json
import tempfile
import unittest
from pathlib import Path
from core.admin_evidence import import_evidence

class AdminEvidenceTests(unittest.TestCase):
    def read(self, **changes):
        data = dict(schema=1, project="Test", anonymous_email_read=True,
                    rls_enabled=True, unconditional_anonymous_policy=True,
                    expired_active_count=0, paid_total=1, paid_with_absolute_url=0)
        data.update(changes)
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "snapshot.json"
            p.write_text(json.dumps(data), encoding="utf-8")
            return import_evidence(p)

    def test_priority(self):
        store = self.read()
        self.assertEqual(store.resumo()["ALTA"], 1)
        self.assertTrue(all(f.verdict == "OWNER_EVIDENCE" for f in store))

    def test_protected(self):
        store = self.read(anonymous_email_read=False, unconditional_anonymous_policy=False)
        self.assertEqual(store.resumo()["ALTA"], 0)

    def test_no_broad_policy(self):
        self.assertEqual(self.read(unconditional_anonymous_policy=False).resumo()["MEDIA"], 1)

    def test_nonzero_aggregate_risk(self):
        store = self.read(expired_active_count=2, paid_with_absolute_url=1)
        self.assertEqual(store.resumo()["MEDIA"], 2)

    def test_reject_bad_fields(self):
        for changes in ({"schema": True}, {"expired_active_count": -1},
                        {"paid_with_absolute_url": 2}, {"anonymous_email_read": "true"},
                        {"extra": "unexpected"}, {"project": "https://example.test"}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                self.read(**changes)

    def test_exports(self):
        store = self.read()
        self.assertEqual(json.loads(store.to_json())["summary"]["total"], 3)
        self.assertIn("OWNER_EVIDENCE", store.to_sarif())
        self.assertIn("Metadados administrativos", store.to_html())

if __name__ == "__main__":
    unittest.main()
