"""Offline tests of report triage. No network or credential handling."""
import json
import unittest

from core.findings import FindingsStore


class ReportTriageTests(unittest.TestCase):
    def add(self, store, module, table="fixture", count=None):
        evidence = {"base": "https://fixture.example.test", "tabela": table}
        if count is not None:
            evidence["colunas_sensiveis"] = count
        return store.add_dict(title="Read observation", module=module,
                              category="supabase-public-read", evidence=evidence)

    def test_sensitive_metadata_is_high_potential_not_confirmed(self):
        store = FindingsStore()
        self.add(store, "columns", count=2)
        result = list(store)[0]
        self.assertEqual(result.severity, "ALTA")
        self.assertEqual(result.verdict, "REVIEW_REQUIRED")
        self.assertEqual(result.confidence, "MEDIA")
        self.assertIn("nao verificados", result.description)

    def test_order_independent_triage_and_single_result(self):
        for order in (("enum", "columns"), ("columns", "enum")):
            with self.subTest(order=order):
                store = FindingsStore()
                for source in order:
                    self.add(store, source, count=2 if source == "columns" else None)
                self.assertEqual(len(store), 1)
                finding = list(store)[0]
                self.assertEqual(finding.severity, "ALTA")
                self.assertEqual(finding.evidence["colunas_sensiveis"], 2)
                self.assertEqual(set(finding.evidence["modules"]), set(order))

    def test_later_weaker_metadata_does_not_downgrade(self):
        store = FindingsStore()
        self.add(store, "columns", count=3)
        self.add(store, "enum", count=0)
        self.assertEqual(list(store)[0].severity, "ALTA")
        self.assertEqual(list(store)[0].evidence["colunas_sensiveis"], 3)

    def test_zero_unknown_and_invalid_counts_not_high(self):
        for count in (0, None, True, -1, "3"):
            with self.subTest(count=count):
                store = FindingsStore()
                self.add(store, "columns", count=count)
                self.assertEqual(list(store)[0].severity, "INFO")
                self.assertEqual(list(store)[0].verdict, "REVIEW_REQUIRED")

    def test_distinct_tables_and_unrelated_findings(self):
        store = FindingsStore()
        self.add(store, "columns", table="a", count=2)
        self.add(store, "columns", table="b", count=0)
        store.add_dict(title="Other", severity="CRITICA", verdict="CONFIRMED")
        self.assertEqual(store.resumo(), {"CRITICA":1,"ALTA":1,"MEDIA":0,"BAIXA":0,"INFO":1})
        self.assertEqual(json.loads(store.to_json())["summary"]["review_required"], 2)
        self.assertIn("REVIEW_REQUIRED", store.to_html())
        self.assertIn("REVIEW_REQUIRED", store.to_sarif())


if __name__ == "__main__":
    unittest.main()
