"""Regressão da classificação de cabeçalhos, sem acesso à rede."""
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from core.findings import FindingsStore
from core.lua_engine import LuaEngine


class HeaderAuditTests(unittest.TestCase):
    def audit(self, headers):
        store = FindingsStore("https://example.test")
        modules = Path(__file__).resolve().parents[1] / "modules"
        response = None if headers is None else SimpleNamespace(headers=headers)
        with patch("core.scope.guarded", return_value=(response, {})):
            engine = LuaEngine(modules_dir=str(modules), store=store)
            output = engine.executar_modulo("headers_audit.lua", {"target": store.target})
        return output, list(store)

    def test_unavailable_is_inconclusive(self):
        output, findings = self.audit(None)
        self.assertIn("inconclusiva", output)
        self.assertEqual(findings, [])

    def test_missing_framing_is_one_medium_finding(self):
        _, findings = self.audit({"Server": "fixture"})
        framing = [f for f in findings if f.category == "framing-protection"]
        self.assertEqual(len(framing), 1)
        self.assertEqual(framing[0].severity, "MEDIA")
        self.assertEqual(sum(f.cwe == "CWE-1021" for f in findings), 1)

    def test_csp_frame_ancestors_without_xfo(self):
        _, findings = self.audit({"Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'"})
        self.assertFalse(any(f.category == "framing-protection" for f in findings))

    def test_xfo_without_csp(self):
        _, findings = self.audit({"X-Frame-Options": "SAMEORIGIN"})
        self.assertFalse(any(f.category == "framing-protection" for f in findings))
        self.assertTrue(any(f.evidence.get("header") == "content-security-policy" for f in findings))

    def test_csp_without_frame_ancestors(self):
        _, findings = self.audit({"Content-Security-Policy": "default-src 'none'"})
        self.assertTrue(any(f.category == "framing-protection" for f in findings))

    def test_wildcard_public_is_observation(self):
        _, findings = self.audit({"Access-Control-Allow-Origin": "*"})
        cors = [f for f in findings if f.category.startswith("cors-")]
        self.assertEqual(len(cors), 1)
        self.assertEqual(cors[0].severity, "INFO")

    def test_wildcard_credentials_not_confirmed_bypass(self):
        _, findings = self.audit({"Access-Control-Allow-Origin": "*",
                                  "Access-Control-Allow-Credentials": "true"})
        cors = [f for f in findings if f.category.startswith("cors-")]
        self.assertEqual(len(cors), 1)
        self.assertEqual(cors[0].severity, "BAIXA")
        self.assertIn("não comprova bypass", cors[0].description)


if __name__ == "__main__":
    unittest.main()
