"""Métricas do motor authz — precisão/recall/FP/FN/cobertura no conjunto conhecido.

Verdade de campo: lab seguro = 0 FIRE esperado; lab com VULN=1 = BOLA em read-cross.
Roda: python tests/test_authz_metrics.py
"""
import json
import sys
import threading
import unittest
from http.client import HTTPConnection
from http.server import HTTPServer

sys.path.insert(0, ".")
sys.path.insert(0, "core")
from lab.server import Handler
from authz import AuthzEngine, load_identities

PORT = 18083
BASE = f"http://127.0.0.1:{PORT}"
ENV_LAB = {"AISCAN_KEY_ANON": "lab-key-anon", "AISCAN_KEY_A": "lab-key-user-a",
           "AISCAN_KEY_B": "lab-key-user-b", "AISCAN_KEY_ADMIN": "lab-key-admin"}
FIRE = ("BOLA_CONFIRMED", "WRITE_OK_CLEANED", "WRITE_ORPHAN")

CATEGORY = {"read-own": "read", "read-cross": "read", "field-email-own": "read",
            "cross-404": "read", "b-own": "read", "public-anon": "public",
            "empty-200": "public", "write-cross": "write", "admin-field-write": "write",
            "admin-fn": "admin", "anon-admin": "admin"}


def mode(open_):
    c = HTTPConnection("127.0.0.1", PORT, timeout=5)
    c.request("GET", f"/__mode?open={1 if open_ else 0}")
    assert json.loads(c.getresponse().read())["vuln"] == open_


class Metrics(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = HTTPServer(("127.0.0.1", PORT), Handler)
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        with open("lab/policy.json", encoding="utf-8") as f:
            cls.policy = json.load(f)
        idents, _ = load_identities(ENV_LAB)
        cls.eng = AuthzEngine(BASE, idents, cls.policy, lab_mode=True)

    @classmethod
    def tearDownClass(cls):
        try:
            mode(False)
        finally:
            cls.srv.shutdown()

    def by_id(self, cid):
        return next(c for c in self.policy["cases"] if c["id"] == cid)

    def test_precision_recall(self):
        mode(False)
        secure = {f["case"]: f["verdict"] for f in self.eng.run_all(self.policy["cases"])}
        fp = [c for c, v in secure.items() if v in FIRE]
        mode(True)
        try:
            vuln = self.eng.run_case(self.by_id("read-cross"))
        finally:
            mode(False)
        tp = 1 if vuln["verdict"] == "BOLA_CONFIRMED" else 0
        fn = 1 - tp
        prec = tp / (tp + len(fp)) if (tp + len(fp)) else 1.0
        rec = tp / (tp + fn)
        print(f"\n[MÉTRICAS] TP={tp} FP={len(fp)}{fp} FN={fn} precisão={prec:.2f} recall={rec:.2f}")
        self.assertEqual(fp, [])
        self.assertEqual(vuln["verdict"], "BOLA_CONFIRMED")
        self.assertEqual(prec, 1.0)
        self.assertEqual(rec, 1.0)

    def test_coverage_by_category(self):
        cats = {}
        for c in self.policy["cases"]:
            cats.setdefault(CATEGORY.get(c["id"], "?"), []).append(c["id"])
        print("\n[COBERTURA]", {k: len(v) for k, v in cats.items()})
        for need in ("read", "write", "admin", "public"):
            self.assertIn(need, cats, f"categoria sem caso: {need}")

    def test_inconclusive_rate(self):
        probe = [self.by_id("empty-200")]
        err500 = {"id": "e500", "desc": "t", "identity": "user_a", "method": "GET",
                  "resource": "/status/500", "params": {}, "expect": "deny", "cross": True}
        err429 = dict(err500, id="e429", resource="/status/429")
        got = [self.eng.run_case(c)["verdict"] for c in probe + [err500, err429]]
        rate = sum(1 for v in got if v == "INCONCLUSIVE") / len(got)
        print(f"\n[INCONCLUSIVOS] {rate:.0%} ({got}) — inconclusivo nao e aprovado nem falha".encode("ascii", "replace").decode())
        self.assertTrue(all(v == "INCONCLUSIVE" for v in got))


if __name__ == "__main__":
    unittest.main(verbosity=2)
