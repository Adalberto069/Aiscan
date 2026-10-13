"""Testes da matriz de autorização contra o lab local (dados sintéticos).

Roda:  python tests/test_authz_lab.py
Nenhum teste toca rede externa, dado real ou produção.
"""
import io
import json
import sys
import threading
import unittest
from contextlib import redirect_stdout
from http.client import HTTPConnection

sys.path.insert(0, ".")
from lab.server import Handler, WRITES
from http.server import HTTPServer

sys.path.insert(0, "core")
from authz import AuthzEngine, AuthzAbort, load_identities

PORT = 18080
BASE = f"http://127.0.0.1:{PORT}"
ENV_LAB = {"AISCAN_KEY_ANON": "lab-key-anon", "AISCAN_KEY_A": "lab-key-user-a",
           "AISCAN_KEY_B": "lab-key-user-b", "AISCAN_KEY_ADMIN": "lab-key-admin"}


def lab_writes():
    c = HTTPConnection("127.0.0.1", PORT, timeout=5)
    c.request("GET", "/__writes")
    return json.loads(c.getresponse().read())["writes"]


class AuthzLab(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = HTTPServer(("127.0.0.1", PORT), Handler)
        cls.th = threading.Thread(target=cls.srv.serve_forever, daemon=True)
        cls.th.start()
        with open("lab/policy.json", encoding="utf-8") as f:
            cls.policy = json.load(f)
        idents, _ = load_identities(ENV_LAB)
        cls.eng = AuthzEngine(BASE, idents, cls.policy, lab_mode=True)

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()

    def verdict(self, cid, eng=None):
        eng = eng or self.eng
        case = next(c for c in self.policy["cases"] if c["id"] == cid)
        return eng.run_case(case)

    def test_1_own_read_allowed(self):
        self.assertEqual(self.verdict("read-own")["verdict"], "OK_ALLOWED")

    def test_2_cross_read_denied(self):
        f = self.verdict("read-cross")
        self.assertEqual(f["verdict"], "OK_DENIED")
        self.assertNotEqual(f["verdict"], "BOLA_CONFIRMED")

    def test_3_cross_write_denied_no_mutation(self):
        w0 = lab_writes()
        eng = AuthzEngine(BASE, load_identities(ENV_LAB)[0], self.policy,
                          lab_mode=True, allow_write={"profiles"})
        f = eng.run_case(next(c for c in self.policy["cases"] if c["id"] == "write-cross"))
        self.assertEqual(f["verdict"], "OK_DENIED")
        self.assertEqual(lab_writes(), w0)  # negado = zero mutação

    def test_4_admin_fn_denied(self):
        self.assertEqual(self.verdict("admin-fn")["verdict"], "OK_DENIED")

    def test_5_public_anon_allowed(self):
        self.assertEqual(self.verdict("public-anon")["verdict"], "OK_ALLOWED")

    def test_6_empty_200_not_bola(self):
        f = self.verdict("empty-200")
        self.assertNotEqual(f["verdict"], "BOLA_CONFIRMED")
        self.assertEqual(f["verdict"], "INCONCLUSIVE")

    def test_7_error_codes_inconclusive(self):
        for path, want in (("/status/500", "INCONCLUSIVE"), ("/status/429", "INCONCLUSIVE")):
            f = self.eng.run_case({"id": "t7", "desc": "t", "identity": "user_a",
                                   "method": "GET", "resource": path, "params": {},
                                   "expect": "deny", "cross": True})
            self.assertEqual(f["verdict"], want, path)
        f404 = self.eng.run_case({"id": "t7b", "desc": "t", "identity": "user_a",
                                  "method": "GET", "resource": "/rest/v1/nope",
                                  "params": {}, "expect": "deny", "cross": True})
        self.assertEqual(f404["verdict"], "OK_DENIED")
        self.assertEqual(f404["confidence"], "BAIXA")

    def test_8_no_secrets_in_output(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            for f in self.eng.run_all(self.policy["cases"]):
                print(AuthzEngine.format(f))
                print(json.dumps(f["evidence"]))
        txt = buf.getvalue()
        for secret in ENV_LAB.values():
            self.assertNotIn(secret, txt)
        self.assertNotIn("lab-key", txt)

    def test_9_missing_creds_inconclusive(self):
        idents, missing = load_identities({})
        self.assertTrue(missing)
        eng = AuthzEngine(BASE, idents, self.policy, lab_mode=True)
        f = eng.run_case(next(c for c in self.policy["cases"] if c["id"] == "read-own"))
        self.assertEqual(f["verdict"], "INCONCLUSIVE")

    def test_10_no_destructive_by_default(self):
        w0 = lab_writes()
        for f in self.eng.run_all(self.policy["cases"]):
            self.assertNotIn(f["verdict"], ("WRITE_OK_CLEANED", "WRITE_ORPHAN"))
        self.assertEqual(lab_writes(), w0)
        # com autorização explícita: cria + limpa, sem órfã
        eng = AuthzEngine(BASE, load_identities(ENV_LAB)[0], self.policy,
                          lab_mode=True, allow_write={"probe"})
        f = eng.run_case({"id": "w", "desc": "probe", "identity": "user_a",
                          "method": "POST", "resource": "/rest/v1/probe",
                          "params": {}, "expect": "deny", "write": True, "cross": False})
        self.assertEqual(f["verdict"], "WRITE_OK_CLEANED")
        posts = [w for w in WRITES if w[0] == "POST"]
        dels = [w for w in WRITES if w[0] == "DELETE"]
        self.assertEqual(sorted(p[1] for p in posts), sorted(d[1] for d in dels))

    def test_11_legit_difference_not_finding(self):
        own = self.verdict("read-own")
        pub = self.verdict("public-anon")
        self.assertEqual(own["verdict"], "OK_ALLOWED")
        self.assertEqual(pub["verdict"], "OK_ALLOWED")  # diferente mas legítimo

    def test_12_scope_guard(self):
        idents, _ = load_identities(ENV_LAB)
        with self.assertRaises(AuthzAbort):
            AuthzEngine("http://10.0.0.9", idents, self.policy)  # interno sem --lab
        with self.assertRaises(AuthzAbort):
            AuthzEngine("http://example.com", idents, self.policy, lab_mode=True)  # lab só local


if __name__ == "__main__":
    unittest.main(verbosity=2)
