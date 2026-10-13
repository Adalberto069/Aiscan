"""Hardening v1.1.1 — escopo de rede, isolamento de identidade, limpeza.

Só mocks + lab local. Nenhuma request sai de 127.0.0.1.
Roda: python tests/test_scope_hardening.py
"""
import io
import json
import sys
import threading
import unittest
from contextlib import redirect_stdout
from http.client import HTTPConnection
from unittest import mock

sys.path.insert(0, ".")
sys.path.insert(0, "core")
from http.server import HTTPServer
from lab.server import Handler
import core.scope as scope
from core.scope import check_url, guarded
from authz import AuthzEngine, load_identities

PORT = 18081
BASE = f"http://127.0.0.1:{PORT}"
ENV_LAB = {"AISCAN_KEY_ANON": "lab-key-anon", "AISCAN_KEY_A": "lab-key-user-a",
           "AISCAN_KEY_B": "lab-key-user-b", "AISCAN_KEY_ADMIN": "lab-key-admin"}


def state(port=PORT):
    c = HTTPConnection("127.0.0.1", port, timeout=5)
    c.request("GET", "/__state")
    return json.loads(c.getresponse().read())


def echo(port=PORT):
    c = HTTPConnection("127.0.0.1", port, timeout=5)
    c.request("GET", "/__echo_last")
    return json.loads(c.getresponse().read())["apikey"]


def fake_ip(*ips):
    def _resolve(host, *a, **k):
        return [(2, 1, 6, "", (str(ip), 0)) for ip in ips]
    return _resolve


class ScopeUnits(unittest.TestCase):
    def test_scheme_userinfo(self):
        self.assertFalse(check_url("file:///etc/passwd")[0])
        self.assertFalse(check_url("ftp://h/x")[0])
        self.assertFalse(check_url("gopher://h/")[0])
        self.assertFalse(check_url("http://user:pass@example.com/")[0])
        self.assertFalse(check_url("https://a:b@127.0.0.1:18081/", lab_mode=True)[0])
        self.assertFalse(check_url("http:///nonsense")[0])

    def test_privates_blocked(self):
        with mock.patch.object(scope.socket, "getaddrinfo", fake_ip("10.1.2.3")):
            self.assertFalse(check_url("http://internal.corp/")[0])
            self.assertFalse(check_url("http://internal.corp/", lab_mode=True)[0])
        with mock.patch.object(scope.socket, "getaddrinfo", fake_ip("::ffff:10.0.0.1")):
            self.assertFalse(check_url("http://[::ffff:10.0.0.1]/")[0])  # v4-mapped
        with mock.patch.object(scope.socket, "getaddrinfo", fake_ip("169.254.9.9")):
            self.assertFalse(check_url("http://x/", lab_mode=True)[0])  # link-local nem no lab
        with mock.patch.object(scope.socket, "getaddrinfo", side_effect=OSError("dns")):
            self.assertFalse(check_url("http://nx.invalid/")[0])  # fail-closed

    def test_loopback_lab_only(self):
        with mock.patch.object(scope.socket, "getaddrinfo", fake_ip("127.0.0.1")):
            self.assertFalse(check_url("http://127.0.0.1:18081/")[0])
            self.assertTrue(check_url("http://127.0.0.1:18081/", lab_mode=True)[0])
        with mock.patch.object(scope.socket, "getaddrinfo", fake_ip("::1")):
            self.assertFalse(check_url("http://[::1]/")[0])
            self.assertTrue(check_url("http://[::1]/", lab_mode=True)[0])

    def test_public_ok(self):
        with mock.patch.object(scope.socket, "getaddrinfo", fake_ip("93.184.215.14")):
            self.assertTrue(check_url("https://example.com:8443/x")[0])  # porta ok, IP público

    def test_redirect_strips_auth_cross_host(self):
        calls = []

        class R:
            def __init__(self, code, loc=None):
                self.status_code, self.headers, self.text = code, {}, ""
                if loc:
                    self.headers = {"Location": loc}

        def fake_req(method, url, headers=None, **k):
            calls.append((url, dict(headers or {})))
            if len(calls) == 1:
                return R(302, "http://other.test/final")
            return R(200)

        with mock.patch.object(scope.requests, "request", side_effect=fake_req):
            with mock.patch.object(scope.socket, "getaddrinfo", fake_ip("93.184.215.14", "93.184.215.15")):
                r, info = guarded("GET", "http://a.test/start",
                                  headers={"Authorization": "Bearer SECRET", "apikey": "SECRET"})
        self.assertIsNotNone(r)
        self.assertNotIn("Authorization", calls[1][1])
        self.assertNotIn("apikey", calls[1][1])
        self.assertIn("Authorization", calls[0][1])

    def test_redirect_to_internal_blocked(self):
        calls = []

        class R:
            status_code, headers, text = 302, {"Location": "http://10.9.9.9/"}, ""

        def fake_req(method, url, headers=None, **k):
            calls.append(url)
            return R()

        def route(host, *a, **k):
            return fake_ip("93.184.215.14" if "start" in host else "10.9.9.9")(host)

        with mock.patch.object(scope.requests, "request", side_effect=fake_req):
            with mock.patch.object(scope.socket, "getaddrinfo", side_effect=route):
                r, info = guarded("GET", "http://start.test/")
        self.assertIsNone(r)
        self.assertIn("bloqueado", info.get("blocked", ""))
        self.assertEqual(len(calls), 1)  # segunda request nunca saiu

    def test_redirect_loop_capped(self):
        class R:
            status_code, headers, text = 302, {"Location": "/x"}, ""

        with mock.patch.object(scope.requests, "request", return_value=R()):
            with mock.patch.object(scope.socket, "getaddrinfo", fake_ip("93.184.215.14")):
                r, info = guarded("GET", "http://a.test/")
        self.assertIsNone(r)
        self.assertIn("redirects", info.get("blocked", ""))


class IsolationLab(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = HTTPServer(("127.0.0.1", PORT), Handler)
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        idents, _ = load_identities(ENV_LAB)
        cls.eng = AuthzEngine(BASE, idents, {"private_fields": ["email"]}, lab_mode=True)

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()

    def test_token_isolation(self):
        self.eng.request("user_b", "GET", "/rest/v1/profiles",
                         {"select": "*", "id": "eq.22222222-2222-2222-2222-222222222222"})
        got = echo()
        self.assertEqual(got, "lab-key-user-b")
        self.assertNotEqual(got, "lab-key-user-a")

    def test_no_session_reuse(self):
        import requests as _rq
        self.assertFalse(any(isinstance(v, _rq.Session) for v in vars(self.eng).values()))
        self.eng.request("user_a", "GET", "/nope", {})  # falha não guarda nada
        self.eng.request("user_b", "GET", "/rest/v1/profiles", {"select": "*", "limit": "1"})
        self.assertEqual(echo(), "lab-key-user-b")

    def test_exception_has_no_token(self):
        closed = AuthzEngine("http://127.0.0.1:9", load_identities(ENV_LAB)[0], {},
                             lab_mode=True, timeout=5)
        r = closed.request("user_a", "GET", "/fechada", {})
        self.assertIsNone(r.get("status"))
        self.assertNotIn("lab-key-user-a", r.get("error", ""))
        # sem credencial: nem tenta
        idents, _ = load_identities({})
        eng2 = AuthzEngine(BASE, idents, {}, lab_mode=True)
        self.assertEqual(eng2.request("user_a", "GET", "/x", {})["error"], "missing-creds")

    def test_no_request_leaves_scope(self):
        seen = []
        real = scope.requests.request

        def spy(method, url, **k):
            from urllib.parse import urlparse
            seen.append(urlparse(url).hostname)
            return real(method, url, **k)

        with mock.patch.object(scope.requests, "request", side_effect=spy):
            self.eng.request("user_a", "GET", "/rest/v1/profiles", {"select": "*", "limit": "1"})
            self.eng.request("anonymous", "GET", "/rest/v1/profiles", {"select": "*", "limit": "1"})
        self.assertTrue(seen)
        self.assertTrue(all(h == "127.0.0.1" for h in seen))

    def test_write_missing_creds_inconclusive(self):
        idents, _ = load_identities({})
        eng = AuthzEngine(BASE, idents, {}, lab_mode=True, allow_write={"probe"})
        f = eng.run_case({"id": "w", "desc": "t", "identity": "user_a", "method": "POST",
                          "resource": "/rest/v1/probe", "params": {}, "expect": "deny",
                          "write": True, "cross": False})
        self.assertEqual(f["verdict"], "INCONCLUSIVE")


class CleanupLab(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = HTTPServer(("127.0.0.1", PORT + 1), Handler)
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        cls.base = f"http://127.0.0.1:{PORT + 1}"
        idents, _ = load_identities(ENV_LAB)
        cls.idents = idents

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()

    def eng(self, **kw):
        return AuthzEngine(self.base, self.idents, {"private_fields": ["email"]},
                           lab_mode=True, allow_write={"probe"}, **kw)

    def wcase(self, mode):
        res = "/rest/v1/probe" + (f"?mode={mode}" if mode else "")
        return {"id": "w", "desc": "t", "identity": "user_a", "method": "POST",
                "resource": res, "params": {}, "expect": "deny", "write": True, "cross": False}

    def test_create_fail_inconclusive(self):
        f = self.eng().run_case(self.wcase("fail"))
        self.assertEqual(f["verdict"], "INCONCLUSIVE")  # 500: pode ter criado

    def test_timeout_after_create_inconclusive(self):
        f = self.eng(timeout=1).run_case(self.wcase("slow"))
        self.assertEqual(f["verdict"], "INCONCLUSIVE")

    def test_badid_orphan(self):
        f = self.eng().run_case(self.wcase("badid"))
        self.assertEqual(f["verdict"], "WRITE_ORPHAN")

    def test_nodelete_orphan(self):
        f = self.eng().run_case(self.wcase("nodelete"))
        self.assertEqual(f["verdict"], "WRITE_ORPHAN")
        st = state(PORT + 1)
        # órfã registrada no lab
        self.assertTrue(len(st["posts"]) > len(st["deletes"]))

    def test_lingering_never_success(self):
        f = self.eng().run_case(self.wcase("lingering"))
        self.assertNotEqual(f["verdict"], "WRITE_OK_CLEANED")
        self.assertEqual(f["verdict"], "WRITE_ORPHAN")

    def test_happy_path_cleaned(self):
        st0 = state(PORT + 1)
        f = self.eng().run_case(self.wcase(""))
        self.assertEqual(f["verdict"], "WRITE_OK_CLEANED")
        st1 = state(PORT + 1)
        self.assertEqual(len(st1["posts"]) - len(st0["posts"]),
                         len(st1["deletes"]) - len(st0["deletes"]))


if __name__ == "__main__":
    unittest.main(verbosity=2)
