"""Lab local AIScan — mock de API REST estilo Supabase/PostgREST, dados 100% sintéticos.

Uso: python lab/server.py [porta]  (padrão 18080, só 127.0.0.1)
NUNCA exponha essa porta. Chaves abaixo são falsas, só valem no lab.
"""
import json
import sys
import uuid
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs

A_ID = "11111111-1111-1111-1111-111111111111"
B_ID = "22222222-2222-2222-2222-222222222222"
PUB_ID = "00000000-0000-0000-0000-000000000000"

KEYS = {  # sintéticas, lab-only
    "lab-key-anon": "anon",
    "lab-key-user-a": "user_a",
    "lab-key-user-b": "user_b",
    "lab-key-admin": "admin_test",
}

ROWS = {
    A_ID: {"id": A_ID, "username": "alice", "email": "alice@example.test", "role": "user"},
    B_ID: {"id": B_ID, "username": "bob", "email": "bob@example.test", "role": "user"},
    PUB_ID: {"id": PUB_ID, "username": "public-catalog", "email": None, "role": "public"},
}
OWNER = {A_ID: "user_a", B_ID: "user_b", PUB_ID: "public"}
WRITES = []  # (metodo, id) — auditoria p/ teste de não-mutação
PROBE = {}  # id -> {"row":..., "nodelete":bool, "lingering":bool} — tabela de teste
LAST_APIKEY = {"value": None}  # última apikey vista (observabilidade de isolamento)
VULN = {"open": False}  # modo quebrado: B legível por A (p/ métricas TP/FN)


def _deny(body="RLS deny"):
    return 403, {"code": "42501", "message": body}


class Handler(BaseHTTPRequestHandler):
    server_version = "LabSupabase/0.1"

    def log_message(self, *a):
        pass

    def _key(self):
        q = parse_qs(urlparse(self.path).query)
        k = self.headers.get("apikey") or (q.get("apikey", [None])[0])
        LAST_APIKEY["value"] = k
        return KEYS.get(k)

    def _send(self, code, obj, extra=None):
        raw = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        u = urlparse(self.path)
        q = parse_qs(u.query)
        if u.path == "/__echo_last":  # antes do _key: ler não pode apagar o registro
            return self._send(200, {"apikey": LAST_APIKEY["value"]})
        ident = self._key()

        if u.path == "/__writes":  # introspecção do lab
            return self._send(200, {"writes": len(WRITES)})

        if u.path == "/__state":  # posts/deletes/vivos (auditoria de limpeza)
            posts = [w for m, w in WRITES if m == "POST"]
            dels = [w for m, w in WRITES if m == "DELETE"]
            return self._send(200, {"posts": posts, "deletes": dels,
                                    "live": sorted(PROBE.keys()),
                                    "orphans": sorted(set(posts) - set(dels)),
                                    "vuln": VULN["open"]})

        if u.path == "/__mode":  # ?open=1 liga lab quebrado (métricas TP/FN)
            q2 = parse_qs(u.query)
            VULN["open"] = q2.get("open", ["0"])[0] == "1"
            return self._send(200, {"vuln": VULN["open"]})

        if u.path == "/status/500":
            return self._send(500, {"error": "boom"})
        if u.path == "/status/429":
            return self._send(429, {"error": "slow down"}, {"Retry-After": "1"})

        if u.path == "/rest/v1/probe":  # leitura de verificação pós-DELETE
            nid = (q.get("id", [""])[0]).replace("eq.", "")
            return self._send(200, [PROBE[nid]["row"]] if nid in PROBE else [])

        if u.path == "/rest/v1/rpc/admin_stats":
            if ident == "admin_test":
                return self._send(200, {"users": 3})
            code, obj = _deny() if ident else (401, {"message": "No API key"})
            return self._send(code, obj)

        if u.path == "/rest/v1/profiles":
            sel = (q.get("select", ["*"])[0])
            pid = (q.get("id", [""])[0]).replace("eq.", "")
            if not ident:
                if pid in ("", PUB_ID):
                    return self._send(200, [] if not pid else [ROWS[PUB_ID]])
                return self._send(401, {"message": "No API key"})
            if pid == "":
                return self._send(200, [])
            if pid not in ROWS:
                return self._send(404, {"code": "PGRST205", "message": "not found"})
            if VULN["open"] and pid == B_ID and ident in ("user_a", "admin_test"):
                return self._send(200, [ROWS[pid]])  # lab QUEBRADO de propósito
            if OWNER[pid] in ("public", ident) or ident == "admin_test":
                row = dict(ROWS[pid])
                if "," in sel and "*" not in sel:
                    keep = [c.strip() for c in sel.split(",")]
                    row = {k: v for k, v in row.items() if k in keep}
                return self._send(200, [row])
            code, obj = _deny()
            return self._send(code, obj)

        return self._send(404, {"message": "no such endpoint"})

    def _mut(self):
        import time as _t
        u = urlparse(self.path)
        q = parse_qs(u.query)
        ident = self._key()
        mode = (q.get("mode", [""])[0])
        if u.path == "/rest/v1/probe" and self.command == "POST":
            if ident not in ("user_a", "user_b"):
                code, obj = _deny() if ident else (401, {"message": "No API key"})
                return self._send(code, obj)
            if mode == "fail":
                return self._send(500, {"error": "boom na criação"})
            if mode == "slow":
                _t.sleep(6)
                return self._send(500, {"error": "tarde demais"})
            if mode == "badid":
                WRITES.append(("POST", "?"))
                return self._send(201, {"noid": True})  # 201 sem id — fixture incompatível
            ln = int(self.headers.get("Content-Length", 0) or 0)
            self.rfile.read(min(ln, 65536))
            nid = str(uuid.uuid4())
            PROBE[nid] = {"row": {"id": nid, "probe": "aiscan"},
                          "nodelete": mode == "nodelete",
                          "lingering": mode == "lingering"}
            WRITES.append(("POST", nid))  # mutação real — registrada
            return self._send(201, {"id": nid})
        if u.path == "/rest/v1/probe" and self.command == "DELETE":
            nid = (q.get("id", [""])[0]).replace("eq.", "")
            if nid in PROBE and PROBE[nid]["nodelete"]:
                return self._send(403, {"code": "42501", "message": "RLS deny delete"})
            if nid in PROBE and not PROBE[nid]["lingering"]:
                del PROBE[nid]
            if nid in PROBE or any(w == nid for m, w in WRITES if m == "POST"):
                # lingering: 204 mas a linha fica — limpeza NÃO confirmável
                WRITES.append(("DELETE", nid))
                return self._send(204, {})
            return self._send(404, {"message": "not found"})
        if u.path == "/rest/v1/profiles" and self.command in ("POST", "PATCH", "DELETE"):
            # negado pelo lab — sem mutação, sem registro
            code, obj = _deny() if ident else (401, {"message": "No API key"})
            return self._send(code, obj)
        return self._send(404, {"message": "no such endpoint"})

    do_POST = _mut
    do_PATCH = _mut
    do_DELETE = _mut


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 18080
    HTTPServer(("127.0.0.1", port), Handler).serve_forever()
