"""Motor de matriz de autorização — testes diferenciais BOLA/IDOR.

Leitura por padrão. Escrita SÓ com lab_mode + allow_write explícito.
Credenciais nunca aparecem em output (ver teste 8).
"""
import ipaddress
import json
import os
import socket
import time
from urllib.parse import urlparse

import requests

SENSITIVE = ("email", "password", "passwd", "token", "secret", "cpf", "phone",
             "ssn", "card", "key", "cookie", "authorization", "set-cookie")
MAX_BODY = 200000


class AuthzAbort(Exception):
    """Identidade ou escopo inválido — execução interrompida."""


def load_identities(env=None):
    """Lê credenciais do ambiente. Retorna (identidades, ausentes)."""
    env = env if env is not None else os.environ
    idents, missing = {}, []
    for name, var in (("anonymous", None), ("user_a", "AISCAN_KEY_A"),
                      ("user_b", "AISCAN_KEY_B"), ("admin_test", "AISCAN_KEY_ADMIN")):
        key = None if var is None else env.get(var)
        idents[name] = {"name": name, "key": key}
        if var and not key and name in ("user_a", "user_b"):
            missing.append(var)
    anon = env.get("AISCAN_KEY_ANON")
    if anon:
        idents["anonymous"] = {"name": "anonymous", "key": anon}
    return idents, missing


def _sens(key):
    k = str(key or "").lower()
    return any(s in k for s in SENSITIVE)


def redact(obj, depth=0):
    """Evidência mínima: chaves sim, valores sensíveis nunca."""
    if depth > 3:
        return "..."
    if isinstance(obj, dict):
        return {str(k)[:40]: ("[redacted]" if _sens(k) else redact(v, depth + 1))
                for k, v in list(obj.items())[:30]}
    if isinstance(obj, (list, tuple)):
        return {"rows": len(obj), "sample": redact(obj[0], depth + 1) if obj else None}
    s = str(obj)
    return s[:40] + ("..." if len(s) > 40 else "")


class AuthzEngine:
    def __init__(self, base_url, identities, policy, lab_mode=False,
                 allow_write=None, timeout=10):
        self.base = base_url.rstrip("/")
        self.identities = identities
        self.policy = policy or {}
        self.lab_mode = lab_mode
        self.allow_write = set(allow_write or [])
        self.timeout = timeout
        self.private_fields = [str(x).lower() for x in self.policy.get("private_fields", [])]
        self._check_scope()

    def _check_scope(self):
        host = urlparse(self.base).hostname or ""
        try:
            ip = ipaddress.ip_address(socket.gethostbyname(host))
        except Exception:
            raise AuthzAbort(f"escopo inválido: não resolve {host}")
        if self.lab_mode:
            if not ip.is_loopback:
                raise AuthzAbort("modo lab só permite 127.0.0.1/localhost")
        elif ip.is_private or ip.is_loopback or ip.is_link_local:
            raise AuthzAbort(f"alvo interno {ip} bloqueado sem --lab")

    def _headers(self, ident):
        h = {"User-Agent": "AIScan-Authz/1.0"}
        if ident.get("key"):
            h["apikey"] = ident["key"]
            h["Authorization"] = "Bearer " + ident["key"]
        return h

    def request(self, ident_name, method, resource, params=None, body=None):
        ident = self.identities.get(ident_name) or {"name": ident_name, "key": None}
        if ident_name != "anonymous" and not ident.get("key"):
            return {"status": None, "error": "missing-creds", "body": None}
        from core.scope import guarded, MAX_BODY
        r, info = guarded(method, self.base + resource, headers=self._headers(ident),
                          params=params or {}, body=body, timeout=self.timeout,
                          lab_mode=self.lab_mode)
        if r is None:
            if info.get("blocked"):
                return {"status": None, "error": "scope-blocked: " + info["blocked"], "body": None}
            return {"status": None, "error": str(info.get("error", "?"))[:120], "body": None}
        try:
            raw = r.text or ""
            try:
                data = r.json() if raw else None
            except Exception:
                data = None
            return {"status": r.status_code, "json": data,
                    "body_len": len(raw), "raw_head": raw[:MAX_BODY]}
        except Exception as e:
            return {"status": None, "error": str(e)[:120], "body": None}

    @staticmethod
    def _rows(parsed):
        if isinstance(parsed, list):
            return parsed
        if isinstance(parsed, dict):
            return [parsed]
        return []

    def _private_hit(self, rows, owner_ok):
        """Dado privado de OUTRO principal presente?"""
        if owner_ok or not rows:
            return []
        hit = []
        for row in rows:
            if not isinstance(row, dict):
                continue
            for k, v in row.items():
                kl = str(k).lower()
                if kl in self.private_fields and v not in (None, "", [], {}):
                    hit.append(kl)
        return sorted(set(hit))

    def run_case(self, case):
        ident = case["identity"]
        expect = case.get("expect", "deny")
        method = case.get("method", "GET")
        ev_base = {"case": case["id"], "desc": case.get("desc", ""), "identity": ident,
                   "op": f"{method} {case['resource']}", "expected": expect,
                   "fix": "restringir policy/RLS ao dono + negar por padrão"}

        if method in ("POST", "PATCH", "DELETE", "PUT") or case.get("write"):
            return self._run_write(case, ev_base)

        obs = self.request(ident, method, case["resource"], case.get("params"))
        if obs.get("error") == "missing-creds":
            return {**ev_base, "observed": "não executado (sem credencial)",
                    "verdict": "INCONCLUSIVE", "severity": "-", "confidence": "ALTA",
                    "evidence": {}, "limitation": "sem AISCAN_KEY_A/B não há diferencial"}
        if obs.get("error") or obs.get("status") in (500, 429):
            return {**ev_base, "observed": f"transiente ({obs.get('error') or obs['status']})",
                    "verdict": "INCONCLUSIVE", "severity": "-", "confidence": "MÉDIA",
                    "evidence": {"status": obs.get("status")},
                    "limitation": "erro transitório não prova nem nega acesso"}
        st = obs.get("status")
        rows = self._rows(obs.get("json"))
        cross = bool(case.get("cross", False))

        if expect == "allow":
            if st in (200, 201, 206) and (rows or case["id"] == "empty-200"):
                return {**ev_base, "observed": f"HTTP {st}, {len(rows)} linha(s)",
                        "verdict": "OK_ALLOWED", "severity": "-", "confidence": "ALTA",
                        "evidence": redact(rows), "limitation": "permitido esperado e observado"}
            return {**ev_base, "observed": f"HTTP {st} (esperava acesso)",
                    "verdict": "INCONCLUSIVE", "severity": "-", "confidence": "MÉDIA",
                    "evidence": {"status": st}, "limitation": "negação inesperada — revisar policy/fixture"}

        # expect == deny
        if st in (401, 403):
            return {**ev_base, "observed": f"HTTP {st} (negado)",
                    "verdict": "OK_DENIED", "severity": "-", "confidence": "MÉDIA",
                    "evidence": {"status": st},
                    "limitation": "status nega, mas não distingue policy de gateway"}
        if st == 404:
            return {**ev_base, "observed": "HTTP 404",
                    "verdict": "OK_DENIED", "severity": "-", "confidence": "BAIXA",
                    "evidence": {"status": 404}, "limitation": "404 pode ser rota inexistente, não policy"}
        if st in (200, 201, 206) and not rows:
            return {**ev_base, "observed": f"HTTP {st} vazio",
                    "verdict": "INCONCLUSIVE", "severity": "-", "confidence": "ALTA",
                    "evidence": {"status": st, "rows": 0},
                    "limitation": "200 vazio não prova BOLA sozinho"}
        if st in (200, 201, 206) and rows:
            hit = self._private_hit(rows, owner_ok=not cross)
            if hit and cross:
                return {**ev_base, "observed": f"HTTP {st} com dado privado de outro ({', '.join(hit)})",
                        "verdict": "BOLA_CONFIRMED", "severity": "CRITICA", "confidence": "ALTA",
                        "evidence": {"status": st, "rows": len(rows), "private_fields": hit,
                                     "sample": redact(rows[:1])},
                        "limitation": "confirmado contra policy explícita; revisar se o campo é intencionalmente público"}
            return {**ev_base, "observed": f"HTTP {st} só com dado público",
                    "verdict": "OK_PUBLIC", "severity": "-", "confidence": "MÉDIA",
                    "evidence": redact(rows), "limitation": "diferença legítima entre papéis não é achado"}
        return {**ev_base, "observed": f"HTTP {st}", "verdict": "INCONCLUSIVE",
                "severity": "-", "confidence": "BAIXA", "evidence": {"status": st},
                "limitation": "resposta fora do mapeado"}

    def _run_write(self, case, ev_base):
        resource = case["resource"]
        table = resource.split("?")[0].rstrip("/").split("/")[-1]
        if not (self.lab_mode and table in self.allow_write):
            return {**ev_base, "observed": f"tabela '{table}' não autorizada (exige --lab + --allow-write {table})",
                    "verdict": "WRITE_BLOCKED", "severity": "-", "confidence": "ALTA",
                    "evidence": {}, "limitation": "mutação nunca roda sem autorização explícita"}
        ident = case["identity"]
        if ident != "anonymous" and not (self.identities.get(ident) or {}).get("key"):
            return {**ev_base, "observed": "não executado (sem credencial)",
                    "verdict": "INCONCLUSIVE", "severity": "-", "confidence": "ALTA",
                    "evidence": {}, "limitation": "sem credencial não há diferencial"}
        szereg = self.request(ident, "POST", resource, case.get("params"), {"probe": "aiscan"})
        pst = szereg.get("status")
        if pst is None:
            return {**ev_base, "observed": f"POST falhou ({szereg.get('error')}) — pode ter criado",
                    "verdict": "INCONCLUSIVE", "severity": "-", "confidence": "ALTA",
                    "evidence": {"error": str(szereg.get("error"))[:80]},
                    "limitation": "timeout/erro após POST: estado desconhecido, nunca afirmar limpeza"}
        if pst in (401, 403, 404):
            return {**ev_base, "observed": f"POST -> {pst}",
                    "verdict": "OK_DENIED", "severity": "-", "confidence": "MÉDIA",
                    "evidence": {"status": pst},
                    "limitation": "escrita negada — sem mutação"}
        if pst >= 500:
            return {**ev_base, "observed": f"POST -> {pst} (pode ter criado antes de falhar)",
                    "verdict": "INCONCLUSIVE", "severity": "-", "confidence": "ALTA",
                    "evidence": {"status": pst},
                    "limitation": "5xx não garante rollback — estado desconhecido"}
        if pst not in (200, 201):
            return {**ev_base, "observed": f"POST -> {pst} (schema rejeitou)",
                    "verdict": "OK_DENIED", "severity": "-", "confidence": "MÉDIA",
                    "evidence": {"status": pst},
                    "limitation": "400/409/422 = barreira de schema, não RLS"}
        nid = None
        try:
            nid = (szereg.get("json") or {}).get("id")
        except Exception:
            pass
        if not nid:
            return {**ev_base, "observed": "POST 201 sem id retornado",
                    "verdict": "WRITE_ORPHAN", "severity": "ALTA", "confidence": "MÉDIA",
                    "evidence": {"status": szereg.get("status")},
                    "limitation": "⚠ linha pode ter ficado órfã — limpar manualmente"}
        d = self.request(ident, "DELETE", resource, {"id": f"eq.{nid}"})
        if d.get("status") not in (200, 204):
            return {**ev_base, "observed": f"POST 201 mas DELETE {d.get('status')}",
                    "verdict": "WRITE_ORPHAN", "severity": "CRITICA", "confidence": "ALTA",
                    "evidence": {"probe_id": str(nid)[:8] + "..."},
                    "limitation": "⚠ LINHA ÓRFÃ — DELETE falhou, limpar manualmente no banco"}
        # DELETE 2xx não basta: confirma que a linha sumiu (lingering mente no status)
        v = self.request(ident, "GET", resource, {"select": "*", "id": f"eq.{nid}"})
        if v.get("status") in (200, 206) and self._rows(v.get("json")):
            return {**ev_base, "observed": "DELETE 2xx mas a linha continua legível",
                    "verdict": "WRITE_ORPHAN", "severity": "CRITICA", "confidence": "ALTA",
                    "evidence": {"probe_id": str(nid)[:8] + "..."},
                    "limitation": "⚠ LIMPEZA NÃO CONFIRMADA — linha órfã, limpar manualmente"}
        if v.get("status") is None:
            return {**ev_base, "observed": "DELETE 2xx mas verificação falhou (rede)",
                    "verdict": "INCONCLUSIVE", "severity": "-", "confidence": "ALTA",
                    "evidence": {"probe_id": str(nid)[:8] + "..."},
                    "limitation": "limpeza não confirmada nunca é sucesso"}
        return {**ev_base, "observed": f"POST 201 + DELETE {d.get('status')} + GET vazio (limpo)",
                "verdict": "WRITE_OK_CLEANED", "severity": "CRITICA", "confidence": "ALTA",
                "evidence": {"probe_id": str(nid)[:8] + "..."},
                "limitation": "escrita anônima/terceiro possível — RLS de INSERT ausente"}

    def run_all(self, cases):
        out = []
        for c in cases:
            f = self.run_case(c)
            out.append(f)
            time.sleep(0.2)  # anti-rate-limit
        return out

    @staticmethod
    def format(f):
        tag = {"BOLA_CONFIRMED": "[FIRE]", "WRITE_ORPHAN": "[FIRE]",
               "WRITE_OK_CLEANED": "[FIRE]"}.get(f["verdict"], "[OK]" if f["verdict"].startswith("OK") else "[?]")
        base = (f"{tag} {f['case']} ({f['identity']}) {f['op']} :: {f['verdict']} "
                f"[esperado: {f['expected']}] conf={f['confidence']}")
        if f["verdict"] in ("BOLA_CONFIRMED", "WRITE_ORPHAN", "WRITE_OK_CLEANED"):
            base += f" sev={f['severity']}"
        return base + f"\n    obs: {f['observed']}\n    limite: {f['limitation']}"
