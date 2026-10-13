"""Motor Lua do AIScan — permite módulos externos em /modules/*.lua."""
import os
import re
import json
import base64
import time
import requests
from lupa import LuaRuntime


class LuaEngine:
    def __init__(self, modules_dir="modules", timeout=8, lab_mode=False, store=None):
        self.modules_dir = modules_dir
        self.timeout = timeout
        self.lab_mode = lab_mode
        self.headers = {'User-Agent': 'AIScan-Lua-Engine/1.0'}
        self.store = store            # FindingsStore opcional (coleta estruturada)
        self._current_module = ""     # setado antes de cada run(ctx)
        self.lua = LuaRuntime(unpack_returned_tuples=True)
        self._injetar_api()

    def _lista_para_lua(self, py_lista):
        tbl = self.lua.table()
        for i, v in enumerate(py_lista or [], start=1):
            tbl[i] = v
        return tbl

    def _dict_para_lua(self, py_dict):
        tbl = self.lua.table()
        for k, v in (py_dict or {}).items():
            tbl[k] = v
        return tbl

    def _injetar_api(self):
        from core.scope import guarded, guarded_stream
        lab = self.lab_mode
        g = self.lua.globals()

        def http_get(url):
            r, info = guarded("GET", url, headers=self.headers,
                              timeout=self.timeout, lab_mode=lab)
            if r is None:
                return f"__ERRO__: {info.get('blocked') or info.get('error')}"
            return (r.text or "")[:20000]

        def http_status(url):
            r, _ = guarded("GET", url, headers=self.headers,
                           timeout=self.timeout, lab_mode=lab)
            return r.status_code if r is not None else -1

        def http_headers(url):
            r, _ = guarded("GET", url, headers=self.headers,
                           timeout=self.timeout, lab_mode=lab)
            if r is None:
                return self.lua.table()
            return self._dict_para_lua(dict(r.headers))

        def http_head(url):
            """Só status, sem corpo — enumeração barata."""
            r, _ = guarded("HEAD", url, headers=self.headers,
                           timeout=self.timeout, lab_mode=lab)
            return r.status_code if r is not None else -1

        def http_cors(url, origin="https://evil.example"):
            """Manda Origin e devolve ACAO/ACAC — teste de CORS sem adivinhar."""
            h = dict(self.headers)
            h['Origin'] = origin
            r, _ = guarded("GET", url, headers=h, timeout=self.timeout, lab_mode=lab)
            tbl = self.lua.table()
            if r is None:
                tbl['status'] = -1
                return tbl
            tbl['status'] = r.status_code
            tbl['allow_origin'] = r.headers.get('Access-Control-Allow-Origin', '')
            tbl['allow_credentials'] = r.headers.get('Access-Control-Allow-Credentials', '')
            return tbl

        def _mutacao(method, url, body=""):
            # Sem seguir redirect: POST/DELETE cross-host silencioso é exfiltração/mutação cega.
            tbl = self.lua.table()
            h = dict(self.headers)
            h['Content-Type'] = 'application/json'
            raw = (body or "").encode('utf-8', errors='replace')[:50000]
            import requests as _rq
            # corpo via stream validado; POST/DELETE passam pelo guarded manual:
            from core.scope import check_url as _ck
            ok, reason = _ck(url, lab)
            if not ok:
                tbl['status'] = -1
                tbl['body'] = "__ERRO__: " + reason
                return tbl
            try:
                r = _rq.request(method, url, data=raw, headers=h,
                                timeout=self.timeout, allow_redirects=False)
                tbl['status'] = r.status_code
                tbl['body'] = (r.text or "")[:20000]
                return tbl
            except Exception as e:
                tbl['status'] = -1
                tbl['body'] = "__ERRO__: %s" % e
                return tbl

        def http_post(url, body=""):
            return _mutacao("POST", url, body)

        def http_delete(url):
            return _mutacao("DELETE", url)

        def find_regex(texto, padrao):
            try:
                achados = re.findall(padrao, texto or "")
                return self._lista_para_lua(achados)
            except Exception:
                return self.lua.table()

        def lower(texto):
            """Lower Unicode-correto (string.lower do Lua corrompe UTF-8 com acentos)."""
            try:
                return (texto or "").lower()
            except Exception:
                return texto or ""

        def preview(texto, limite=180):
            """Corte seguro p/ exibir amostra (string.sub do Lua pode partir UTF-8 no meio)."""
            try:
                t = (texto or "").replace("\n", " ").replace("\r", "")
                if len(t) > limite:
                    t = t[:limite] + "...[cortado]"
                return t.encode('utf-8', 'replace').decode('utf-8', 'replace')
            except Exception:
                return ""

        def painel(json_texto, max_linhas=5):
            """Uma linha por row só com campo relevante (id/username/email/título/preço/flags).
            O dump completo continua no prova — painel é leitura de 5 segundos."""
            try:
                data = json.loads(json_texto or "")
                rows = data if isinstance(data, list) else [data]
                rows = [r for r in rows if isinstance(r, dict)][:max(1, int(max_linhas or 5))]
                if not rows:
                    return "0 linhas"
                prefs = ("username", "email", "title", "name", "is_banned", "banned_reason",
                         "price", "is_paid", "role", "status", "id")
                linhas = []
                for r in rows:
                    keep = [k for k in prefs if k in r]
                    for k in r.keys():
                        if k not in keep and len(keep) < 6:
                            keep.append(k)
                    partes = []
                    for k in keep[:6]:
                        v = str(r.get(k))
                        if len(v) > 40:
                            v = v[:40] + "..."
                        partes.append(f"{k}={v}")
                    linhas.append("  " + " | ".join(partes))
                return "\n".join(linhas)
            except Exception as e:
                return f"[painel ilegível: {e}]"

        def tabela(json_texto, max_linhas=3, mascarar=False):
            """Linhas como lista vertical chave = valor (tabela horizontal quebra
            com 15+ colunas). Retorna texto — o Lua embute no output.
            mascarar=True troca valores sensíveis por [redacted] (modo --redact)."""
            try:
                data = json.loads(json_texto or "")

                def _sens(k):
                    kl = str(k).lower()
                    return any(s in kl for s in ("email", "password", "passwd", "token",
                                                "secret", "cpf", "phone", "ssn", "card"))
                rows = data if isinstance(data, list) else [data]
                rows = [r for r in rows if isinstance(r, dict)][:max(1, int(max_linhas or 3))]
                if not rows:
                    return "0 linhas"
                ncols = 0
                linhas = []
                for i, r in enumerate(rows, 1):
                    ncols = max(ncols, len(r))
                    linhas.append(f"-- linha {i} --")
                    for k, v in r.items():
                        s = str(v)
                        if mascarar and _sens(k):
                            s = "[redacted]"
                        elif len(s) > 120:
                            s = s[:120] + "..."
                        linhas.append(f"  {k} = {s}")
                head = f"{len(rows)} linha(s) x {ncols} colunas"
                return head + "\n" + "\n".join(linhas)
            except Exception as e:
                return f"[tabela ilegível: {e}]"

        def http_get_full(url, max_bytes=500000):
            """Bundle inteiro (http_get corta em 20KB — vendor de 1MB+ esconde a config)."""
            try:
                cap = max(1024, min(int(max_bytes or 500000), 2000000))
            except Exception:
                cap = 500000
            txt, info = guarded_stream(url, headers=self.headers,
                                       timeout=self.timeout, cap=cap, lab_mode=lab)
            if txt is None:
                return f"__ERRO__: {info.get('blocked') or info.get('error')}"
            return txt

        def decode_jwt_payload(token):
            """Devolve {ok, role, ref} — separa anon (front ok) de service_role (P0)."""
            tbl = self.lua.table()
            try:
                partes = (token or "").split(".")
                if len(partes) != 3:
                    tbl['ok'] = False
                    return tbl
                pay = partes[1] + "=" * (-len(partes[1]) % 4)
                data = json.loads(base64.urlsafe_b64decode(pay).decode('utf-8', errors='replace'))
                tbl['ok'] = True
                tbl['role'] = str(data.get('role', ''))
                tbl['ref'] = str(data.get('ref', data.get('iss', '')))
                return tbl
            except Exception:
                tbl['ok'] = False
                return tbl

        def openapi_tables(spec_text):
            """Nomes de tabelas do OpenAPI spec do PostgREST — sem adivinhar. Lua não tem JSON."""
            try:
                spec = json.loads(spec_text or "")
                tabs = []
                for path in (spec.get('paths') or {}).keys():
                    seg = (path or "").strip("/").split("/")[0]
                    if seg and seg not in tabs and re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', seg):
                        tabs.append(seg)
                return self._lista_para_lua(tabs)
            except Exception:
                return self.lua.table()

        def json_keys(json_text):
            """Chaves do 1º objeto de um array JSON — colunas sem vazar valores."""
            try:
                data = json.loads(json_text or "")
                if isinstance(data, list) and data and isinstance(data[0], dict):
                    return self._lista_para_lua(list(data[0].keys()))
                return self.lua.table()
            except Exception:
                return self.lua.table()

        def rest_count(base, key, tabela):
            """Total real de linhas via Prefer: count=exact. {status, total} (-1 = negado/erro)."""
            tbl = self.lua.table()
            h = dict(self.headers)
            h['apikey'] = key
            h['Authorization'] = 'Bearer ' + key
            h['Prefer'] = 'count=exact'
            r, _ = guarded("GET", base + '/rest/v1/' + tabela + '?select=*&limit=1',
                           headers=h, timeout=self.timeout, lab_mode=lab)
            tbl['status'] = -1
            tbl['total'] = -1
            if r is None:
                return tbl
            try:
                tbl['status'] = r.status_code
                cr = r.headers.get('Content-Range', '')
                if '/' in cr:
                    tail = cr.rsplit('/', 1)[1]
                    if tail.isdigit():
                        tbl['total'] = int(tail)
                return tbl
            except Exception:
                return tbl

        def throttle(ms=200):
            """Pausa anti-rate-limit entre requests."""
            try:
                time.sleep(max(0, min(int(ms or 0), 5000)) / 1000.0)
            except Exception:
                pass
            return True

        def add_finding(tbl):
            """Módulo reporta achado estruturado. tbl = tabela Lua com chaves:
            title, severity, confidence, category, cwe, description, remediation,
            evidence (string ou tabela). Sem store, é no-op silencioso."""
            if self.store is None or tbl is None:
                return False
            from core.findings import Finding

            def _get(k, d=""):
                try:
                    v = tbl[k]
                    return d if v is None else v
                except Exception:
                    return d

            ev = _get("evidence", "")
            # tabela Lua -> dict Python (lupa expõe .items() nas tabelas)
            try:
                if hasattr(ev, "items"):
                    ev = {str(k): v for k, v in ev.items()}
            except Exception:
                ev = str(ev)
            self.store.add(Finding(
                title=str(_get("title", "(sem título)")),
                severity=str(_get("severity", "INFO")),
                confidence=str(_get("confidence", "MEDIA")),
                module=self._current_module or "lua",
                category=str(_get("category", "")),
                cwe=str(_get("cwe", "")),
                description=str(_get("description", "")),
                remediation=str(_get("remediation", "")),
                evidence=ev,
            ))
            return True

        g['add_finding'] = add_finding
        g['http_get'] = http_get
        g['http_status'] = http_status
        g['http_head'] = http_head
        g['http_cors'] = http_cors
        g['http_post'] = http_post
        g['http_delete'] = http_delete
        g['http_headers'] = http_headers
        g['find_regex'] = find_regex
        g['lower'] = lower
        g['preview'] = preview
        g['tabela'] = tabela
        g['painel'] = painel
        g['http_get_full'] = http_get_full
        g['decode_jwt_payload'] = decode_jwt_payload
        g['openapi_tables'] = openapi_tables
        g['json_keys'] = json_keys
        g['rest_count'] = rest_count
        g['throttle'] = throttle
        g['AISGAN_VERSION'] = '1.0.0-PRO'

    def listar_modulos(self):
        if not os.path.isdir(self.modules_dir):
            return []
        return sorted(f for f in os.listdir(self.modules_dir) if f.endswith('.lua'))

    @staticmethod
    def _sanitizar(valor):
        """Deixa strings seguras pro roundtrip Python->Lua->Python (acentos pt-BR quebravam o decode)."""
        if isinstance(valor, str):
            return valor.encode('utf-8', 'replace').decode('utf-8', 'replace')
        if isinstance(valor, list):
            return [LuaEngine._sanitizar(v) for v in valor]
        if isinstance(valor, dict):
            return {k: LuaEngine._sanitizar(v) for k, v in valor.items()}
        return valor

    def executar_modulo(self, nome_arquivo, contexto):
        """Executa modules/<nome> com tabela ctx. O .lua deve definir run(ctx) retornando string."""
        caminho = os.path.join(self.modules_dir, nome_arquivo)
        if not os.path.isfile(caminho):
            return f"[-] Módulo não encontrado: {caminho}"
        with open(caminho, 'r', encoding='utf-8') as f:
            codigo = f.read()
        self._current_module = nome_arquivo
        antes = len(self.store) if self.store is not None else 0
        try:
            self.lua.execute(codigo)
            run_fn = self.lua.globals()['run']
            if run_fn is None:
                return "[-] Módulo sem função run(ctx)."
            resultado = str(run_fn(self._sanitizar(contexto)))
        except Exception as e:
            return f"[-] Erro no módulo Lua {nome_arquivo}: {e}"
        # Fallback: módulo que não chamou add_finding ainda tem suas linhas
        # [FIRE] convertidas em achados, para nada se perder no relatório.
        if self.store is not None and len(self.store) == antes:
            self._coletar_das_linhas(nome_arquivo, contexto, resultado)
        return resultado

    def _coletar_das_linhas(self, nome_arquivo, contexto, saida):
        """Parser de ponte: linhas '[FIRE] ...' viram Finding genérico."""
        from core.findings import Finding
        cat = nome_arquivo[:-4] if nome_arquivo.endswith(".lua") else nome_arquivo
        alvo = ""
        try:
            alvo = str(contexto.get("target", "")) if hasattr(contexto, "get") else ""
        except Exception:
            pass
        for linha in (saida or "").split("\n"):
            ls = linha.strip()
            if not ls.startswith("[FIRE]"):
                continue
            texto = ls[len("[FIRE]"):].strip()
            low = texto.lower()
            if any(w in low for w in ("critic", "p0", "service_role", "crítico")):
                sev = "CRITICA"
            else:
                sev = "ALTA"
            self.store.add(Finding(
                title=texto[:160], severity=sev, confidence="MEDIA",
                module=nome_arquivo, target=alvo, category=cat,
                evidence={"line": texto[:400]}))
