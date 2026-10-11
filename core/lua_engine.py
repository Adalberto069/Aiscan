"""Motor Lua do AIScan — permite módulos externos em /modules/*.lua."""
import os
import re
import json
import base64
import time
import requests
from lupa import LuaRuntime


class LuaEngine:
    def __init__(self, modules_dir="modules", timeout=8):
        self.modules_dir = modules_dir
        self.timeout = timeout
        self.headers = {'User-Agent': 'AIScan-Lua-Engine/1.0'}
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
        g = self.lua.globals()

        def http_get(url):
            try:
                r = requests.get(url, headers=self.headers, timeout=self.timeout)
                return r.text[:20000]
            except Exception as e:
                return f"__ERRO__: {e}"

        def http_status(url):
            try:
                r = requests.get(url, headers=self.headers, timeout=self.timeout)
                return r.status_code
            except Exception:
                return -1

        def http_headers(url):
            try:
                r = requests.get(url, headers=self.headers, timeout=self.timeout)
                return self._dict_para_lua(dict(r.headers))
            except Exception:
                return self.lua.table()

        def http_head(url):
            """Só status, sem corpo — enumeração barata."""
            try:
                r = requests.head(url, headers=self.headers, timeout=self.timeout,
                                  allow_redirects=True)
                return r.status_code
            except Exception:
                return -1

        def http_cors(url, origin="https://evil.example"):
            """Manda Origin e devolve ACAO/ACAC — teste de CORS sem adivinhar."""
            try:
                h = dict(self.headers)
                h['Origin'] = origin
                r = requests.get(url, headers=h, timeout=self.timeout)
                tbl = self.lua.table()
                tbl['status'] = r.status_code
                tbl['allow_origin'] = r.headers.get('Access-Control-Allow-Origin', '')
                tbl['allow_credentials'] = r.headers.get('Access-Control-Allow-Credentials', '')
                return tbl
            except Exception:
                tbl = self.lua.table()
                tbl['status'] = -1
                return tbl

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

        def http_get_full(url, max_bytes=500000):
            """Bundle inteiro (http_get corta em 20KB — vendor de 1MB+ esconde a config)."""
            try:
                cap = max(1024, min(int(max_bytes or 500000), 2000000))
                partes, total = [], 0
                with requests.get(url, headers=self.headers, timeout=self.timeout,
                                  stream=True) as r:
                    for c in r.iter_content(chunk_size=65536):
                        if not c:
                            continue
                        total += len(c)
                        if total > cap:
                            partes.append(c[:cap - (total - len(c))])
                            break
                        partes.append(c)
                return b"".join(partes).decode('utf-8', errors='replace')
            except Exception as e:
                return f"__ERRO__: {e}"

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
            try:
                h = dict(self.headers)
                h['apikey'] = key
                h['Authorization'] = 'Bearer ' + key
                h['Prefer'] = 'count=exact'
                r = requests.get(base + '/rest/v1/' + tabela + '?select=*&limit=1',
                                 headers=h, timeout=self.timeout)
                tbl['status'] = r.status_code
                total = -1
                cr = r.headers.get('Content-Range', '')
                if '/' in cr:
                    tail = cr.rsplit('/', 1)[1]
                    if tail.isdigit():
                        total = int(tail)
                tbl['total'] = total
                return tbl
            except Exception:
                tbl['status'] = -1
                tbl['total'] = -1
                return tbl

        def throttle(ms=200):
            """Pausa anti-rate-limit entre requests."""
            try:
                time.sleep(max(0, min(int(ms or 0), 5000)) / 1000.0)
            except Exception:
                pass
            return True

        g['http_get'] = http_get
        g['http_status'] = http_status
        g['http_head'] = http_head
        g['http_cors'] = http_cors
        g['http_headers'] = http_headers
        g['find_regex'] = find_regex
        g['lower'] = lower
        g['preview'] = preview
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
        try:
            self.lua.execute(codigo)
            run_fn = self.lua.globals()['run']
            if run_fn is None:
                return "[-] Módulo sem função run(ctx)."
            resultado = run_fn(self._sanitizar(contexto))
            return str(resultado)
        except Exception as e:
            return f"[-] Erro no módulo Lua {nome_arquivo}: {e}"
