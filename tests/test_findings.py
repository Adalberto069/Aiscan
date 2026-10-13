"""Testes do modelo de achados e sua integração com o motor Lua."""
import json
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from core.findings import Finding, FindingsStore, normalizar_severidade  # noqa: E402


def test_normaliza_severidade():
    assert normalizar_severidade("critico") == "CRITICA"
    assert normalizar_severidade("HIGH") == "ALTA"
    assert normalizar_severidade("-") == "INFO"
    assert normalizar_severidade("xpto") == "INFO"
    assert normalizar_severidade("") == "INFO"


def test_dedupe_e_ordem():
    s = FindingsStore("https://alvo")
    s.add(Finding(title="b", severity="BAIXA", module="m", category="c"))
    s.add(Finding(title="a", severity="CRITICA", module="m", category="c"))
    # duplicata exata (mesmo module+target+category+title) é ignorada
    s.add(Finding(title="a", severity="CRITICA", module="m", category="c"))
    assert len(s) == 2
    ordem = [f.severity for f in s.ordenados()]
    assert ordem == ["CRITICA", "BAIXA"]  # crítica primeiro


def test_target_default_herdado_do_store():
    s = FindingsStore("https://alvo")
    s.add(Finding(title="x", module="m", category="c"))
    assert s.ordenados()[0].target == "https://alvo"


def test_resumo_sempre_todas_chaves():
    s = FindingsStore()
    s.add(Finding(title="x", severity="ALTA", module="m", category="c"))
    r = s.resumo()
    assert set(r) == {"CRITICA", "ALTA", "MEDIA", "BAIXA", "INFO"}
    assert r["ALTA"] == 1 and r["CRITICA"] == 0


def test_json_valido_e_completo():
    s = FindingsStore("https://alvo")
    s.add(Finding(title="t", severity="critico", module="m", category="c",
                  cwe="CWE-1", evidence={"k": "v"}))
    d = json.loads(s.to_json())
    assert d["summary"]["total"] == 1
    assert d["findings"][0]["severity"] == "CRITICA"
    assert d["findings"][0]["cwe"] == "CWE-1"


def test_sarif_estrutura_minima():
    s = FindingsStore("https://alvo")
    s.add(Finding(title="t", severity="CRITICA", module="m", category="broken-access-control"))
    sarif = json.loads(s.to_sarif())
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "AIScan"
    assert run["results"][0]["level"] == "error"
    assert run["results"][0]["ruleId"] == "broken-access-control"
    assert len(run["tool"]["driver"]["rules"]) == 1


def test_html_contem_titulo_e_escapa():
    s = FindingsStore("https://alvo")
    s.add(Finding(title="<script>x</script>", severity="ALTA", module="m", category="c"))
    h = s.to_html()
    assert "<html" in h
    assert "&lt;script&gt;" in h          # título escapado
    assert "<script>x</script>" not in h  # nunca cru


def _engine_com_modulo(tmp_path, codigo, store):
    """Cria um .lua temporário e devolve (engine, nome)."""
    from core.lua_engine import LuaEngine
    (tmp_path / "mod.lua").write_text(codigo, encoding="utf-8")
    eng = LuaEngine(modules_dir=str(tmp_path), store=store)
    return eng, "mod.lua"


def test_lua_add_finding_estruturado(tmp_path):
    s = FindingsStore("https://alvo")
    codigo = """
function run(ctx)
  add_finding({title="achado lua", severity="critico", category="supabase-rls",
               cwe="CWE-284", confidence="ALTA",
               evidence={tabela="profiles", rows="4"}})
  return "[OK] rodou"
end
"""
    eng, nome = _engine_com_modulo(tmp_path, codigo, s)
    eng.executar_modulo(nome, {"target": "https://alvo"})
    assert len(s) == 1
    f = s.ordenados()[0]
    assert f.title == "achado lua"
    assert f.severity == "CRITICA"
    assert f.module == "mod.lua"
    assert f.category == "supabase-rls"
    assert isinstance(f.evidence, dict) and f.evidence.get("tabela") == "profiles"


def test_lua_fallback_parseia_fire(tmp_path):
    """Módulo legado sem add_finding: linhas [FIRE] viram achados."""
    s = FindingsStore("https://alvo")
    codigo = """
function run(ctx)
  local o = {}
  table.insert(o, "[*] cabecalho")
  table.insert(o, "[FIRE] CRITICO tabela legivel: profiles")
  table.insert(o, "[FIRE] header ausente: CSP")
  table.insert(o, "[+] fim")
  return table.concat(o, "\\n")
end
"""
    eng, nome = _engine_com_modulo(tmp_path, codigo, s)
    eng.executar_modulo(nome, {"target": "https://alvo"})
    assert len(s) == 2
    sevs = sorted(f.severity for f in s)
    assert sevs == ["ALTA", "CRITICA"]  # 'CRITICO' -> CRITICA, outro -> ALTA


def test_lua_estruturado_tem_prioridade_sobre_fallback(tmp_path):
    """Se o módulo chamou add_finding, o fallback de linhas NÃO roda."""
    s = FindingsStore("https://alvo")
    codigo = """
function run(ctx)
  add_finding({title="estruturado", severity="ALTA", category="c"})
  return "[FIRE] isto NAO deve virar achado duplicado"
end
"""
    eng, nome = _engine_com_modulo(tmp_path, codigo, s)
    eng.executar_modulo(nome, {"target": "https://alvo"})
    assert len(s) == 1
    assert s.ordenados()[0].title == "estruturado"
