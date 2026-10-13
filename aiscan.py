import os
import sys
import time
import argparse
from rich.console import Console
from rich.table import Table
from core.scanner import AIParser
from core.exploits import AIScanExploits
from core.ai_engine import AISecurityAgent
from core.lua_engine import LuaEngine

console = Console()

def exibir_loading_pontos(texto, duracao=2):
    sys.stdout.write(texto)
    sys.stdout.flush()
    for _ in range(duracao * 2):
        time.sleep(0.4)
        sys.stdout.write(".")
        sys.stdout.flush()
    print("\n")

def exibir_banner_ascii():
    banner = """
    [bold green]
     █████╗ ██╗███████╗ ██████╗ █████╗ ███╗   ██╗
    ██╔══██╗██║██╔════╝██╔════╝██╔══██╗████╗  ██║
    ███████║██║███████╗██║     ███████║██╔██╗ ██║
    ██╔══██║██║╚════██║██║     ██╔══██║██║╚██╗██║
    ██║  ██║██║███████║╚██████╗██║  ██║██║ ╚████║
    ╚═╝  ╚═╝╚═╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
    [/bold green]
    [bold white]   =[/bold white] [bold green]AIScan Framework v1.0.0-PRO[/bold green]                 [bold white]=[/bold white]
    [bold white]   =[/bold white] [bold cyan]Focado em Vulnerabilidades de Sites feitos por IA[/bold cyan] [bold white]=[/bold white]
    [bold white]   =[/bold white] [bold yellow]Modos disponíveis: MANUAL | PRO_MAX (AI)[/bold yellow]         [bold white]=[/bold white]
    [dim font_style="italic"]     [SYS_LOG: ATIVO] // LOC: 0x7FFF // Nível: Elite[/]
    """
    console.print(banner)

def normalizar_url(alvo):
    """Garante scheme (requests exige http:// ou https://).
    Loopback/rede privada sem scheme => http; resto => https."""
    if alvo.startswith(('http://', 'https://')):
        return alvo
    host = alvo.split("/")[0].split(":")[0].lower()
    if host in ("localhost",) or host.startswith(("127.", "10.", "192.168.")):
        return 'http://' + alvo
    if host.startswith("172."):
        try:
            seg = int(host.split(".")[1])
            if 16 <= seg <= 31:
                return 'http://' + alvo
        except Exception:
            pass
    return 'https://' + alvo

def executar_scan(alvo, modo="MANUAL", fases=None, modulo_unico=None, animar=True, show_data=False, lab_mode=False, store=None):
    """Pipeline único usado pelo console interativo E pelo CLI direto.
    fases: subset de {'recon','exploit','lua','pro'} — None = tudo (pro só se modo PRO).
    show_data: opt-in — exibe valores reais (PII) nos módulos de escopo. Padrão: redacted.
    store: FindingsStore opcional — coleta achados estruturados p/ export."""
    from core.scope import check_url
    ok, motivo = check_url(normalizar_url(alvo), lab_mode)
    if not ok:
        console.print(f"[bold red][-] Escopo bloqueado: {motivo} (use --lab p/ 127.0.0.1).[/bold red]")
        return
    if fases is None:
        fases = {'recon', 'exploit', 'lua', 'pro'}
    else:
        fases = set(fases)

    if modulo_unico:
        parser_tmp = AIParser(alvo, lab_mode=lab_mode)
        html_tmp, techs_tmp = "", []
        if parser_tmp.capturar_html():
            html_tmp = parser_tmp.html_content
            techs_tmp = parser_tmp.detectar_infraestrutura()["techs_detectadas"]
        else:
            console.print("[bold red][-] Não foi possível conectar ao alvo.[/bold red]")
            return
        engine = LuaEngine(lab_mode=lab_mode, store=store)
        ctx = {"target": normalizar_url(alvo), "html": html_tmp, "techs": techs_tmp, "show_data": show_data}
        console.print(f"[bold cyan][*] Executando módulo Lua: {modulo_unico}[/bold cyan]")
        # markup=False: output Lua usa [TAGS] literais ([redacted] sumia comido pelo Rich)
        console.print(engine.executar_modulo(modulo_unico, ctx), markup=False)
        return

    console.print(f"\n[bold yellow][*] Iniciando ataque contra {alvo} usando modo {modo}...[/bold yellow]")
    if animar:
        exibir_loading_pontos("[bold cyan][*] Capturando e extraindo estruturas de build[/bold cyan]", duracao=2)

    parser = AIParser(alvo, lab_mode=lab_mode)
    if not parser.capturar_html():
        console.print("[bold red][-] Erro crítico: Não foi possível conectar ao servidor alvo.[/bold red]\n")
        return

    detecoes = parser.detectar_infraestrutura()

    if 'recon' in fases:
        table_res = Table(title=f"Resultado do Reconhecimento: {alvo}")
        table_res.add_column("Análise", style="bold cyan")
        table_res.add_column("Status / Detalhes", style="white")
        table_res.add_row("Gerado por IA?", "SIM" if detecoes["is_ai_generated"] else "NÃO DETECTADO")
        table_res.add_row("Tecnologias", ", ".join(detecoes["techs_detectadas"]) if detecoes["techs_detectadas"] else "Nenhuma")
        console.print(table_res)
        for alerta in detecoes["alertas"]:
            console.print(f"[bold red]{alerta}[/bold red]")
        if store is not None:
            for alerta in detecoes["alertas"]:
                store.add_dict(title=alerta.replace("[🚨] ALERTA: ", ""), severity="INFO",
                               confidence="ALTA", module="scanner", category="recon",
                               description="Conexão direta com backend exposta no cliente.",
                               evidence={"techs": detecoes["techs_detectadas"]})

    if 'exploit' in fases:
        console.print("\n[bold yellow][*] Iniciando varredura de exploits locais...[/bold yellow]")
        exploit_engine = AIScanExploits(alvo, lab_mode=lab_mode)
        saida_exploit = exploit_engine.testar_supabase_rest_exposto(parser.html_content)
        console.print(saida_exploit)
        if store is not None:
            for ln in saida_exploit.split("\n"):
                if "VULNERABILIDADE CRÍTICA" in ln:
                    store.add_dict(title="Supabase REST: tabelas legíveis com anon key (RLS ausente/permissiva)",
                                   severity="CRITICA", confidence="ALTA", module="exploits",
                                   category="supabase-rls", cwe="CWE-284",
                                   description=ln.split(":", 1)[-1].strip()[:300],
                                   remediation="Habilitar RLS por tabela e policies restritas ao dono.",
                                   evidence={"line": ln.strip()[:400]})

    if 'lua' in fases:
        console.print("\n[bold yellow][*] Executando módulos Lua (/modules)...[/bold yellow]")
        try:
            lua_engine = LuaEngine(lab_mode=lab_mode, store=store)
            ctx = {"target": normalizar_url(alvo), "html": parser.html_content, "techs": detecoes["techs_detectadas"], "show_data": show_data}
            placar = {}
            for mod_nome in lua_engine.listar_modulos():
                console.print(f"\n[bold cyan]--- {mod_nome} ---[/bold cyan]")
                saida = lua_engine.executar_modulo(mod_nome, ctx)
                console.print(saida, markup=False)
                placar[mod_nome] = sum(1 for ln in saida.split("\n") if ln.startswith(("[FIRE]", "[FALHA]")))
            quadro = Table(title="Quadro geral (FIRE por módulo)", title_style="bold green")
            quadro.add_column("Módulo", style="bold cyan")
            quadro.add_column("Achados", style="white")
            for mod_nome, n in placar.items():
                quadro.add_row(mod_nome, str(n))
            console.print(quadro)
        except Exception as e:
            console.print(f"[bold red][-] Falha no motor Lua: {e}[/bold red]")

    if modo == "PRO" and 'pro' in fases:
        console.print("\n[bold purple][*] Acionando Módulo Pro Max: Solicitando análise do agente autônomo...[/bold purple]")
        console.print("[dim][*] O PRO consulta a IA online — aguarde até ~90s sem apertar Ctrl+C.[/dim]")
        agente = AISecurityAgent()
        relatorio_ia = agente.analisar_com_ia(parser.html_content, detecoes["techs_detectadas"])
        console.print("\n[bold magenta]=== RELATÓRIO DO AGENTE DE IA ===[/bold magenta]")
        console.print(relatorio_ia)
        console.print("[bold magenta]=================================[/bold magenta]\n")

def modo_uso_rapido():
    console.print("[bold yellow]Uso:[/bold yellow] python aiscan.py -u <alvo> [-m pro] [--only recon,lua] [--module x.lua]")
    console.print("[dim]Ex: python aiscan.py -u hiddenmod.com.br -m pro[/dim]")
    console.print("[dim]Authz lab: AISCAN_KEY_A=.. AISCAN_KEY_B=.. python aiscan.py -u 127.0.0.1:18080 --authz --lab[/dim]")


def executar_authz(args, store=None):
    """Fase de matriz de autorização — diferencial entre identidades."""
    import json as _json
    from core.authz import AuthzEngine, AuthzAbort, load_identities
    console.print("\n[bold yellow][*] Fase authz: testes diferenciais de autorização...[/bold yellow]")
    policy_path = args.policy or ("lab/policy.json" if args.lab else None)
    if not policy_path:
        console.print("[bold red][-] --authz exige --policy <arquivo> (ou --lab p/ política do lab).[/bold red]")
        return
    try:
        with open(policy_path, encoding="utf-8") as f:
            policy = _json.load(f)
    except Exception as e:
        console.print(f"[bold red][-] Política ilegível: {e}[/bold red]")
        return
    identidades, ausentes = load_identities()
    if ausentes and not args.lab:
        console.print(f"[bold yellow][!] Sem {', '.join(ausentes)} — casos com identidade somem em INCONCLUSIVE.[/bold yellow]")
    allow = [t.strip() for t in (args.allow_write or "").split(",") if t.strip()]
    try:
        eng = AuthzEngine(normalizar_url(args.alvo), identidades, policy,
                          lab_mode=args.lab, allow_write=allow)
    except AuthzAbort as e:
        console.print(f"[bold red][-] Authz abortado: {e}[/bold red]")
        return
    achados = eng.run_all(policy.get("cases", []))
    for f in achados:
        console.print(AuthzEngine.format(f), markup=False)
    if store is not None:
        _fire = {"BOLA_CONFIRMED", "WRITE_ORPHAN", "WRITE_OK_CLEANED"}
        _cwe = {"BOLA_CONFIRMED": "CWE-639", "WRITE_ORPHAN": "CWE-284",
                "WRITE_OK_CLEANED": "CWE-284"}
        for f in achados:
            if f["verdict"] not in _fire:
                continue
            store.add_dict(
                title=f"{f['verdict']}: {f['op']} ({f['identity']})",
                severity=f.get("severity", "ALTA"), confidence=f.get("confidence", "MEDIA"),
                module="authz", category="broken-access-control",
                cwe=_cwe.get(f["verdict"], "CWE-284"), verdict=f["verdict"],
                description=f.get("observed", ""), remediation=f.get("fix", ""),
                evidence=f.get("evidence", {}))
    n_fire = sum(1 for f in achados if f["verdict"] in ("BOLA_CONFIRMED", "WRITE_ORPHAN", "WRITE_OK_CLEANED"))
    n_inc = sum(1 for f in achados if f["verdict"] == "INCONCLUSIVE")
    console.print(f"\n[bold magenta]=== AUTHZ: {len(achados)} casos, {n_fire} FIRE, {n_inc} inconclusivos ===[/bold magenta]")


# Modo wpsscan: só CLI direto, sem console interativo
def main_cli():
    # stdout UTF-8: sem isso o banner/tabelas (█ ┏ ━) quebram com cp1252 ao redirecionar
    try:
        sys.stdout.reconfigure(encoding='utf-8')
        sys.stderr.reconfigure(encoding='utf-8')
    except Exception:
        pass
    ap = argparse.ArgumentParser(prog="aiscan.py", description="AIScan Framework — scanner de sites vibe-coded (Lovable/Bolt/v0).")
    ap.add_argument("-u", "-a", "--url", "--alvo", dest="alvo", help="alvo (ex: hiddenmod.com.br)")
    ap.add_argument("-m", "--mode", dest="modo", default="MANUAL", help="MANUAL ou PRO (padrão: MANUAL)")
    ap.add_argument("--only", dest="fases", default=None, help="fases separadas por vírgula: recon,exploit,lua,pro (padrão: tudo)")
    ap.add_argument("--module", dest="modulo", default=None, help="roda um módulo Lua só (ex: headers_audit.lua)")
    ap.add_argument("--list-modules", dest="listar", action="store_true", help="lista /modules e sai")
    ap.add_argument("--redact", dest="redact", action="store_true",
                    help="mascara PII no escopo (padrão: mostra valores reais)")
    ap.add_argument("--authz", dest="authz", action="store_true",
                    help="fase de matriz de autorização (BOLA/IDOR diferencial)")
    ap.add_argument("--policy", dest="policy", default=None,
                    help="JSON de política esperada (padrão no --lab: lab/policy.json)")
    ap.add_argument("--lab", dest="lab", action="store_true",
                    help="modo laboratório: permite 127.0.0.1, chaves sintéticas via env")
    ap.add_argument("--allow-write", dest="allow_write", default=None,
                    help="tabela(s) p/ teste de escrita, vírgula (exige --lab; padrão: bloqueado)")
    ap.add_argument("--json", dest="json_out", default=None,
                    help="grava achados estruturados em JSON (ex: out.json)")
    ap.add_argument("--sarif", dest="sarif_out", default=None,
                    help="grava achados em SARIF 2.1.0 (GitHub code scanning)")
    ap.add_argument("--html", dest="html_out", default=None,
                    help="grava relatório HTML autocontido (ex: report.html)")
    args = ap.parse_args()

    if args.listar:
        for mod_nome in LuaEngine().listar_modulos():
            print(mod_nome)
        return

    if not args.alvo:
        exibir_banner_ascii()
        modo_uso_rapido()
        sys.exit(2)

    modo = args.modo.upper()
    if modo not in ["MANUAL", "PRO"]:
        console.print("[bold red][-] Modos aceitos: MANUAL ou PRO[/bold red]")
        sys.exit(2)
    fases = [f.strip().lower() for f in args.fases.split(",")] if args.fases else None
    if fases and not set(fases) <= {'recon', 'exploit', 'lua', 'pro'}:
        console.print("[bold red][-] Fases válidas: recon,exploit,lua,pro[/bold red]")
        sys.exit(2)
    exibir_banner_ascii()
    from core.findings import FindingsStore
    store = FindingsStore(target=normalizar_url(args.alvo))
    executar_scan(args.alvo, modo, fases=fases, modulo_unico=args.modulo, animar=False,
                  show_data=(not args.redact), lab_mode=args.lab, store=store)
    if args.authz:
        executar_authz(args, store=store)
    exportar_relatorios(store, args)


def exportar_relatorios(store, args):
    """Grava JSON/SARIF/HTML conforme flags e imprime resumo por severidade."""
    destinos = [(args.json_out, store.to_json), (args.sarif_out, store.to_sarif),
                (args.html_out, store.to_html)]
    escreveu = False
    for caminho, serializa in destinos:
        if not caminho:
            continue
        try:
            with open(caminho, "w", encoding="utf-8") as f:
                f.write(serializa())
            console.print(f"[bold green][+] Relatório gravado: {caminho}[/bold green]")
            escreveu = True
        except Exception as e:
            console.print(f"[bold red][-] Falha ao gravar {caminho}: {e}[/bold red]")
    if escreveu or len(store):
        r = store.resumo()
        resumo = "  ".join(f"{s}={r[s]}" for s in ("CRITICA", "ALTA", "MEDIA", "BAIXA", "INFO"))
        console.print(f"[bold magenta]=== ACHADOS: {len(store)} total · {resumo} ===[/bold magenta]")

if __name__ == "__main__":
    main_cli()
