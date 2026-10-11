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
    """Garante scheme p/ os módulos Lua (requests exige http:// ou https://)."""
    if alvo.startswith(('http://', 'https://')):
        return alvo
    return 'https://' + alvo

def executar_scan(alvo, modo="MANUAL", fases=None, modulo_unico=None, animar=True, show_data=False):
    """Pipeline único usado pelo console interativo E pelo CLI direto.
    fases: subset de {'recon','exploit','lua','pro'} — None = tudo (pro só se modo PRO).
    show_data: opt-in — exibe valores reais (PII) nos módulos de escopo. Padrão: redacted."""
    if fases is None:
        fases = {'recon', 'exploit', 'lua', 'pro'}
    else:
        fases = set(fases)

    if modulo_unico:
        parser_tmp = AIParser(alvo)
        html_tmp, techs_tmp = "", []
        if parser_tmp.capturar_html():
            html_tmp = parser_tmp.html_content
            techs_tmp = parser_tmp.detectar_infraestrutura()["techs_detectadas"]
        else:
            console.print("[bold red][-] Não foi possível conectar ao alvo.[/bold red]")
            return
        engine = LuaEngine()
        ctx = {"target": normalizar_url(alvo), "html": html_tmp, "techs": techs_tmp, "show_data": show_data}
        console.print(f"[bold cyan][*] Executando módulo Lua: {modulo_unico}[/bold cyan]")
        # markup=False: output Lua usa [TAGS] literais ([redacted] sumia comido pelo Rich)
        console.print(engine.executar_modulo(modulo_unico, ctx), markup=False)
        return

    console.print(f"\n[bold yellow][*] Iniciando ataque contra {alvo} usando modo {modo}...[/bold yellow]")
    if animar:
        exibir_loading_pontos("[bold cyan][*] Capturando e extraindo estruturas de build[/bold cyan]", duracao=2)

    parser = AIParser(alvo)
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

    if 'exploit' in fases:
        console.print("\n[bold yellow][*] Iniciando varredura de exploits locais...[/bold yellow]")
        exploit_engine = AIScanExploits(alvo)
        console.print(exploit_engine.testar_supabase_rest_exposto(parser.html_content))

    if 'lua' in fases:
        console.print("\n[bold yellow][*] Executando módulos Lua (/modules)...[/bold yellow]")
        try:
            lua_engine = LuaEngine()
            ctx = {"target": normalizar_url(alvo), "html": parser.html_content, "techs": detecoes["techs_detectadas"], "show_data": show_data}
            for mod_nome in lua_engine.listar_modulos():
                console.print(f"\n[bold cyan]--- {mod_nome} ---[/bold cyan]")
                console.print(lua_engine.executar_modulo(mod_nome, ctx), markup=False)
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
    ap.add_argument("--show-data", dest="show_data", action="store_true",
                    help="exibe valores reais (PII) nos módulos de escopo — só no teu próprio alvo")
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
    executar_scan(args.alvo, modo, fases=fases, modulo_unico=args.modulo, animar=False,
                  show_data=args.show_data)

if __name__ == "__main__":
    main_cli()
