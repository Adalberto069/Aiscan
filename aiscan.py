import os
import sys
import time
from rich.console import Console
from rich.table import Table
from core.scanner import AIParser
from core.exploits import AIScanExploits
from core.ai_engine import AISecurityAgent

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
    [dim font_style="italic"]     [SYS_LOG: ATIVO] // LOC: 0x7FFF // Nível: Elite[/dim]
    """
    console.print(banner)

def iniciar_console_interativo():
    alvo = "Não configurado"
    modo = "MANUAL"
    
    exibir_loading_pontos("[bold cyan][*] Inicializando módulos do AIScan[/bold cyan]", duracao=1)
    exibir_banner_ascii()
    
    while True:
        try:
            prompt = f"[bold white]aiscan[/bold white] [bold red]dev(scanner)[/bold red] > "
            comando = console.input(prompt).strip().split()
            
            if not comando:
                continue
                
            cmd_principal = comando[0].lower()
            
            if cmd_principal in ["exit", "quit"]:
                console.print("[bold red][*] Desligando AIScan Framework... [SYS_LOG: CLOSED][/bold red]")
                break
                
            elif cmd_principal == "help":
                table = Table(title="Comandos Disponíveis", title_style="bold green")
                table.add_column("Comando", style="bold cyan")
                table.add_column("Descrição", style="white")
                table.add_row("set target <url>", "Configura o site que será inspecionado")
                table.add_row("set mode <manual/pro>", "Muda entre varredura clássica ou assistida por IA")
                table.add_row("show options", "Exibe as configurações atuais do ambiente")
                table.add_row("run", "Inicia a varredura contra o alvo configurado")
                table.add_row("exit", "Fecha o console do AIScan")
                console.print(table)
                
            elif cmd_principal == "set" and len(comando) >= 3:
                var = comando[1].lower()
                valor = comando[2]
                if var == "target":
                    alvo = valor
                    console.print(f"[bold green][+] TARGET => {alvo}[/bold green]")
                elif var == "mode":
                    if valor.upper() in ["MANUAL", "PRO"]:
                        modo = valor.upper()
                        console.print(f"[bold green][+] MODE => {modo}[/bold green]")
                    else:
                        console.print("[bold red][-] Modos aceitos: MANUAL ou PRO[/bold red]")
                else:
                    console.print(f"[bold red][-] Variável '{var}' desconhecida.[/bold red]")
                    
            elif cmd_principal == "show" and len(comando) > 1 and comando[1].lower() == "options":
                table = Table(title="Configurações Globais", title_style="bold yellow")
                table.add_column("Parâmetro", style="bold cyan")
                table.add_column("Valor Atual", style="white")
                table.add_row("TARGET", alvo)
                table.add_row("MODE", modo)
                console.print(table)
                
            elif cmd_principal in ["run", "exploit"]:
                if alvo == "Não configurado":
                    console.print("[bold red][-] Erro: Configure um alvo válido antes de rodar (set target <url>).[/bold red]")
                    continue
                
                console.print(f"\n[bold yellow][*] Iniciando ataque contra {alvo} usando modo {modo}...[/bold yellow]")
                exibir_loading_pontos("[bold cyan][*] Capturando e extraindo estruturas de build[/bold cyan]", duracao=2)
                
                parser = AIParser(alvo)
                if not parser.capturar_html():
                    console.print("[bold red][-] Erro crítico: Não foi possível conectar ao servidor alvo.[/bold red]\n")
                    continue
                
                detecoes = parser.detectar_infraestrutura()
                
                table_res = Table(title=f"Resultado do Reconhecimento: {alvo}")
                table_res.add_column("Análise", style="bold cyan")
                table_res.add_column("Status / Detalhes", style="white")
                table_res.add_row("Gerado por IA?", "SIM" if detecoes["is_ai_generated"] else "NÃO DETECTADO")
                table_res.add_row("Tecnologias", ", ".join(detecoes["techs_detectadas"]) if detecoes["techs_detectadas"] else "Nenhuma")
                console.print(table_res)
                
                for alerta in detecoes["alertas"]:
                    console.print(f"[bold red]{alerta}[/bold red]")
                
                console.print("\n[bold yellow][*] Iniciando varredura de exploits locais...[/bold yellow]")
                exploit_engine = AIScanExploits(alvo)
                resultado_exploit = exploit_engine.testar_supabase_rest_exposto(parser.html_content)
                console.print(resultado_exploit)
                
                if modo == "PRO":
                    console.print("\n[bold purple][*] Acionando Módulo Pro Max: Solicitando análise do agente autônomo...[/bold purple]")
                    agente = AISecurityAgent()
                    relatorio_ia = agente.analisar_com_ia(parser.html_content, detecoes["techs_detectadas"])
                    console.print("\n[bold magenta]=== RELATÓRIO DO AGENTE DE IA ===[/bold magenta]")
                    console.print(relatorio_ia)
                    console.print("[bold magenta]=================================[/bold magenta]\n")
                    
            else:
                console.print("[bold red][-] Comando inválido. Digite 'help' para ver os comandos suportados.[/bold red]")
                
        except KeyboardInterrupt:
            console.print("\n[bold red][*] Use 'exit' para fechar o framework com segurança.[/bold red]")

if __name__ == "__main__":
    iniciar_console_interativo()
