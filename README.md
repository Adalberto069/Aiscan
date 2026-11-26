![AISCAN](docs/assets/banner.svg)

# AIScan

Framework modular de auditoria de segurança para aplicações web e APIs, com foco em aplicações criadas por ferramentas de IA (vibe coding). Desenvolvido em Python, com módulos Lua e relatórios técnicos.

**Status:** beta · **Versão testada do Python:** 3.12.10 (Windows)

> Use somente em sistemas próprios ou com autorização expressa. Para aprender, utilize o laboratório local com dados sintéticos.

## Índice

- [Recursos](#recursos)
- [Instalação](#instalação)
- [Primeira execução](#primeira-execução)
- [Laboratório local](#laboratório-local)
- [Opções da CLI](#opções-da-cli)
- [Interpretando os resultados](#interpretando-os-resultados)
- [Solução de problemas](#solução-de-problemas)
- [Arquitetura](#arquitetura)

## Recursos

- Reconhecimento de tecnologias e indicadores de plataformas de desenvolvimento por IA.
- Auditoria de cabeçalhos HTTP, CORS, configurações de Supabase e Firebase e exposição de informações.
- Motor modular Lua e matriz de autorização em laboratório.
- Relatórios HTML, JSON e SARIF com severidade, confiança, CWE e recomendações.
- Integração opcional com Gemini. Não é necessária para o modo manual.

## Instalação

### Requisitos

- [Python 3.12](https://www.python.org/downloads/) (versão validada: 3.12.10).
- [Git](https://git-scm.com/downloads).
- Conexão à internet para baixar o projeto e suas dependências.

Recomenda-se um ambiente virtual exclusivo para o AIScan.

### Windows (PowerShell)

Se Python ou Git ainda não estiverem instalados, instale-os pelos links acima ou pelo Winget:

```powershell
winget install --id Python.Python.3.12 --exact --scope user
winget install --id Git.Git --exact
```

Reabra o terminal e verifique:

```powershell
python --version
git --version
```

Baixe o projeto, crie o ambiente virtual e instale as dependências:

```powershell
git clone https://github.com/Adalberto069/Aiscan.git
cd Aiscan
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe aiscan.py --help
```

Os exemplos chamam diretamente o Python do ambiente virtual, sem precisar alterar a política de execução de scripts do PowerShell.

### Linux e macOS

Com Git e Python 3.12 instalados:

```bash
git clone https://github.com/Adalberto069/Aiscan.git
cd Aiscan
python3.12 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python aiscan.py --help
```

No Linux, pode ser necessário instalar o pacote de suporte a ambientes virtuais correspondente à sua distribuição. A instalação nesses sistemas não foi reproduzida nesta validação.

## Primeira execução

Os comandos abaixo são para Windows. No Linux/macOS, substitua `.\.venv\Scripts\python.exe` por `.venv/bin/python`.

### 1. Validar a instalação

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
.\.venv\Scripts\python.exe aiscan.py --list-modules
```

### 2. Auditoria inicial de uma aplicação autorizada

Substitua `https://example.com` pelo endereço do seu próprio site ou de um sistema cuja auditoria tenha sido autorizada.

```powershell
.\.venv\Scripts\python.exe aiscan.py -u https://example.com --only recon --redact
.\.venv\Scripts\python.exe aiscan.py -u https://example.com --module headers_audit.lua --redact
```

### 3. Exportar relatórios

```powershell
.\.venv\Scripts\python.exe aiscan.py -u https://example.com --module headers_audit.lua --redact --html auditoria.html --json auditoria.json --sarif auditoria.sarif
```

Abra o HTML no navegador. O JSON é útil para integração e o SARIF para ferramentas compatíveis de análise de segurança.

**Privacidade:** a versão beta pode apresentar informações sensíveis no terminal e nos relatórios mesmo com `--redact`. Esse parâmetro reduz a exposição em determinados módulos, mas não garante anonimização completa. Não publique saídas brutas e não envie dados reais a serviços externos.

## Laboratório local

O laboratório incluído simula uma API e usa dados fictícios. É o ambiente recomendado para testar o comportamento do scanner sem afetar sistemas reais.

Terminal 1 (na pasta do projeto):

```powershell
.\.venv\Scripts\python.exe lab/server.py 18080
```

Terminal 2 (na mesma pasta):

```powershell
.\.venv\Scripts\python.exe aiscan.py -u http://127.0.0.1:18080 --lab --redact
```

Esse comando executa o fluxo manual com os módulos disponíveis. O laboratório não reproduz todas as tecnologias encontradas em produção, portanto alguns módulos podem não se aplicar.

Para testar a matriz de autorização com identidades sintéticas, consulte [o guia do laboratório](lab/README.md). Mantenha o serviço restrito ao loopback.

## Opções da CLI

| Opção | Finalidade |
| --- | --- |
| `--help` | Exibe a ajuda |
| `-u`, `--url` | Define o endereço autorizado |
| `--list-modules` | Lista os módulos |
| `--module` | Executa um módulo específico |
| `--only` | Seleciona fases do pipeline |
| `--mode MANUAL` | Análise sem solicitar parecer de IA (padrão) |
| `--mode PRO` | Inclui análise complementar via Gemini, quando configurado |
| `--redact` | Reduz a exposição de dados em módulos compatíveis |
| `--lab` | Habilita o ambiente de testes local |
| `--authz` | Matriz de autorização com política definida |
| `--policy` | Arquivo JSON da política esperada |
| `--html`, `--json`, `--sarif` | Exportam resultados para os respectivos formatos |

O modo PRO depende da variável de ambiente `GEMINI_API_KEY`, da disponibilidade dos modelos e de acesso à API. Use apenas material sintético ou previamente sanitizado com autorização para processamento externo. Nunca grave a chave no repositório.

## Interpretando os resultados

| Indicador | Significado |
| --- | --- |
| `[OK]` | A verificação não encontrou o problema específico |
| `[FALHA]` / `[FIRE]` | Configuração ausente ou possível vulnerabilidade a revisar |
| `[?]` / inconclusivo | Evidência insuficiente; não significa que o sistema esteja seguro |

As severidades vão de informativa a crítica. Um alerta não é necessariamente uma vulnerabilidade confirmada. Chaves públicas de SDK podem ser legítimas, tecnologias como Vite não comprovam autoria por IA, e módulos diferentes podem sinalizar a mesma causa.

### Validação registrada

Em 26/11/2026, a instalação com Python 3.12.10 no Windows foi concluída e a descoberta de testes retornou **33 testes aprovados de 33** naquela execução. Uma varredura autorizada em modo manual executou os **11 módulos** e terminou com código de saída zero. Isso valida a execução naquela configuração, não garante a precisão em todos os alvos nem certifica a segurança de uma aplicação.

## Solução de problemas

- **Python não encontrado no Windows:** se o comando abrir a Microsoft Store, instale Python pelo site oficial ou pelo Winget, reabra o terminal e verifique o PATH. Se necessário, use o caminho do interpretador instalado.
- **pip não encontrado:** use o Python correto com `-m pip`. Se necessário, inicialize o pip com `python -m ensurepip --upgrade` e recrie o ambiente virtual.
- **Instalação lenta:** a dependência antiga do Gemini pode fazer o pip pesquisar várias versões compatíveis. Consulte a saída do instalador; não ignore erros de resolução nem force versões incompatíveis.
- **Módulo não encontrado:** execute os comandos na raiz do AIScan e use o Python do ambiente virtual.
- **Gemini indisponível:** utilize o modo manual; falhas de autenticação, cotas e disponibilidade do modelo não impedem a auditoria manual.

## Arquitetura

| Diretório | Finalidade |
| --- | --- |
| `core/` | Motor de auditoria, escopo, autorização e relatórios |
| `modules/` | Verificações extensíveis em Lua |
| `lab/` | Ambiente local com dados sintéticos |
| `tests/` | Testes automatizados |
| `docs/` | Documentação técnica |

Mais informações: [arquitetura técnica](docs/ARCHITECTURE.md) e [laboratório](lab/README.md).

## Uso responsável

Utilize exclusivamente em sistemas próprios ou expressamente autorizados, com escopo definido. Proteja dados pessoais e credenciais, limite o impacto dos testes e revise as evidências antes de compartilhá-las. Não interprete um relatório sem alertas como prova de segurança. O AIScan é uma ferramenta auxiliar de auditoria, não substitui uma avaliação profissional completa.
