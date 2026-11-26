![AISCAN](docs/assets/banner.svg)

# AIScan

Framework modular de auditoria de segurança para aplicações web e APIs. Desenvolvido em Python, com extensibilidade por módulos Lua e geração de relatórios técnicos.

**Status:** beta.

## Recursos

- Verificação de configurações de segurança HTTP, CORS e exposição de informações.
- Auditoria de configurações de acesso em Supabase e Firebase.
- Identificação de possíveis credenciais expostas em recursos públicos.
- Verificação diferencial de autorização com ambiente de laboratório local.
- Relatórios JSON, SARIF e HTML, com severidade, confiança, CWE e recomendações de correção.
- Integração opcional com Gemini para análise complementar.

## Instalação

```bash
git clone https://github.com/Adalberto069/Aiscan.git
cd Aiscan
pip install -r requirements.txt
python aiscan.py --help
```

## Arquitetura

| Diretório | Finalidade |
| --- | --- |
| core | Motor de auditoria, escopo, autorização e relatórios |
| modules | Verificações extensíveis em Lua |
| lab | Ambiente local de validação |
| tests | Testes de autorização, escopo e resultados |

## Validação

Consulte a [documentação do laboratório](lab/README.md) para executar verificações em ambiente controlado. Os testes estão disponíveis em [tests](tests/).

## Uso responsável

Utilize exclusivamente em sistemas próprios ou com autorização expressa. Proteja credenciais e evidências de auditoria, revise os relatórios antes de compartilhar e valide os achados manualmente. O scanner não substitui uma avaliação completa de segurança.

## Documentação técnica

[Arquitetura, componentes e validação](docs/ARCHITECTURE.md).
