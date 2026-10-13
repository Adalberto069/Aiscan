# AIScan Framework v1.0.0-PRO (BETA)

Scanner tático focado em **sites vibe-coded** — Lovable.dev, v0.dev, Bolt.new.
A febre desses builders entrega código rápido e segurança zero: a AIScan caça
exatamente isso.

## Por que existe

IA geradora prioriza ship > segurança. O padrão se repete:

- Supabase com anon key no bundle e **sem RLS** (leitura/escrita aberta)
- Firebase com rules abertas
- Headers de segurança ausentes
- Secrets no JS (`VITE_*`, `NEXT_PUBLIC_*`, Stripe, Google keys)

## Uso

```
pip install -r requirements.txt
# PRO_MAX (opcional, IA):
# Windows: setx GEMINI_API_KEY "sua-chave"
python aiscan.py
```

## Uso (estilo wpsscan — só CLI direto)

```
python aiscan.py -u hiddenmod.com.br
python aiscan.py -u hiddenmod.com.br -m pro
python aiscan.py -u hiddenmod.com.br --only recon,lua
python aiscan.py -u hiddenmod.com.br --module headers_audit.lua
python aiscan.py --list-modules
```
`-u/-a` = alvo, `-m` = manual/pro, `--only recon,exploit,lua,pro` = fases,
`--module` = um Lua só, `--redact` = mascara PII (padrão: mostra valores reais).

### Relatórios (JSON / SARIF / HTML)

```
python aiscan.py -u alvo.com --json out.json      # achados estruturados
python aiscan.py -u alvo.com --sarif out.sarif    # SARIF 2.1.0 (GitHub code scanning)
python aiscan.py -u alvo.com --html report.html   # relatório autocontido
```
Cada achado carrega severidade (CRITICA..INFO), confiança, categoria, CWE,
correção e evidência **já redacted** (o relatório é seguro de compartilhar,
mesmo sem `--redact`). Os três podem ser combinados num só run; vale também
com `--authz`. Deduplicação por módulo+alvo+categoria+título.

Matriz de autorização (BOLA/IDOR diferencial, leitura por padrão):

```
AISCAN_KEY_A=.. AISCAN_KEY_B=.. python aiscan.py -u <api> --authz --policy policy.json
python aiscan.py -u 127.0.0.1:18080 --authz --lab                      # contra o lab local
python aiscan.py -u 127.0.0.1:18080 --authz --lab --allow-write probe  # + escrita em tabela dedicada
```
Sem as chaves, os casos somem em `INCONCLUSIVE`. Escrita nunca roda sem
`--lab` + `--allow-write`. Ver `lab/README.md`.
Escopo: só http/https, sem credencial na URL, sem IP interno (loopback só
com `--lab`), redirects seguidos com revalidação e sem vazar auth. Alvo
privado sem `--lab` aborta antes do primeiro request.

## Módulos Lua (`/modules`)

Comunidade escreve payload sem tocar no core Python.
API exposta: `http_get` (20KB), `http_get_full` (até 2MB, p/ bundles),
`http_status`, `http_head`, `http_cors`, `http_headers`,
`find_regex` (regex Python), `lower`, `preview`, `decode_jwt_payload`,
`openapi_tables`, `json_keys`, `rest_count`, `throttle`.

| Módulo | O que faz |
|---|---|
| `ai_signatures.lua` | fingerprint 9 sinais vibe-code + veredito |
| `supabase_enum.lua` | anon key do bundle + 12 tabelas via `?apikey=`, 200-com-dado = FIRE |
| `supabase_columns.lua` | rows (count=exact) + cols por tabela, PII marcada `[redacted]` |
| `headers_audit.lua` | 6 headers que IA nunca configura |
| `js_secrets.lua` | 14 patterns (Stripe/OpenAI/Anthropic/AWS/GH/Slack) no HTML + 5 bundles, quentes primeiro |
| `firebase_open.lua` | Firebase RTDB com leitura pública (`/.json` 200) |
| `firebase_rules.lua` | rules.json legível + shallow=true com dados |
| `env_leak.lua` | `/.env*`, `/api/env`, `/api/config` com secrets = P0 |
| `cors_wildcard.lua` | eco de Origin arbitrária (bypass same-origin) |
| `sourcemap_exposed.lua` | `<bundle>.map` com sources = fonte vazando |
| `storage_bucket_public.lua` | buckets Supabase Storage enumeráveis sem auth |

## Stack

Python + `requests` + `bs4` + `rich` + `lupa` (Lua) + Gemini (PRO_MAX).

## Status

BETA — `run` cobre recon → exploit → Lua → relatório IA.
Próximo: `env_leak`, `cors_wildcard`.
