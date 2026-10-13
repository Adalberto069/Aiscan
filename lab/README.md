# Lab Authz — laboratório local de matriz de autorização

Mock de API REST estilo Supabase/PostgREST com dados 100% sintéticos.
Só escuta em `127.0.0.1`. Nunca exponha a porta.

## Subir

```
python lab/server.py 18080
```

## Contas de teste (sintéticas, só valem no lab)

| Identidade | Variável de ambiente | Valor |
|---|---|---|
| anonymous | `AISCAN_KEY_ANON` | `lab-key-anon` |
| user_a (alice) | `AISCAN_KEY_A` | `lab-key-user-a` |
| user_b (bob) | `AISCAN_KEY_B` | `lab-key-user-b` |
| admin_test | `AISCAN_KEY_ADMIN` | `lab-key-admin` |

Em alvo real, gere contas descartáveis no teu projeto e exporte as chaves
nas mesmas variáveis. Nunca cole chave em ticket, log ou commit.

## Política esperada (`lab/policy.json`)

Cada caso: `identity`, `method`, `resource`, `params`, `expect` (allow/deny),
`cross` (o recurso é de OUTRO principal?) e `write` (é mutação?).
`private_fields` lista o que conta como dado privado (ex: `email`).

## Rodar a fase

```
AISCAN_KEY_A=lab-key-user-a AISCAN_KEY_B=lab-key-user-b \
python aiscan.py -u 127.0.0.1:18080 --authz --lab
```

Escrita de laboratório (tabela dedicada `probe`, cria + deleta + confere):

```
... --authz --lab --allow-write probe
```

## Testes

```
python tests/test_authz_lab.py        # 12 testes, lab sobe sozinho em thread
python tests/test_scope_hardening.py  # 18 testes: escopo, isolamento, limpeza
python tests/test_authz_metrics.py    # 3 testes: precisão/recall/cobertura
```

## Modo quebrado (métricas TP/FN)

```
GET /__mode?open=1   # B legível por A (BOLA presente de propósito)
GET /__mode?open=0   # volta ao seguro
GET /__state         # posts/deletes/vivos/órfãs/vuln
GET /__echo_last     # última apikey vista (teste de isolamento)
```
Só `127.0.0.1`. `/rest/v1/probe?mode=fail|slow|badid|nodelete|lingering`
simula cada falha de limpeza.
