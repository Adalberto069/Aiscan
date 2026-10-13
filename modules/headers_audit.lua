-- modules/headers_audit.lua
-- Audita headers de segurança que IA quase nunca configura
-- ctx = { target=... }

function run(ctx)
  local target = ctx['target'] or ""
  if target == "" then
    return "[-] headers_audit: sem target."
  end
  local h = http_headers(target)
  local out = {"[*] headers_audit: " .. target}
  local checar = {
    "content-security-policy",
    "x-frame-options",
    "strict-transport-security",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy"
  }
  -- normaliza keys pra lower
  local norm = {}
  for k, v in pairs(h) do
    norm[string.lower(k)] = v
  end
  -- clickjacking-relevantes sobem a severidade; o resto é higiene (BAIXA).
  local clickjack = {["content-security-policy"]=true, ["x-frame-options"]=true}
  for _, nome in ipairs(checar) do
    if norm[nome] == nil then
      table.insert(out, "[FALHA] ausente: " .. nome .. " (clickjacking/MIME/sniffing conforme o caso)")
      local sev = clickjack[nome] and "MEDIA" or "BAIXA"
      local cwe = clickjack[nome] and "CWE-1021" or "CWE-693"
      add_finding({title="Header de segurança ausente: " .. nome,
                   severity=sev, confidence="ALTA", category="missing-security-header",
                   cwe=cwe, description="Resposta não envia " .. nome .. ".",
                   remediation="Adicionar o header " .. nome .. " na borda (CDN/servidor).",
                   evidence={header=nome, target=target}})
    else
      table.insert(out, "[OK] presente: " .. nome)
    end
  end
  -- CORS: wildcard e * + credentials (bypass de same-origin). key ASCII, valor cru.
  local acao = norm["access-control-allow-origin"]
  local acac = norm["access-control-allow-credentials"]
  if acao == "*" then
    if acac ~= nil and lower(acac) == "true" then
      table.insert(out, "[FIRE] CORS * + credentials — bypass de same-origin")
      add_finding({title="CORS wildcard com credenciais (bypass de same-origin)",
                   severity="ALTA", confidence="ALTA", category="cors-misconfig",
                   cwe="CWE-942", description="Access-Control-Allow-Origin: * junto de Allow-Credentials: true.",
                   remediation="Refletir apenas origens confiáveis; nunca usar * com credenciais.",
                   evidence={allow_origin="*", allow_credentials="true", target=target}})
    else
      table.insert(out, "[FIRE] CORS wildcard (Access-Control-Allow-Origin: *)")
      add_finding({title="CORS wildcard (Access-Control-Allow-Origin: *)",
                   severity="MEDIA", confidence="ALTA", category="cors-misconfig",
                   cwe="CWE-942", description="API responde com Access-Control-Allow-Origin: *.",
                   remediation="Restringir a origens conhecidas se a resposta tiver dado sensível.",
                   evidence={allow_origin="*", target=target}})
    end
  else
    table.insert(out, "[OK] sem CORS wildcard no GET simples (eco sob Origin no cors_wildcard.lua)")
  end
  return table.concat(out, "\n")
end
