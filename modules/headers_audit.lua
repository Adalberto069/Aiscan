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
  for _, nome in ipairs(checar) do
    if norm[nome] == nil then
      table.insert(out, "[FALHA] ausente: " .. nome .. " (clickjacking/MIME/sniffing conforme o caso)")
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
    else
      table.insert(out, "[FIRE] CORS wildcard (Access-Control-Allow-Origin: *)")
    end
  else
    table.insert(out, "[OK] sem CORS wildcard no GET simples (eco sob Origin no cors_wildcard.lua)")
  end
  return table.concat(out, "\n")
end
