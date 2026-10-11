-- modules/cors_wildcard.lua
-- Testa se a API ecoa Origin arbitraria (bypass de same-origin)
-- ctx = { target=..., html=..., techs=... }

function run(ctx)
  local target = ctx['target'] or ""
  if target == "" then
    return "[-] cors_wildcard: sem target."
  end
  local base = target:gsub("/$", "")
  local paths = {"/", "/api", "/api/config", "/api/health", "/rest/v1/"}
  local out = {"[*] cors_wildcard: Origin https://evil.example"}
  local fire = 0
  for _, p in ipairs(paths) do
    local url = base .. p
    local r = http_cors(url, "https://evil.example")
    if r == nil or r['status'] == -1 then
      table.insert(out, "[-] falha ao conectar: " .. url)
    else
      local acao = r['allow_origin'] or ""
      local acac = lower(r['allow_credentials'] or "")
      if acao == "https://evil.example" then
        fire = fire + 1
        table.insert(out, "[FIRE] eco de Origin em " .. url .. " (ACAO=evil, creds=" .. acac .. ")")
      elseif acao == "*" then
        if acac == "true" then
          fire = fire + 1
          table.insert(out, "[FIRE] wildcard + credentials em " .. url)
        else
          table.insert(out, "[FIRE] wildcard ACAO:* em " .. url)
          fire = fire + 1
        end
      end
    end
  end
  if fire > 0 then
    table.insert(out, "[VEREDITO] CRITICO — CORS permite origem arbitraria (" .. fire .. " ponto(s)).")
  else
    table.insert(out, "[VEREDITO] ok — nenhuma origem arbitraria ecoada.")
  end
  return table.concat(out, "\n")
end
