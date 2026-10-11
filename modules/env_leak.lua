-- modules/env_leak.lua
-- Arquivos .env e endpoints de config expostos (P0 se com secret)
-- ctx = { target=..., html=..., techs=... }

function run(ctx)
  local target = ctx['target'] or ""
  if target == "" then
    return "[-] env_leak: sem target."
  end
  local base = target:gsub("/$", "")
  local paths = {"/.env", "/.env.local", "/.env.production", "/api/env", "/api/config"}
  local out = {"[*] env_leak: " .. base}
  local p0 = 0
  for _, p in ipairs(paths) do
    local url = base .. p
    local code = http_head(url)
    if code == 200 then
      local body = http_get(url)
      if string.sub(body, 1, 8) == "__ERRO__" then
        table.insert(out, "[?] " .. p .. " (HTTP 200, falha ao ler corpo)")
      else
        local hits = find_regex(body, "(?:KEY|TOKEN|SECRET|PASSWORD)[A-Za-z_]*=")
        if #hits > 0 then
          p0 = p0 + 1
          table.insert(out, "[FIRE] P0 " .. url .. " com secrets :: " .. preview(tostring(hits[1]), 40))
        else
          table.insert(out, "[?] " .. url .. " (HTTP 200, sem KEY=/TOKEN=/SECRET= visível)")
        end
      end
    elseif code ~= -1 and code ~= 404 then
      table.insert(out, "[-] " .. p .. " (HTTP " .. tostring(code) .. ")")
    end
  end
  if p0 > 0 then
    table.insert(out, "[VEREDITO] P0 — .env/config com secrets acessível.")
  else
    table.insert(out, "[VEREDITO] ok — nenhum .env/config com secret.")
  end
  return table.concat(out, "\n")
end
