-- modules/firebase_open.lua
-- Firebase Realtime Database exposto publicamente (leitura sem auth)
-- ctx = { target=..., html=..., techs=... }

function run(ctx)
  local html = ctx['html'] or ""

  local hits = find_regex(html, "https?://[a-zA-Z0-9\\-]+\\.firebaseio\\.com")
  if hits == nil or #hits == 0 then
    return "[-] firebase_open: nenhuma base *.firebaseio.com no HTML."
  end

  -- dedup preservando ordem
  local bases, seen = {}, {}
  for _, u in ipairs(hits) do
    if not seen[u] then
      seen[u] = true
      table.insert(bases, u)
    end
  end

  local out = {"[*] firebase_open: " .. #bases .. " base(s) pra testar"}
  local vuln = 0

  for _, base in ipairs(bases) do
    local url = base .. "/.json"
    local body = http_get(url) or ""
    if string.sub(body, 1, 8) == "__ERRO__" then
      table.insert(out, "[-] falha ao conectar: " .. url)
    else
      local status = http_status(url)
      local low = lower(body)
      local denied = (low:find("permission denied", 1, true) ~= nil)
        or (low:find("permission_denied", 1, true) ~= nil)
      if status == 200 and not denied then
        vuln = vuln + 1
        table.insert(out, "[FIRE] CRITICO " .. url .. " (HTTP 200) leitura publica :: " .. preview(body, 120))
      elseif status == 401 or status == 403 or denied then
        table.insert(out, "[OK] " .. url .. " (HTTP " .. tostring(status) .. ") regra bloqueia leitura")
      else
        table.insert(out, "[?] " .. url .. " (HTTP " .. tostring(status) .. ") sem exposicao confirmada")
      end
    end
  end

  if vuln > 0 then
    table.insert(out, "[VEREDITO] CRITICO — " .. vuln .. " de " .. #bases .. " base(s) com leitura publica.")
  else
    table.insert(out, "[VEREDITO] ok — nenhuma base exposta.")
  end
  return table.concat(out, "\n")
end
