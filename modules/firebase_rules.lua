-- modules/firebase_rules.lua
-- Regras do Firebase: leitura (shallow) e escrita (rules.json)
-- ctx = { target=..., html=..., techs=... }

function run(ctx)
  local html = ctx['html'] or ""
  local hits = find_regex(html, "https?://[a-zA-Z0-9\\-]+\\.firebaseio\\.com")
  if hits == nil or #hits == 0 then
    return "[-] firebase_rules: nenhuma base *.firebaseio.com no HTML."
  end
  local bases, seen = {}, {}
  for _, u in ipairs(hits) do
    if not seen[u] then seen[u] = true table.insert(bases, u) end
  end
  local out = {"[*] firebase_rules: " .. #bases .. " base(s)"}
  local fire = 0
  for _, base in ipairs(bases) do
    -- escrita: rules.json legivel expoe (e sugere) regras abertas
    local rurl = base .. "/.settings/rules.json"
    local rbody = http_get(rurl)
    if string.sub(rbody, 1, 8) == "__ERRO__" then
      table.insert(out, "[-] falha ao conectar: " .. rurl)
    else
      local low = lower(rbody)
      if low:find("permission denied", 1, true) then
        table.insert(out, "[OK] rules.json protegido: " .. base)
      elseif low:find(".read", 1, true) or low:find(".write", 1, true) then
        if low:find("true", 1, true) then
          fire = fire + 1
          table.insert(out, "[FIRE] regras legiveis com true em .read/.write: " .. base .. " :: " .. preview(rbody, 120))
        else
          table.insert(out, "[?] rules.json legivel sem true literal: " .. base)
        end
      end
    end
    -- leitura fina: shallow=true confirma dados alcancaveis
    local surl = base .. "/.json?shallow=true"
    local sbody = http_get(surl)
    if string.sub(sbody, 1, 8) ~= "__ERRO__" then
      local slow = lower(sbody)
      if not slow:find("permission denied", 1, true) and not slow:find("error", 1, true) and #sbody > 10 then
        fire = fire + 1
        table.insert(out, "[FIRE] shallow=true com dados: " .. base)
      end
    end
  end
  if fire > 0 then
    table.insert(out, "[VEREDITO] CRITICO — regras/dados Firebase abertos.")
  else
    table.insert(out, "[VEREDITO] ok — regras segurando.")
  end
  return table.concat(out, "\n")
end
