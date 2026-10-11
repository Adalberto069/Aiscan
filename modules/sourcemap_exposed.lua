-- modules/sourcemap_exposed.lua
-- Testa <bundle>.map — sourcemap vaza codigo-fonte original
-- ctx = { target=..., html=..., techs=... }

function run(ctx)
  local html = ctx['html'] or ""
  local target = ctx['target'] or ""
  local js = find_regex(html, "https?://[^\"'\\s]+\\.js[^\"'\\s]*")
  local rel = find_regex(html, "/assets/[^\"'\\s]+\\.js")
  for _, r in ipairs(rel) do
    if #js < 6 then table.insert(js, r) end
  end
  if #js == 0 then
    return "[-] sourcemap_exposed: nenhum bundle .js no HTML."
  end
  local out = {"[*] sourcemap_exposed: " .. #js .. " bundle(s) (limite 3)"}
  local fire = 0
  local n = 0
  for _, u in ipairs(js) do
    if n >= 3 then break end
    n = n + 1
    local full = u
    if string.sub(u, 1, 1) == "/" then full = target .. u end
    local map_url = full .. ".map"
    if http_head(map_url) == 200 then
      local body = http_get(map_url)
      if string.sub(body, 1, 8) == "__ERRO__" then
        table.insert(out, "[?] " .. map_url .. " (HTTP 200, falha ao ler)")
      elseif #find_regex(body, "\"sources\"") > 0 then
        fire = fire + 1
        table.insert(out, "[FIRE] sourcemap com sources: " .. map_url)
      else
        table.insert(out, "[?] " .. map_url .. " (HTTP 200, sem bloco sources)")
      end
    end
  end
  if fire > 0 then
    table.insert(out, "[VEREDITO] ALTA — codigo-fonte original vazando via .map.")
  else
    table.insert(out, "[VEREDITO] ok — nenhum .map com sources.")
  end
  return table.concat(out, "\n")
end
