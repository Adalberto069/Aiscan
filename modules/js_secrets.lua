-- modules/js_secrets.lua
-- OBRIGATÓRIO BETA: caça secrets no HTML + bundle JS (padrão vibe-coded)
-- ctx = { target=..., html=... }
-- NOTE: find_regex usa regex Python (não pattern Lua).

function run(ctx)
  local html = ctx['html'] or ""
  local target = ctx['target'] or ""
  local out = {"[*] js_secrets: varredura de chaves expostas"}

  local py_patterns = {
    {"eyJ[A-Za-z0-9_\\-]+\\.eyJ[A-Za-z0-9_\\-]+\\.[A-Za-z0-9_\\.\\-]+", "JWT/Supabase-anon (formato eyJ...)"},
    {"sbp_[a-f0-9]+", "Supabase sbp_ token"},
    {"sk_live_[A-Za-z0-9]{24,}", "Stripe secret sk_live"},
    {"pk_live_[A-Za-z0-9]{24,}", "Stripe publishable pk_live"},
    {"sk\\-proj\\-[A-Za-z0-9_\\-]{40,}", "OpenAI project key"},
    {"sk\\-ant\\-[A-Za-z0-9_\\-]{40,}", "Anthropic key"},
    {"sk\\-[A-Za-z0-9]{20,}T3BlbkFJ[A-Za-z0-9]{20,}", "OpenAI legacy key"},
    {"AKIA[0-9A-Z]{16}", "AWS access key"},
    {"ghp_[A-Za-z0-9]{36}", "GitHub PAT"},
    {"xox[baprs]\\-[A-Za-z0-9\\-]+", "Slack token"},
    {"AIza[0-9A-Za-z\\-_]+", "Google API key (AIza...)"},
    {"VITE_[A-Z_]+", "VITE_* env vazada no front"},
    {"NEXT_PUBLIC_[A-Z_]+", "NEXT_PUBLIC_* env vazada no front"},
    {"supabase\\.co", "URL supabase no codigo"},
  }
  local achou = 0
  for _, p in ipairs(py_patterns) do
    local hits = find_regex(html, p[1])
    if #hits > 0 then
      achou = achou + 1
      table.insert(out, "[FIRE] " .. p[2] .. " x" .. #hits .. " :: " .. preview(tostring(hits[1]), 60))
    end
  end

  local js_urls = find_regex(html, "https?://[^\"'\\s]+\\.js[^\"'\\s]*")
  local rel = find_regex(html, "/assets/[^\"'\\s]+\\.js")
  for _, r in ipairs(rel) do
    if #js_urls < 10 then table.insert(js_urls, r) end
  end
  -- prioridade: bundle com nome quente primeiro (chave vive fora do vendor)
  local quentes, frios = {}, {}
  for _, u in ipairs(js_urls) do
    local l = lower(u)
    if l:find("supabase", 1, true) or l:find("firebase", 1, true) or l:find("config", 1, true) or l:find("env", 1, true) then
      table.insert(quentes, u)
    else
      table.insert(frios, u)
    end
  end
  for _, u in ipairs(frios) do table.insert(quentes, u) end
  js_urls = quentes
  if #js_urls == 0 then
    table.insert(out, "[-] nenhum bundle .js achado no HTML (site pode ser SSR puro).")
  else
    table.insert(out, "[*] " .. #js_urls .. " bundle(s) JS pra auditar (limite 5, quentes primeiro)")
    local n, vistas = 0, {}
    for _, u in ipairs(js_urls) do
      if n >= 5 then break end
      local full = u
      if string.sub(u, 1, 1) == "/" then
        full = target .. u
      end
      if not vistas[full] then
        vistas[full] = true
        n = n + 1
      -- bundle full: secret mora além dos 20KB do http_get (medido: 552KB+)
      local body = http_get_full(full, 2000000)
      if string.sub(body, 1, 8) == "__ERRO__" then
        table.insert(out, "[-] falha ao baixar: " .. u)
      else
        for _, p in ipairs(py_patterns) do
          local hits = find_regex(body, p[1])
          if #hits > 0 then
            achou = achou + 1
            table.insert(out, "[FIRE] bundle " .. u .. " :: " .. p[2] .. " x" .. #hits)
          end
        end
      end
      end
    end
  end

  if achou == 0 then
    table.insert(out, "[OK] nenhuma secret classica no HTML/bundles (amostra 5 arquivos).")
  else
    table.insert(out, "[VEREDITO] " .. achou .. " sinal(is) de secret — tratar como P1 ate provar que e public/anon com RLS.")
  end
  return table.concat(out, "\n")
end
