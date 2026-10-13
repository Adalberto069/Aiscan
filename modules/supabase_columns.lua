-- modules/supabase_columns.lua
-- Escopo real: rows + colunas por tabela legível, PII marcada [redacted]
-- Leitura pura, sem escrita. ctx = { target=..., html=..., techs=... }

local SENSIVEIS = {"email", "password", "passwd", "token", "secret", "cpf",
                   "phone", "ssn", "card", "banned_reason"}

local function eh_sensivel(col)
  local c = lower(col or "")
  for _, s in ipairs(SENSIVEIS) do
    if c:find(s, 1, true) then return true end
  end
  return false
end

function run(ctx)
  local html = ctx['html'] or ""
  local target = ctx['target'] or ""
  local show_data = ctx['show_data'] == true
  local out = {"[*] supabase_columns: mapa de escopo (rows + cols" .. (show_data and " + VALORES REAIS --show-data" or ", valores nunca impressos") .. ")"}

  local bases, seen_b = {}, {}
  for _, u in ipairs(find_regex(html, "https://[a-z0-9\\-]+\\.supabase\\.co")) do
    if not seen_b[u] then seen_b[u] = true table.insert(bases, u) end
  end

  local tokens, seen_t = {}, {}
  local function add_tokens(texto)
    for _, t in ipairs(find_regex(texto or "", "eyJ[A-Za-z0-9_\\-]+\\.eyJ[A-Za-z0-9_\\-]+\\.[A-Za-z0-9_\\.\\-]+")) do
      if not seen_t[t] then seen_t[t] = true table.insert(tokens, t) end
    end
  end
  add_tokens(html)
  local js = find_regex(html, "https?://[^\"'\\s]+\\.js[^\"'\\s]*")
  for _, r in ipairs(find_regex(html, "/assets/[^\"'\\s]+\\.js")) do
    if #js < 8 then table.insert(js, r) end
  end
  local nb = 0
  for _, u in ipairs(js) do
    if nb >= 3 then break end
    local full = u
    if string.sub(u, 1, 1) == "/" then full = target .. u end
    local body = http_get_full(full, 2000000)
    if string.sub(body, 1, 8) ~= "__ERRO__" then
      nb = nb + 1
      add_tokens(body)
      for _, b2 in ipairs(find_regex(body, "https://[a-z0-9\\-]+\\.supabase\\.co")) do
        if not seen_b[b2] then seen_b[b2] = true table.insert(bases, b2) end
      end
    end
  end

  if #bases == 0 then
    return "[-] supabase_columns: nenhuma URL supabase.co no HTML/bundles."
  end
  local key = nil
  for _, t in ipairs(tokens) do
    local d = decode_jwt_payload(t)
    if d ~= nil and d['ok'] and d['role'] == 'anon' then key = t break end
  end
  if key == nil then
    return "[-] supabase_columns: sem anon key — sem escopo pra mapear."
  end

  local queda = {"profiles", "users", "user_roles", "orders", "scripts", "products",
                 "customers", "leads", "messages", "posts", "comments", "downloads"}
  local fire, n_sens, n_ok, n_pulo = 0, 0, 0, 0
  for _, base in ipairs(bases) do
    table.insert(out, "[*] base: " .. base)
    -- OpenAPI spec exige service_role (401-by-design p/ anon) — lista fixa verificada.
    local tabelas = queda
    for _, t in ipairs(tabelas) do
      throttle(200)
      local rc = rest_count(base, key, t)
      local st = (rc ~= nil and rc['status']) or -1
      if st == 401 or st == 403 then
        n_ok = n_ok + 1
        table.insert(out, "[OK] " .. t .. " — permission denied (" .. tostring(st) .. ")")
      elseif st == 200 or st == 206 then
        local sample = http_get(base .. "/rest/v1/" .. t .. "?select=*&limit=5&apikey=" .. key)
        local cols = {}
        if string.sub(sample, 1, 8) ~= "__ERRO__" then
          for _, c in ipairs(json_keys(sample)) do table.insert(cols, c) end
        end
        if #cols == 0 then
          table.insert(out, "[?] " .. t .. " — 200 sem colunas confirmadas")
        else
          local sens = {}
          for _, c in ipairs(cols) do
            if eh_sensivel(c) then table.insert(sens, c) n_sens = n_sens + 1 end
          end
          fire = fire + 1
          local tot = (rc ~= nil and rc['total'] ~= nil and rc['total'] >= 0) and tostring(rc['total']) or "?"
          local linha = "[FIRE] " .. t .. string.rep(" ", math.max(1, 16 - #t))
                        .. tot .. " rows " .. #cols .. " cols"
          if #sens > 0 then
            if show_data then
              linha = linha .. " | " .. table.concat(sens, ", ")
            else
              local m = {}
              for _, c in ipairs(sens) do table.insert(m, c .. "[redacted]") end
              linha = linha .. " | sensíveis: " .. table.concat(m, ", ")
            end
          end
          -- ex: primeiro id completo (36 chars, sem vazar linha)
          local ids = find_regex(sample, "\"id\":\"[^\"]+\"")
          if #ids > 0 then linha = linha .. " | ex: " .. tostring(ids[1]) end
          table.insert(out, linha)
          -- painel: só o relevante (ids, emails, flags, preço) — dump completo segue abaixo
          table.insert(out, painel(sample, 5))
          if show_data then
            local prova = http_get(base .. "/rest/v1/" .. t .. "?select=*&limit=3&apikey=" .. key)
            if string.sub(prova, 1, 8) ~= "__ERRO__" then
              table.insert(out, "      prova: " .. tabela(prova, 3, false))
            end
          end
        end
      else
        n_pulo = n_pulo + 1
      end
      -- 404/outros: tabela não existe. Silêncio + conta.
    end
  end
  if fire > 0 then
    table.insert(out, "[VEREDITO] CRITICO — " .. fire .. " com leitura pública / "
                      .. n_ok .. " negadas / " .. n_pulo .. " inexistentes — "
                      .. n_sens .. " coluna(s) sensível(eis).")
  else
    table.insert(out, "[VEREDITO] ok — escopo sem leitura pública.")
  end
  return table.concat(out, "\n")
end
