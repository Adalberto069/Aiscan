-- modules/supabase_enum.lua
-- RLS real: acha anon key (HTML + bundles full) e testa /rest/v1/<tabela>
-- ctx = { target=..., html=..., techs=... }

function run(ctx)
  local html = ctx['html'] or ""
  local target = ctx['target'] or ""
  local out = {"[*] supabase_enum: cacada RLS com anon key"}

  local bases, seen_b = {}, {}
  local function add_base(u)
    if u ~= nil and not seen_b[u] then seen_b[u] = true table.insert(bases, u) end
  end
  for _, u in ipairs(find_regex(html, "https://[a-z0-9\\-]+\\.supabase\\.co")) do add_base(u) end

  -- JWTs no HTML + bundles full. Medido em campo: config Supabase mora além
  -- de 500KB no vendor (byte ~552k) — caçada vai a 2MB por bundle.
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
      for _, b2 in ipairs(find_regex(body, "https://[a-z0-9\\-]+\\.supabase\\.co")) do add_base(b2) end
    end
  end

  if #bases == 0 then
    return "[-] supabase_enum: nenhuma URL supabase.co no HTML/bundles."
  end

  local anon, svc = {}, {}
  for _, t in ipairs(tokens) do
    local d = decode_jwt_payload(t)
    if d ~= nil and d['ok'] then
      if d['role'] == 'service_role' then table.insert(svc, t)
      elseif d['role'] == 'anon' then table.insert(anon, t) end
    end
  end
  for _, t in ipairs(svc) do
    table.insert(out, "[FIRE] P0 service_role exposta no front :: " .. preview(t, 40))
  end
  if #anon == 0 then
    table.insert(out, "[-] URL Supabase visível, mas sem anon key no HTML/bundles — não dá pra validar RLS. Cheque o bundle JS.")
    return table.concat(out, "\n")
  end

  local key = anon[1]
  table.insert(out, "[*] anon key pescada (role=anon) — testando tabelas com auth...")
  -- OpenAPI spec exige service_role (401-by-design p/ anon) — lista fixa verificada.
  local tabelas = {"profiles", "users", "user_roles", "orders", "scripts", "products",
                   "customers", "leads", "messages", "posts", "comments", "downloads"}
  local expostas = {}
  for _, base in ipairs(bases) do
    for _, t in ipairs(tabelas) do
      throttle(200)
      local url = base .. "/rest/v1/" .. t .. "?select=*&limit=1&apikey=" .. key
      local code = http_status(url)
      if code == 200 or code == 206 then
        local body = http_get(url)
        if string.sub(body, 1, 8) ~= "__ERRO__" then
          local low = lower(body)
          if #body > 10 and not low:find("42501", 1, true) and not low:find("permission denied", 1, true) then
            table.insert(expostas, t)
            table.insert(out, "[FIRE] CRITICO tabela legível: " .. t .. " em " .. base .. " :: " .. preview(body, 120))
          end
        end
      end
      -- 401/403 = policy bloqueia; 404 = tabela não existe. Ambos: silêncio.
    end
  end
  if #expostas == 0 then
    table.insert(out, "[+] RLS segurando: nenhuma tabela comum legível com a anon key.")
  else
    table.insert(out, "[VEREDITO] CRITICO — RLS off/permissivo: " .. #expostas .. " tabela(s) com dados.")
  end
  return table.concat(out, "\n")
end
