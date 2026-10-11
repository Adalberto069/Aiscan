-- modules/storage_bucket_public.lua
-- Supabase Storage com buckets enumeraveis sem auth (vazamento de nomes/paths)
-- ctx = { target=..., html=..., techs=... }

function run(ctx)
  local html = ctx['html'] or ""
  local hits = find_regex(html, "https://[a-z0-9\\-]+\\.supabase\\.co")
  if hits == nil or #hits == 0 then
    return "[-] storage_bucket_public: nenhuma URL supabase.co no HTML."
  end
  local bases, seen = {}, {}
  for _, u in ipairs(hits) do
    if not seen[u] then seen[u] = true table.insert(bases, u) end
  end
  local out = {"[*] storage_bucket_public: " .. #bases .. " base(s)"}
  local fire = 0
  for _, base in ipairs(bases) do
    local url = base .. "/storage/v1/bucket"
    local body = http_get(url)
    if string.sub(body, 1, 8) == "__ERRO__" then
      table.insert(out, "[-] falha ao conectar: " .. url)
    else
      local names = find_regex(body, "\"name\"\\s*:\\s*\"[^\"]+\"")
      if #names > 0 then
        fire = fire + 1
        table.insert(out, "[FIRE] buckets enumeraveis sem auth (" .. #names .. "): " .. url)
        for i = 1, math.min(#names, 5) do
          table.insert(out, "      :: " .. preview(tostring(names[i]), 60))
        end
      else
        table.insert(out, "[OK] bucket list sem nomes enumeraveis: " .. base)
      end
    end
  end
  if fire > 0 then
    table.insert(out, "[VEREDITO] ALTA — buckets/storage enumeravel sem auth.")
  else
    table.insert(out, "[VEREDITO] ok — storage sem enumeracao anonima.")
  end
  return table.concat(out, "\n")
end
