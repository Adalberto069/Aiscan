-- modules/ai_signatures.lua
-- Fingerprint de site vibe-coded: Lovable / Bolt / v0 / Firebase / Supabase / Next static
-- ctx = { html=..., techs=... }

function run(ctx)
  -- lower() é Python (Unicode-correto). string.lower do Lua corrompe UTF-8.
  local html = lower(ctx['html'] or "")
  local out = {"[*] ai_signatures: fingerprint de build IA"}
  local sigs = {
    {"lovable", "Lovable.dev"},
    {"bolt\\.new", "Bolt.new"},
    {"data-radix-", "Shadcn/Radix (v0.app)"},
    {"src=\"main\\.tsx\"", "Vite main.tsx (Bolt/Lovable)"},
    {"/assets/index-", "Vite bundle hash (Bolt/Lovable)"},
    {"supabase\\.co", "Supabase exposto no front"},
    {"firebaseio\\.com", "Firebase exposto no front"},
    {"_next/static", "Next.js static (v0/Lovable export)"},
    {"tailwindcss", "Tailwind (default dos geradores IA)"}
  }
  local score = 0
  for _, s in ipairs(sigs) do
    local hits = find_regex(html, s[1])
    if #hits > 0 then
      score = score + 1
      table.insert(out, "[+] " .. s[2] .. " x" .. #hits)
    end
  end
  if score >= 3 then
    table.insert(out, "[VEREDITO] ALTA confiança: site vibe-coded (" .. score .. "/9 sinais). Prioridade máxima pra RLS/headers/keys expostas.")
  elseif score >= 1 then
    table.insert(out, "[VEREDITO] MÉDIA: " .. score .. " sinal(is). Vale auditar JS bundle.")
  else
    table.insert(out, "[VEREDITO] BAIXA: nenhum sinal clássico.")
  end
  return table.concat(out, "\n")
end
