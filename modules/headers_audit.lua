-- Auditoria de cabeçalhos HTTP: presença, contexto e evidência.
function run(ctx)
  local target = ctx['target'] or ""
  if target == "" then return "[-] headers_audit: sem target." end
  local out = {"[*] headers_audit: " .. target}
  local norm = {}
  for k, v in pairs(http_headers(target)) do
    norm[string.lower(k)] = v
  end
  if next(norm) == nil then
    return table.concat({out[1], "[?] Resposta sem cabeçalhos disponíveis; auditoria inconclusiva."}, "\n")
  end

  local function report(title, sev, category, cwe, description, fix, evidence)
    add_finding({title=title, severity=sev, confidence="ALTA",
                 category=category, cwe=cwe, description=description,
                 remediation=fix, evidence=evidence})
  end

  local csp = lower(norm["content-security-policy"] or "")
  local xfo = lower(norm["x-frame-options"] or ""):match("^%s*(.-)%s*$")
  local has_ancestors = false
  for directive in csp:gmatch("[^;]+") do
    local name, value = directive:match("^%s*([^%s]+)%s+(.+)")
    if name == "frame-ancestors" and value:match("%S") and not value:find("*", 1, true) then
      has_ancestors = true
    end
  end
  if not has_ancestors and xfo ~= "deny" and xfo ~= "sameorigin" then
    table.insert(out, "[FALHA] Proteção contra enquadramento não identificada.")
    report("Proteção contra enquadramento não identificada", "MEDIA",
           "framing-protection", "CWE-1021",
           "Não foi identificada uma restrição de enquadramento reconhecida. O impacto depende de uma interface sensível e requer validação.",
           "Definir frame-ancestors conforme a política da aplicação e verificar em navegador.",
           {csp_present=csp ~= "", xfo_present=xfo ~= ""})
  else
    table.insert(out, "[OK] Indicador de proteção contra enquadramento presente (validar política).")
  end

  local headers = {"content-security-policy", "strict-transport-security",
                   "x-content-type-options", "referrer-policy", "permissions-policy"}
  for _, name in ipairs(headers) do
    if norm[name] == nil or norm[name]:match("^%s*$") then
      table.insert(out, "[FALHA] ausente: " .. name)
      -- Sem duplicar ausência de CSP como falha de clickjacking.
      report("Header de segurança ausente: " .. name, "BAIXA",
             "missing-security-header", "CWE-693",
             "Resposta não envia " .. name .. ". Ausência não comprova exploração.",
             "Avaliar e configurar o header conforme a política da aplicação.",
             {header=name})
    else
      table.insert(out, "[OK] presente: " .. name)
    end
  end

  local acao = norm["access-control-allow-origin"]
  local acac = lower(norm["access-control-allow-credentials"] or "")
  if acao == "*" then
    if acac == "true" then
      table.insert(out, "[FIRE] CORS wildcard com credenciais: configuração incompatível com navegadores.")
      report("CORS wildcard com credenciais", "BAIXA", "cors-misconfig", "CWE-942",
             "Navegadores conformes bloqueiam respostas credentialed com ACAO wildcard; isso não comprova bypass.",
             "Usar origens explícitas quando credenciais forem necessárias.",
             {allow_origin="*", allow_credentials=true})
    else
      table.insert(out, "[INFO] CORS wildcard: pode ser intencional em recursos públicos.")
      report("CORS wildcard observado", "INFO", "cors-observation", "",
             "Acesso cross-origin público não é, por si só, uma vulnerabilidade.",
             "Revisar a classificação dos recursos retornados.",
             {allow_origin="*"})
    end
  else
    table.insert(out, "[OK] sem CORS wildcard nesta resposta.")
  end
  return table.concat(out, "\n")
end
