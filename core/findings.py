"""Modelo central de achados do AIScan.

Antes disso cada módulo devolvia só string e o pipeline contava "[FIRE]" na
unha — frágil e sem severidade/CWE/evidência real. Aqui os achados viram dado
estruturado, deduplicado e serializável (JSON, SARIF 2.1.0, HTML).

Nada de PII crua: a evidência já deve chegar redacted pelos módulos. Este
módulo não mascara valores de novo — só transporta e formata.
"""
import html as _html
import json
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone

# Severidade canônica (pt-BR, como o resto do projeto). Ordem = prioridade.
SEV_ORDER = ["CRITICA", "ALTA", "MEDIA", "BAIXA", "INFO"]
SEV_RANK = {s: i for i, s in enumerate(SEV_ORDER)}

# Severidade -> nível SARIF.
_SARIF_LEVEL = {"CRITICA": "error", "ALTA": "error", "MEDIA": "warning",
                "BAIXA": "note", "INFO": "note"}

# Cor por severidade (chips do HTML). Paleta acessível em claro/escuro.
_SEV_COLOR = {"CRITICA": "#b4232a", "ALTA": "#c2410c", "MEDIA": "#b45309",
              "BAIXA": "#2563eb", "INFO": "#475569"}


def normalizar_severidade(valor, default="INFO"):
    """Aceita variações ('critico', 'high', '-') e devolve canônico."""
    if not valor:
        return default
    v = str(valor).strip().upper()
    alias = {"CRITICAL": "CRITICA", "CRÍTICA": "CRITICA", "CRITICO": "CRITICA",
             "CRÍTICO": "CRITICA", "HIGH": "ALTA", "MEDIUM": "MEDIA",
             "MÉDIA": "MEDIA", "MÉDIO": "MEDIA", "LOW": "BAIXA", "-": "INFO"}
    v = alias.get(v, v)
    return v if v in SEV_RANK else default


@dataclass
class Finding:
    """Um achado. `evidence` é dict/str já seguro para log."""
    title: str
    severity: str = "INFO"
    confidence: str = "MEDIA"
    module: str = ""
    target: str = ""
    category: str = ""
    cwe: str = ""              # ex: "CWE-1021"
    description: str = ""
    remediation: str = ""
    evidence: object = field(default_factory=dict)
    verdict: str = ""          # passthrough do veredito original (authz etc.)
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc)
                           .isoformat(timespec="seconds"))

    def __post_init__(self):
        self.severity = normalizar_severidade(self.severity)
        self.confidence = (self.confidence or "MEDIA").upper()

    @property
    def rank(self):
        return SEV_RANK.get(self.severity, len(SEV_ORDER))

    def dedupe_key(self):
        """Dois achados do mesmo módulo+alvo+título+categoria são o mesmo."""
        return (self.module, self.target, self.category, self.title)


class FindingsStore:
    """Coletor único do scan. Deduplica e ordena por severidade."""

    def __init__(self, target=""):
        self.target = target
        self._itens = []
        self._vistos = set()

    def add(self, finding):
        if not isinstance(finding, Finding):
            return None
        if not finding.target:
            finding.target = self.target
        k = finding.dedupe_key()
        if k in self._vistos:
            return None
        self._vistos.add(k)
        self._itens.append(finding)
        return finding

    def add_dict(self, **kw):
        return self.add(Finding(**kw))

    def __len__(self):
        return len(self._itens)

    def __iter__(self):
        return iter(self.ordenados())

    def ordenados(self):
        return sorted(self._itens, key=lambda f: (f.rank, f.module, f.title))

    def apenas_fire(self):
        """Achados que valem alarme (exclui INFO/BAIXA informativos)."""
        return [f for f in self.ordenados() if f.severity in ("CRITICA", "ALTA", "MEDIA")]

    def resumo(self):
        """Contagem por severidade, sempre com todas as chaves."""
        r = {s: 0 for s in SEV_ORDER}
        for f in self._itens:
            r[f.severity] = r.get(f.severity, 0) + 1
        return r

    # ---- serializers -------------------------------------------------------

    def to_json(self, indent=2):
        payload = {
            "tool": "AIScan",
            "version": "1.0.0-PRO",
            "target": self.target,
            "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "summary": {"total": len(self._itens), **self.resumo()},
            "findings": [asdict(f) for f in self.ordenados()],
        }
        return json.dumps(payload, ensure_ascii=False, indent=indent)

    def to_sarif(self):
        """SARIF 2.1.0 — consumível por GitHub code scanning, DefectDojo etc."""
        regras, idx_regra = [], {}
        resultados = []
        for f in self.ordenados():
            rule_id = f.category or "generic"
            if rule_id not in idx_regra:
                idx_regra[rule_id] = len(regras)
                regras.append({
                    "id": rule_id,
                    "name": rule_id.replace("-", " ").title().replace(" ", ""),
                    "shortDescription": {"text": rule_id},
                    "properties": {"tags": [c for c in (f.cwe,) if c]},
                })
            resultados.append({
                "ruleId": rule_id,
                "ruleIndex": idx_regra[rule_id],
                "level": _SARIF_LEVEL.get(f.severity, "note"),
                "message": {"text": f"{f.title}"
                            + (f" — {f.description}" if f.description else "")},
                "properties": {
                    "severity": f.severity, "confidence": f.confidence,
                    "module": f.module, "cwe": f.cwe, "verdict": f.verdict,
                    "remediation": f.remediation,
                    "evidence": f.evidence,
                },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": f.target or self.target}
                    }
                }],
            })
        sarif = {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {"driver": {
                    "name": "AIScan",
                    "version": "1.0.0-PRO",
                    "informationUri": "https://github.com/",
                    "rules": regras,
                }},
                "results": resultados,
            }],
        }
        return json.dumps(sarif, ensure_ascii=False, indent=2)

    def to_html(self):
        return _render_html(self)


def _ev_to_html(ev):
    if ev in (None, "", {}, []):
        return ""
    try:
        txt = json.dumps(ev, ensure_ascii=False, indent=2) if not isinstance(ev, str) else ev
    except Exception:
        txt = str(ev)
    return f"<pre class='ev'>{_html.escape(txt)}</pre>"


def _render_html(store):
    resumo = store.resumo()
    gerado = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    tiles = []
    for s in SEV_ORDER:
        n = resumo.get(s, 0)
        cor = _SEV_COLOR[s]
        apagado = "" if n else " style='opacity:.4'"
        tiles.append(
            f"<div class='tile'{apagado}><span class='dot' style='background:{cor}'></span>"
            f"<span class='n'>{n}</span><span class='lbl'>{s}</span></div>")

    linhas = []
    for f in store.ordenados():
        cor = _SEV_COLOR.get(f.severity, "#475569")
        cwe = f"<span class='cwe'>{_html.escape(f.cwe)}</span>" if f.cwe else ""
        rem = (f"<div class='rem'><b>Correção:</b> {_html.escape(f.remediation)}</div>"
               if f.remediation else "")
        desc = f"<div class='desc'>{_html.escape(f.description)}</div>" if f.description else ""
        linhas.append(f"""
      <details class='card'>
        <summary>
          <span class='chip' style='background:{cor}'>{_html.escape(f.severity)}</span>
          <span class='title'>{_html.escape(f.title)}</span>
          {cwe}
          <span class='meta'>{_html.escape(f.module)} · conf {_html.escape(f.confidence)}</span>
        </summary>
        <div class='body'>
          {desc}{rem}
          {_ev_to_html(f.evidence)}
        </div>
      </details>""")

    if not linhas:
        linhas = ["<p class='empty'>Nenhum achado registrado neste scan.</p>"]

    return f"""<!doctype html>
<html lang='pt-BR'><head><meta charset='utf-8'>
<meta name='viewport' content='width=device-width,initial-scale=1'>
<title>AIScan — {_html.escape(store.target)}</title>
<style>
  :root {{ color-scheme: light dark; }}
  body {{ font: 15px/1.5 ui-sans-serif,system-ui,Segoe UI,Roboto,sans-serif;
    margin:0; background:#0f1115; color:#e6e8ec; }}
  @media (prefers-color-scheme: light) {{ body {{ background:#f6f7f9; color:#1a1c20; }} }}
  .wrap {{ max-width:960px; margin:0 auto; padding:32px 20px 64px; }}
  h1 {{ font-size:22px; margin:0 0 2px; }}
  .sub {{ opacity:.65; font-size:13px; margin-bottom:24px; }}
  .tiles {{ display:flex; gap:12px; flex-wrap:wrap; margin-bottom:28px; }}
  .tile {{ display:flex; align-items:center; gap:8px; padding:12px 16px;
    border:1px solid #ffffff22; border-radius:12px; background:#ffffff0a; }}
  .tile .dot {{ width:10px; height:10px; border-radius:50%; }}
  .tile .n {{ font-size:20px; font-weight:700; }}
  .tile .lbl {{ font-size:12px; opacity:.7; letter-spacing:.04em; }}
  .card {{ border:1px solid #ffffff1c; border-radius:12px; margin-bottom:10px;
    background:#ffffff08; overflow:hidden; }}
  summary {{ display:flex; align-items:center; gap:10px; padding:12px 16px;
    cursor:pointer; list-style:none; }}
  summary::-webkit-details-marker {{ display:none; }}
  .chip {{ color:#fff; font-size:11px; font-weight:700; padding:2px 8px;
    border-radius:999px; letter-spacing:.03em; }}
  .title {{ font-weight:600; }}
  .cwe {{ font-size:11px; opacity:.7; border:1px solid #ffffff33;
    padding:1px 6px; border-radius:6px; }}
  .meta {{ margin-left:auto; font-size:12px; opacity:.6; }}
  .body {{ padding:0 16px 14px; }}
  .desc {{ margin:4px 0 8px; opacity:.9; }}
  .rem {{ margin:4px 0 8px; font-size:13px; opacity:.85; }}
  pre.ev {{ background:#00000040; border:1px solid #ffffff14; border-radius:8px;
    padding:10px 12px; overflow:auto; font-size:12.5px; }}
  .empty {{ opacity:.6; }}
</style></head>
<body><div class='wrap'>
  <h1>AIScan — relatório de achados</h1>
  <div class='sub'>Alvo: <b>{_html.escape(store.target or '—')}</b> · {len(store)} achado(s) · {gerado}</div>
  <div class='tiles'>{''.join(tiles)}</div>
  {''.join(linhas)}
</div></body></html>"""
