import re
from bs4 import BeautifulSoup
from core.scope import guarded

class AIParser:
    def __init__(self, url, lab_mode=False):
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        self.url = url
        self.lab_mode = lab_mode
        self.headers = {'User-Agent': 'AIScan-Engine/2.0 (Security Research/Bug Bounty)'}
        self.html_content = ""

    def capturar_html(self):
        r, info = guarded("GET", self.url, headers=self.headers, timeout=10,
                          lab_mode=self.lab_mode)
        if r is None:
            return False
        if r.status_code == 200:
            self.html_content = (r.text or "")
            self._carregar_bundles()
            return True
        return False

    def _carregar_bundles(self, limite=5):
        """Baixa bundles /assets/*.js e concatena — HTML casca Lovable não dispara nada sozinho."""
        try:
            baixados = 0
            for src in re.findall(r'src="(/assets/[^"]+\.js[^"]*)"', self.html_content or ""):
                if baixados >= limite:
                    break
                base = self.url.rstrip('/')
                r, _ = guarded("GET", base + src.split('"')[0], headers=self.headers,
                               timeout=8, lab_mode=self.lab_mode)
                if r is not None and r.status_code == 200 and r.text:
                    self.html_content += "\n<!-- bundle:" + src + " -->\n" + r.text[:30000]
                    baixados += 1
        except Exception:
            pass

    # Assinatura -> (label, peso). Score >= 3 decide IA.
    PESOS = [
        ("lovable", ("Lovable.dev", 3)),
        ("bolt.new", ("Bolt.new", 3)),
        ("v0.dev", ("v0.dev", 3)),
        ("data-radix-", ("Shadcn/Radix (v0.app)", 2)),
        ("--radix-popper", ("Shadcn/Radix (v0.app)", 2)),
        ("/assets/index-", ("Vite bundle hash (Bolt/Lovable)", 2)),
        ('src="main.tsx"', ("Vite main.tsx (Bolt/Lovable)", 2)),
        ("tailwindcss", ("Tailwind CSS Engine", 1)),
        ("supabase.co", ("Supabase Backend", 1)),
        ("firebaseio.com", ("Firebase Realtime DB", 1)),
        ("_next/static", ("Next.js static export", 1)),
    ]

    def detectar_infraestrutura(self):
        resultados = {
            "is_ai_generated": False,
            "techs_detectadas": [],
            "alertas": [],
            "score": 0,
        }

        if not self.html_content:
            return resultados

        html_low = self.html_content.lower()
        score, vistas = 0, set()

        for sinal, (label, peso) in self.PESOS:
            if sinal in html_low and label not in vistas:
                vistas.add(label)
                score += peso
                resultados["techs_detectadas"].append(label)

        resultados["score"] = score
        resultados["is_ai_generated"] = score >= 3

        if "supabase.co" in html_low and score >= 2:
            resultados["alertas"].append("[🚨] ALERTA: Conexão direta com banco Supabase identificada!")

        if "firebaseio.com" in html_low and score >= 2:
            resultados["alertas"].append("[🚨] ALERTA: Endpoints do Firebase vazando no cliente.")

        return resultados
