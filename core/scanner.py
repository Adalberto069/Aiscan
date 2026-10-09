import requests
import re
from bs4 import BeautifulSoup

class AIParser:
    def __init__(self, url):
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        self.url = url
        self.headers = {'User-Agent': 'AIScan-Engine/2.0 (Security Research/Bug Bounty)'}
        self.html_content = ""

    def capturar_html(self):
        try:
            response = requests.get(self.url, headers=self.headers, timeout=10)
            if response.status_code == 200:
                self.html_content = response.text
                return True
            return False
        except Exception:
            return False

    def detectar_infraestrutura(self):
        resultados = {
            "is_ai_generated": False,
            "techs_detectadas": [],
            "alertas": []
        }

        if not self.html_content:
            return resultados

        html_low = self.html_content.lower()

        # 1. Busca por assinaturas estruturais de ferramentas No-Code / Build de IA (Lovable e Bolt.new)
        if "lovable" in html_low or "bolt.new" in html_low:
            resultados["techs_detectadas"].append("Mecanismo Autônomo de IA (Lovable/Bolt)")
            resultados["is_ai_generated"] = True

        if "src/integrations/supabase" in html_low or 'src="main.tsx"' in html_low or "/assets/index-" in html_low:
            resultados["techs_detectadas"].append("Vite Build Engine (Padrão Bolt.new/Lovable)")
            resultados["is_ai_generated"] = True

        # 2. Busca por componentes estruturais de injeção de código do Radix / Shadcn (Assinatura v0.app)
        if "data-radix-" in html_low or "--radix-popper" in html_low:
            resultados["techs_detectadas"].append("Shadcn/ui Components (Assinatura v0.app)")
            resultados["is_ai_generated"] = True

        # 3. Busca refinada de Tailwind para evitar falsos positivos
        if "tailwindcss" in html_low or "tw-body" in html_low:
            resultados["techs_detectadas"].append("Tailwind CSS Engine")
            resultados["is_ai_generated"] = True

        # 4. Detecção de conexões diretas expostas no front-end
        if "supabase.co" in html_low:
            resultados["techs_detectadas"].append("Supabase Backend")
            resultados["alertas"].append("[🚨] ALERTA: Conexão direta com banco Supabase identificada!")
            resultados["is_ai_generated"] = True

        if "firebaseio.com" in html_low:
            resultados["techs_detectadas"].append("Firebase Realtime DB")
            resultados["alertas"].append("[🚨] ALERTA: Endpoints do Firebase vazando no cliente.")
            resultados["is_ai_generated"] = True

        return resultados
