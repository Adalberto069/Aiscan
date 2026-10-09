import requests
import re
from bs4 import BeautifulSoup

class AIParser:
    def __init__(self, url):
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        self.url = url
        self.headers = {'User-Agent': 'AIScan-Engine/2.0 (Security Research)'}
        self.html_content = ""

    def capturar_html(self):
        """Baixa o conteúdo do site alvo"""
        try:
            response = requests.get(self.url, headers=self.headers, timeout=10)
            if response.status_code == 200:
                self.html_content = response.text
                return True
            return False
        except Exception:
            return False

    def detectar_infraestrutura(self):
        """Busca por assinaturas específicas de criadores de IA em estruturas modernas"""
        resultados = {
            "is_ai_generated": False,
            "techs_detectadas": [],
            "alertas": []
        }

        if not self.html_content:
            return resultados

        soup = BeautifulSoup(self.html_content, 'html.parser')
        html_low = self.html_content.lower()

        # 1. Detecção de Frameworks de Build modernos usados por Lovable/v0/Bolt
        if "next" in html_low or "__next" in html_low or "next/script" in html_low:
            resultados["techs_detectadas"].append("Next.js App (Padrão v0/Lovable Premium)")
            resultados["is_ai_generated"] = True
            
        if "vite" in html_low or "assets/index" in html_low:
            resultados["techs_detectadas"].append("Vite Build Engine (Padrão Bolt.new/Lovable)")
            resultados["is_ai_generated"] = True

        # 2. Detecção profunda de estilos (Busca classes mesmo compiladas)
        classes_tailwind = len(soup.find_all(class_=re.compile(r'^(tw-|p-|m-|bg-|text-|flex|grid)')))
        if "tailwindcss" in html_low or classes_tailwind > 5 or "styles" in html_low:
            resultados["techs_detectadas"].append("Tailwind CSS Engine")
            resultados["is_ai_generated"] = True

        # 3. Detecção de conexões de Banco de Dados diretas no Front-end (Falha clássica de IA)
        if "supabase.co" in html_low or "supabase" in html_low:
            resultados["techs_detectadas"].append("Supabase Backend Extensível")
            resultados["alertas"].append("[🚨] ALERTA: Conexão direta com banco Supabase identificada!")
            resultados["is_ai_generated"] = True

        if "firebaseio.com" in html_low or "firebase" in html_low:
            resultados["techs_detectadas"].append("Firebase Realtime DB")
            resultados["alertas"].append("[🚨] ALERTA: Endpoints do Firebase vazando no cliente.")
            resultados["is_ai_generated"] = True

        return resultados
