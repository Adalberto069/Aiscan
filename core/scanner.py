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
        """Busca por assinaturas específicas de criadores de IA"""
        resultados = {
            "is_ai_generated": False,
            "techs_detectadas": [],
            "alertas": []
        }

        if not self.html_content:
            return resultados

        soup = BeautifulSoup(self.html_content, 'html.parser')

        # 1. Detecção de Tailwind massivo (padrão do Lovable, v0, Bolt)
        classes_tailwind = len(soup.find_all(class_=re.compile(r'^(tw-|p-|m-|bg-|text-)')))
        if "tailwindcss" in self.html_content or classes_tailwind > 15:
            resultados["techs_detectadas"].append("Tailwind CSS (Forte indício de IA de Código)")
            resultados["is_ai_generated"] = True

        # 2. Detecção de conexões de Banco de Dados diretas no Front-end (Falha clássica de IA)
        if "supabase.co" in self.html_content or "supabase" in self.html_content:
            resultados["techs_detectadas"].append("Supabase Backend")
            resultados["alertas"].append("[🚨] Conexão Supabase exposta! Verificar políticas de segurança RLS.")
            resultados["is_ai_generated"] = True

        if "firebaseio.com" in self.html_content:
            resultados["techs_detectadas"].append("Firebase Backend")
            resultados["alertas"].append("[🚨] Firebase detectado no cliente.")
            resultados["is_ai_generated"] = True

        return resultados
