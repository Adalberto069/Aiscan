import os
import google.generativeai as genai

class AISecurityAgent:
    def __init__(self):
        # Carrega a chave de API que você gerou no Google AI Studio
        self.api_key = os.getenv("GEMINI_API_KEY")
        if self.api_key:
            genai.configure(api_key=self.api_key)
            # Usando o modelo flash estável para respostas rápidas no terminal
            self.model = genai.GenerativeModel('gemini-1.5-flash')
        else:
            self.model = None

    def analisar_com_ia(self, html_alvo, techs_detectadas):
        """Modo Pro Max: Envia o contexto do site para a IA gerar o vetor de ataque"""
        if not self.model:
            return "❌ Erro: Chave GEMINI_API_KEY não encontrada no ambiente. Configure para usar o Modo Pro Max."

        # Prompt do sistema que treina a IA do scanner em tempo real
        prompt_sistema = (
            "Você é o motor inteligente do AIScan, uma ferramenta avançada de Bug Bounty especializada em sites gerados por IA.\n"
            "Analise o código HTML/JS fornecido abaixo e as tecnologias detectadas.\n"
            "Identifique possíveis falhas de lógica, componentes mal configurados (como Supabase/Tailwind) e sugira vetores de ataque ou testes manuais específicos para o Bug Hunter testar.\n\n"
            f"[TECNOLOGIAS DETECTADAS]: {techs_detectadas}\n"
            f"[CÓDIGO FONTE ALVO]:\n{html_alvo[:4000]}" # Limita para não estourar o limite de tokens básico
        )

        try:
            response = self.model.generate_content(prompt_sistema)
            return response.text
        except Exception as e:
            return f"❌ Erro na comunicação com o motor de IA: {str(e)}"
