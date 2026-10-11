import os
import google.generativeai as genai

class AISecurityAgent:
    # Verificados vivos via ping em 2026-10-11: 3.5-flash OK (~2s).
    # Mortos: 1.5-flash (404), 2.0-flash (404), 2.5-flash-lite (404). Sem cota: 3.8-flash (429).
    MODELOS_FALLBACK = ['gemini-3.5-flash', 'gemini-flash-latest']

    def __init__(self, model_name=None):
        # Carrega a chave de API que você gerou no Google AI Studio
        self.api_key = os.getenv("GEMINI_API_KEY")
        self.model = None
        self.model_name = model_name
        if self.api_key:
            genai.configure(api_key=self.api_key)
            # Tenta o modelo pedido, senão o primeiro do fallback que responder
            candidatos = [model_name] if model_name else list(self.MODELOS_FALLBACK)
            for cand in candidatos:
                try:
                    self.model = genai.GenerativeModel(cand)
                    self.model_name = cand
                    break
                except Exception:
                    continue
        else:
            self.model = None

    def analisar_com_ia(self, html_alvo, techs_detectadas):
        """Modo Pro Max: Envia o contexto do site para a IA gerar o vetor de ataque"""
        if not self.model:
            return "❌ Erro: Chave GEMINI_API_KEY não encontrada no ambiente. Configure para usar o Modo Pro Max."

        # Prompt de auditoria defensiva: o operador audita o próprio site.
        # Enquadramento defensivo gera achados concretos; framing ofensivo gera recusa.
        prompt_sistema = (
            "Você é um auditor de segurança defensiva. O operador está auditando o PRÓPRIO site, "
            "gerado por ferramenta de IA (Lovable/Bolt/v0), e pede uma revisão de hardening.\n"
            "A partir do HTML parcial e das tecnologias detectadas, liste achados CONCRETOS e ACIONÁVEIS, "
            "ordenados por severidade, cada um com: (1) o que observar, (2) onde verificar no código/resposta HTTP, "
            "(3) como corrigir. Cubra: Row Level Security do Supabase, chaves expostas no bundle JS (VITE_*/NEXT_PUBLIC_*), "
            "headers ausentes (CSP, X-Frame-Options, Permissions-Policy), Firebase rules, CORS e validação só-no-front.\n"
            "Seja específico com o material fornecido; nada de conselho genérico.\n\n"
            f"[TECNOLOGIAS DETECTADAS]: {techs_detectadas}\n"
            f"[CÓDIGO FONTE ALVO]:\n{html_alvo[:4000]}" # Limita para não estourar o limite de tokens básico
        )

        import time

        def _gerar(modelo):
            return modelo.generate_content(prompt_sistema, request_options={'timeout': 90}).text

        try:
            try:
                return _gerar(self.model)
            except Exception as e1:
                # Retry 1x com backoff: a API do tier gratuito oscila (504 intermitente)
                if "504" in str(e1) or "Deadline" in str(e1) or "timeout" in str(e1).lower():
                    time.sleep(8)
                    try:
                        return _gerar(self.model)
                    except Exception:
                        pass
                raise
        except Exception as e:
            # Se o modelo atual foi descontinuado, tenta o próximo do fallback
            err = str(e)
            if "404" in err or "not found" in err.lower() or "no longer available" in err:
                for cand in self.MODELOS_FALLBACK:
                    if cand == self.model_name:
                        continue
                    try:
                        self.model = genai.GenerativeModel(cand)
                        self.model_name = cand
                        return _gerar(self.model)
                    except Exception:
                        continue
            return f"❌ Erro na comunicação com o motor de IA: {err}"
