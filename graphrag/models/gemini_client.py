import os
from .base import LLMClient
from .report_generator import build_prompt, SYSTEM


class GeminiClient(LLMClient):
    model_id = "gemini-1.5-pro"
    display_name = "Gemini 1.5 Pro"
    _COST_IN  = 1.25   # $ per 1M input tokens
    _COST_OUT = 5.00   # $ per 1M output tokens

    def __init__(self, api_key: str = ""):
        self.api_key = api_key or os.getenv("GOOGLE_API_KEY", "")

    @property
    def is_available(self) -> bool:
        return bool(self.api_key)

    def generate_report(self, analysis: dict, code: str) -> dict:
        import google.generativeai as genai
        genai.configure(api_key=self.api_key)
        model = genai.GenerativeModel(
            self.model_id,
            system_instruction=SYSTEM,
        )
        response = model.generate_content(build_prompt(analysis, code))
        text = response.text

        usage = getattr(response, "usage_metadata", None)
        inp = getattr(usage, "prompt_token_count", 0) or 0
        out = getattr(usage, "candidates_token_count", 0) or 0
        cost = round((inp * self._COST_IN + out * self._COST_OUT) / 1_000_000, 6)

        return {"text": text, "input_tokens": inp, "output_tokens": out, "cost_usd": cost}

    def generate_raw(self, system: str, prompt: str) -> dict:
        import google.generativeai as genai
        genai.configure(api_key=self.api_key)
        kwargs = {"system_instruction": system} if system else {}
        model = genai.GenerativeModel(self.model_id, **kwargs)
        response = model.generate_content(prompt)
        text = response.text
        usage = getattr(response, "usage_metadata", None)
        inp = getattr(usage, "prompt_token_count", 0) or 0
        out = getattr(usage, "candidates_token_count", 0) or 0
        cost = round((inp * self._COST_IN + out * self._COST_OUT) / 1_000_000, 6)
        return {"text": text, "input_tokens": inp, "output_tokens": out, "cost_usd": cost}
