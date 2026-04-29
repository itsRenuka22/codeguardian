import os
from .base import LLMClient
from .report_generator import build_prompt, SYSTEM

# gpt-4o pricing (per 1M tokens)
_COST_IN  = 2.50
_COST_OUT = 10.00


class OpenAIClient(LLMClient):
    model_id = "gpt-4o"
    display_name = "GPT-4o"

    def __init__(self, api_key: str = ""):
        self.api_key = api_key or os.getenv("OPENAI_API_KEY", "")

    @property
    def is_available(self) -> bool:
        return bool(self.api_key)

    def generate_report(self, analysis: dict, code: str) -> dict:
        from openai import OpenAI
        client = OpenAI(api_key=self.api_key)
        resp = client.chat.completions.create(
            model=self.model_id,
            max_tokens=1024,
            messages=[
                {"role": "system", "content": SYSTEM},
                {"role": "user",   "content": build_prompt(analysis, code)},
            ],
        )
        text = resp.choices[0].message.content
        inp  = resp.usage.prompt_tokens
        out  = resp.usage.completion_tokens
        cost = round((inp * _COST_IN + out * _COST_OUT) / 1_000_000, 6)
        return {"text": text, "input_tokens": inp, "output_tokens": out, "cost_usd": cost}

    def generate_raw(self, system: str, prompt: str) -> dict:
        from openai import OpenAI
        client = OpenAI(api_key=self.api_key)
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})
        resp = client.chat.completions.create(
            model=self.model_id,
            max_tokens=512,
            messages=messages,
        )
        text = resp.choices[0].message.content
        inp  = resp.usage.prompt_tokens
        out  = resp.usage.completion_tokens
        cost = round((inp * _COST_IN + out * _COST_OUT) / 1_000_000, 6)
        return {"text": text, "input_tokens": inp, "output_tokens": out, "cost_usd": cost}
