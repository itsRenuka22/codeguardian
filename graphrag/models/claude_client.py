import os
from .base import LLMClient
from .report_generator import build_prompt, SYSTEM

# claude-sonnet-4-6 pricing (per 1M tokens)
_COST_IN  = 3.00
_COST_OUT = 15.00


class ClaudeClient(LLMClient):
    model_id = "claude-sonnet-4-6"
    display_name = "Claude Sonnet 4.6"

    def __init__(self, api_key: str = ""):
        self.api_key = api_key or os.getenv("ANTHROPIC_API_KEY", "")

    @property
    def is_available(self) -> bool:
        return bool(self.api_key)

    def generate_report(self, analysis: dict, code: str) -> dict:
        import anthropic
        client = anthropic.Anthropic(api_key=self.api_key)
        msg = client.messages.create(
            model=self.model_id,
            max_tokens=1024,
            system=SYSTEM,
            messages=[{"role": "user", "content": build_prompt(analysis, code)}],
        )
        text = msg.content[0].text
        inp  = msg.usage.input_tokens
        out  = msg.usage.output_tokens
        cost = round((inp * _COST_IN + out * _COST_OUT) / 1_000_000, 6)
        return {"text": text, "input_tokens": inp, "output_tokens": out, "cost_usd": cost}

    def generate_raw(self, system: str, prompt: str) -> dict:
        import anthropic
        client = anthropic.Anthropic(api_key=self.api_key)
        kwargs = {
            "model": self.model_id,
            "max_tokens": 512,
            "messages": [{"role": "user", "content": prompt}],
        }
        if system:
            kwargs["system"] = system
        msg = client.messages.create(**kwargs)
        text = msg.content[0].text
        inp  = msg.usage.input_tokens
        out  = msg.usage.output_tokens
        cost = round((inp * _COST_IN + out * _COST_OUT) / 1_000_000, 6)
        return {"text": text, "input_tokens": inp, "output_tokens": out, "cost_usd": cost}
