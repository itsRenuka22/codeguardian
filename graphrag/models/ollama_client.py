import json
import urllib.request
from .base import LLMClient
from .report_generator import build_prompt

_DISPLAY = {
    "deepseek-r1:latest": "DeepSeek R1 (Ollama)",
    "qwen2.5:7b":         "Qwen 2.5 7B (Ollama)",
    "qwen2.5:14b":        "Qwen 2.5 14B (Ollama)",
    "gemma3:1b":          "Gemma 3 1B (Ollama)",
}


class OllamaClient(LLMClient):
    model_id = "deepseek-r1:latest"
    display_name = "DeepSeek R1 (Ollama)"

    def __init__(self, base_url: str = "http://localhost:11434", model: str = "deepseek-r1:latest"):
        self.base_url = base_url.rstrip("/")
        self._model   = model
        self.model_id = model
        self.display_name = _DISPLAY.get(model, f"{model} (Ollama)")

    @property
    def is_available(self) -> bool:
        try:
            with urllib.request.urlopen(f"{self.base_url}/api/tags", timeout=2) as r:
                data = json.loads(r.read())
            pulled = {m["name"] for m in data.get("models", [])}
            return self._model in pulled
        except Exception:
            return False

    def generate_report(self, analysis: dict, code: str) -> dict:
        payload = json.dumps({
            "model":  self._model,
            "prompt": build_prompt(analysis, code),
            "stream": False,
        }).encode()
        req = urllib.request.Request(
            f"{self.base_url}/api/generate",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=120) as r:
            data = json.loads(r.read())
        return {
            "text":          data.get("response", ""),
            "input_tokens":  data.get("prompt_eval_count", 0),
            "output_tokens": data.get("eval_count", 0),
            "cost_usd":      0.0,
        }

    def generate_raw(self, system: str, prompt: str) -> dict:
        payload_dict = {
            "model":  self._model,
            "prompt": prompt,
            "stream": False,
        }
        if system:
            payload_dict["system"] = system
        payload = json.dumps(payload_dict).encode()
        req = urllib.request.Request(
            f"{self.base_url}/api/generate",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=120) as r:
            data = json.loads(r.read())
        return {
            "text":          data.get("response", ""),
            "input_tokens":  data.get("prompt_eval_count", 0),
            "output_tokens": data.get("eval_count", 0),
            "cost_usd":      0.0,
        }
