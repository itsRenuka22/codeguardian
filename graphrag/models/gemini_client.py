"""
Gemini Flash LLM client via OpenRouter API
Uses OpenAI-compatible interface at https://openrouter.ai/api/v1
"""

import asyncio
import logging
import os
from typing import Optional

from openai import OpenAI

logger = logging.getLogger(__name__)

_MODEL = "google/gemini-2.5-flash"
_BASE_URL = "https://openrouter.ai/api/v1"


class GeminiClient:
    """
    Gemini Flash via OpenRouter.
    Drop-in replacement for the previous direct-REST implementation —
    same class name, same method signatures, same return types.
    """

    display_name = "Gemini Flash (OpenRouter)"
    _TIMEOUT_S = 120

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.getenv("OPENROUTER_API_KEY", "")
        self.model_name = _MODEL

        if not self.api_key:
            logger.warning("OPENROUTER_API_KEY not set — GeminiClient unavailable")
        else:
            self._client = OpenAI(
                api_key=self.api_key,
                base_url=_BASE_URL,
                timeout=self._TIMEOUT_S,
            )
            print(f"✅ Using OpenRouter with {_MODEL}")
            logger.info(f"✓ GeminiClient ready via OpenRouter ({_MODEL})")

    @property
    def is_available(self) -> bool:
        return bool(self.api_key)

    # ── core sync call ────────────────────────────────────────────────────────

    def _generate_sync(self, prompt: str) -> str:
        if not self.api_key:
            raise Exception("OPENROUTER_API_KEY not set. Cannot call Gemini via OpenRouter.")

        try:
            response = self._client.chat.completions.create(
                model=self.model_name,
                messages=[{"role": "user", "content": prompt}],
                temperature=0.7,
                max_tokens=4096,
            )
            text = response.choices[0].message.content or ""
            logger.info(f"✓ OpenRouter generated {len(text)} chars")
            return text

        except Exception as e:
            msg = str(e)
            logger.error(f"OpenRouter error: {msg}")

            if "429" in msg or "quota" in msg.lower() or "rate" in msg.lower():
                raise Exception(
                    f"OpenRouter rate limit hit for {_MODEL}. "
                    "Try again shortly or switch to a local Ollama model."
                )
            elif "401" in msg or "unauthorized" in msg.lower():
                raise Exception(
                    "Invalid OPENROUTER_API_KEY. Check your environment variable."
                )
            else:
                raise Exception(f"OpenRouter API error: {msg}")

    # ── public methods (same signatures as before) ────────────────────────────

    def generate(self, prompt: str, system_prompt: str = "") -> str:
        full_prompt = f"{system_prompt}\n\n{prompt}" if system_prompt else prompt
        return self._generate_sync(full_prompt)

    async def generate_async(self, prompt: str, system_prompt: str = "") -> str:
        full_prompt = f"{system_prompt}\n\n{prompt}" if system_prompt else prompt
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._generate_sync, full_prompt)

    def generate_report(self, analysis: dict, code: str) -> dict:
        """Compatibility method used by agent/report_generator integration."""
        from .report_generator import build_prompt, SYSTEM
        try:
            prompt = build_prompt(analysis, code)
            text = self.generate(prompt, SYSTEM)
            if not text:
                raise ValueError("Empty response from OpenRouter")
            return {"text": text, "input_tokens": 0, "output_tokens": 0, "cost_usd": 0.0}
        except Exception as e:
            logger.error(f"generate_report failed: {e}", exc_info=True)
            raise

    def generate_raw(self, system: str, prompt: str) -> dict:
        """Compatibility method used by HybridCritic._call_llm()."""
        try:
            text = self.generate(prompt, system)
            if not text:
                raise ValueError("Empty response from OpenRouter")
            return {"text": text, "input_tokens": 0, "output_tokens": 0, "cost_usd": 0.0}
        except Exception as e:
            logger.error(f"generate_raw failed: {e}", exc_info=True)
            raise
