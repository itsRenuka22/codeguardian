import os
import logging
from .base import LLMClient
from .report_generator import build_prompt, SYSTEM

logger = logging.getLogger(__name__)


class GeminiClient(LLMClient):
    # Use gemini-1.5-flash which is the stable, widely available model
    model_id = "gemini-1.5-flash"
    display_name = "Gemini Flash"
    _COST_IN  = 0.075  # $ per 1M input tokens (Flash pricing)
    _COST_OUT = 0.30   # $ per 1M output tokens (Flash pricing)
    _TIMEOUT_S = 60    # Gemini Flash is typically fast

    def __init__(self, api_key: str = ""):
        self.api_key = api_key or os.getenv("GOOGLE_API_KEY", "")
        if not self.api_key:
            logger.warning("GOOGLE_API_KEY not configured")

    @property
    def is_available(self) -> bool:
        return bool(self.api_key)

    def generate_report(self, analysis: dict, code: str) -> dict:
        """Generate security report using Gemini API"""
        try:
            import google.generativeai as genai

            # Configure with API key
            genai.configure(api_key=self.api_key)

            # Initialize model
            model = genai.GenerativeModel(
                self.model_id,
                system_instruction=SYSTEM,
                generation_config={
                    "temperature": 0.7,
                    "top_p": 0.95,
                    "max_output_tokens": 4096,
                }
            )

            # Generate content
            prompt = build_prompt(analysis, code)
            logger.info(f"Calling Gemini with prompt length: {len(prompt)}")

            response = model.generate_content(prompt)

            if not response or not response.text:
                logger.error("Empty response from Gemini")
                raise ValueError("Gemini returned empty response")

            text = response.text

            # Extract token usage
            usage = getattr(response, "usage_metadata", None)
            inp = getattr(usage, "prompt_token_count", 0) or 0
            out = getattr(usage, "candidates_token_count", 0) or 0
            cost = round((inp * self._COST_IN + out * self._COST_OUT) / 1_000_000, 6)

            logger.info(f"✓ Gemini generated {len(text)} chars, {inp} input tokens, {out} output tokens")

            return {"text": text, "input_tokens": inp, "output_tokens": out, "cost_usd": cost}

        except Exception as e:
            logger.error(f"Gemini generation failed: {str(e)}", exc_info=True)
            raise

    def generate_raw(self, system: str, prompt: str) -> dict:
        """Generate raw response using Gemini API"""
        try:
            import google.generativeai as genai

            genai.configure(api_key=self.api_key)

            kwargs = {
                "generation_config": {
                    "temperature": 0.7,
                    "top_p": 0.95,
                    "max_output_tokens": 4096,
                }
            }
            if system:
                kwargs["system_instruction"] = system

            model = genai.GenerativeModel(self.model_id, **kwargs)
            response = model.generate_content(prompt)

            if not response or not response.text:
                raise ValueError("Gemini returned empty response")

            text = response.text
            usage = getattr(response, "usage_metadata", None)
            inp = getattr(usage, "prompt_token_count", 0) or 0
            out = getattr(usage, "candidates_token_count", 0) or 0
            cost = round((inp * self._COST_IN + out * self._COST_OUT) / 1_000_000, 6)

            return {"text": text, "input_tokens": inp, "output_tokens": out, "cost_usd": cost}

        except Exception as e:
            logger.error(f"Gemini raw generation failed: {str(e)}", exc_info=True)
            raise
