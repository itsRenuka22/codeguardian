"""
Google Gemini Flash LLM client
Uses direct API calls to match working curl command exactly
"""

import asyncio
import logging
import os
import requests
from typing import Optional

logger = logging.getLogger(__name__)


class GeminiClient:
    """
    Google Gemini Flash LLM client
    Uses direct REST API calls with v1beta endpoint
    Matches the working curl command exactly
    """

    display_name = "Gemini Flash"
    _TIMEOUT_S = 120  # 2 minute timeout for API calls

    def __init__(self, api_key: Optional[str] = None):
        """Initialize Gemini client with direct API access"""
        self.api_key = api_key or os.getenv('GOOGLE_API_KEY', '')

        # CRITICAL: Use exact endpoint from working curl
        # Model: gemini-flash-latest (free tier)
        # Version: v1beta (matches curl)
        self.model_name = 'gemini-flash-latest'
        self.api_version = 'v1beta'
        self.base_url = f'https://generativelanguage.googleapis.com/{self.api_version}'
        self.endpoint = f'{self.base_url}/models/{self.model_name}:generateContent'

        if self.api_key:
            logger.info(f"✓ Gemini client initialized")
            logger.info(f"  Model: {self.model_name}")
            logger.info(f"  Endpoint: {self.endpoint}")
            logger.info(f"  API Version: {self.api_version}")
        else:
            logger.warning("GOOGLE_API_KEY not configured")

    @property
    def is_available(self) -> bool:
        """Check if API key is configured"""
        return bool(self.api_key)

    async def generate_async(self, prompt: str, system_prompt: str = "") -> str:
        """
        Generate response asynchronously

        Args:
            prompt: User prompt
            system_prompt: System instructions (optional)

        Returns:
            Generated text
        """

        try:
            # Combine prompts
            if system_prompt:
                full_prompt = f"{system_prompt}\n\n{prompt}"
            else:
                full_prompt = prompt

            logger.info(f"Calling Gemini API...")
            logger.debug(f"Prompt length: {len(full_prompt)} chars")

            # Run in executor since requests is synchronous
            loop = asyncio.get_event_loop()
            response = await loop.run_in_executor(
                None,
                self._generate_sync,
                full_prompt
            )

            logger.info(f"✓ Gemini generated {len(response)} chars")
            return response

        except Exception as e:
            logger.error(f"Gemini async generation error: {str(e)}")
            raise

    def _generate_sync(self, prompt: str) -> str:
        """
        Synchronous generation using direct REST API
        Matches the working curl command exactly

        Args:
            prompt: Full prompt text

        Returns:
            Generated text
        """

        try:
            # Request body matching curl command structure
            request_body = {
                "contents": [
                    {
                        "parts": [
                            {
                                "text": prompt
                            }
                        ]
                    }
                ],
                "generationConfig": {
                    "temperature": 0.7,
                    "topP": 0.95,
                    "topK": 40,
                    "maxOutputTokens": 4096
                }
            }

            # Headers matching curl command
            headers = {
                'Content-Type': 'application/json',
                'X-goog-api-key': self.api_key
            }

            logger.debug(f"POST {self.endpoint}")

            # Make POST request (exactly like curl)
            response = requests.post(
                self.endpoint,
                headers=headers,
                json=request_body,
                timeout=self._TIMEOUT_S
            )

            logger.debug(f"Response status: {response.status_code}")

            # Check for errors
            if response.status_code != 200:
                error_text = response.text
                logger.error(f"Gemini API error: {response.status_code}")
                logger.error(f"Error details: {error_text[:200]}")

                # Handle specific errors
                if response.status_code == 429:
                    raise Exception(
                        f"Gemini API quota exceeded. "
                        f"Please use DeepSeek R1 or Gemma 3 1B instead, "
                        f"or wait and try again later."
                    )
                elif response.status_code == 401:
                    raise Exception(
                        f"Invalid Google API key. "
                        f"Check GOOGLE_API_KEY in .env file."
                    )
                elif response.status_code == 400:
                    raise Exception(
                        f"Bad request to Gemini API: {error_text[:200]}"
                    )
                else:
                    raise Exception(
                        f"Gemini API error {response.status_code}: {error_text[:200]}"
                    )

            # Parse response
            response_data = response.json()
            logger.debug(f"Response keys: {response_data.keys()}")

            # Extract text from response
            # Response structure: {"candidates": [{"content": {"parts": [{"text": "..."}]}}]}
            if 'candidates' in response_data and response_data['candidates']:
                candidate = response_data['candidates'][0]

                if 'content' in candidate:
                    content = candidate['content']

                    if 'parts' in content and content['parts']:
                        parts = content['parts']
                        text_parts = [part.get('text', '') for part in parts if 'text' in part]

                        if text_parts:
                            generated_text = ''.join(text_parts)
                            logger.info(f"✓ Extracted {len(generated_text)} chars")
                            return generated_text

            # If we couldn't extract text, log the response and return error
            logger.warning(f"Could not extract text from response: {response_data}")
            return "Error: No text generated by Gemini API"

        except requests.exceptions.Timeout:
            logger.error(f"Gemini API request timed out after {self._TIMEOUT_S}s")
            raise Exception("Gemini API request timed out. Try again or use DeepSeek R1.")

        except requests.exceptions.ConnectionError:
            logger.error("Cannot connect to Gemini API")
            raise Exception("Cannot connect to Gemini API. Check internet connection.")

        except Exception as e:
            error_msg = str(e)
            logger.error(f"Gemini sync error: {error_msg}")

            # Re-raise known exceptions
            if "quota" in error_msg.lower() or "429" in error_msg:
                raise
            elif "401" in error_msg or "invalid" in error_msg.lower():
                raise
            else:
                raise Exception(f"Gemini API error: {error_msg}")

    def generate(self, prompt: str, system_prompt: str = "") -> str:
        """
        Synchronous generate (for non-async contexts)

        Args:
            prompt: User prompt
            system_prompt: System instructions (optional)

        Returns:
            Generated text
        """

        if system_prompt:
            full_prompt = f"{system_prompt}\n\n{prompt}"
        else:
            full_prompt = prompt

        return self._generate_sync(full_prompt)

    def generate_report(self, analysis: dict, code: str) -> dict:
        """
        Generate security report using Gemini API
        (Compatibility method for agent integration)
        """
        from .report_generator import build_prompt, SYSTEM

        try:
            prompt = build_prompt(analysis, code)
            logger.info(f"Calling Gemini for report (prompt length: {len(prompt)})")

            text = self.generate(prompt, SYSTEM)

            if not text:
                logger.error("Empty response from Gemini")
                raise ValueError("Gemini returned empty response")

            logger.info(f"✓ Gemini generated report: {len(text)} chars")

            # Return standard format (no token tracking for direct API)
            return {
                "text": text,
                "input_tokens": 0,
                "output_tokens": 0,
                "cost_usd": 0.0
            }

        except Exception as e:
            logger.error(f"Gemini report generation failed: {str(e)}", exc_info=True)
            raise

    def generate_raw(self, system: str, prompt: str) -> dict:
        """
        Generate raw response using Gemini API
        (Compatibility method)
        """
        try:
            text = self.generate(prompt, system)

            if not text:
                raise ValueError("Gemini returned empty response")

            logger.info(f"✓ Gemini generated: {len(text)} chars")

            return {
                "text": text,
                "input_tokens": 0,
                "output_tokens": 0,
                "cost_usd": 0.0
            }

        except Exception as e:
            logger.error(f"Gemini raw generation failed: {str(e)}", exc_info=True)
            raise
