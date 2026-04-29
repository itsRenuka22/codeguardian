from abc import ABC, abstractmethod


class LLMClient(ABC):
    model_id: str = ""
    display_name: str = ""

    @abstractmethod
    def generate_report(self, analysis: dict, code: str) -> dict:
        """
        Returns:
          {"text": str, "input_tokens": int, "output_tokens": int, "cost_usd": float}
        """
        ...

    @abstractmethod
    def generate_raw(self, system: str, prompt: str) -> dict:
        """
        Send a raw system+user prompt without any report formatting.
        Returns: {"text": str, "input_tokens": int, "output_tokens": int, "cost_usd": float}
        """
        ...

    @property
    @abstractmethod
    def is_available(self) -> bool: ...
