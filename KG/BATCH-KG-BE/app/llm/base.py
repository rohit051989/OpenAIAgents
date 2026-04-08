"""Abstract base class for all LLM provider implementations."""

from abc import ABC, abstractmethod
from typing import Any


class BaseLLM(ABC):
    """Common interface every LLM provider must implement."""

    @abstractmethod
    def generate(
        self,
        messages: list[dict[str, str]],
        temperature: float = 0.1,
        max_tokens: int | None = None,
        json_mode: bool = False,
    ) -> str:
        """Return a plain-text completion."""

    @abstractmethod
    def generate_json(
        self,
        messages: list[dict[str, str]],
        temperature: float = 0.1,
        max_tokens: int | None = None,
    ) -> dict[str, Any]:
        """Return a parsed JSON completion."""
