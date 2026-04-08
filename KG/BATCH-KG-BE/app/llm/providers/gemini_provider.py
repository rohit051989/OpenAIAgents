"""GeminiLLM provider using google-generativeai."""
from __future__ import annotations

import json
from typing import Any

from app.llm.base import BaseLLM

try:
    import google.generativeai as genai  # type: ignore
except ImportError as exc:  # pragma: no cover
    raise ImportError(
        "google-generativeai is required for GeminiLLM. "
        "Install it with: pip install google-generativeai"
    ) from exc


class GeminiLLM(BaseLLM):
    """Wrapper around Google Gemini via the generativeai SDK."""

    def __init__(self, api_key: str, model: str = "gemini-1.5-pro") -> None:
        genai.configure(api_key=api_key)
        self._model = genai.GenerativeModel(model)
        self._model_name = model

    # ------------------------------------------------------------------
    def generate(self, prompt: str, **kwargs: Any) -> str:
        response = self._model.generate_content(prompt)
        return response.text or ""

    def generate_json(self, prompt: str, **kwargs: Any) -> dict[str, Any]:
        full_prompt = (
            f"{prompt}\n\n"
            "Respond ONLY with valid JSON — no markdown fences, no extra text."
        )
        raw = self.generate(full_prompt, **kwargs).strip()
        # Strip optional ```json … ``` wrapper that Gemini sometimes adds
        if raw.startswith("```"):
            raw = raw.split("\n", 1)[-1]
            if raw.endswith("```"):
                raw = raw[: raw.rfind("```")]
        return json.loads(raw)
