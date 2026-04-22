"""AWS Bedrock LLM provider."""

import json
import logging
import boto3

from typing import Any
from botocore.config import Config
from app.llm.base import BaseLLM

logger = logging.getLogger(__name__)


class BedrockLLM(BaseLLM):
    """AWS Bedrock provider using the Converse API (supports Claude, Titan, etc.)."""

    def __init__(
        self,
        model_id: str,
        region: str = "us-east-1",
        access_key_id: str | None = None,
        secret_access_key: str | None = None,
        http_proxy: str | None = None,
        https_proxy: str | None = None,
    ):
        
        kwargs: dict[str, Any] = {"region_name": region, "service_name": "bedrock-runtime"}
        if access_key_id and secret_access_key:
            kwargs["aws_access_key_id"] = access_key_id
            kwargs["aws_secret_access_key"] = secret_access_key
        if http_proxy and https_proxy:
            kwargs["config"] = Config(proxies={"http": http_proxy, "https": https_proxy})

        self.client = boto3.client(**kwargs)
        self.model_id = model_id

    def generate(
        self,
        messages: list[dict[str, str]],
        temperature: float = 0.1,
        max_tokens: int | None = None,
        json_mode: bool = False,
    ) -> str:
        # Convert to Bedrock Converse format
        bedrock_messages = [
            {"role": m["role"], "content": [{"text": m["content"]}]}
            for m in messages
            if m["role"] in ("user", "assistant")
        ]
        system_prompt = next(
            (m["content"] for m in messages if m["role"] == "system"), None
        )

        kwargs: dict[str, Any] = {
            "modelId": self.model_id,
            "messages": bedrock_messages,
            "inferenceConfig": {"temperature": temperature},
        }
        if max_tokens:
            kwargs["inferenceConfig"]["maxTokens"] = max_tokens
        if system_prompt:
            kwargs["system"] = [{"text": system_prompt}]

        response = self.client.converse(**kwargs)
        return response["output"]["message"]["content"][0]["text"]

    def generate_json(
        self,
        messages: list[dict[str, str]],
        temperature: float = 0.1,
        max_tokens: int | None = None,
    ) -> dict[str, Any]:
        # Instruct the model to respond in JSON
        json_messages = list(messages)
        if json_messages and json_messages[-1]["role"] == "user":
            json_messages[-1] = {
                "role": "user",
                "content": json_messages[-1]["content"] + "\n\nRespond with valid JSON only.",
            }
        text = self.generate(json_messages, temperature, max_tokens)
        # Strip markdown code fences if present
        text = text.strip()
        if text.startswith("```"):
            text = text.split("```")[1]
            if text.startswith("json"):
                text = text[4:]
        return json.loads(text.strip())
