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
        profile_name: str | None = None,
        http_proxy: str | None = None,
        https_proxy: str | None = None,
    ):
        # Build a Session so we can honour an explicit named profile (e.g. an SSO
        # profile created via `aws configure sso`).  When profile_name is None
        # boto3 falls back to its full credential chain in order:
        #   1. Explicit keys passed here
        #   2. AWS_* environment variables
        #   3. ~/.aws/credentials (aws configure)
        #   4. ~/.aws/config SSO profiles (aws configure sso + aws sso login)
        #   5. IAM instance/task role
        session = boto3.Session(
            aws_access_key_id=access_key_id or None,
            aws_secret_access_key=secret_access_key or None,
            region_name=region,
            profile_name=profile_name or None,
        )

        client_kwargs: dict[str, Any] = {}
        if http_proxy and https_proxy:
            client_kwargs["config"] = Config(proxies={"http": http_proxy, "https": https_proxy})

        self.client = session.client("bedrock-runtime", **client_kwargs)
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
