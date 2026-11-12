import os
from pathlib import Path

import tiktoken

from config import Config
from trace import TerminalStatus, Trace


_TOKENIZER_CACHE = Path("/app/tiktoken-cache")
if _TOKENIZER_CACHE.is_dir():
    os.environ.setdefault("TIKTOKEN_CACHE_DIR", str(_TOKENIZER_CACHE))


class ModelCallDenied(RuntimeError):
    def __init__(self, reason: TerminalStatus):
        self.reason = reason
        super().__init__(reason)


class ModelRuntime:
    def __init__(self, invoke_model, trace: Trace, config: Config):
        self.invoke_model = invoke_model
        self.trace = trace
        self.config = config

    @property
    def used_tokens(self) -> int:
        return self.trace.usage.input + self.trace.usage.output

    def call(self, alert_id: str, messages: list, role: str = "controller"):
        output_limit = self.config.budget["output_allowance"]
        reserved = self._estimated_input_tokens(messages) + output_limit
        reserved += self.config.budget.get("input_safety_margin", 128)
        if self.used_tokens + reserved > self.config.budget["max_tokens"]:
            raise ModelCallDenied(TerminalStatus.BUDGET_EXHAUSTED)

        reply = self.invoke_model(messages=messages, output_allowance=output_limit)
        usage = self._usage(reply)
        self.trace.event(
            "model_call", alert_id=alert_id, role=role,
            model=self.config.model["name"], usage=usage,
        )
        if self.used_tokens >= self.config.budget["max_tokens"]:
            raise ModelCallDenied(TerminalStatus.BUDGET_EXHAUSTED)
        return reply

    def _estimated_input_tokens(self, messages: list) -> int:
        if self.config.model.get("provider") != "openai":
            return 0
        encoding = tiktoken.encoding_for_model(self.config.model["name"])
        content_tokens = sum(
            len(encoding.encode(message.content if isinstance(message.content, str)
                                else str(message.content)))
            for message in messages
        )
        return content_tokens + 3 * len(messages) + 3

    @staticmethod
    def _usage(reply) -> dict:
        metadata = getattr(reply, "usage_metadata", {}) or {}
        details = metadata.get("input_token_details", {}) or {}
        return {
            "input": metadata.get("input_tokens", metadata.get("input", 0)),
            "output": metadata.get("output_tokens", metadata.get("output", 0)),
            "cache_read": details.get("cache_read", 0),
            "cache_write": details.get("cache_creation", 0),
        }
