import json
import os
from pathlib import Path

import tiktoken
from langchain_core.utils.function_calling import convert_to_openai_tool

from config import Config
from tools import ToolBundle
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
        tokens = 3 * len(messages) + 3
        for message in messages:
            content = message.content if isinstance(message.content, str) else json.dumps(message.content)
            tokens += len(encoding.encode(content))
            if getattr(message, "tool_calls", None):
                tokens += len(encoding.encode(json.dumps(message.tool_calls)))
        schemas = [convert_to_openai_tool(tool) for tool in ToolBundle.get_all_tools()]
        return tokens + len(encoding.encode(json.dumps(schemas)))

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
