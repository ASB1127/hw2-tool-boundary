from config import Config
from trace import TerminalStatus, Trace


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
        if self.used_tokens >= self.config.budget["max_tokens"]:
            raise ModelCallDenied(TerminalStatus.BUDGET_EXHAUSTED)

        output_limit = self.config.budget["output_allowance"]
        reply = self.invoke_model(messages=messages, output_allowance=output_limit)
        usage = self._usage(reply)
        self.trace.event(
            "model_call", alert_id=alert_id, role=role,
            model=self.config.model["name"], usage=usage,
        )
        return reply

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
