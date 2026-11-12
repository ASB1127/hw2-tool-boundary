from types import SimpleNamespace

import pytest
from langchain_core.messages import HumanMessage

from model_runtime import ModelCallDenied, ModelRuntime
from trace import Trace


def test_discards_reply_that_reaches_budget_limit(tmp_path):
    config = SimpleNamespace(
        budget={"max_tokens": 10, "output_allowance": 4, "input_safety_margin": 0},
        model={"name": "test"},
    )
    reply = SimpleNamespace(usage_metadata={"input_tokens": 7, "output_tokens": 3})

    with Trace("test", tmp_path / "trace.jsonl") as trace:
        runtime = ModelRuntime(lambda **_: reply, trace, config)
        with pytest.raises(ModelCallDenied) as error:
            runtime.call("alert", [])
        assert error.value.reason == "budget_exhausted"
        assert runtime.used_tokens == 10
        trace.terminal("budget_exhausted")


def test_reserves_openai_input_before_call(tmp_path):
    config = SimpleNamespace(
        budget={"max_tokens": 8, "output_allowance": 1, "input_safety_margin": 0},
        model={"name": "gpt-4.1", "provider": "openai"},
    )

    with Trace("test", tmp_path / "trace.jsonl") as trace:
        runtime = ModelRuntime(
            lambda **_: pytest.fail("reserved request must not call the model"),
            trace,
            config,
        )
        with pytest.raises(ModelCallDenied):
            runtime.call("alert", [HumanMessage(content="one token")])
        assert runtime.used_tokens == 0
        trace.terminal("budget_exhausted")
