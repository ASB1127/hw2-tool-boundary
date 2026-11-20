from types import SimpleNamespace

import pytest
from langchain_core.messages import AIMessage, HumanMessage

from model_runtime import ModelCallDenied, ModelRuntime
from tools import ToolBundle
from trace import Trace, read_events


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


@pytest.mark.parametrize("include_tool_call", [False, True])
def test_openai_reservation_includes_tool_schemas_and_calls(tmp_path, monkeypatch, include_tool_call):
    config = SimpleNamespace(
        budget={"max_tokens": 100000, "output_allowance": 5, "input_safety_margin": 2},
        model={"name": "gpt-4.1", "provider": "openai"},
    )
    plain = [AIMessage(content="")]
    messages = [AIMessage(content="", tool_calls=[{
        "name": "search", "args": {"pattern": "sensitive_argument " * 100}, "id": "call-1",
    }])] if include_tool_call else plain

    with Trace("test", tmp_path / "trace.jsonl") as trace:
        runtime = ModelRuntime(lambda **_: pytest.fail("model must not be called"), trace, config)
        if include_tool_call:
            baseline = runtime._estimated_input_tokens(plain)
        else:
            with monkeypatch.context() as patch:
                patch.setattr(ToolBundle, "get_all_tools", lambda: [])
                baseline = runtime._estimated_input_tokens(messages)
        assert runtime._estimated_input_tokens(messages) > baseline
        config.budget["max_tokens"] = baseline + 7
        with pytest.raises(ModelCallDenied) as error:
            runtime.call("alert", messages)
        assert error.value.reason == "budget_exhausted"
        assert runtime.used_tokens == 0
        trace.terminal("budget_exhausted")


def test_permitted_openai_call_records_actual_usage(tmp_path):
    config = SimpleNamespace(
        budget={"max_tokens": 100000, "output_allowance": 50, "input_safety_margin": 10},
        model={"name": "gpt-4.1", "provider": "openai"},
    )
    reply = AIMessage(content="done", usage_metadata={
        "input_tokens": 12, "output_tokens": 3, "total_tokens": 15,
    })
    with Trace("test", tmp_path / "trace.jsonl") as trace:
        runtime = ModelRuntime(lambda **_: reply, trace, config)
        assert runtime.call("alert", [HumanMessage(content="hello")]) == reply
        assert runtime.used_tokens == 15
        trace.terminal("complete")
    assert read_events(tmp_path / "trace.jsonl")[0]["usage"]["input"] == 12
    assert read_events(tmp_path / "trace.jsonl")[0]["usage"]["output"] == 3


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
