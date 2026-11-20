from types import SimpleNamespace

import pytest
from langchain_core.messages import AIMessage, HumanMessage

from model_runtime import ModelCallDenied, ModelRuntime
from trace import Trace, read_events


def config(max_tokens=100000):
    return SimpleNamespace(
        budget={"max_tokens": max_tokens, "output_allowance": 50, "input_safety_margin": 10},
        model={"name": "gpt-4.1", "provider": "openai"},
    )


def test_reservation_counts_discovered_schemas_and_tool_calls(tmp_path):
    tools = {"search": SimpleNamespace(description="Search files", input_schema={
        "type": "object", "properties": {"pattern": {"type": "string"}},
    })}
    plain = [AIMessage(content="")]
    calls = [AIMessage(content="", tool_calls=[{
        "name": "search", "args": {"pattern": "sensitive argument " * 100}, "id": "call-1",
    }])]
    cfg = config()
    with Trace("test", tmp_path / "trace.jsonl") as trace:
        invoke = lambda **kwargs: pytest.fail("model must not be called")
        without_tools = ModelRuntime(invoke, trace, cfg, {})
        runtime = ModelRuntime(invoke, trace, cfg, tools)
        assert runtime._estimated_input_tokens(plain) > without_tools._estimated_input_tokens(plain)
        assert runtime._estimated_input_tokens(calls) > runtime._estimated_input_tokens(plain)
        cfg.budget["max_tokens"] = without_tools._estimated_input_tokens(plain) + 60
        with pytest.raises(ModelCallDenied):
            runtime.call("alert", plain)
        cfg.budget["max_tokens"] = runtime._estimated_input_tokens(plain) + 60
        with pytest.raises(ModelCallDenied) as error:
            runtime.call("alert", calls)
        assert error.value.reason == "budget_exhausted"
        assert runtime.used_tokens == 0
        trace.terminal("budget_exhausted")


def test_permitted_call_records_actual_usage(tmp_path):
    cfg = config()
    reply = AIMessage(content="done", usage_metadata={
        "input_tokens": 12, "output_tokens": 3, "total_tokens": 15,
    })
    with Trace("test", tmp_path / "trace.jsonl") as trace:
        runtime = ModelRuntime(lambda **kwargs: reply, trace, cfg, {})
        assert runtime.call("alert", [HumanMessage(content="hello")]) == reply
        assert runtime.used_tokens == 15
        trace.terminal("complete")
    assert read_events(tmp_path / "trace.jsonl")[0]["usage"]["input"] == 12
    assert read_events(tmp_path / "trace.jsonl")[0]["usage"]["output"] == 3


def test_reply_at_budget_limit_is_recorded_and_discarded(tmp_path):
    cfg = config()
    reply = AIMessage(content="done", usage_metadata={
        "input_tokens": 99997, "output_tokens": 3, "total_tokens": 100000,
    })
    with Trace("test", tmp_path / "trace.jsonl") as trace:
        runtime = ModelRuntime(lambda **kwargs: reply, trace, cfg, {})
        with pytest.raises(ModelCallDenied):
            runtime.call("alert", [])
        assert runtime.used_tokens == 100000
        trace.terminal("budget_exhausted")
