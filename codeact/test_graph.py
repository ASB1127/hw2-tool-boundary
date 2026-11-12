import json

from langchain_core.messages import AIMessage

from dispatcher import Dispatcher
from graph import build_graph, opening_messages
from kernel import Kernel
from trace import Trace


class Runtime:
    class Config:
        budget = {"max_steps": 10}

    config = Config()

    def __init__(self, replies):
        self.replies = iter(replies)
        self.calls = 0

    def call(self, alert_id, messages):
        self.calls += 1
        return next(self.replies)


def test_invalid_classification_label_returns_to_controller(tmp_path):
    (tmp_path / "alert.py").write_text("x = 1\n")
    alert = {
        "alert_id": "a",
        "filename": "alert.py",
        "line_number": 1,
        "test_id": "B001",
    }
    runtime = Runtime([
        AIMessage(content=json.dumps({"label": 2, "rationale": "bad", "evidence": []})),
        AIMessage(content=json.dumps({
            "label": 0,
            "rationale": "safe value",
            "evidence": [{"path": "alert.py", "start_line": 1, "end_line": 1}],
        })),
    ])

    result = build_graph(runtime=runtime, kernel=Kernel(tmp_path)).invoke({
        "alert_id": "a",
        "alert": alert,
        "stage": "classification",
        "messages": opening_messages(alert, "classification"),
    })

    assert runtime.calls == 2
    assert result["agent_status"] == "classified"
    assert result["label"] == 0


def test_tool_call_is_dispatched_before_classification(tmp_path):
    (tmp_path / "alert.py").write_text("safe = 1\n")
    alert = {"alert_id": "a", "filename": "alert.py", "line_number": 1, "test_id": "B001"}
    runtime = Runtime([
        AIMessage(content="", tool_calls=[{
            "name": "read_file", "args": {"path": "alert.py"}, "id": "read-1",
        }]),
        AIMessage(content=json.dumps({
            "label": 0, "rationale": "safe value",
            "evidence": [{"path": "alert.py", "start_line": 1, "end_line": 1}],
        })),
    ])

    with Trace("test", tmp_path / "trace.jsonl") as trace:
        result = build_graph(
            trace, runtime, Kernel(tmp_path), Dispatcher(tmp_path, trace, "a"),
        ).invoke({
            "alert_id": "a", "alert": alert, "stage": "classification",
            "messages": opening_messages(alert, "classification"),
        })
        trace.terminal("complete")

    assert runtime.calls == 2
    assert result["agent_status"] == "classified"
    assert result["observations"] == [{
        "tool": "read_file", "args": {"path": "alert.py"}, "ok": True,
        "result": "safe = 1\n",
    }]


def test_owasp_dispatcher_searches_selected_alert_only(tmp_path):
    (tmp_path / "testcode").mkdir()
    (tmp_path / "testcode" / "BenchmarkTest00011.py").write_text("sql = 'selected'\n")
    (tmp_path / "testcode" / "BenchmarkTest00012.py").write_text("sql = 'other'\n")

    with Trace("test", tmp_path / "trace.jsonl") as trace:
        result = Dispatcher(
            tmp_path, trace, "a",
            selected_alert_file="testcode/BenchmarkTest00011.py", is_owasp=True,
        )({"tool": "search", "args": {"pattern": "sql"}})
        trace.terminal("complete")

    assert result.result == "testcode/BenchmarkTest00011.py:1: sql = 'selected'"


def test_remediation_requires_a_successful_code_action_before_edited(tmp_path):
    (tmp_path / "alert.py").write_text("unsafe = 1\n")
    alert = {"alert_id": "a", "filename": "alert.py", "line_number": 1, "test_id": "B001"}
    runtime = Runtime([
        AIMessage(content=json.dumps({"status": "edited", "summary": "fixed it"})),
        AIMessage(content="```python\nfrom pathlib import Path\nPath('alert.py').write_text('safe = 1\\n')\n```"),
        AIMessage(content=json.dumps({"status": "edited", "summary": "replaced unsafe code"})),
    ])

    result = build_graph(runtime=runtime, kernel=Kernel(tmp_path)).invoke({
        "alert_id": "a", "alert": alert, "stage": "remediation",
        "messages": opening_messages(alert, "remediation"),
    })

    assert runtime.calls == 3
    assert result["agent_status"] == "remediation_completed"
    assert result["edit_outcome"] == "edited"
    assert result["observations"][0]["action"] == "code_action"
    assert (tmp_path / "alert.py").read_text() == "safe = 1\n"
