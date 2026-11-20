import asyncio
import json
from types import SimpleNamespace

from langchain_core.messages import AIMessage

from graph import build_graph, opening_messages


class Runtime:
    config = SimpleNamespace(budget={"max_steps": 3})

    def call(self, alert_id, messages):
        return AIMessage(content=json.dumps({
            "label": 0,
            "rationale": "The flagged value is not used insecurely.",
            "evidence": [{"path": "target.py", "start_line": 1, "end_line": 1}],
        }))


def test_ainvoke_returns_validated_classification(tmp_path):
    (tmp_path / "target.py").write_text("value = 1\n")
    dispatcher = SimpleNamespace(ws=tmp_path)
    alert = {"alert_id": "alert-1", "filename": "target.py", "line_number": 1}

    result = asyncio.run(build_graph(runtime=Runtime(), dispatcher=dispatcher).ainvoke({
        "alert_id": "alert-1",
        "alert": alert,
        "stage": "classification",
        "messages": opening_messages(alert, "classification"),
    }))

    assert result["agent_status"] == "classified"
    assert result["label"] == 0
