import asyncio
import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from jsonschema import Draft202012Validator

import runner
from config import Config
from runner import _remediation_from_result, _target_commit
from model_runtime import ModelCallDenied
from trace import TerminalStatus, read_events


@pytest.mark.parametrize("outcome", ["accepted", "rejected", "skipped"])
def test_remediation_trace_records_checks_separately(tmp_path, monkeypatch, outcome):
    checks = {"applies": True, "touches_flagged_line": False, "clean_rescan": True}
    if outcome == "skipped":
        checks = dict.fromkeys(checks)
    remediation = {"status": outcome, "diff": "", "checks": checks}
    events = []
    trace = SimpleNamespace(event=lambda kind, **fields: events.append((kind, fields)))

    class Client:
        async def call_tool(self, name, args):
            return SimpleNamespace(is_error=False)

    async def classify(*args):
        return {"agent_status": "classified", "label": 1, "rationale": "reason", "evidence": []}

    async def remediate(*args):
        return {}

    monkeypatch.setattr(runner, "remediate_alert_with_model", remediate)
    monkeypatch.setattr(runner, "_remediation_from_result", lambda result: remediation)
    alert = {"alert_id": "a", "test_id": "B1", "filename": "a.py", "line_number": 1,
             "issue_severity": "MEDIUM", "issue_confidence": "HIGH"}
    rows = {}
    asyncio.run(runner._process_alert(Config(), alert, tmp_path, trace, rows, classify,
                                      None, Client(), {}))

    event = next(fields for kind, fields in events if fields.get("node") == "remediation")
    assert event["checks"] == rows["a"]["remediation"]["checks"] == checks
    assert event["remediation_status"] == outcome
    assert "alert_status" not in event and "label" not in event
    assert sum("alert_status" in fields for _, fields in events) == 1


@pytest.mark.parametrize("cutoff", [TerminalStatus.BUDGET_EXHAUSTED,
                                   TerminalStatus.MAX_STEPS, TerminalStatus.NO_PROGRESS])
@pytest.mark.parametrize("raises", [False, True])
def test_remediation_cutoff_stops_run_and_preserves_classification(tmp_path, monkeypatch, cutoff, raises):
    raw = lambda name: {"filename": name, "line_number": 1, "test_id": "B001",
                        "issue_severity": "MEDIUM", "issue_confidence": "HIGH",
                        "issue_text": "issue", "code": "code"}
    monkeypatch.setattr(runner, "Scan", lambda fixture: SimpleNamespace(
        discover=lambda scan: [raw("a.py"), raw("b.py")]))

    class Workspace:
        def __init__(self, *args, **kwargs):
            pass

        def __enter__(self):
            return tmp_path

        def __exit__(self, *args):
            pass

    class Client:
        def __init__(self, *args):
            pass

        async def connect(self):
            return [SimpleNamespace(name=name) for name in
                    ("configure_alerts", "set_alert", "validate_evidence")]

        async def call_tool(self, name, args):
            return SimpleNamespace(is_error=False)

        async def close(self):
            pass

    calls = []

    async def classify(alert, *args):
        calls.append(alert["filename"])
        return {"agent_status": "classified", "label": 1, "rationale": "reason",
                "evidence": [{"path": alert["filename"], "start_line": 1, "end_line": 1}]}

    async def remediate(*args):
        if raises:
            raise ModelCallDenied(cutoff)
        return {"agent_status": cutoff}

    monkeypatch.setattr(runner, "AgentWorkspace", Workspace)
    monkeypatch.setattr(runner, "MCPClient", Client)
    monkeypatch.setattr(runner, "remediate_alert_with_model", remediate)
    config = Config(fixture=tmp_path, scan={"paths": ["radicale"], "bandit_version": "1.9.4",
                                          "min_severity": "MEDIUM"},
                    budget={"max_tokens": 100}, mcp={"config": "unused"},
                    target_commits={"radicale": "a" * 40})
    output = tmp_path / "output"
    report = runner.run(config, output, classifier=classify, invoke_model=lambda **kwargs: None)

    assert calls == ["a.py"]
    first, second = report["alerts"]
    assert (first["status"], first["label"], first["remediation"]["status"]) == (
        "classified", 1, "skipped")
    assert second["status"] == ("budget_exhausted" if cutoff == TerminalStatus.BUDGET_EXHAUSTED else "error")
    assert report["budget"]["exhausted"] == (cutoff == TerminalStatus.BUDGET_EXHAUSTED)
    events = read_events(output / "trace.jsonl")
    assert events[-1]["status"] == cutoff
    assert next(event for event in events if event.get("node") == "remediation")["checks"] == first["remediation"]["checks"]
    assert len([event for event in events if "alert_status" in event]) == 2
    root = Path(__file__).resolve().parent.parent
    report_schema = json.loads((root / "report.schema.json").read_text())
    trace_schema = json.loads((root / "trace.schema.json").read_text())
    Draft202012Validator(report_schema).validate(report)
    trace_validator = Draft202012Validator(trace_schema)
    for event in events:
        trace_validator.validate(event)


def test_target_commit_is_selected_for_each_required_target():
    scans = {
        "owasp": {
            "paths": ["testcode/BenchmarkTest000*.py"], "exclude": [],
            "min_severity": "MEDIUM", "bandit_version": "1.9.4",
        },
        "radicale": {
            "paths": ["radicale"], "exclude": ["radicale/tests"],
            "min_severity": "MEDIUM", "bandit_version": "1.9.4",
        },
        "sglang": {
            "paths": [
                "python/sglang/multimodal_gen/runtime",
                "scripts/playground/replay_request_dump.py",
            ],
            "exclude": [], "min_severity": "MEDIUM", "bandit_version": "1.9.4",
        },
    }
    commits = {target: f"pinned-{target}" for target in scans}

    for target, scan in scans.items():
        assert _target_commit(Config(scan=scan, target_commits=commits)) == commits[target]


def test_remediation_not_edited_is_skipped():
    result = _remediation_from_result({
        "edit_outcome": "not_edited",
        "remediation_summary": "No safe minimal patch exists.",
    })

    assert result["status"] == "skipped"
    assert result["summary"] == "No safe minimal patch exists."
    assert result["checks"] == {
        "applies": None, "touches_flagged_line": None, "clean_rescan": None,
    }


def test_remediation_not_edited_preserves_prior_rejected_patch():
    result = _remediation_from_result({
        "edit_outcome": "not_edited",
        "observations": [{
            "tool": "edit",
            "ok": True,
            "result": json.dumps({
                "status": "rejected",
                "diff": "--- before\n+++ after\n",
                "checks": {
                    "applies": True,
                    "touches_flagged_line": True,
                    "clean_rescan": False,
                },
            }),
        }],
    })

    assert result["status"] == "rejected"
    assert result["checks"]["clean_rescan"] is False


def test_remediation_later_accepted_edit_beats_earlier_rejection():
    result = _remediation_from_result({"observations": [
        {
            "tool": "edit",
            "ok": True,
            "result": json.dumps({
                "status": "rejected", "diff": "", "checks": {
                    "applies": True, "touches_flagged_line": False, "clean_rescan": True,
                },
            }),
        },
        {
            "tool": "edit",
            "ok": True,
            "result": json.dumps({
                "status": "accepted", "diff": "--- before\n+++ after\n", "checks": {
                    "applies": True, "touches_flagged_line": True, "clean_rescan": True,
                },
            }),
        },
    ]})

    assert result["status"] == "accepted"
    assert result["checks"]["touches_flagged_line"] is True


def test_remediation_tool_error_is_not_a_patch_rejection():
    result = _remediation_from_result({"observations": [{
        "tool": "edit", "ok": False, "result": "refused: wrong file",
    }]})

    assert result["status"] == "skipped"


def test_remediation_uses_structured_edit_observation():
    result = _remediation_from_result({"observations": [{
        "tool": "edit",
        "ok": True,
        "result": json.dumps({
            "status": "accepted",
            "diff": "--- before\n+++ after\n",
            "checks": {
                "applies": True,
                "touches_flagged_line": True,
                "clean_rescan": True,
            },
        }),
    }]})

    assert result["status"] == "accepted"
