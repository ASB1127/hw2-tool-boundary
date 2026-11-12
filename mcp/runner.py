from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path
from typing import TypedDict

from langchain_core.messages import AIMessage, HumanMessage

from config import Config
from dispatcher import Dispatcher
from graph import build_graph, opening_messages, validate_classification
from model_runtime import ModelCallDenied, ModelRuntime
from provider import model
from scan import Scan
from trace import TerminalStatus, Trace
from workspace import AgentWorkspace


class Alert(TypedDict):
    alert_id: str
    filename: str
    line_number: int
    test_id: str
    issue_severity: str
    issue_confidence: str
    issue_text: str
    code: str


def scripted_model(messages, output_allowance):
    alert = json.loads(next(message.content for message in messages
                            if isinstance(message, HumanMessage)))
    return AIMessage(
        content=json.dumps({
            "label": 0,
            "rationale": "Scripted classifier result.",
            "evidence": [{
                "path": alert["filename"],
                "start_line": alert["line_number"],
                "end_line": alert["line_number"],
            }],
        }),
        usage_metadata={"input_tokens": 0, "output_tokens": 0, "total_tokens": 0},
    )


def scripted_classifier(alert: Alert, workspace: Path, trace: Trace,
                        config: Config, runtime: ModelRuntime) -> dict:
    dispatcher = Dispatcher(workspace, trace, alert["alert_id"])
    return build_graph(trace, runtime, dispatcher).invoke({
        "alert_id": alert["alert_id"],
        "alert": alert,
        "messages": opening_messages(alert),
    })


def run(config: Config, output: Path, classifier=scripted_classifier,
        invoke_model=None) -> dict:
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    rows = {}
    alerts = []
    terminal_status = TerminalStatus.COMPLETE
    fatal_error = None

    with Trace("run", output / "trace.jsonl") as trace:
        try:
            runtime = ModelRuntime(model(config) if invoke_model is None else invoke_model,
                                   trace, config)
            alerts = _alerts(Scan(config.fixture).discover(config.scan))
            for index, alert in enumerate(alerts):
                status = _process_alert(config, alert, trace, rows, classifier, runtime)
                if status is not None:
                    terminal_status = status
                    row_status = "budget_exhausted" if status == TerminalStatus.BUDGET_EXHAUSTED else "error"
                    for pending in alerts[index:]:
                        _settle(rows, trace, pending, row_status, None, "", [])
                    break
        except Exception as error:
            terminal_status = TerminalStatus.ERROR
            fatal_error = error
            trace.event("state_change", node="runner", error=str(error))
            for alert in alerts:
                _settle(rows, trace, alert, "error", None, str(error), [])
        finally:
            report = _report(config, alerts, rows, trace, terminal_status, fatal_error)
            (output / "report.json").write_text(
                json.dumps(report, indent=2) + "\n", encoding="utf-8"
            )
            trace.terminal(terminal_status)

    if fatal_error is not None:
        raise fatal_error
    return report


def _process_alert(config: Config, alert: Alert, trace: Trace, rows: dict,
                   classifier, runtime: ModelRuntime) -> str | None:
    try:
        with AgentWorkspace(
            config,
            is_owasp=_is_owasp(config),
            case=Path(alert["filename"]).stem,
        ) as workspace:
            result = classifier(alert, workspace, trace, config, runtime)
            if not isinstance(result, dict):
                raise ValueError("classifier result is not an object")
            status = result.get("status")
            if status == "classified":
                result = validate_classification(result, workspace)
            elif status not in {
                "error", TerminalStatus.BUDGET_EXHAUSTED,
                TerminalStatus.MAX_STEPS, TerminalStatus.NO_PROGRESS,
            }:
                raise ValueError("classifier returned an invalid status")
    except ModelCallDenied as error:
        return error.reason
    except Exception as error:
        _settle(rows, trace, alert, "error", None, str(error), [])
        return None

    if result["status"] == "error":
        rationale = result.get("rationale")
        _settle(rows, trace, alert, "error", None,
                rationale if isinstance(rationale, str) and rationale else "classifier error", [])
        return None
    if result["status"] != "classified":
        return result["status"]
    _settle(rows, trace, alert, "classified", result["label"],
            result["rationale"], result["evidence"])
    return None


def alert_id(path: str, line: int, test_id: str) -> str:
    fingerprint = f"{path}:{line}:{test_id}"
    digest = hashlib.sha256(fingerprint.encode()).hexdigest()[:12]
    return f"{Path(path).stem}-{line}-{test_id}-{digest}"


def _alerts(raw_alerts: list[dict]) -> list[Alert]:
    alerts: list[Alert] = []
    for raw in raw_alerts:
        filename = raw["filename"].removeprefix("./")
        line_number = raw["line_number"]
        test_id = raw["test_id"]
        alerts.append({
            "alert_id": alert_id(filename, line_number, test_id),
            "filename": filename,
            "line_number": line_number,
            "test_id": test_id,
            "issue_severity": raw["issue_severity"],
            "issue_confidence": raw["issue_confidence"],
            "issue_text": raw["issue_text"],
            "code": raw["code"],
        })
    return sorted(alerts, key=lambda alert: (
        alert["filename"], alert["line_number"], alert["test_id"]
    ))


def _settle(rows: dict, trace: Trace, alert: Alert, status: str,
            label: int | None, rationale: str, evidence: list[dict]) -> None:
    if alert["alert_id"] in rows:
        return
    rows[alert["alert_id"]] = {
        "alert_id": alert["alert_id"],
        "test_id": alert["test_id"],
        "path": alert["filename"],
        "line": alert["line_number"],
        "severity": alert["issue_severity"],
        "confidence": alert["issue_confidence"],
        "label": label,
        "status": status,
        "rationale": rationale,
        "evidence": evidence,
    }
    trace.event(
        "state_change", alert_id=alert["alert_id"], node="submit",
        alert_status=status, label=label,
    )


def _report(config: Config, alerts: list[Alert], rows: dict, trace: Trace,
            terminal_status: str, error: Exception | None) -> dict:
    usage = trace.usage.as_dict()
    report = {
        "target": {"input": str(config.fixture), "commit": _commit(config.fixture)},
        "scan": {
            "bandit_version": config.scan["bandit_version"],
            "min_severity": config.scan["min_severity"],
            "alert_count": len(alerts),
        },
        "budget": {
            "max_tokens": config.budget["max_tokens"],
            "used_tokens": usage["input"] + usage["output"],
            "exhausted": terminal_status == TerminalStatus.BUDGET_EXHAUSTED,
        },
        "alerts": [rows[alert["alert_id"]] for alert in alerts],
    }
    if error is not None:
        report["error"] = str(error)
    return report


def _is_owasp(config: Config) -> bool:
    return config.scan["paths"] == ["testcode/BenchmarkTest000*.py"]


def _commit(fixture: Path) -> str:
    return subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=fixture, text=True
    ).strip()
