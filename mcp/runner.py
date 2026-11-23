from __future__ import annotations

import asyncio
import hashlib
import json
from pathlib import Path
from typing import TypedDict

from langchain_core.messages import AIMessage, HumanMessage

from client import MCPClient
from config import Config
from dispatcher import Dispatcher
from graph import build_graph, opening_messages
from model_runtime import ModelCallDenied, ModelRuntime
from provider import model
from scan import Scan
from trace import TerminalStatus, Trace
from workspace import AgentWorkspace


TARGET_BY_PATHS = {
    ("testcode/BenchmarkTest000*.py",): "owasp",
    ("radicale",): "radicale",
    (
        "python/sglang/multimodal_gen/runtime",
        "scripts/playground/replay_request_dump.py",
    ): "sglang",
}


class Alert(TypedDict):
    alert_id: str
    filename: str
    line_number: int
    test_id: str
    issue_severity: str
    issue_confidence: str
    issue_text: str
    code: str


def split_discovered_tools(discovered):
    """Separate the host-only alert selector from model-facing MCP tools."""
    all_tools = {tool.name: tool for tool in discovered}
    host_controls = {
        "configure_alerts": all_tools["configure_alerts"],
        "set_alert": all_tools["set_alert"],
        "validate_evidence": all_tools["validate_evidence"],
    }
    model_tools = {
        name: tool for name, tool in all_tools.items() if name not in host_controls
    }
    return host_controls, model_tools


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


async def _run_alert_stage(alert: Alert, workspace: Path, trace: Trace,
                           runtime: ModelRuntime, client: MCPClient,
                           model_tools: dict, stage: str) -> dict:
    dispatcher = Dispatcher(workspace, trace, alert["alert_id"], model_tools, client)
    return await build_graph(trace, runtime, dispatcher).ainvoke({
        "alert_id": alert["alert_id"],
        "alert": alert,
        "stage": stage,
        "messages": opening_messages(alert, stage),
    })


async def classify_alert_with_model(alert: Alert, workspace: Path, trace: Trace,
                                    config: Config, runtime: ModelRuntime, client: MCPClient,
                                    model_tools: dict) -> dict:
    return await _run_alert_stage(alert, workspace, trace, runtime, client,
                                  model_tools, "classification")


async def remediate_alert_with_model(alert: Alert, workspace: Path, trace: Trace,
                                     runtime: ModelRuntime, client: MCPClient,
                                     model_tools: dict) -> dict:
    return await _run_alert_stage(alert, workspace, trace, runtime, client,
                                  model_tools, "remediation")


def run(config: Config, output: Path, classifier=classify_alert_with_model,
        invoke_model=None) -> dict:
    return asyncio.run(_run(config, output, classifier, invoke_model))


async def _run(config: Config, output: Path, classifier=classify_alert_with_model,
               invoke_model=None) -> dict:
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    rows = {}
    alerts = []
    terminal_status = TerminalStatus.COMPLETE
    fatal_error = None

    with Trace("run", output / "trace.jsonl") as trace:
        try:
            alerts = _alerts(Scan(config.fixture).discover(config.scan))
            with AgentWorkspace(config, is_owasp=_is_owasp(config)) as workspace:
                alert_map = {
                    alert["alert_id"]: {
                        "filename": alert["filename"],
                        "line_number": alert["line_number"],
                        "test_id": alert["test_id"],
                    }
                    for alert in alerts
                }
                mcp_config = Path(config.mcp["config"])
                if not mcp_config.is_absolute():
                    mcp_config = Path(__file__).parent.parent / mcp_config
                client = MCPClient(str(workspace), mcp_config)
                try:
                    discovered_tools = await client.connect()
                    host_controls, model_tools = split_discovered_tools(discovered_tools)
                    await client.call_tool("configure_alerts", {
                        "alerts": alert_map,
                        "pinned_root": str(config.fixture.resolve()),
                    })
                    trace.event("discovery", server="analysis", tools=sorted(model_tools))
                    runtime = ModelRuntime(
                        model(config, model_tools) if invoke_model is None else invoke_model,
                        trace, config, model_tools,
                    )
                    for index, alert in enumerate(alerts):
                        status = await _process_alert(
                            config, alert, workspace, trace, rows, classifier, runtime,
                            client, model_tools,
                        )
                        if status is not None:
                            terminal_status = status
                            row_status = "budget_exhausted" if status == TerminalStatus.BUDGET_EXHAUSTED else "error"
                            for pending in alerts[index:]:
                                _settle(rows, trace, pending, row_status, None, "", [])
                            break
                finally:
                    await client.close()
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


async def _process_alert(config: Config, alert: Alert, workspace: Path, trace: Trace,
                         rows: dict, classifier, runtime: ModelRuntime, client: MCPClient,
                         model_tools: dict) -> str | None:
    try:
        await client.call_tool("set_alert", {"alert_id": alert["alert_id"]})
        result = await classifier(
            alert, workspace, trace, config, runtime, client, model_tools,
        )
        if not isinstance(result, dict):
            raise ValueError("classifier result is not an object")
        status = result.get("agent_status")
        if status not in {
            "classified", "error", TerminalStatus.BUDGET_EXHAUSTED,
            TerminalStatus.MAX_STEPS, TerminalStatus.NO_PROGRESS,
        }:
            raise ValueError("classifier returned an invalid status")
    except ModelCallDenied as error:
        return error.reason
    except Exception as error:
        _settle(rows, trace, alert, "error", None, str(error), [])
        return None

    if result["agent_status"] == "error":
        rationale = result.get("rationale")
        _settle(rows, trace, alert, "error", None,
                rationale if isinstance(rationale, str) and rationale else "classifier error", [])
        return None
    if result["agent_status"] != "classified":
        return result["agent_status"]

    evidence_check = await client.call_tool(
        "validate_evidence", {"evidence": result["evidence"]},
    )
    if evidence_check.is_error:
        _settle(rows, trace, alert, "error", None, "server rejected evidence", [])
        return None

    remediation = _skipped_remediation()
    remediation_cutoff = None
    if result["label"] == 1:
        trace.event("routing", alert_id=alert["alert_id"], decision="remediation", by="runtime")
        try:
            remediation_result = await remediate_alert_with_model(
                alert, workspace, trace, runtime, client, model_tools,
            )
        except ModelCallDenied as error:
            remediation_result = {"agent_status": error.reason}
        except Exception:
            remediation_result = {}
        if remediation_result.get("agent_status") in {
            TerminalStatus.BUDGET_EXHAUSTED, TerminalStatus.MAX_STEPS, TerminalStatus.NO_PROGRESS,
        }:
            remediation_cutoff = remediation_result["agent_status"]
        else:
            remediation = _remediation_from_result(remediation_result)
        trace.event("state_change", alert_id=alert["alert_id"], node="remediation",
                    remediation_status=remediation["status"], checks=remediation["checks"])
    else:
        trace.event("routing", alert_id=alert["alert_id"], decision="skip_remediation", by="runtime")
    _settle(rows, trace, alert, "classified", result["label"],
            result["rationale"], result["evidence"], remediation)
    return remediation_cutoff


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


def _skipped_remediation() -> dict:
    return {"status": "skipped", "diff": "",
            "checks": {"applies": None, "touches_flagged_line": None, "clean_rescan": None}}


def _remediation_from_result(result: dict) -> dict:
    patch_result = None
    for observation in result.get("observations", []):
        if observation.get("tool") != "edit" or not observation.get("ok"):
            continue
        try:
            patch = json.loads(observation["result"])
        except (KeyError, json.JSONDecodeError):
            continue
        if not {"status", "diff", "checks"} <= patch.keys():
            continue
        patch = {key: patch[key] for key in ("status", "diff", "checks")}
        if patch["status"] in {"accepted", "rejected"}:
            patch_result = patch
    if patch_result is not None:
        return patch_result
    skipped = _skipped_remediation()
    if result.get("edit_outcome") == "not_edited":
        skipped["summary"] = result.get("remediation_summary", "")
    return skipped


def _settle(rows: dict, trace: Trace, alert: Alert, status: str,
            label: int | None, rationale: str, evidence: list[dict],
            remediation: dict | None = None) -> None:
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
        "remediation": _skipped_remediation() if remediation is None else remediation,
    }
    trace.event(
        "state_change", alert_id=alert["alert_id"], node="submit",
        alert_status=status, label=label,
    )


def _report(config: Config, alerts: list[Alert], rows: dict, trace: Trace,
            terminal_status: str, error: Exception | None) -> dict:
    usage = trace.usage.as_dict()
    report = {
        "target": {"input": str(config.fixture), "commit": _target_commit(config)},
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


def _target_commit(config: Config) -> str:
    try:
        target = TARGET_BY_PATHS[tuple(config.scan["paths"])]
        return config.target_commits[target]
    except KeyError as error:
        raise ValueError("scan paths have no configured pinned commit") from error
