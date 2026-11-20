"""MCP stdio server and its model-visible tool handlers."""

from __future__ import annotations

import argparse
import shutil
from pathlib import Path
from typing import Callable, Literal, TypeVar

from cldk.analysis.commons.results import EntrypointCoverage, SliceNode
from cldk.models.python import PyCallableOverview
from mcp.server import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import CallToolResult, TextContent
from typing_extensions import TypedDict

import backend


T = TypeVar("T")
HOST_ONLY_TOOLS = frozenset({"configure_alerts", "set_alert", "validate_evidence"})


class ConfiguredResult(TypedDict):
    configured: int


class SelectedAlertResult(TypedDict):
    alert_id: str
    path: str


class EvidenceResult(TypedDict):
    valid: bool


DataflowEdge = TypedDict("DataflowEdge", {"from": str, "to": str, "variable": str | None})


class DataflowResult(TypedDict):
    edges: list[DataflowEdge]
    total: int
    complete: bool


class EntryPointsResult(TypedDict):
    entrypoints: list[PyCallableOverview]
    coverage: EntrypointCoverage


class SearchHit(TypedDict):
    file: str
    line: int
    text: str


class PatchChecks(TypedDict):
    applies: bool | None
    touches_flagged_line: bool | None
    clean_rescan: bool | None


class EditResult(TypedDict):
    status: Literal["accepted", "rejected"]
    diff: str
    checks: PatchChecks


class CWE(TypedDict, total=False):
    id: int
    link: str


class BanditAlert(TypedDict):
    code: str
    col_offset: int
    end_col_offset: int | None
    filename: str
    issue_confidence: str
    issue_cwe: CWE
    issue_severity: str
    issue_text: str
    line_number: int
    line_range: list[int]
    more_info: str
    test_id: str
    test_name: str


CallResults = list[SliceNode]
SearchResults = list[SearchHit]
RescanResults = list[BanditAlert]


def _call(operation: Callable[[], T]) -> T:
    try:
        return operation()
    except PermissionError as error:
        raise ToolError(f"refused: kernel: {error}") from error
    except (FileNotFoundError, ValueError) as error:
        raise ToolError(f"refused: {error}") from error


class RefusalMCPServer(MCPServer):
    async def call_tool(self, name, arguments, context=None):
        try:
            return await super().call_tool(name, arguments, context)
        except ToolError as error:
            cause = error.__cause__
            if isinstance(cause, ToolError) and str(cause).startswith("refused:"):
                return CallToolResult(content=[TextContent(type="text", text=str(cause))], is_error=True)
            raise


class MCPServerApp:
    """One MCP server instance and the workspace state shared by its handlers."""

    def __init__(self, workspace: Path, *, alerts: dict[str, dict] | None = None,
                 pinned_root: Path | None = None):
        self.workspace = Path(workspace).resolve()
        self.is_owasp = any(self.workspace.glob("testcode/BenchmarkTest*.py"))
        self.alerts = {} if alerts is None else alerts
        self.pinned_root = Path(pinned_root).resolve() if pinned_root is not None else None
        self.active_alert: dict | None = None
        self.mcp = RefusalMCPServer("analysis")
        for handler in (
            self.configure_alerts, self.set_alert, self.validate_evidence, self.locate, self.source, self.callers, self.callees,
            self.dataflow, self.entry_points, self.read_file, self.search, self.edit,
            self.rescan,
        ):
            self.mcp.tool()(handler)

    def selected(self, path: str | None = None) -> dict:
        if self.active_alert is None:
            raise ToolError("refused: no alert selected")
        if path is not None and path != self.active_alert["filename"]:
            raise ToolError("refused: path is not the selected alert file")
        return self.active_alert

    def readable_path(self, path: str | None = None) -> str | None:
        if not self.is_owasp:
            return None
        return self.selected(path)["filename"]

    def analysis_files(self) -> tuple[str, ...] | None:
        return (self.selected()["filename"],) if self.is_owasp else None

    def configure_alerts(self, alerts: dict[str, dict], pinned_root: str) -> ConfiguredResult:
        """Host-only control: install alert metadata and its immutable baseline."""
        baseline = Path(pinned_root).resolve()
        if not baseline.is_dir():
            raise ToolError("refused: pinned baseline is not a directory")
        self.alerts = alerts
        self.pinned_root = baseline
        return {"configured": len(alerts)}

    def set_alert(self, alert_id: str) -> SelectedAlertResult:
        """Host-only control: select the alert whose file tools may edit."""
        alert = self.alerts.get(alert_id)
        if alert is None:
            candidate = f"testcode/{alert_id}.py"
            if not (self.workspace / candidate).is_file():
                raise ToolError(f"refused: unknown alert: {alert_id}")
            alert = {"alert_id": alert_id, "filename": candidate}
        if self.is_owasp and (self.active_alert is None
                              or self.active_alert["filename"] != alert["filename"]):
            backend._clear_scoped_cldk_analyses(self.workspace)
        self.active_alert = alert
        return {"alert_id": alert_id, "path": alert["filename"]}

    def validate_evidence(self, evidence: list[dict]) -> EvidenceResult:
        """Host-only control: validate model evidence against the selected scope."""
        for item in evidence:
            self.readable_path(item["path"])
        _call(lambda: backend._validate_evidence(self.workspace, evidence))
        return {"valid": True}

    def locate(self, path: str, line: int) -> str:
        """Return the enclosing callable signature, or module scope."""
        self.readable_path(path)
        return _call(lambda: backend._locate(
            self.workspace, path, line, target_files=self.analysis_files(),
        ))

    def source(self, signature: str) -> str:
        """Return source text for a callable signature."""
        allowed_path = self.readable_path()
        return _call(lambda: backend._source(
            self.workspace, signature, allowed_path=allowed_path,
            target_files=self.analysis_files(),
        ))

    def callers(self, name: str, module: str | None = None) -> CallResults:
        """Return callers of a callable, including their source locations."""
        allowed_path = self.readable_path()
        return _call(lambda: backend._callers(
            self.workspace, name, module, allowed_path=allowed_path,
            target_files=self.analysis_files(),
        ))

    def callees(self, name: str, module: str | None = None) -> CallResults:
        """Return callees of a callable, including external targets."""
        allowed_path = self.readable_path()
        return _call(lambda: backend._callees(
            self.workspace, name, module, allowed_path=allowed_path,
            target_files=self.analysis_files(),
        ))

    def dataflow(self, path: str, line: int) -> DataflowResult:
        """Return data-dependence edges for the callable enclosing a source line."""
        self.readable_path(path)
        return _call(lambda: backend._dataflow(
            self.workspace, path, line, target_files=self.analysis_files(),
        ))

    def entry_points(self) -> EntryPointsResult:
        """Return route handlers and CLDK's entrypoint coverage report."""
        allowed_path = self.readable_path()
        result = _call(lambda: backend._entry_points(
            self.workspace, target_files=self.analysis_files(),
        ))
        if allowed_path is not None:
            result["entrypoints"] = [
                entrypoint for entrypoint in result["entrypoints"]
                if entrypoint["path"] == allowed_path
            ]
        return result

    def read_file(self, path: str, start: int | None = None, end: int | None = None) -> str:
        """Read a workspace file, optionally over an inclusive line range."""
        self.readable_path(path)
        return _call(lambda: backend._read_file(self.workspace, path, start, end))

    def search(self, pattern: str, path: str | None = None) -> SearchResults:
        """Search workspace Python source, optionally limited to one path."""
        allowed_path = self.readable_path(path)
        return _call(lambda: backend._search(
            self.workspace, pattern, path=path,
            selected_alert_file=allowed_path, is_owasp=self.is_owasp,
        ))

    def edit(self, path: str, old: str, new: str) -> EditResult:
        """Replace one exact occurrence in the selected alert file and validate it."""
        alert = self.selected(path)
        if self.pinned_root is None:
            raise ToolError("refused: pinned baseline is not configured")
        if "line_number" not in alert or "test_id" not in alert:
            raise ToolError("refused: selected alert lacks scan metadata")
        return _call(lambda: backend._edit(
            self.workspace, path, old, new, pinned_root=self.pinned_root, alert=alert,
        ))

    def rescan(self, path: str) -> RescanResults:
        """Return Bandit 1.9.4 MEDIUM-or-higher alerts for the selected alert file."""
        self.selected(path)
        return _call(lambda: backend._rescan(self.workspace, path))

    def run(self) -> None:
        self.mcp.run(transport="stdio")


def _prepare_standalone_workspace(workspace: Path, target: Path = Path("/target")) -> None:
    if workspace.is_dir() and any(workspace.iterdir()):
        return
    workspace.mkdir(parents=True, exist_ok=True)
    for name in (
        "testcode", "helpers", "app.py", "radicale",
        "python/sglang/multimodal_gen/runtime",
        "scripts/playground/replay_request_dump.py",
    ):
        source = target / name
        destination = workspace / name
        if source.is_dir():
            shutil.copytree(source, destination)
        elif source.is_file():
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, destination)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--workspace", type=Path, required=True)
    args = parser.parse_args()
    if args.workspace.resolve() == Path("/sandbox/work/target"):
        _prepare_standalone_workspace(args.workspace)
    MCPServerApp(args.workspace).run()


if __name__ == "__main__":
    main()
