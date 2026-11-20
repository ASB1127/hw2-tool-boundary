import asyncio
from types import SimpleNamespace

import pytest
from jsonschema import validate
from pydantic import TypeAdapter, ValidationError
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import CallToolRequestParams

from backend import (
    _ANALYSES, _callees as callees, _callers as callers, _dataflow as dataflow,
    _edit as edit, _entry_points as entry_points, _locate as locate, _rescan as rescan,
    _search as search, _source as source,
)
from server import (
    BanditAlert, CallResults, ConfiguredResult, DataflowResult, EditResult,
    EntryPointsResult, EvidenceResult, HOST_ONLY_TOOLS, MCPServerApp,
    SearchResults, SelectedAlertResult, _prepare_standalone_workspace,
)


def test_result_types_describe_and_validate_expected_shapes():
    examples = [
        (ConfiguredResult, {"configured": 1}),
        (SelectedAlertResult, {"alert_id": "a", "path": "a.py"}),
        (EvidenceResult, {"valid": True}),
        (DataflowResult, {"edges": [{"from": "a", "to": "b", "variable": None}],
                          "total": 1, "complete": True}),
        (EntryPointsResult, {"entrypoints": [], "coverage": {}}),
        (EditResult, {"status": "rejected", "diff": "", "checks": {
            "applies": None, "touches_flagged_line": None, "clean_rescan": None}}),
        (CallResults, [{"file": "a.py", "line": 1, "callable": "a.f", "kind": "callable",
                        "name": None, "ref": "id"}]),
        (SearchResults, [{"file": "a.py", "line": 1, "text": "x"}]),
        (BanditAlert, {"code": "x", "col_offset": 0, "end_col_offset": None,
                       "filename": "a.py", "issue_confidence": "HIGH", "issue_cwe": {},
                       "issue_severity": "MEDIUM", "issue_text": "issue", "line_number": 1,
                       "line_range": [1], "more_info": "url", "test_id": "B1", "test_name": "test"}),
    ]
    for result_type, value in examples:
        adapter = TypeAdapter(result_type)
        assert adapter.validate_python(value)
        assert adapter.json_schema()
    with pytest.raises(ValidationError):
        TypeAdapter(DataflowResult).validate_python({"edges": [], "total": "bad", "complete": True})
    with pytest.raises(ValidationError):
        TypeAdapter(SearchResults).validate_python([{"file": "a.py"}])


def test_all_tools_publish_output_schemas(tmp_path):
    tools = asyncio.run(MCPServerApp(tmp_path).mcp.list_tools())
    assert tools
    assert all(tool.output_schema is not None for tool in tools)


@pytest.mark.parametrize(("name", "args", "valid", "invalid"), [
    ("configure_alerts", {"alerts": {}, "pinned_root": "/tmp"},
     {"configured": 1}, {"unexpected": 1}),
    ("set_alert", {"alert_id": "a"}, {"alert_id": "a", "path": "a.py"}, {"alert_id": "a"}),
    ("validate_evidence", {"evidence": []}, {"valid": True}, {"valid": []}),
    ("dataflow", {"path": "a.py", "line": 1},
     {"edges": [{"from": "a", "to": "b", "variable": None}], "total": 1, "complete": True},
     {"edges": [{"from": "a"}], "total": 1, "complete": True}),
    ("entry_points", {}, {"entrypoints": [], "coverage": {}}, {"entrypoints": "bad", "coverage": {}}),
    ("edit", {"path": "a.py", "old": "a", "new": "b"},
     {"status": "accepted", "diff": "diff", "checks": {
         "applies": True, "touches_flagged_line": True, "clean_rescan": True}},
     {"status": "accepted", "diff": "diff", "checks": {"applies": True}}),
    ("search", {"pattern": "x"}, [{"file": "a.py", "line": 1, "text": "x"}],
     [{"file": "a.py"}]),
    ("locate", {"path": "a.py", "line": 1}, "module scope", {"wrong": "type"}),
    ("source", {"signature": "a.f"}, "def f(): pass", {"wrong": "type"}),
    ("read_file", {"path": "a.py"}, "content", {"wrong": "type"}),
    ("callers", {"name": "f"},
     [{"file": "a.py", "line": 1, "callable": "a.f", "kind": "callable", "name": None, "ref": "id"}],
     [{"file": "a.py"}]),
    ("callees", {"name": "f"},
     [{"file": "a.py", "line": 1, "callable": "a.f", "kind": "callable", "name": None, "ref": "id"}],
     [{"file": "a.py"}]),
    ("rescan", {"path": "a.py"}, [{
        "code": "x", "col_offset": 0, "end_col_offset": None, "filename": "a.py",
        "issue_confidence": "HIGH", "issue_cwe": {"id": 1, "link": "url"},
        "issue_severity": "MEDIUM", "issue_text": "issue", "line_number": 1,
        "line_range": [1], "more_info": "url", "test_id": "B001", "test_name": "test",
     }], [{"filename": "a.py"}]),
])
def test_mcp_validates_tool_results(tmp_path, monkeypatch, name, args, valid, invalid):
    server = MCPServerApp(tmp_path).mcp
    tool = server._tool_manager.get_tool(name)

    async def call():
        return await server._handle_call_tool(None, CallToolRequestParams(name=name, arguments=args))

    monkeypatch.setattr(tool, "fn", lambda **kwargs: valid)
    result = asyncio.run(call())
    assert not result.is_error
    schema = next(item.output_schema for item in asyncio.run(server.list_tools()) if item.name == name)
    validate(result.structured_content, schema)
    monkeypatch.setattr(tool, "fn", lambda **kwargs: invalid)
    assert asyncio.run(call()).is_error


def test_standalone_workspace_copies_only_permitted_entries(tmp_path):
    target = tmp_path / "target"
    workspace = tmp_path / "work" / "target"
    for name in ("testcode", "helpers"):
        (target / name).mkdir(parents=True)
        (target / name / "file.py").write_text(name)
    (target / "app.py").write_text("app")
    (target / "expectedresults.csv").write_text("secret")

    _prepare_standalone_workspace(workspace, target)
    assert {path.name for path in workspace.iterdir()} == {"testcode", "helpers", "app.py"}
    assert (workspace / "testcode" / "file.py").read_text() == "testcode"
    (workspace / "app.py").write_text("edited")
    _prepare_standalone_workspace(workspace, target)
    assert (workspace / "app.py").read_text() == "edited"


def test_standalone_workspace_detects_radicale_and_sglang_entries(tmp_path):
    target = tmp_path / "target"
    workspace = tmp_path / "work" / "target"
    (target / "radicale").mkdir(parents=True)
    (target / "radicale" / "app.py").write_text("radicale")
    runtime = target / "python/sglang/multimodal_gen/runtime"
    runtime.mkdir(parents=True)
    (runtime / "app.py").write_text("sglang")
    replay = target / "scripts/playground/replay_request_dump.py"
    replay.parent.mkdir(parents=True)
    replay.write_text("replay")

    _prepare_standalone_workspace(workspace, target)

    assert (workspace / "radicale/app.py").read_text() == "radicale"
    assert (workspace / "python/sglang/multimodal_gen/runtime/app.py").read_text() == "sglang"
    assert (workspace / "scripts/playground/replay_request_dump.py").read_text() == "replay"


def test_server_marks_os_permission_errors(tmp_path, monkeypatch):
    server = MCPServerApp(tmp_path)

    def denied(*args, **kwargs):
        raise PermissionError("access denied")

    monkeypatch.setattr("backend._read_file", denied)
    with pytest.raises(ToolError, match="^refused: kernel: access denied"):
        server.read_file("target.py")
    result = asyncio.run(server.mcp.call_tool("read_file", {"path": "target.py"}))
    assert result.is_error
    assert result.content[0].text == "refused: kernel: access denied"


def test_server_marks_set_alert_host_only(tmp_path):
    tools = asyncio.run(MCPServerApp(tmp_path).mcp.list_tools())
    offered = {tool.name for tool in tools} - HOST_ONLY_TOOLS
    assert offered == {
        "locate", "source", "callers", "callees", "dataflow", "entry_points",
        "read_file", "search", "edit", "rescan",
    }
    assert HOST_ONLY_TOOLS == {"configure_alerts", "set_alert", "validate_evidence"}


def test_host_alert_selection_contextualizes_edits(tmp_path, monkeypatch):
    workspace = tmp_path / "workspace"
    pinned = tmp_path / "pinned"
    workspace.mkdir()
    pinned.mkdir()
    (workspace / "target.py").write_text("old")
    alert = {"filename": "target.py", "line_number": 1, "test_id": "B105"}
    server = MCPServerApp(workspace, alerts={"alert-A": alert}, pinned_root=pinned)
    set_alert = server.mcp._tool_manager.get_tool("set_alert").fn
    edit_current = server.mcp._tool_manager.get_tool("edit").fn
    calls = []
    monkeypatch.setattr(
        "backend._edit",
        lambda *args, **kwargs: calls.append((args, kwargs)) or {"status": "accepted"},
    )

    assert set_alert("alert-A") == {"alert_id": "alert-A", "path": "target.py"}
    assert edit_current("target.py", "old", "new") == {"status": "accepted"}
    assert calls == [
        ((workspace.resolve(), "target.py", "old", "new"),
         {"pinned_root": pinned.resolve(), "alert": alert})
    ]
    with pytest.raises(ToolError, match="selected alert file"):
        edit_current("other.py", "old", "new")


def test_owasp_read_file_requires_the_selected_case(tmp_path):
    (tmp_path / "testcode").mkdir()
    (tmp_path / "testcode" / "BenchmarkTest00011.py").write_text("selected")
    (tmp_path / "testcode" / "BenchmarkTest00012.py").write_text("withheld")
    server = MCPServerApp(tmp_path)
    server.set_alert("BenchmarkTest00011")

    assert server.read_file("testcode/BenchmarkTest00011.py") == "selected"
    with pytest.raises(ToolError, match="selected alert file"):
        server.read_file("testcode/BenchmarkTest00012.py")


def test_owasp_cldk_analysis_is_limited_to_the_selected_case(tmp_path, monkeypatch):
    (tmp_path / "testcode").mkdir()
    selected = "testcode/BenchmarkTest00011.py"
    (tmp_path / selected).write_text("def handler():\n    pass\n")
    calls = []
    analysis = SimpleNamespace(
        locate=lambda path, line: SimpleNamespace(
            callable=SimpleNamespace(signature="testcode.BenchmarkTest00011.handler")
        )
    )
    monkeypatch.setattr("backend.CLDK", SimpleNamespace(
        python=lambda **kwargs: calls.append(kwargs) or analysis
    ))
    _ANALYSES.clear()
    server = MCPServerApp(tmp_path, alerts={
        "alert-A": {"filename": selected, "line_number": 1, "test_id": "B105"}
    })
    server.set_alert("alert-A")

    assert server.locate(selected, 1).endswith("handler")
    assert calls[0]["target_files"] == [selected]


def test_owasp_selecting_a_new_case_discards_the_previous_cldk_analysis(tmp_path, monkeypatch):
    (tmp_path / "testcode").mkdir()
    first = "testcode/BenchmarkTest00011.py"
    second = "testcode/BenchmarkTest00012.py"
    (tmp_path / first).write_text("def handler():\n    pass\n")
    (tmp_path / second).write_text("def handler():\n    pass\n")
    analysis = SimpleNamespace(locate=lambda path, line: SimpleNamespace(
        callable=SimpleNamespace(signature="testcode.handler")
    ))
    monkeypatch.setattr("backend.CLDK", SimpleNamespace(python=lambda **kwargs: analysis))
    _ANALYSES.clear()
    server = MCPServerApp(tmp_path, alerts={
        "first": {"filename": first, "line_number": 1, "test_id": "B105"},
        "second": {"filename": second, "line_number": 1, "test_id": "B105"},
    })

    server.set_alert("first")
    server.locate(first, 1)
    assert len(_ANALYSES) == 1
    server.set_alert("second")
    assert not _ANALYSES
    server.locate(second, 1)
    assert len(_ANALYSES) == 1


def test_cldk_tools_share_a_workspace_analysis(tmp_path, monkeypatch):
    path = tmp_path / "target.py"
    path.write_text("def handler():\n    pass\n")
    analysis = SimpleNamespace(
        locate=lambda path, line: SimpleNamespace(
            callable=SimpleNamespace(signature="target.handler")
        ),
        get_method_bodies=lambda signatures: {"target.handler": "def handler():\n    pass\n"},
        callers_of=lambda name, in_module: [{"file": "caller.py", "line": 4}],
        callees_of=lambda name, in_module: [{"file": "callee.py", "line": 8}],
        get_ddg=lambda signature: SimpleNamespace(
            edges=[SimpleNamespace(src="node-1", dst="node-2", var="request")],
            total=1,
            complete=True,
        ),
        get_entrypoints=lambda: [{"signature": "target.handler"}],
        get_entrypoint_coverage=lambda: {"frameworks_detected": ["flask"]},
    )
    calls = []
    monkeypatch.setattr("backend.CLDK", SimpleNamespace(
        python=lambda **kwargs: calls.append(kwargs) or analysis
    ))
    _ANALYSES.clear()

    assert locate(tmp_path, "target.py", 1) == "target.handler"
    assert source(tmp_path, "target.handler").startswith("def handler")
    assert callers(tmp_path, "handler") == [{"file": "caller.py", "line": 4}]
    assert callees(tmp_path, "handler") == [{"file": "callee.py", "line": 8}]
    assert dataflow(tmp_path, "target.py", 1)["edges"] == [
        {"from": "node-1", "to": "node-2", "variable": "request"}
    ]
    assert entry_points(tmp_path)["entrypoints"] == [{"signature": "target.handler"}]
    assert calls == [{
        "project_path": tmp_path.resolve(),
        "analysis_level": "program_dependency_graph",
        "target_files": None,
    }]


def test_edit_accepts_only_a_patch_that_passes_all_checks(tmp_path, monkeypatch):
    pinned = tmp_path / "pinned"
    workspace = tmp_path / "workspace"
    pinned.mkdir()
    workspace.mkdir()
    (pinned / "target.py").write_text("value = old\n")
    (workspace / "target.py").write_text("value = old\n")
    alert = {"filename": "target.py", "line_number": 1, "test_id": "B105"}
    monkeypatch.setattr("backend._applies", lambda root, diff: True)
    monkeypatch.setattr("backend._rescan", lambda ws, path: [])

    result = edit(workspace, "target.py", "old", "new", pinned_root=pinned, alert=alert)

    assert result["status"] == "accepted"
    assert result["checks"] == {
        "applies": True, "touches_flagged_line": True, "clean_rescan": True,
    }
    assert "-value = old" in result["diff"]
    assert "+value = new" in result["diff"]


def test_edit_replaces_one_exact_occurrence(tmp_path):
    path = tmp_path / "target.py"
    path.write_text("value = old\n")

    assert edit(tmp_path, "target.py", "old", "new") == "edited target.py"
    assert path.read_text() == "value = new\n"

    with pytest.raises(ValueError, match="exactly once"):
        edit(tmp_path, "target.py", "missing", "new")


def test_rescan_runs_bandit_on_only_the_requested_file(tmp_path, monkeypatch):
    path = tmp_path / "target.py"
    path.write_text("password = 'secret'\n")
    calls = []

    class FakeScan:
        def __init__(self, workspace):
            calls.append(("workspace", workspace))

        def discover(self, config):
            calls.append(("config", config))
            return [{"test_id": "B105"}]

    monkeypatch.setattr("backend.Scan", FakeScan)

    assert rescan(tmp_path, "target.py") == [{"test_id": "B105"}]
    assert calls == [
        ("workspace", tmp_path),
        ("config", {"paths": ["target.py"], "exclude": [], "min_severity": "MEDIUM"}),
    ]


def test_owasp_search_only_reads_selected_alert(tmp_path):
    (tmp_path / "testcode").mkdir()
    selected = tmp_path / "testcode" / "BenchmarkTest00011.py"
    selected.write_text("sql = 'selected'\n")
    (tmp_path / "testcode" / "BenchmarkTest00012.py").write_text("sql = 'other'\n")

    assert search(
        tmp_path, "sql", selected_alert_file="testcode/BenchmarkTest00011.py", is_owasp=True,
    ) == [{"file": "testcode/BenchmarkTest00011.py", "line": 1, "text": "sql = 'selected'"}]
    with pytest.raises(ValueError, match="selected alert"):
        search(tmp_path, "sql", is_owasp=True)
