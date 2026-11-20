import asyncio
import json
import os
import sys
from pathlib import Path
from types import SimpleNamespace

from client import MCPClient
from dispatcher import Dispatcher
from runner import _remediation_from_result


async def _run_direct_owasp_test():
    workspace = Path(__file__).parent.parent / "targets" / "BenchmarkPython"
    client = MCPClient(str(workspace), Path(__file__).parent.parent / "mcp.json")
    client.params.command = sys.executable
    try:
        tools = {tool.name for tool in await client.connect()}
        assert "set_alert" in tools

        selected = await client.call_tool(
            "set_alert", {"alert_id": "BenchmarkTest00011"},
        )
        assert not selected.is_error

        allowed = await client.call_tool(
            "read_file", {"path": "testcode/BenchmarkTest00011.py"},
        )
        assert not allowed.is_error

        for tool, args in [
            ("read_file", {"path": "expectedresults-0.1.csv"}),
            ("read_file", {"path": ".git/config"}),
            ("read_file", {"path": "testcode/BenchmarkTest00012.py"}),
            ("edit", {"path": "../outside.py", "old": "x", "new": "y"}),
            ("edit", {"path": "testcode/BenchmarkTest00012.py", "old": "x", "new": "y"}),
        ]:
            refused = await client.call_tool(tool, args)
            assert refused.is_error
            assert refused.content[0].text.startswith("refused:")
    finally:
        await client.close()


def test_direct_owasp_selection_enforces_case_restrictions():
    asyncio.run(_run_direct_owasp_test())


def test_malformed_result_is_rejected_over_stdio(tmp_path):
    async def run():
        client = MCPClient(str(tmp_path), Path(__file__).parent.parent / "mcp.json")
        client.params.command = sys.executable
        client.params.args = ["-c", (
            "import backend, server; "
            "backend._dataflow = lambda *args, **kwargs: "
            "{'edges': [{'from': 'a'}], 'total': 1, 'complete': True}; "
            "server.main()"
        ), "--workspace", str(tmp_path)]
        try:
            tools = await client.connect()
            assert tools and all(tool.output_schema is not None for tool in tools)
            result = await client.call_tool("dataflow", {"path": "a.py", "line": 1})
            assert result.is_error
        finally:
            await client.close()

    asyncio.run(run())


def test_typed_results_preserve_search_and_edit_wire_formats(tmp_path):
    workspace, baseline = tmp_path / "workspace", tmp_path / "baseline"
    workspace.mkdir()
    baseline.mkdir()
    for root in (workspace, baseline):
        (root / "target.py").write_text("value = 'old'\n")

    async def run():
        client = MCPClient(str(workspace), Path(__file__).parent.parent / "mcp.json")
        client.params.command = sys.executable
        client.params.env["PATH"] = str(Path(sys.executable).parent) + os.pathsep + os.environ.get("PATH", "")
        try:
            tools = {tool.name: tool for tool in await client.connect()}
            configured = await client.call_tool("configure_alerts", {
                "alerts": {"a": {"filename": "target.py", "line_number": 1, "test_id": "B999"}},
                "pinned_root": str(baseline),
            })
            assert not configured.is_error
            assert not (await client.call_tool("set_alert", {"alert_id": "a"})).is_error
            trace = SimpleNamespace(event=lambda *args, **kwargs: None)
            dispatcher = Dispatcher(workspace, trace, "a", tools, client)

            search = await dispatcher({"tool": "search", "args": {"pattern": "old"}})
            assert search.ok and search.result == "target.py:1: value = 'old'"
            empty = await dispatcher({"tool": "search", "args": {"pattern": "missing"}})
            assert empty.ok and empty.result == "no matches"

            edit = await dispatcher({"tool": "edit", "args": {
                "path": "target.py", "old": "old", "new": "new",
            }})
            assert edit.ok
            patch = json.loads(edit.result)
            assert patch["status"] == "accepted"
            assert patch["checks"] == {
                "applies": True, "touches_flagged_line": True, "clean_rescan": True,
            }
            assert _remediation_from_result({"observations": [edit.to_dict()]}) == patch
        finally:
            await client.close()

    asyncio.run(run())
