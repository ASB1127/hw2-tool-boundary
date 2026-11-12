from types import SimpleNamespace

import pytest

from server import (
    _ANALYSES, callers, callees, dataflow, edit, entry_points, locate, rescan,
    search, source,
)


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
    monkeypatch.setattr("server.CLDK", SimpleNamespace(
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
    assert calls == [{"project_path": tmp_path.resolve(), "analysis_level": "program_dependency_graph"}]


def test_edit_accepts_only_a_patch_that_passes_all_checks(tmp_path, monkeypatch):
    pinned = tmp_path / "pinned"
    workspace = tmp_path / "workspace"
    pinned.mkdir()
    workspace.mkdir()
    (pinned / "target.py").write_text("value = old\n")
    (workspace / "target.py").write_text("value = old\n")
    alert = {"filename": "target.py", "line_number": 1, "test_id": "B105"}
    monkeypatch.setattr("server._applies", lambda root, diff: True)
    monkeypatch.setattr("server.rescan", lambda ws, path: [])

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

    monkeypatch.setattr("server.Scan", FakeScan)

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
