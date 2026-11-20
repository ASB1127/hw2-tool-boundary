from types import SimpleNamespace

from workspace import AgentWorkspace


def test_mcp_owasp_workspace_keeps_cases_but_withholds_answer_key(tmp_path):
    source = tmp_path / "source"
    (source / "testcode").mkdir(parents=True)
    (source / "testcode" / "BenchmarkTest00011.py").write_text("first")
    (source / "testcode" / "BenchmarkTest00012.py").write_text("second")
    (source / "expectedresults-0.1.csv").write_text("withheld")
    config = SimpleNamespace(fixture=source, workspace_prefix="mcp-")

    with AgentWorkspace(config, is_owasp=True) as workspace:
        assert (workspace / "testcode" / "BenchmarkTest00011.py").read_text() == "first"
        assert (workspace / "testcode" / "BenchmarkTest00012.py").read_text() == "second"
        assert not (workspace / "expectedresults-0.1.csv").exists()
