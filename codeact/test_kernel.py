from pathlib import Path

from kernel import Kernel


def test_kernel_persists_one_alert_namespace(tmp_path):
    kernel = Kernel(tmp_path)

    assert kernel.run("x = 41") == {
        "ok": True, "output": "", "stderr": "", "error": "",
    }
    assert kernel.run("print(x + 1)") == {
        "ok": True, "output": "42\n", "stderr": "", "error": "",
    }
    assert kernel.run("print(WORKSPACE)") == {
        "ok": True, "output": f"{tmp_path}\n", "stderr": "", "error": "",
    }
    assert kernel.run("import sys; print('warning', file=sys.stderr)") == {
        "ok": True, "output": "", "stderr": "warning\n", "error": "",
    }

    (tmp_path / "relative.txt").write_text("workspace file")
    original_directory = Path.cwd()
    assert kernel.run("print(open('relative.txt').read())") == {
        "ok": True, "output": "workspace file\n", "stderr": "", "error": "",
    }
    assert Path.cwd() == original_directory


def test_kernel_returns_tracebacks_and_isolates_alerts(tmp_path):
    first_workspace = tmp_path / "first"
    second_workspace = tmp_path / "second"
    first_workspace.mkdir()
    second_workspace.mkdir()
    first = Kernel(first_workspace)
    second = Kernel(second_workspace)

    first.run("x = 41")
    failed = first.run('raise ValueError("x")')
    assert failed["ok"] is False
    assert "ValueError: x" in failed["error"]

    result = second.run("print(x)")
    assert result["ok"] is False
    assert "NameError" in result["error"]
