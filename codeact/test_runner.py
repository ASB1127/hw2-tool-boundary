from types import SimpleNamespace

from runner import _accept_remediation


def test_edited_remediation_requires_a_successful_code_action(tmp_path):
    alert = {"filename": "alert.py", "line_number": 1, "test_id": "B001"}
    (tmp_path / "alert.py").write_text("x = 1\n")

    remediation = _accept_remediation(
        SimpleNamespace(fixture=tmp_path), alert, tmp_path,
        {"edit_outcome": "edited", "observations": []},
    )

    assert remediation == {
        "status": "rejected",
        "diff": "",
        "checks": {
            "applies": None,
            "touches_flagged_line": None,
            "clean_rescan": None,
        },
    }
