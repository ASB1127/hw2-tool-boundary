from pathlib import Path

from workspace import PathEscapeException, resolve


def validate_classification(result, workspace: Path) -> dict:
    if not isinstance(result, dict):
        raise ValueError("classification is not an object")
    label = result.get("label")
    rationale = result.get("rationale")
    evidence = result.get("evidence")
    if type(label) is not int or label not in (0, 1):
        raise ValueError("label must be 0 or 1")
    if not isinstance(rationale, str) or not rationale.strip():
        raise ValueError("rationale must be non-empty text")
    if not isinstance(evidence, list) or not evidence:
        raise ValueError("evidence must be a non-empty list")

    for item in evidence:
        if not isinstance(item, dict):
            raise ValueError("evidence item must be an object")
        path = item.get("path")
        start = item.get("start_line")
        end = item.get("end_line")
        if (not isinstance(path, str) or not path or path.startswith("./")
                or "\\" in path or type(start) is not int or type(end) is not int
                or start < 1 or end < start):
            raise ValueError("invalid evidence range")
        try:
            target = resolve(workspace, path)
        except PathEscapeException as error:
            raise ValueError("evidence path is outside the workspace") from error
        if not target.is_file():
            raise ValueError(f"evidence file does not exist: {path}")
        if end > len(target.read_text(encoding="utf-8", errors="replace").splitlines()):
            raise ValueError(f"evidence range is outside {path}")

    return {"agent_status": "classified", "label": label,
            "rationale": rationale, "evidence": evidence}


def validate_remediation(result) -> dict:
    if not isinstance(result, dict):
        raise ValueError("remediation is not an object")
    outcome = result.get("status")
    summary = result.get("summary")
    if outcome not in {"edited", "not_edited"}:
        raise ValueError("remediation status must be edited or not_edited")
    if not isinstance(summary, str) or not summary.strip():
        raise ValueError("remediation summary must be non-empty text")
    if set(result) != {"status", "summary"}:
        raise ValueError("remediation has unexpected keys")
    return {
        "agent_status": "remediation_completed",
        "edit_outcome": outcome,
        "remediation_summary": summary,
    }
