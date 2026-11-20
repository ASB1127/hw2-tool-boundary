from __future__ import annotations

import difflib
import re
import subprocess
from pathlib import Path

from cldk import CLDK

from scan import Scan
from workspace import resolve


# Internal helpers only; this module registers no MCP tools.
SEARCH_MAX_HITS = 10
FILE_MAX_LINES = 200
_ANALYSES = {}
__all__: tuple[str, ...] = ()


def _get_cached_cldk_analysis(ws: Path, target_files: tuple[str, ...] | None = None):
    root = Path(ws).resolve()
    key = root, target_files
    if key not in _ANALYSES:
        _ANALYSES[key] = CLDK.python(
            project_path=root, analysis_level="program_dependency_graph",
            target_files=list(target_files) if target_files is not None else None,
        )
    return _ANALYSES[key]


def _clear_scoped_cldk_analyses(ws: Path) -> None:
    """Discard per-file CLDK analyses for a workspace, retaining full-project ones."""
    root = Path(ws).resolve()
    for key in [key for key in _ANALYSES if key[0] == root and key[1] is not None]:
        del _ANALYSES[key]


def _validate_evidence(ws: Path, evidence: list[dict]) -> None:
    """Confirm evidence files and line ranges within the server workspace."""
    for item in evidence:
        target = resolve(ws, item["path"])
        if not target.is_file():
            raise ValueError(f"evidence file does not exist: {item['path']}")
        if item["end_line"] > len(target.read_text(encoding="utf-8", errors="replace").splitlines()):
            raise ValueError(f"evidence range is outside {item['path']}")


def _dump(value):
    return value.model_dump(mode="json") if hasattr(value, "model_dump") else value


def _locate(ws: Path, path: str, line: int, *,
            target_files: tuple[str, ...] | None = None) -> str:
    """Return the enclosing callable signature, or ``module scope``."""
    if line < 1:
        raise ValueError("line numbers start at 1")
    target = resolve(ws, path)
    if not target.is_file():
        raise FileNotFoundError(f"no such file: {path}")
    found = _get_cached_cldk_analysis(ws, target_files).locate(
        target.relative_to(Path(ws).resolve()).as_posix(), line
    )
    return found.callable.signature if found.callable else "module scope"


def _source(ws: Path, signature: str, *, allowed_path: str | None = None,
            target_files: tuple[str, ...] | None = None) -> str:
    """Return source text for one callable, optionally restricted to one file."""
    analysis = _get_cached_cldk_analysis(ws, target_files)
    if allowed_path is not None and not any(
        callable.signature == signature and callable.path == allowed_path
        for callable in analysis.get_callables_overview()
    ):
        raise ValueError("callable is not in the selected alert file")
    body = analysis.get_method_bodies([signature]).get(signature)
    if body is None:
        raise ValueError(f"no source for callable: {signature}")
    return body


def _callers(ws: Path, name: str, module: str | None = None,
             *, allowed_path: str | None = None,
             target_files: tuple[str, ...] | None = None) -> list[dict]:
    """Return callers of ``name``, optionally limited to one source file."""
    nodes = [_dump(node) for node in _get_cached_cldk_analysis(ws, target_files).callers_of(name, in_module=module)]
    return nodes if allowed_path is None else [node for node in nodes if node["file"] == allowed_path]


def _callees(ws: Path, name: str, module: str | None = None,
             *, allowed_path: str | None = None,
             target_files: tuple[str, ...] | None = None) -> list[dict]:
    """Return callees of ``name``, optionally limited to one source file or externals."""
    nodes = [_dump(node) for node in _get_cached_cldk_analysis(ws, target_files).callees_of(name, in_module=module)]
    return nodes if allowed_path is None else [
        node for node in nodes if node["file"] == allowed_path or node["kind"] == "external"
    ]


def _dataflow(ws: Path, path: str, line: int, *,
              target_files: tuple[str, ...] | None = None) -> dict:
    """Return the enclosing callable's first page of CLDK DDG edges."""
    signature = _locate(ws, path, line, target_files=target_files)
    if signature == "module scope":
        raise ValueError(f"no enclosing callable at {path}:{line}")
    page = _get_cached_cldk_analysis(ws, target_files).get_ddg(signature)
    return {
        "edges": [
            {"from": edge.src, "to": edge.dst, "variable": edge.var}
            for edge in page.edges
        ],
        "total": page.total,
        "complete": page.complete,
    }


def _entry_points(ws: Path, *, target_files: tuple[str, ...] | None = None) -> dict:
    """Return CLDK route handlers and its entrypoint-detection coverage report."""
    analysis = _get_cached_cldk_analysis(ws, target_files)
    return {
        "entrypoints": [_dump(entrypoint) for entrypoint in analysis.get_entrypoints()],
        "coverage": _dump(analysis.get_entrypoint_coverage()),
    }


def _read_file(ws: Path, path: str, start: int | None = None,
              end: int | None = None) -> str:
    """Read a workspace file, optionally from `start` through `end` (1-based)."""
    if start is not None and start < 1 or end is not None and end < 1:
        raise ValueError("line numbers start at 1")
    if start is not None and end is not None and start > end:
        raise ValueError("start must not exceed end")

    target = resolve(ws, path)
    if not target.is_file():
        raise FileNotFoundError(f"no such file: {path}")

    text = target.read_text(encoding="utf-8", errors="replace")
    lines = text.splitlines()
    first = start or 1
    last = min(end or len(lines), len(lines))
    stop = min(last, first + FILE_MAX_LINES - 1)
    result = "\n".join(lines[first - 1:stop])
    if stop < last:
        return f"{result}\n\n(truncated; request start={stop + 1})"
    if start is None and end is None:
        return text
    return result


def _patch_diff(pinned_root: Path, ws: Path, path: str) -> str:
    """Return the zero-context diff from the pinned file to its workspace copy."""
    original = resolve(pinned_root, path).read_text(encoding="utf-8", errors="replace")
    edited = resolve(ws, path).read_text(encoding="utf-8", errors="replace")
    return "".join(difflib.unified_diff(
        original.splitlines(keepends=True), edited.splitlines(keepends=True),
        fromfile=f"a/{path}", tofile=f"b/{path}", n=0,
    ))


def _applies(pinned_root: Path, diff: str) -> bool:
    return subprocess.run(
        ["git", "apply", "--check", "--unidiff-zero", "-"],
        cwd=pinned_root, input=diff, text=True, capture_output=True,
    ).returncode == 0


def _touches_flagged_line(diff: str, line: int) -> bool:
    for start, count in re.findall(r"^@@ -(\d+)(?:,(\d+))?", diff, re.MULTILINE):
        if int(count or 1) and int(start) <= line < int(start) + int(count or 1):
            return True
    return False


def _clean_rescan(ws: Path, alert: dict) -> bool:
    return not any(
        item["filename"] == alert["filename"]
        and item["line_number"] == alert["line_number"]
        and item["test_id"] == alert["test_id"]
        for item in _rescan(ws, alert["filename"])
    )


def patch_checks(pinned_root: Path, ws: Path, alert: dict) -> dict:
    """Compute the required patch-acceptance checks for one edited alert file."""
    path = alert["filename"]
    diff = _patch_diff(pinned_root, ws, path)
    checks = {"applies": None, "touches_flagged_line": None, "clean_rescan": None}
    if diff:
        checks = {
            "applies": _applies(pinned_root, diff),
            "touches_flagged_line": _touches_flagged_line(diff, alert["line_number"]),
            "clean_rescan": _clean_rescan(ws, alert),
        }
    return {"status": "accepted" if diff and all(checks.values()) else "rejected",
            "diff": diff, "checks": checks}


def _edit(ws: Path, path: str, old: str, new: str, *,
         pinned_root: Path | None = None, alert: dict | None = None) -> str | dict:
    """Replace exactly one occurrence and, when contextualized, validate the patch."""
    if not old:
        raise ValueError("old must not be empty")
    if (pinned_root is None) != (alert is None):
        raise ValueError("pinned_root and alert must be supplied together")
    if alert is not None and alert["filename"] != path:
        raise ValueError("edit path must match the selected alert")

    target = resolve(ws, path)
    if not target.is_file():
        raise FileNotFoundError(f"no such file: {path}")

    text = target.read_text(encoding="utf-8", errors="replace")
    count = text.count(old)
    if count != 1:
        raise ValueError(f"old must occur exactly once; found {count}")
    target.write_text(text.replace(old, new, 1), encoding="utf-8")
    if alert is None:
        return f"edited {path}"
    return patch_checks(pinned_root, ws, alert)


def _rescan(ws: Path, path: str) -> list[dict]:
    """Return MEDIUM-or-higher Bandit 1.9.4 alerts for one workspace file."""
    target = resolve(ws, path)
    if not target.is_file():
        raise FileNotFoundError(f"no such file: {path}")
    return Scan(ws).discover({
        "paths": [target.relative_to(Path(ws).resolve()).as_posix()],
        "exclude": [],
        "min_severity": "MEDIUM",
    })


def _search(ws: Path, pattern: str, *, path: str | None = None,
           selected_alert_file: str | None = None, is_owasp: bool = False) -> list[dict]:
    """Return matching lines from the selected OWASP case or target Python files."""
    try:
        expression = re.compile(pattern)
    except re.error as error:
        raise ValueError(f"invalid pattern {pattern!r}: {error}") from error

    root = Path(ws).resolve()
    if is_owasp:
        if not selected_alert_file:
            raise ValueError("an OWASP search requires a selected alert")
        if path is not None and path != selected_alert_file:
            raise ValueError("an OWASP search is limited to the selected alert")
        candidates = [resolve(root, selected_alert_file)]
    elif path is not None:
        candidates = [resolve(root, path)]
    else:
        candidates = sorted(root.glob("**/*.py"))

    hits = []
    for candidate in candidates:
        if not candidate.is_file():
            continue
        target = resolve(root, candidate.relative_to(root).as_posix())
        if ".git" in target.relative_to(root).parts:
            continue
        for line_number, line in enumerate(
            target.read_text(encoding="utf-8", errors="replace").splitlines(), 1
        ):
            if expression.search(line):
                hits.append({"file": target.relative_to(root).as_posix(),
                             "line": line_number, "text": line})
                if len(hits) >= SEARCH_MAX_HITS:
                    return hits
    return hits
