from __future__ import annotations

import re
from enum import Enum
from pathlib import Path

from langchain_core.tools import tool

from workspace import resolve, PathEscapeException


SEARCH_MAX_HITS = 10
FILE_MAX_LINES = 200
DIR_MAX_ENTRIES = 100

def read_file(ws: Path, path: str, start: int | None = None,
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


def search(ws: Path, pattern: str, *, selected_alert_file: str | None = None,
           is_owasp: bool = False) -> list[dict]:
    """Return matching lines from the selected OWASP case or target Python files."""
    try:
        expression = re.compile(pattern)
    except re.error as error:
        raise ValueError(f"invalid pattern {pattern!r}: {error}") from error

    root = Path(ws).resolve()
    if is_owasp:
        if not selected_alert_file:
            raise ValueError("an OWASP search requires a selected alert")
        candidates = [resolve(root, selected_alert_file)]
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

def list_directory(ws: Path, path: str = ".") -> list[dict]:
    """List files and directories in a workspace-relative directory."""
    target = resolve(ws, path)

    if not target.is_dir():
        raise FileNotFoundError(f"no such directory: {path}")

    root = Path(ws).resolve()
    entries = []

    for child in sorted(target.iterdir(), key=lambda p: p.name):
        # Reuse workspace containment checks for every entry.
        try:
            resolved = resolve(root, child.relative_to(root).as_posix())
        except PathEscapeException:
            continue

        entries.append({
            "name": child.name,
            "type": "directory" if resolved.is_dir() else "file",
        })

        if len(entries) >= DIR_MAX_ENTRIES:
            break

    return entries


class TOOLS(Enum):
    read_file = (read_file,)
    search = (search,)
    list_directory = (list_directory,)

    def __call__(self, *args, **kwargs):
        return self.value[0](*args, **kwargs)


def _dispatcher_executes(name: str):
    raise RuntimeError(
        f"{name} was called directly; tool execution belongs to the dispatcher")


@tool("read_file")
def read_file_schema(path: str, start: int | None = None,
                     end: int | None = None) -> str:
    """Read a repository-relative file.

    `start` and `end` select an inclusive, 1-based line range. Each call
    returns at most 200 lines and names the next `start` when truncated.
    """
    _dispatcher_executes("read_file")


@tool("search")
def search_schema(pattern: str) -> str:
    """Search the current OWASP alert file or target Python files with a regex."""
    _dispatcher_executes("search")

@tool("list_directory")
def list_directory_schema(path: str = ".") -> str:
    """List files and subdirectories at a repository-relative path.

    Returns up to 100 entries. Refuses paths outside the workspace
    and nonexistent directories.
    """
    _dispatcher_executes("list_directory")


class ToolBundle:
    READ_FILE = read_file_schema
    SEARCH = search_schema
    LIST_DIRECTORY = list_directory_schema

    @classmethod
    def get_all_tools(cls) -> list:
        return [cls.READ_FILE, cls.SEARCH, cls.LIST_DIRECTORY]
