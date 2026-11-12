from __future__ import annotations

import shutil
import tempfile
from pathlib import Path


WITHHELD_GLOBS = (".git",)
OWASP_WITHHELD_GLOBS = (
    "**/expectedresults*.csv",
    "testcode/BenchmarkTest*.py",
    "templates/web/*/BenchmarkTest*.html",
)
STASH_SUFFIX = "-withheld"


class PathEscapeException(ValueError):
    pass


def resolve(root: Path, path: str) -> Path:
    """Return a repository-relative path inside ``root``."""
    requested = Path(path)
    if requested.is_absolute() or ".." in requested.parts:
        raise PathEscapeException(f"unsafe workspace path: {path!r}")

    root = Path(root).resolve()
    candidate = (root / requested).resolve()
    if not candidate.is_relative_to(root):
        raise PathEscapeException(f"{path!r} resolves outside the workspace root")
    return candidate


class AgentWorkspace:
    def __init__(self, config, *, is_owasp: bool, case: str | None = None,
                 keep: bool = False):
        self.config = config
        self.is_owasp = is_owasp
        self.case = case
        self.keep = keep
        self.root: Path | None = None
        self.stash: Path | None = None

    def __enter__(self) -> Path:
        if self.root is not None:
            raise RuntimeError("workspace already open")
        if self.is_owasp and not self.case:
            raise ValueError("an OWASP workspace requires the current alert case")

        source = Path(self.config.fixture).resolve()
        if not source.is_dir():
            raise FileNotFoundError(f"fixture not found: {source}")

        dest = Path(tempfile.mkdtemp(prefix=self.config.workspace_prefix))
        try:
            shutil.copytree(source, dest, dirs_exist_ok=True, symlinks=True)
        except BaseException:
            shutil.rmtree(dest, ignore_errors=True)
            raise

        self.root = dest.resolve()
        self.stash = self._withhold()
        return self.root

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        if self.root is None:
            return
        self._restore()
        if self.keep or exc_type is not None:
            print(f"workspace kept for inspection: {self.root}")
        else:
            shutil.rmtree(self.root, ignore_errors=True)
        self.root = None

    def withheld(self) -> list[Path]:
        if self.stash is None or not self.stash.is_dir():
            return []
        return sorted(p for p in self.stash.rglob("*") if p.is_file())

    def _withhold(self) -> Path:
        stash = self.root.parent / f"{self.root.name}{STASH_SUFFIX}"
        patterns = WITHHELD_GLOBS
        if self.is_owasp:
            patterns += OWASP_WITHHELD_GLOBS

        for pattern in patterns:
            for path in sorted(self.root.glob(pattern)):
                if path.stem == self.case:
                    continue
                target = stash / path.relative_to(self.root)
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.move(str(path), str(target))
        return stash

    def _restore(self) -> None:
        if self.stash is None or not self.stash.is_dir():
            return
        for path in sorted(self.stash.rglob("*")):
            if path.is_file() or path.is_symlink():
                target = self.root / path.relative_to(self.stash)
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.move(str(path), str(target))
        shutil.rmtree(self.stash, ignore_errors=True)
        self.stash = None
