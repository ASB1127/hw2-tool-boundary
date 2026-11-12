from __future__ import annotations

import json
import subprocess
import tempfile
from pathlib import Path


class Scan:
    def __init__(self, input_root: Path):
        self.input_root = Path(input_root)

    def expand_paths(self, patterns: list[str]) -> list[str]:
        paths = []
        for pattern in patterns:
            matches = sorted(self.input_root.glob(pattern))
            if not matches:
                raise ValueError(f"scan path matched nothing: {pattern}")
            paths.extend(path.relative_to(self.input_root).as_posix() for path in matches)
        return paths

    def bandit_args(self, scan_config: dict, paths: list[str], report: Path) -> list[str]:
        args = [
            "bandit", "-q", "-r",
            "--severity-level", scan_config["min_severity"].lower(),
            "-f", "json", "-o", str(report),
        ]
        if scan_config["exclude"]:
            args += ["-x", ",".join(scan_config["exclude"])]
        return [*args, *paths]

    def discover(self, scan_config: dict) -> list[dict]:
        root = Path(self.input_root).resolve()
        paths = self.expand_paths(scan_config["paths"])

        with tempfile.TemporaryDirectory(dir=root.parent) as output_dir:
            report = Path(output_dir) / "bandit.json"
            try:
                completed = subprocess.run(
                    self.bandit_args(scan_config, paths, report),
                    cwd=root, text=True, capture_output=True,
                )
            except FileNotFoundError as error:
                raise RuntimeError(
                    "Bandit 1.9.4 was not found; activate the environment or install dependencies."
                ) from error
            if completed.returncode not in (0, 1):  # 1 means Bandit found alerts.
                raise RuntimeError(completed.stderr.strip() or "Bandit failed")
            alerts = json.loads(report.read_text(encoding="utf-8"))["results"]

        for alert in alerts:
            alert["filename"] = alert["filename"].removeprefix("./")
        return alerts
