import argparse
import subprocess
import sys
import tomllib
from pathlib import Path


_ROOT = Path(__file__).resolve().parent


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--config", type=Path, required=True)
    args = parser.parse_args()

    with args.config.open("rb") as file:
        kind = tomllib.load(file).get("agent", {}).get("kind")
    if kind not in {"codeact", "mcp"}:
        parser.error("config agent.kind must be codeact or mcp")

    completed = subprocess.run([
        sys.executable, _ROOT / kind / "main.py",
        "--input", args.input,
        "--output", args.output,
        "--config", args.config,
    ])
    raise SystemExit(completed.returncode)


if __name__ == "__main__":
    main()
