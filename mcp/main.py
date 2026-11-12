import argparse
from pathlib import Path

from config import load_config
from runner import run


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--config", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)

    config = load_config(args.config, args.input)
    try:
        run(config, args.output)
    except RuntimeError as error:
        parser.exit(1, f"error: {error}\n")


if __name__ == "__main__":
    main()
