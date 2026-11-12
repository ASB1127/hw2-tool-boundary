import json
import tomllib
from dataclasses import dataclass, field, replace
from pathlib import Path

from jsonschema import validate


_PROJECT_ROOT = Path(__file__).resolve().parent
_SCHEMA_PATH = _PROJECT_ROOT.parent / "config.schema.json"


@dataclass(frozen=True)
class Config:
    fixture: Path = _PROJECT_ROOT / "targets" / "BenchmarkPython"
    scan: dict = field(default_factory=dict)
    model: dict = field(default_factory=lambda: {"provider": "openai", "name": "gpt-4o-mini"})
    budget: dict = field(default_factory=dict)
    agent: dict = field(default_factory=dict)
    mcp: dict = field(default_factory=dict)
    sandbox: dict = field(default_factory=dict)
    target_commit: str = ""
    workspace_prefix: str = "hw1-"

    def with_(self, **overrides) -> "Config":
        return replace(self, **overrides)


def load_config(path: Path, fixture: Path) -> Config:
    with Path(path).open("rb") as file:
        data = tomllib.load(file)
    validate(data, json.loads(_SCHEMA_PATH.read_text(encoding="utf-8")))
    return Config(
        fixture=Path(fixture),
        scan=data["scan"],
        model=data["model"],
        budget=data["budget"],
        agent=data["agent"],
        mcp=data["mcp"],
        sandbox=data["sandbox"],
        target_commit=data.get("target", {}).get("commit", ""),
    )
