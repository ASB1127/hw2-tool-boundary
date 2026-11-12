from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass
from enum import Enum
from pathlib import Path

class TerminalStatus(str,Enum):
    __str__ = str.__str__
    COMPLETE = "complete"
    BUDGET_EXHAUSTED = "budget_exhausted"
    MAX_STEPS = "max_steps"
    NO_PROGRESS = "no_progress"
    ERROR = "error"

    @classmethod
    def values(cls) -> frozenset[str]:
        return frozenset(status.value for status in cls)

class EventKind(str,Enum):
    __str__ = str.__str__
    MODEL_CALL = "model_call"
    TOOL_REQUEST = "tool_request"
    TOOL_RESULT = "tool_result"
    STATE_CHANGE = "state_change"
    ROUTING = "routing"
    TERMINAL= "terminal"

    @classmethod
    def values(cls) -> frozenset[str]:
        return frozenset(kind.value for kind in cls)

@dataclass
class USAGE:
    input: int = 0
    output: int = 0
    cache_read: int = 0
    cache_write: int = 0

    def add(self, **counts: int) -> None:
        for name, value in counts.items():
            if not hasattr(self, name):
                raise ValueError(f"unknown token counter: {name!r}")
            setattr(self, name, getattr(self, name) + int(value))
    def as_dict(self) -> dict[str, int]:
        return asdict(self)

class NoTerminalStatus(Exception):
    """A run was closed without stating how it ended."""

class Trace:
    def __init__(self, run_id: str, path: Path, on_event=None, on_close=None):
        self.run_id = run_id
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._fh = self.path.open("w", encoding="utf-8")
        self._step = 0
        self._terminal: str | None = None
        self.usage = USAGE()
        self.on_event = on_event
        self.on_close = on_close

    def event(self, kind: str, **fields) -> dict:
        if kind not in EventKind.values():
            raise ValueError(f"unknown event kind {kind!r}; add it to EventKind deliberately")
        if self._terminal is not None:
            raise RuntimeError(f"{self.run_id} already ended with {self._terminal!r}")
        if kind == "model_call" and fields.get("usage"):
            self.usage.add(**fields["usage"])

        fields.setdefault("alert_id", None)
        self._step += 1
        record = {"step": self._step, "ts": time.time(), "run_id": self.run_id, "kind": kind, **fields}
        self._fh.write(json.dumps(record, default=str) + "\n")
        self._fh.flush()
        if self.on_event is not None:
            self.on_event(record)
        return record

    def terminal(self, status: str) -> dict:
        if status not in TerminalStatus.values():
            raise ValueError(f"unknown terminal status {status!r}; one of {sorted(TerminalStatus.values())}")
        record = self.event("terminal", status=status, usage_total=self.usage.as_dict())
        self._terminal = status
        return record

    def close(self) -> None:
        if self.on_close is not None:
            try:
                self.on_close(self)
            except Exception:
                pass
        self._fh.close()
        if self._terminal is None:
            raise NoTerminalStatus(f"{self.run_id} closed without a terminal status — see {self.path}")

    def __enter__(self) -> "Trace":
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        if exc_type is not None and self._terminal is None:
            self.event("state_change", node="runtime", exception=exc_type.__name__, message=str(exc_value))
            self.terminal("error")
        self.close()


def read_events(path: Path) -> list[dict]:
    return [json.loads(line) for line in Path(path).read_text().splitlines() if line.strip()]


def kinds(events: list[dict]) -> list[str]:
    return [event["kind"] for event in events]


def stable(events: list[dict]) -> list[dict]:
    return [{k: v for k, v in event.items() if k != "ts"} for event in events]


def compare(a: Path, b: Path) -> list[str]:
    left, right = stable(read_events(a)), stable(read_events(b))
    diffs = []
    for i in range(max(len(left), len(right))):
        x = left[i] if i < len(left) else None
        y = right[i] if i < len(right) else None
        if x != y:
            diffs.append(f"step {i + 1}: {x} != {y}")
    return diffs
