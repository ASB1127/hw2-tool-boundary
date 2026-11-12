import inspect
from dataclasses import asdict, dataclass, field
from pathlib import Path

from tools import SEARCH_MAX_HITS, TOOLS
from trace import Trace
from workspace import PathEscapeException

def registry_from_enum(tools=TOOLS) -> dict:
     return {member.name: member.value[0] for member in tools}


@dataclass
class Observation:
    tool: str
    args: dict = field(default_factory=dict)
    ok: bool = True
    result: str = ""

    def to_dict(self):
        return asdict(self)

class Dispatcher:
    def __init__(self, ws: Path, trace: Trace, alert_id: str,
                 registry: dict | None = None):
        self.ws = Path(ws)
        self.trace = trace
        self.alert_id = alert_id
        self.registry = registry_from_enum() if registry is None else registry

    def __call__(self, request:dict) -> Observation:
        return self.dispatch(request)

    def _refuse(self, tool: str, args: dict, reason: str) -> Observation:
        obs = Observation(tool=tool, args=args, ok=False, result=reason)
        self.trace.event("tool_result", alert_id=self.alert_id,
                         tool=tool, ok=False, error=reason)
        return obs

    def _observe(self, tool: str, args: dict, result: str) -> Observation:
        obs = Observation(tool=tool, args=args, ok=True, result=result)
        self.trace.event("tool_result", alert_id=self.alert_id,
                         tool=tool, ok=True, chars=len(result))
        return obs

    def _render(self, tool: str, value) -> str:
        """Tool return value -> the string the model reads."""
        if tool == "search":
            if not value:
                return "no matches"
            lines = [f"{h['file']}:{h['line']}: {h['text']}" for h in value]
            if len(value) >= SEARCH_MAX_HITS:
                lines.append(f"... stopped at {SEARCH_MAX_HITS} matches; "
                             "narrow the pattern to see the rest")
            return "\n".join(lines)
        return str(value)

    def dispatch(self, request) -> Observation:
        if not isinstance(request, dict):
            tool, args, reason = "invalid_request", {}, "tool request must be an object"
        else:
            tool = request.get("tool")
            args = request.get("args", {})
            reason = None
            if not isinstance(tool, str) or not tool:
                tool, reason = "invalid_request", "tool must be a non-empty string"
            elif not isinstance(args, dict):
                args, reason = {}, "tool args must be an object"
        self.trace.event("tool_request", alert_id=self.alert_id,
                         tool=tool, args=args)
        if reason:
            return self._refuse(tool, args, reason)
        function = self.registry.get(tool)
        if function is None:
            return self._refuse(tool, args,
                                f"unregistered tool {tool!r}; "
                                f"available: {', '.join(sorted(self.registry))}")

        try:
            inspect.signature(function).bind(self.ws, **args)
        except TypeError as e:
            return self._refuse(tool, args, f"incorrect args for {tool}: {e}")

        try:
            res = function(self.ws, **args)
        except PathEscapeException as e:
            return self._refuse(tool, args, f"refused: {e}")
        except (FileNotFoundError, ValueError) as e:
            return self._refuse(tool, args, f"tool error: {e}")
        except TypeError as e:
            return self._refuse(tool, args, f"bad argument type for {tool}: {e}")
        
        return self._observe(tool, args, self._render(tool, res))


