from dataclasses import asdict, dataclass, field
from pathlib import Path
from client import MCPClient
from backend import SEARCH_MAX_HITS
from jsonschema import ValidationError, validate
from trace import Trace


@dataclass
class Observation:
    tool: str
    args: dict = field(default_factory=dict)
    ok: bool = True
    result: str = ""

    def to_dict(self):
        return asdict(self)


class Dispatcher:
    def __init__(self, ws: Path, trace: Trace, alert_id: str, registry: dict, client: MCPClient):
        self.ws = Path(ws)
        self.trace = trace
        self.alert_id = alert_id
        self.registry = registry
        self.client = client

    async def __call__(self, request: dict) -> Observation:
        return await  self.dispatch(request)


    def _refuse(self, tool: str, args: dict, reason: str,
                refused_by: str = "dispatcher") -> Observation:
        obs = Observation(tool=tool, args=args, ok=False, result=reason)
        self.trace.event("tool_result", alert_id=self.alert_id,
                         tool=tool, ok=False, error=reason, via="mcp",
                         refused_by=refused_by)
        return obs

    def _observe(self, tool: str, args: dict, result: str) -> Observation:
        obs = Observation(tool=tool, args=args, ok=True, result=result)
        self.trace.event("tool_result", alert_id=self.alert_id,
                         tool=tool, ok=True, chars=len(result), via="mcp")
        return obs

    def _render(self, tool: str, result) -> str:
        """MCP tool result -> the string the model reads."""
        if result.is_error:
            return "\n".join(getattr(content, "text", str(content))
                             for content in result.content)
        if tool == "search":
            hits = result.structured_content["result"]
            if not hits:
                return "no matches"
            lines = [f"{hit['file']}:{hit['line']}: {hit['text']}" for hit in hits]
            if len(hits) >= SEARCH_MAX_HITS:
                lines.append(f"... stopped at {SEARCH_MAX_HITS} matches; "
                             "narrow the pattern to see the rest")
            return "\n".join(lines)
        return "\n".join(getattr(content, "text", str(content))
                         for content in result.content)

    async def dispatch(self, request) -> Observation:
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
        self.trace.event("tool_request", alert_id=self.alert_id, tool=tool, args=args,
                         via="mcp")
        if reason:
            return self._refuse(tool, args, reason)
        definition = self.registry.get(tool)
        if definition is None:
            return self._refuse(tool, args, f"unregistered tool {tool!r}; "
                                f"available: {', '.join(sorted(self.registry))}")
        try:
            validate(args, definition.input_schema)
        except ValidationError as error:
            return self._refuse(tool, args,
                                f"incorrect args for {tool}: {error.message}")
        try:
            result = await self.client.call_tool(tool, args)
        except Exception as error:
            return self._refuse(tool, args, f"MCP call failed: {error}")
        rendered = self._render(tool, result)
        if result.is_error:
            refused_by = "kernel" if rendered.startswith("refused: kernel: ") else "server"
            return self._refuse(tool, args, rendered, refused_by=refused_by)
        return self._observe(tool, args, rendered)
