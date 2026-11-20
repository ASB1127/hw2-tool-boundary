import asyncio
from types import SimpleNamespace

import pytest

from dispatcher import Dispatcher


@pytest.mark.parametrize(("message", "layer"), [
    ("refused: kernel: [Errno 13] Permission denied", "kernel"),
    ("refused: unsafe workspace path", "server"),
    ("refused: path named refused: kernel: secret", "server"),
    ("Error executing tool read_file: refused: kernel: secret", "server"),
])
def test_mcp_refusal_attribution(tmp_path, message, layer):
    events = []
    trace = SimpleNamespace(event=lambda kind, **fields: events.append((kind, fields)))

    class Client:
        async def call_tool(self, name, args):
            return SimpleNamespace(is_error=True, content=[SimpleNamespace(text=message)])

    tool = SimpleNamespace(input_schema={"type": "object"})
    dispatcher = Dispatcher(tmp_path, trace, "alert", {"read_file": tool}, Client())
    observation = asyncio.run(dispatcher({"tool": "read_file", "args": {}}))

    assert not observation.ok
    assert events[-1][1]["refused_by"] == layer
