import asyncio
from types import SimpleNamespace

from client import MCPClient


def test_client_initializes_discovers_calls_and_closes(monkeypatch):
    events = []

    class Transport:
        async def __aenter__(self):
            events.append("transport enter")
            return "read", "write"

        async def __aexit__(self, *args):
            events.append("transport exit")

    class Session:
        def __init__(self, read, write):
            assert (read, write) == ("read", "write")

        async def __aenter__(self):
            events.append("session enter")

        async def __aexit__(self, *args):
            events.append("session exit")

        async def initialize(self):
            events.append("initialize")

        async def list_tools(self):
            return SimpleNamespace(tools=["locate"])

        async def call_tool(self, name, arguments):
            return {"name": name, "arguments": arguments}

    monkeypatch.setattr("client.stdio_client", lambda params: Transport())
    monkeypatch.setattr("client.ClientSession", Session)

    async def run():
        client = MCPClient("/sandbox/work/target")
        assert await client.connect() == ["locate"]
        assert await client.call_tool("locate", {"path": "a.py", "line": 1}) == {
            "name": "locate", "arguments": {"path": "a.py", "line": 1},
        }
        await client.close()

    asyncio.run(run())
    assert events == [
        "transport enter", "session enter", "initialize", "session exit", "transport exit",
    ]
