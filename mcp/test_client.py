import asyncio
from pathlib import Path
from types import SimpleNamespace

from mcp.client import stdio as mcp_stdio

from client import MCP_SHUTDOWN_GRACE_SECONDS, MCPClient


MCP_CONFIG = Path(__file__).parent.parent / "mcp.json"


def test_client_extends_mcp_shutdown_grace_period():
    assert mcp_stdio.PROCESS_TERMINATION_TIMEOUT == MCP_SHUTDOWN_GRACE_SECONDS == 15.0


def test_client_starts_server_with_only_its_workspace():
    client = MCPClient("/sandbox/work/target", MCP_CONFIG)

    assert client.params.args == ["-m", "server", "--workspace", "/sandbox/work/target"]


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
        client = MCPClient("/sandbox/work/target", MCP_CONFIG)
        assert await client.connect() == ["locate"]
        assert await client.call_tool("locate", {"path": "a.py", "line": 1}) == {
            "name": "locate", "arguments": {"path": "a.py", "line": 1},
        }
        await client.close()

    asyncio.run(run())
    assert events == [
        "transport enter", "session enter", "initialize", "session exit", "transport exit",
    ]
